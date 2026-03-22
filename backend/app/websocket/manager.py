"""WebSocket event manager for real-time scan updates.

Celery workers can't access the Socket.IO server directly (different process).
We use Redis pub/sub as a bridge:
  - Workers call `publish_event()` to push events to Redis
  - FastAPI background task subscribes to Redis and emits via Socket.IO
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any

import redis

from app.config import settings

logger = logging.getLogger(__name__)

# DEV_MODE: direct emit without Redis
_sio = None
_main_loop = None


def init_dev_mode(sio, loop) -> None:
    """Call once at startup in DEV_MODE to enable direct socket.io emission."""
    global _sio, _main_loop
    _sio = sio
    _main_loop = loop

# Redis channel for scan events
SCAN_EVENTS_CHANNEL = "sealr:scan_events"


class WebSocketManager:
    """Emits events to Socket.IO rooms for scan progress tracking."""

    def __init__(self, sio):
        self.sio = sio

    async def emit_scan_started(self, scan_id: str):
        await self.sio.emit(
            "scan_event",
            {"scan_id": scan_id, "event_type": "scan.started", "message": "Scan started", "metadata": {"status": "cloning"}},
            room=f"scan_{scan_id}",
        )

    async def emit_scan_progress(
        self, scan_id: str, scanner: str, progress: int, message: str
    ):
        await self.sio.emit(
            "scan_event",
            {
                "scan_id": scan_id,
                "event_type": "scan.progress",
                "message": message,
                "metadata": {"scanner": scanner, "progress": progress},
            },
            room=f"scan_{scan_id}",
        )

    async def emit_vulnerability_found(
        self, scan_id: str, vulnerability: dict[str, Any]
    ):
        await self.sio.emit(
            "scan_event",
            {"scan_id": scan_id, "event_type": "scan.vulnerability.found", "message": f"Found: {vulnerability.get('title', 'unknown')}", "metadata": vulnerability},
            room=f"scan_{scan_id}",
        )

    async def emit_fix_generated(
        self, scan_id: str, fix: dict[str, Any]
    ):
        await self.sio.emit(
            "scan_event",
            {"scan_id": scan_id, "event_type": "scan.fix.generated", "message": f"Fix generated ({fix.get('model', 'unknown')})", "metadata": fix},
            room=f"scan_{scan_id}",
        )

    async def emit_fix_validated(
        self, scan_id: str, fix_id: str, build_passed: bool
    ):
        await self.sio.emit(
            "scan_event",
            {
                "scan_id": scan_id,
                "event_type": "scan.fix.validated",
                "message": f"Fix {'passed' if build_passed else 'failed'} validation",
                "metadata": {"fix_id": fix_id, "build_passed": build_passed},
            },
            room=f"scan_{scan_id}",
        )

    async def emit_pr_created(
        self, scan_id: str, fix_id: str, pr_url: str
    ):
        await self.sio.emit(
            "scan_event",
            {"scan_id": scan_id, "event_type": "scan.pr.created", "message": f"PR created: {pr_url}", "metadata": {"fix_id": fix_id, "pr_url": pr_url}},
            room=f"scan_{scan_id}",
        )

    async def emit_scan_completed(
        self, scan_id: str, summary: dict[str, Any]
    ):
        await self.sio.emit(
            "scan_event",
            {"scan_id": scan_id, "event_type": "scan.completed", "message": "Scan completed", "metadata": summary},
            room=f"scan_{scan_id}",
        )

    async def emit_scan_failed(self, scan_id: str, error: str):
        await self.sio.emit(
            "scan_event",
            {"scan_id": scan_id, "event_type": "scan.failed", "message": error, "metadata": {}},
            room=f"scan_{scan_id}",
        )

    async def handle_redis_event(self, event_data: dict):
        """Route a Redis pub/sub event to the correct Socket.IO room."""
        scan_id = event_data.get("scan_id")
        if not scan_id:
            return
        await self.sio.emit("scan_event", event_data, room=f"scan_{scan_id}")


# ---------------------------------------------------------------------------
# Redis pub/sub bridge (used by Celery workers)
# ---------------------------------------------------------------------------

def publish_event(
    scan_id: str,
    event_type: str,
    message: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Publish a scan event — directly to socket.io in DEV_MODE, via Redis in production."""
    payload = {
        "scan_id": scan_id,
        "event_type": event_type,
        "message": message,
        "metadata": metadata or {},
        "timestamp": datetime.utcnow().isoformat(),
    }

    if settings.DEV_MODE:
        if _sio and _main_loop:
            try:
                current = asyncio.get_event_loop()
            except RuntimeError:
                current = None

            if current is _main_loop:
                # Called from within the main event loop (BackgroundTasks path)
                current.create_task(_sio.emit("scan_event", payload, room=f"scan_{scan_id}"))
            elif _main_loop.is_running():
                # Called from a worker thread (ThreadPoolExecutor / create_pr_task path)
                asyncio.run_coroutine_threadsafe(
                    _sio.emit("scan_event", payload, room=f"scan_{scan_id}"),
                    _main_loop,
                )
        return

    try:
        r = redis.from_url(settings.REDIS_URL)
        r.publish(SCAN_EVENTS_CHANNEL, json.dumps(payload))
        r.close()
    except Exception as e:
        logger.error(f"Failed to publish event to Redis: {e}")


async def start_redis_subscriber(ws_manager: WebSocketManager) -> None:
    """Background task that subscribes to Redis and forwards events to Socket.IO."""
    try:
        r = redis.from_url(settings.REDIS_URL)
        pubsub = r.pubsub()
        pubsub.subscribe(SCAN_EVENTS_CHANNEL)
        logger.info("Redis subscriber started for scan events")

        while True:
            message = pubsub.get_message(ignore_subscribe_messages=True, timeout=0.1)
            if message and message["type"] == "message":
                try:
                    event_data = json.loads(message["data"])
                    await ws_manager.handle_redis_event(event_data)
                except (json.JSONDecodeError, Exception) as e:
                    logger.error(f"Error processing Redis message: {e}")
            await asyncio.sleep(0.05)
    except Exception as e:
        logger.error(f"Redis subscriber error: {e}")
