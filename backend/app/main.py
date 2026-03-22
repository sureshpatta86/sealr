import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import socketio
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.api import auth, dashboard, fixes, health, languages, repositories, scans, vulnerabilities, webhooks
from app.config import settings
from app.utils.database import init_db
from app.websocket.manager import WebSocketManager, start_redis_subscriber, init_dev_mode

# Rate limiter — 60 requests/minute per IP by default
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])

# Socket.IO server
sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins=[settings.FRONTEND_URL],
)

ws_manager = WebSocketManager(sio)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    if settings.DEV_MODE:
        init_dev_mode(sio, asyncio.get_event_loop())
    subscriber_task = None
    if not settings.DEV_MODE:
        subscriber_task = asyncio.create_task(start_redis_subscriber(ws_manager))
    yield
    if subscriber_task:
        subscriber_task.cancel()


app = FastAPI(
    title="Sealr API",
    description="GitHub Vulnerability Scanner & Auto-Fix Platform",
    version="2.0.0",
    lifespan=lifespan,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routers
app.include_router(health.router)
app.include_router(auth.router, prefix="/api")
app.include_router(languages.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(vulnerabilities.router, prefix="/api")
app.include_router(fixes.router, prefix="/api")
app.include_router(repositories.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(webhooks.router, prefix="/api")

# Mount Socket.IO as ASGI sub-application
socket_app = socketio.ASGIApp(sio, other_asgi_app=app)


@sio.on("connect")
async def on_connect(sid, environ):
    pass


@sio.on("join_scan")
async def on_join_scan(sid, data):
    scan_id = data.get("scan_id")
    if scan_id:
        await sio.enter_room(sid, f"scan_{scan_id}")


@sio.on("leave_scan")
async def on_leave_scan(sid, data):
    scan_id = data.get("scan_id")
    if scan_id:
        await sio.leave_room(sid, f"scan_{scan_id}")


@sio.on("disconnect")
async def on_disconnect(sid):
    pass
