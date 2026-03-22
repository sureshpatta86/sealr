#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

# Load .env so USE_LOCAL_INFRA is available
if [ -f "$ROOT/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
fi

cleanup() {
  echo ""
  echo "Stopping..."
  kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
  wait "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
  if [ "${USE_LOCAL_INFRA:-true}" = "true" ]; then
    echo "Stopping infra..."
    docker compose -f "$ROOT/docker/docker-compose.yml" down
  fi
}
trap cleanup INT TERM EXIT

if [ "${USE_LOCAL_INFRA:-true}" = "true" ]; then
  echo "Starting infra..."
  docker compose -f "$ROOT/docker/docker-compose.yml" up -d
else
  echo "Skipping infra (USE_LOCAL_INFRA=false)"
fi

# Kill anything already on ports 8000 and 3000
for PORT in 8000 3000; do
  PIDS=$(lsof -ti :"$PORT" 2>/dev/null) || true
  if [ -n "$PIDS" ]; then
    echo "Killing existing process on port $PORT (PID $PIDS)..."
    kill -9 $PIDS 2>/dev/null || true
  fi
done

echo "Starting backend..."
(cd "$ROOT/backend" && . venv/bin/activate && uvicorn app.main:socket_app --reload --port 8000) &
BACKEND_PID=$!

echo "Starting frontend..."
(cd "$ROOT/frontend" && npm run dev) &
FRONTEND_PID=$!

echo "Backend PID: $BACKEND_PID | Frontend PID: $FRONTEND_PID"
echo "Press Ctrl+C to stop both."

wait "$BACKEND_PID" "$FRONTEND_PID"
