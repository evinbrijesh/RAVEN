#!/usr/bin/env bash
# Unified backend runner for RAVEN:
# Runs database migrations, launches the background evaluator worker,
# and starts the FastAPI control plane API in the foreground.
# Gracefully propagates termination signals (SIGTERM/SIGINT) to both processes.

set -euo pipefail

echo "==> [RAVEN] Bootstrapping backend services..."

# 1. Initialize SQLite schema & run migrations
echo "==> [RAVEN] Running SQLite database migrations..."
python -c "
from app.infrastructure.db.sqlite import Database
from app.config import get_settings
settings = get_settings()
db = Database(settings.database_path)
db.migrate()
print(f'==> [RAVEN] Database migrated successfully at: {settings.database_path}')
"

# 2. Start Evaluator Worker in the background
echo "==> [RAVEN] Starting evaluation worker daemon..."
python -m evaluator.worker &
WORKER_PID=$!
echo "==> [RAVEN] Evaluation worker started with PID ${WORKER_PID}"

# 3. Trap signals for graceful shutdown of worker
cleanup() {
    echo "==> [RAVEN] Received termination signal. Stopping evaluation worker (PID: ${WORKER_PID})..."
    kill -TERM "$WORKER_PID" 2>/dev/null || true
    wait "$WORKER_PID" 2>/dev/null || true
    echo "==> [RAVEN] Worker stopped. Exiting."
}
trap cleanup SIGTERM SIGINT EXIT

# 4. Start FastAPI Control Plane API in foreground
PORT="${PORT:-${RAVEN_API_PORT:-8000}}"
HOST="${RAVEN_API_HOST:-0.0.0.0}"
echo "==> [RAVEN] Starting FastAPI server on ${HOST}:${PORT}..."
uvicorn app.main:app --host "$HOST" --port "$PORT"
