#!/usr/bin/env bash
# RAVEN dev runner: API + evaluator worker in background, web in foreground.
# Cleans up background processes when the script exits (Ctrl+C included).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

mkdir -p "$ROOT/data"
export RAVEN_DATABASE_URL="${RAVEN_DATABASE_URL:-sqlite:///$ROOT/data/raven.db}"

(cd "$ROOT/apps/api" && uv run uvicorn app.main:app --reload --host "${RAVEN_API_HOST:-0.0.0.0}" --port "${RAVEN_API_PORT:-8000}") &
PIDS+=($!)

(cd "$ROOT/workers/evaluator" && uv run python -m evaluator.worker) &
PIDS+=($!)

API_PORT="${RAVEN_API_PORT:-8000}"
echo "Waiting for RAVEN API to bind on port $API_PORT..."
for _ in $(seq 1 40); do
  if curl -s "http://127.0.0.1:$API_PORT/health" >/dev/null 2>&1; then
    echo "✓ RAVEN API is healthy"
    break
  fi
  sleep 0.25
done

(cd "$ROOT/apps/web" && npm run dev) &
PIDS+=($!)

wait -n
