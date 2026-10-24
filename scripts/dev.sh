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

(cd "$ROOT/apps/api" && uv run uvicorn app.main:app --reload --host "${RAVEN_API_HOST:-0.0.0.0}" --port "${RAVEN_API_PORT:-8000}") &
PIDS+=($!)

(cd "$ROOT/workers/evaluator" && uv run python -m evaluator.worker) &
PIDS+=($!)

(cd "$ROOT/apps/web" && npm run dev) &
PIDS+=($!)

wait -n
