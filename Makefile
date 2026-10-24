# RAVEN — top-level task runner (hackathon profile by default)

API_DIR := apps/api
WORKER_DIR := workers/evaluator
WEB_DIR := apps/web

.PHONY: install dev api worker web test lint clean data-dir

install: data-dir
	uv sync --directory $(API_DIR)
	uv sync --directory $(WORKER_DIR)
	cd $(WEB_DIR) && npm install

data-dir:
	mkdir -p data

api: data-dir
	uv run --directory $(API_DIR) uvicorn app.main:app --reload \
		--host $${RAVEN_API_HOST:-0.0.0.0} --port $${RAVEN_API_PORT:-8000}

worker: data-dir
	uv run --directory $(WORKER_DIR) python -m evaluator.worker

web:
	cd $(WEB_DIR) && npm run dev

# Hackathon profile: API + worker in background, web in foreground.
# scripts/dev.sh cleans up background processes on exit.
dev: data-dir
	./scripts/dev.sh

test:
	uv run --directory $(API_DIR) pytest tests -q
	uv run --directory $(WORKER_DIR) pytest tests -q

lint:
	uv run --directory $(API_DIR) ruff check app tests
	uv run --directory $(WORKER_DIR) ruff check evaluator tests
	cd $(WEB_DIR) && npx tsc --noEmit

clean:
	rm -rf $(API_DIR)/.pytest_cache $(WORKER_DIR)/.pytest_cache data/*.sqlite*
