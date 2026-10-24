# infra/ — Docker, Compose, nginx

Deployment scaffolding for the hackathon profile (blueprint §9):
**Next.js + FastAPI + one worker process + SQLite + optional Redis.**

## Files

| File | Purpose |
| --- | --- |
| `Dockerfile.api` | FastAPI control plane image (uv workspace, port 8000) |
| `Dockerfile.worker` | Evaluation worker image (imports `app.*` domain; ships fixtures + attack catalog) |
| `Dockerfile.web` | Next.js standalone image (port 3000) |
| `docker-compose.yml` | api + worker + web + shared SQLite volume; optional redis (commented) and nginx (`proxy` profile) |
| `nginx.conf` | SSE-safe reverse proxy config (buffering off on the event stream) |

## Run

```bash
# from the repo root
docker compose -f infra/docker-compose.yml up --build

# with the optional reverse proxy (http://localhost:8080)
docker compose -f infra/docker-compose.yml --profile proxy up --build
```

- Web: http://localhost:3000
- API: http://localhost:8000/docs (health: `/health`, readiness: `/ready`)

All build contexts are the **repo root** (`-f infra/...` from the root), because
the uv workspace and repo-root-relative paths (`repo_root()`, attack catalog,
ShopHelper fixtures) must resolve inside the images.

## Volume and state

One named volume `raven-data` is mounted at `/data` in **both** `api` and
`worker`:

- `RAVEN_DATABASE_URL=sqlite:////data/raven.db` — single shared SQLite file
- `RAVEN_EVIDENCE_DIR=/data/evidence` — transcripts, diffs, report artifacts

The API owns schema migrations at startup; the worker starts only after the
API healthcheck passes.

Backup / restore:

```bash
docker run --rm -v raven_raven-data:/data -v "$PWD:/backup" alpine \
  tar czf /backup/raven-data.tgz -C /data .

docker run --rm -v raven_raven-data:/data -v "$PWD:/backup" alpine \
  sh -c "cd /data && tar xzf /backup/raven-data.tgz"
```

Reset the demo state: `docker compose -f infra/docker-compose.yml down -v`.

## Optional Redis

Uncomment the `redis` service in `docker-compose.yml` and set
`RAVEN_REDIS_URL=redis://redis:6379/0` (in `.env` or the service env blocks).
With the variable empty, the stack uses the in-process SQLite queue — the
default and the demo-safe choice.

## Prerequisites and known limits

- `Dockerfile.web` expects `apps/web` to provide `package.json`, a `build`
  script, and `output: "standalone"` in `next.config.*`. Until the frontend
  lands, the `web` service build will fail; `api` and `worker` build
  independently.
- `uv.lock` is gitignored, so image builds resolve dependencies fresh. If a
  lockfile is ever committed, switch the `uv sync` steps to `--frozen` for
  reproducible builds.
- Images run as root so the shared SQLite volume is writable without
  pre-provisioned ownership. Acceptable for the hackathon profile; the
  production profile should run non-root with managed Postgres/Redis.
- Model credentials come from the host environment / `.env` at runtime and are
  never copied into images or logs (CLAUDE.md safety rule 10).
