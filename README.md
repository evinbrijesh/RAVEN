# RAVEN — Red-team Analysis, Verification, Enforcement, and Normal-use Assurance

RAVEN is a bounded, human-supervised security regression system for LLM
applications. It scans a built-in local ShopHelper bot with an approved attack
suite, judges results with deterministic checks plus an optional structured
LLM judge, proposes hardening as a reviewable diff, requires explicit human
approval, and re-tests both security and normal-use behavior — turning LLM
security from a one-time audit into a repeatable regression suite.

## Quickstart (hackathon profile)

```bash
make install
make dev
```

- Web: http://localhost:3000
- API: http://localhost:8000/docs (health: `/health`, readiness: `/ready`)

The default profile uses SQLite and an in-process worker queue — no external
services required. A Docker Compose profile (api + worker + web + SQLite
volume, optional Redis and nginx proxy) lives in `infra/`:

```bash
docker compose -f infra/docker-compose.yml up --build
```

For the recommended 5-minute pitch walkthrough, see `docs/DEMO_SCRIPT.md`.

## What it does

1. **Scan** the built-in ShopHelper target with ~12 approved attack cases
   across four categories: prompt injection, canary leakage, sensitive-data
   probing, tool misuse.
2. **Judge** every run with deterministic checks (canary, secret, PII,
   tool-policy) first; an optional structured LLM judge adds semantic
   analysis. Disagreements resolve to `needs_review`, never a guess.
3. **Propose** at most one hardening change per failed case, shown as a diff.
4. **Approve** — nothing is applied without an explicit human decision.
5. **Retest** security (attack now blocked) and utility (benign suite still
   passes), saving regression cases for future scans.
6. **Report** with full evidence, exportable as JSON and Markdown.

Every run is bounded: attack count, retries, timeouts, concurrency, and
model-call budgets are enforced in code.

## Repository layout

```text
apps/web/               Next.js frontend (scan setup, live progress, findings, report)
apps/api/               FastAPI control plane (scans, findings, policies, reports, SSE)
workers/evaluator/      Evaluation worker (state machine, targets, judges, hardening, regression)
packages/contracts/     Shared JSON/OpenAPI schemas
packages/attack-catalog/ Versioned attack and benign cases
packages/ui/            Optional shared UI primitives
fixtures/               ShopHelper fixtures and demo scan config (synthetic data only)
infra/                  Dockerfiles, docker-compose, nginx (SSE-safe proxy)
docs/                   PRD, architecture, threat model, API contract, demo script
```

See `docs/ARCHITECTURE_SCAFFOLD.md` for the full blueprint and `CLAUDE.md`
for coding conventions and safety rules.

## Scan lifecycle

```text
created → reconning → attacking → judging → hardening_proposed
        → awaiting_approval → retesting → completed
```

Any phase can end in `failed_partial` (case timeouts, model unavailability —
partial results are preserved) or `failed_fatal`. The full status and finding
label vocabulary is defined in `CLAUDE.md`.

## Safety model

RAVEN only evaluates the built-in ShopHelper simulation. It never performs
real refunds, emails, payments, or network actions; all target and model
output is treated as untrusted data; hardening changes are never
auto-deployed; and a clean result is explicitly not a security guarantee.
Details: `SECURITY.md`, `docs/THREAT_MODEL.md`.

## Configuration

Copy `.env.example` to `.env`. Key variables:

| Variable | Purpose |
| --- | --- |
| `RAVEN_DATABASE_URL` | SQLite path for the hackathon profile |
| `RAVEN_REDIS_URL` | Empty → in-process queue; set to enable Redis |
| `RAVEN_MODEL_PROVIDER` / `_NAME` / `_API_KEY` / `_BASE_URL` | Model plane; `none` runs deterministic-only |
| `RAVEN_MAX_ATTACK_CASES`, `RAVEN_MAX_MODEL_CALLS`, ... | Scan budgets (enforced, configurable) |
| `NEXT_PUBLIC_API_URL` | API base URL for the web app |

## Development

```bash
make test    # API + worker pytest suites
make lint    # ruff + tsc
make clean   # remove caches and local SQLite data
```

Core logic is testable without an LLM; the model provider defaults to `none`.

## Deferred scope

Arbitrary external HTTP targets, SARIF, GitHub Actions, full MITRE ATLAS
taxonomy, Postgres/Redis by default, multi-agent swarms, and automatic
production changes are intentionally out of the MVP. See `CLAUDE.md`.

## License

See `LICENSE`. Security disclosures: `SECURITY.md`.
