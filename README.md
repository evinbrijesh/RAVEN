# RAVEN — Red-team Analysis, Verification, Enforcement, and Normal-use Assurance

RAVEN is a bounded, human-supervised security regression system for LLM
applications. It scans a built-in local ShopHelper bot with an approved attack
suite, judges results with deterministic checks plus an optional structured
LLM judge, proposes hardening, requires human approval, and re-tests both
security and normal-use behavior.

## Quickstart (hackathon profile)

```bash
make install
make dev
```

- Web: http://localhost:3000
- API: http://localhost:8000/docs

The default profile uses SQLite and an in-process worker queue — no external
services required. Redis/PostgreSQL profiles are available via Docker Compose
(see `infra/`).

## Repository layout

See `docs/ARCHITECTURE_SCAFFOLD.md` for the full blueprint and `CLAUDE.md`
for coding conventions and safety rules.

## Safety

RAVEN only evaluates the built-in ShopHelper simulation. It never performs
real refunds, emails, payments, or network actions, and hardening changes are
never auto-deployed — they require explicit human approval and only apply to
the temporary evaluation target. See `SECURITY.md`.
