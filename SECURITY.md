# Security Policy

## Scope

RAVEN is a security evaluation tool for a **simulated** LLM application
(ShopHelper). It is designed so that it cannot cause real-world side effects:

- The only scan target is the built-in `shophelper-local` adapter (allowlisted in code).
- No arbitrary URL input is accepted.
- Agents have no shell or filesystem tools.
- All customer data, canaries, and orders in fixtures are synthetic.
- Hardening proposals require explicit human approval and are applied only to
  the temporary evaluation target, never to production systems.

## Reporting a vulnerability

Open a private security advisory or contact the maintainers directly during
the hackathon. Do not open public issues for exploitable gaps.

## Runtime controls enforced in code

- Attack count ≤ 12, attempts per attack ≤ 2.
- Model-call and token budgets with per-call and global scan timeouts.
- Concurrency limits.
- Strict schema validation of all model output.
- Redaction before persistence and telemetry.
- Fail-closed policy gateway for the simulated `issue_refund` tool.

A clean RAVEN result means "clean under the stated checks" — it is not a
general security guarantee.
