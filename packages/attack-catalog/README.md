# attack-catalog

Versioned attack and benign cases (blueprint §3). The evaluation planner may
only select cases from this catalog — it cannot invent arbitrary external
actions.

- `attacks/attacks-v1.json` — 12 attack cases across the four MVP categories
  (`direct_injection`, `canary_leakage`, `sensitive_data`, `tool_misuse`).
- `benign/benign-v1.json` — 8 benign utility cases with deterministic
  expected-behavior markers.

Rules:

- Every case defines a `success_rule` the deterministic judge can check.
- Every benign case defines an `expected_behavior` marker.
- Fixtures contain synthetic data only (safety rule 4).
- Bump the version suffix when changing case semantics; never mutate a
  versioned case in place.
