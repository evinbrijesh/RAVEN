# 🛡️ raven-guard
### Deterministic, Fail-Closed Runtime Policy Gateway for LLM Applications

`raven-guard` is a lightweight, zero-heavyweight-dependency Python security SDK extracted from the **RAVEN** AI security framework. It provides runtime protection for LLM tool executions, enforcing policies directly compiled by RAVEN's automated hardening agent (`raven-policy.yaml`).

[![Tests](https://img.shields.io/badge/coverage-100%25-emerald?style=for-the-badge)](https://github.com/evinbrijesh/RAVEN)
[![Zero Heavy Dependencies](https://img.shields.io/badge/dependencies-zero%20heavy-indigo?style=for-the-badge)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)

---

## ⚡ Why raven-guard?

When an LLM is prompt-injected or jailbroken, system prompt guardrails often fail. **`raven-guard` acts as the deterministic last line of defense at runtime**:
- **Fail-Closed by Default:** Unknown tools or tools without explicit policies are rejected.
- **Enforces Parameter Bounds:** Blocks financial thresholds (e.g. refund > $100), negative amounts, or malformed payloads before they execute.
- **Human Approval Escalation:** Automatically rejects unapproved high-value operations with `ApprovalRequiredError`.
- **Identity & Order Verification:** Prevents unauthorized cross-customer access by requiring cryptographic verification tokens.
- **Seamless Function Decorator:** Drop-in `@gateway.protect(tool="...")` for sync and async Python tool functions.

---

## 🚀 Quickstart

### 1. Installation

```bash
pip install raven-guard
```

### 2. Define or Compile Policy (`raven-policy.yaml`)

```yaml
version: "hardened-gateway-v2"
description: "Hardened deterministic policy gateway compiled by RAVEN."
fail_closed: true

tools:
  - tool: "issue_refund"
    conditions:
      - "verified_order_id_present"
      - "verified_user_present"
      - "amount_below_threshold"
    high_value_action: "human_approval_required"
    amount_threshold: 100.0
    on_violation: "deny_and_log"

  - tool: "get_order"
    conditions:
      - "verified_order_id_present"
    on_violation: "deny_and_log"
```

### 3. Protect Your Python Tools with Decorators

```python
from raven_guard import PolicyGateway, security_context, PolicyViolationError, ApprovalRequiredError

gateway = PolicyGateway("raven-policy.yaml")

# Protect sync or async functions
@gateway.protect(tool="issue_refund")
def process_refund(order_id: str, amount: float):
    return {"status": "success", "order_id": order_id, "refunded": amount}

# 1. Unverified call -> Fail-Closed Denied!
try:
    process_refund(order_id="ORD-101", amount=50.0)
except PolicyViolationError as err:
    print(f"Blocked by RAVEN Guard: {err.reason}")  # missing_verified_user

# 2. Legitimate verified call within bounds -> Allowed
with security_context(verified_user=True, verified_order_id=True):
    result = process_refund(order_id="ORD-101", amount=50.0)
    print(result)  # {'status': 'success', 'order_id': 'ORD-101', 'refunded': 50.0}

# 3. High-value prompt-injected attack ($500 refund) -> Escalated to Human Approval!
try:
    with security_context(verified_user=True, verified_order_id=True):
        process_refund(order_id="ORD-101", amount=500.0)
except ApprovalRequiredError as err:
    print(f"Escalated to human supervisor: {err.reason}")  # high_value_action:approval_required
```

---

## 🔍 Direct Authorization API

You can also evaluate tool calls directly without decorators:

```python
from raven_guard import PolicyGateway, SecurityContext

gateway = PolicyGateway("raven-policy.yaml")

context = SecurityContext(
    verified_user=True,
    verified_order_id=True,
    user_id="user_88",
    order_id="ORD-101",
)

decision = gateway.authorize(
    tool="issue_refund",
    arguments={"order_id": "ORD-101", "amount": 25.0},
    context=context,
)

if not decision:
    print(f"Denied: {decision.reason} | Violations: {decision.violations}")
else:
    print("Authorized!")
```

---

## 🛡️ Condition Catalog

| Condition | Verification Enforced |
|---|---|
| `verified_order_id_present` | Requires `verified_order_id=True` and a valid `order_id` in arguments or context. |
| `verified_user_present` | Requires `verified_user=True` in context. |
| `amount_below_threshold` | Requires `amount < amount_threshold` (default `$100.00`). |
| `user_id_matches_context` | Ensures `user_id` passed by model matches authenticated user session. |
| `custom_conditions` | Registered via `gateway.register_condition("name", validator_fn)`. |

---

## 📜 License

MIT License. Developed by the RAVEN Frontier Security Team.
