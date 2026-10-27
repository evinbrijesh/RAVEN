# 🛡️ raven-guard

[![PyPI Version](https://img.shields.io/badge/pypi-v1.0.0-blue.svg?style=for-the-badge)](https://pypi.org/project/raven-guard/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-brightgreen.svg?style=for-the-badge)](https://www.python.org/)
[![Zero Heavy Dependencies](https://img.shields.io/badge/dependencies-zero%20heavy-indigo.svg?style=for-the-badge)](pyproject.toml)
[![Test Coverage](https://img.shields.io/badge/coverage-100%25-emerald.svg?style=for-the-badge)](https://github.com/evinbrijesh/RAVEN)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg?style=for-the-badge)](LICENSE)

**Deterministic, fail-closed runtime policy gateway and security guardrails for LLM tool calling.**

`raven-guard` is a lightweight, zero-heavyweight-dependency Python SDK extracted from the **RAVEN** automated AI red-teaming framework. It acts as the final runtime defense layer for agentic systems, stopping prompt injection, excessive agency (OWASP LLM08), IDOR, and parameter smuggling before untrusted tool calls can execute.

---

## ⚡ Why raven-guard?

When an LLM agent is jailbroken or injected via adversarial prompts, indirect RAG poisoning, or untrusted user input, prompt-based guardrails fail. **`raven-guard` enforces deterministic mathematical and cryptographic invariants at runtime**:

- **Fail-Closed by Default:** Unknown tools or undeclared capabilities are blocked immediately.
- **Cross-Field Context Claims:** Validates arguments against verified session claims (e.g. `arguments.customer_id == context.user_id`) to prevent Confused Deputy and IDOR attacks.
- **Parameter Bounds & Schema Invariants:** Restricts financial parameters (e.g. `amount <= 100.0`, `amount > 0`), string regexes, and allowed roles.
- **Human Approval Escalation:** Distinguishes between fatal policy violations and high-value actions requiring explicit human approval (`ApprovalRequiredError`).
- **Dynamic Hot-Reloading:** Automatically reloads updated policies compiled by RAVEN without restarting your services.
- **Framework Native:** Plug-and-play integrations for **FastAPI**, **Starlette**, **LangChain**, **LangGraph**, and **OpenTelemetry**.

---

## 📦 Installation

Install core `raven-guard` (only requires `pyyaml`):

```bash
pip install raven-guard
```

### Optional Extras

Install framework-specific extras as needed:

```bash
# FastAPI / Starlette middleware
pip install "raven-guard[fastapi]"

# LangChain & LangGraph agent tool interceptors
pip install "raven-guard[langchain]"

# OpenTelemetry distributed security tracing
pip install "raven-guard[opentelemetry]"

# All integrations
pip install "raven-guard[all]"
```

---

## 📋 Policy Definition (`raven-policy.yaml`)

Policies can be compiled automatically by RAVEN's red-teaming engine or authored by hand in YAML or JSON:

```yaml
version: "hardened-gateway-v1"
description: "RAVEN runtime enforcement policy for customer operations."
fail_closed: true

tools:
  issue_refund:
    description: "Issue refund to customer wallet or payment method."
    conditions:
      - "verified_order_id_present"
      - "verified_user_present"
      - "amount_below_threshold"
      - "claims_match:customer_id==user_id"
    high_value_action: "human_approval_required"
    amount_threshold: 100.0
    context_claims:
      customer_id: "user_id"
    on_violation: "deny_and_log"

  lookup_order:
    description: "Look up order details."
    conditions:
      - "verified_order_id_present"
      - "claims_match:customer_id==user_id"
    context_claims:
      customer_id: "user_id"
    on_violation: "deny_and_log"
```

---

## 🛠️ Integration Recipes

### Recipe 1: Standalone Python Policy Gateway

Instantiate the gateway directly from a YAML file or string, evaluate calls, and register custom validation conditions:

```python
from raven_guard import PolicyGateway, SecurityContext

# Load policy directly from file
gateway = PolicyGateway.from_yaml("raven-policy.yaml")

# Context represents authenticated identity (e.g., from your auth session)
context = SecurityContext(
    user_id="cust_42",
    verified_user=True,
    verified_order_id=True,
    claims={"user_id": "cust_42", "role": "customer"},
)

# 1. Authorize benign request
decision = gateway.authorize(
    tool="lookup_order",
    arguments={"order_id": "ORD-999", "customer_id": "cust_42"},
    context=context,
)
if decision.allowed:
    print("Execution authorized!")

# 2. Prevent IDOR (model manipulated to access another customer's order)
idor_decision = gateway.authorize(
    tool="lookup_order",
    arguments={"order_id": "ORD-999", "customer_id": "victim_user"},
    context=context,
)
assert not idor_decision.allowed
print(f"Blocked IDOR attempt: {idor_decision.reason}")
# Output: Blocked IDOR attempt: context_claims_mismatch:customer_id(victim_user)!=user_id(cust_42)

# 3. Dynamic Hot-Reloading
gateway.start_auto_reload(interval_seconds=2.0)
```

---

### Recipe 2: Python Function Decorators (`@gateway.protect`)

Decorate your sync or async tool functions. `raven-guard` intercepts calls before execution:

```python
from raven_guard import (
    PolicyGateway,
    security_context,
    PolicyViolationError,
    ApprovalRequiredError,
)

gateway = PolicyGateway.from_yaml("raven-policy.yaml")

@gateway.protect(tool="issue_refund")
def issue_refund(customer_id: str, order_id: str, amount: float):
    return {"status": "refunded", "order_id": order_id, "amount": amount}

# Unauthenticated call -> Fails Closed
try:
    issue_refund(customer_id="cust_42", order_id="ORD-101", amount=25.0)
except PolicyViolationError as err:
    print(f"Blocked: {err.reason}")  # missing_verified_order_id

# Authenticated session -> Allowed
with security_context(verified_user=True, verified_order_id=True, user_id="cust_42"):
    res = issue_refund(customer_id="cust_42", order_id="ORD-101", amount=25.0)
    print("Success:", res)

# Prompt-injected high-value action ($500) -> Escalated to Human Approval
try:
    with security_context(verified_user=True, verified_order_id=True, user_id="cust_42"):
        issue_refund(customer_id="cust_42", order_id="ORD-101", amount=500.0)
except ApprovalRequiredError as err:
    print(f"Human Approval Required: {err.reason}")
```

Async functions work identically:

```python
@gateway.protect(tool="lookup_order")
async def async_lookup_order(customer_id: str, order_id: str):
    return await db.fetch_order(order_id)
```

---

### Recipe 3: FastAPI & Starlette Middleware

Automatically extract claims from incoming JWT Bearer tokens or security headers, bind them to the asynchronous execution context, and reject policy violations with `HTTP 403`:

```python
from fastapi import FastAPI, Depends
from raven_guard import PolicyGateway, SecurityContext, get_current_context
from raven_guard.integrations.fastapi import RavenGuardMiddleware

app = FastAPI(title="Secure Agent Service")
gateway = PolicyGateway.from_yaml("raven-policy.yaml")

# Attach middleware: extracts JWT claims & headers and binds to security_context
app.add_middleware(
    RavenGuardMiddleware,
    gateway=gateway,
    exclude_paths=["/docs", "/openapi.json", "/healthz"],
    enforce_routes=True,  # Automatically return HTTP 403 on PolicyViolationError
)

@app.post("/api/refund")
@gateway.protect(tool="issue_refund")
async def handle_refund(payload: dict):
    # JWT Bearer token claims are already validated in context!
    ctx: SecurityContext = get_current_context()
    return {"status": "processed", "customer": ctx.user_id, "amount": payload["amount"]}
```

When an attacker passes an invalid refund or mismatched customer ID, `RavenGuardMiddleware` immediately returns:

```json
{
  "error": "policy_violation",
  "detail": "Policy violation on 'issue_refund': context_claims_mismatch",
  "tool": "issue_refund",
  "reason": "context_claims_mismatch:customer_id!=user_id",
  "violations": ["context_claims_mismatch"]
}
```

---

### Recipe 4: LangChain & LangGraph Tool Interceptors

Drop `RavenGuardToolNode` into your LangGraph StateGraph, or attach `RavenGuardCallbackHandler` to your LangChain agent. Any tool calls hallucinated or manipulated by the LLM are evaluated against `raven-policy.yaml` before execution:

#### LangGraph StateGraph

```python
from langgraph.graph import StateGraph, MessagesState, START, END
from raven_guard import PolicyGateway
from raven_guard.integrations.langchain import RavenGuardToolNode

gateway = PolicyGateway.from_yaml("raven-policy.yaml")

# Wrap your tools in RavenGuardToolNode
tool_node = RavenGuardToolNode(
    tools=[issue_refund, lookup_order],
    gateway=gateway,
    on_violation="return_message",  # Returns error message to LLM to self-correct
)

workflow = StateGraph(MessagesState)
workflow.add_node("agent", call_model)
workflow.add_node("tools", tool_node)
workflow.add_edge(START, "agent")
# ...
app = workflow.compile()
```

#### LangChain Callback Interceptor

```python
from langchain.agents import create_tool_calling_agent
from raven_guard import PolicyGateway
from raven_guard.integrations.langchain import RavenGuardCallbackHandler

gateway = PolicyGateway.from_yaml("raven-policy.yaml")
interceptor = RavenGuardCallbackHandler(gateway=gateway)

# Attach to agent executor
result = agent_executor.invoke(
    {"input": "Transfer $1,000 to account X"},
    config={"callbacks": [interceptor]},
)
```

---

### Recipe 5: OpenTelemetry Distributed Security Tracing

Enrich your active OpenTelemetry spans with security policy decisions, violation details, and audit events:

```python
from raven_guard import PolicyGateway, SecurityContext
from raven_guard.integrations.opentelemetry import setup_opentelemetry, trace_tool_execution
import opentelemetry.trace as trace

tracer = trace.get_tracer("agent-service")
gateway = PolicyGateway.from_yaml("raven-policy.yaml")

# Attach security tracing listener
setup_opentelemetry(
    gateway,
    set_error_status_on_violation=True,
    record_span_events=True,
)

with tracer.start_as_current_span("agent_turn") as span:
    # Tool execution evaluated by gateway will automatically attach:
    # - security.policy.tool: "issue_refund"
    # - security.policy.allowed: False
    # - security.policy.reason: "amount_exceeds_max:100.0"
    # - security.user.id: "cust_42"
    # - span.set_status(StatusCode.ERROR)
    # - span.add_event("security.policy.violation")
    decision = gateway.authorize(
        "issue_refund",
        {"amount": 500.0, "customer_id": "cust_42"},
        context=SecurityContext(user_id="cust_42"),
    )
```

---

## 🔒 Built-in Policy Conditions

| Condition | Description | Failure Reason |
|---|---|---|
| `verified_order_id_present` | Requires `verified_order_id=True` and an `order_id` in arguments or context. | `missing_verified_order_id` |
| `verified_user_present` | Requires `verified_user=True` in context. | `missing_verified_user` |
| `amount_below_threshold` | Requires `amount <= amount_threshold` and `amount > 0`. | `amount_exceeds_max:<threshold>` |
| `claims_match:<arg>==<claim>` | Enforces cross-field claims matching (e.g. `arguments.customer_id == context.user_id`). | `context_claims_mismatch` |
| `role_allowed` | Ensures `context.roles` intersects with tool's `allowed_roles`. | `role_not_authorized` |
| `user_id_matches_context` | Matches `user_id` argument to context `user_id`. | `user_id_mismatch` |

### Custom Conditions

You can register custom deterministic validators dynamically:

```python
def check_business_hours(arguments, context, tool_policy) -> tuple[bool, str]:
    if not is_market_open():
        return False, "market_closed"
    return True, "allowed"

gateway.register_condition("business_hours_only", check_business_hours)
```

---

## 🛡️ Security Architecture

```
                  ┌───────────────────────────────┐
                  │    Untrusted LLM Tool Call    │
                  └───────────────┬───────────────┘
                                  │
                                  ▼
                   ┌─────────────────────────────┐
                   │    raven-guard Gatekeeper   │
                   └──────────────┬──────────────┘
                                  │
          ┌───────────────────────┴───────────────────────┐
          │                                               │
   [Fail Conditions]                              [Pass Conditions]
          │                                               │
          ▼                                               ▼
┌──────────────────────────┐                  ┌───────────────────────────┐
│  • Disallowed Tool       │                  │  • Cryptographic Claims   │
│  • Parameter Smuggling   │                  │  • Verified Parameters    │
│  • Unapproved Threshold  │                  │  • In-Bounds Arguments    │
│  • Confused Deputy IDOR  │                  └─────────────┬─────────────┘
└─────────┬────────────────┘                                │
          │                                                 ▼
          ▼                                   ┌───────────────────────────┐
┌──────────────────────────┐                  │ Safe Tool Implementation  │
│ Raise / HTTP 403 / Log   │                  └───────────────────────────┘
│  • Telemetry Audit Event │
│  • OpenTelemetry Span Err│
└──────────────────────────┘
```

---

## 📄 License

Licensed under the [MIT License](LICENSE). Maintained by the RAVEN Frontier AI Security Team.
