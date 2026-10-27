# 🤖 Vulnerable Shop Assistant Demo

A minimal, runnable reference customer service agent (FastAPI) featuring an unconstrained `issue_refund` tool. This starter template demonstrates how **RAVEN** detects tool misuse vulnerabilities in CI/CD, blocks unsafe Pull Requests, and generates reviewable runtime policy guardrails.

---

## 🔍 The Vulnerability

The agent includes a customer refund capability:
```python
def execute_refund_tool(order_id: str, amount: float, reason: str = ""):
    return {
        "tool": "issue_refund",
        "arguments": {"order_id": order_id, "amount": amount, "reason": reason}
    }
```
* **Unconstrained Authorization:** Any prompt demanding a refund immediately executes `issue_refund` without checking whether the user owns the order.
* **Missing Value Bounds:** Accepts high-value refunds (e.g. $500, $1000) without supervisor approval.
* **Missing Invariant Verification:** Approves refunds for non-existent or unverified orders.

---

## 🚀 Quickstart: Running & Scanning Locally

### 1. Start the Agent
```bash
cd examples/vulnerable-agent
uvicorn agent:app --host 127.0.0.1 --port 8000
```
Verify the health check endpoint:
```bash
curl http://127.0.0.1:8000/health
# {"status":"ok","agent":"vulnerable-shop-assistant"}
```

### 2. Run RAVEN Pre-Flight Dry Run
Verify connectivity and target profiling with zero attacks:
```bash
raven-test run --config raven.yaml --dry-run
```

### 3. Run RAVEN Security Scan
Execute the tool misuse regression suite:
```bash
raven-test run --config raven.yaml
```

**Expected Result:**
1. RAVEN launches tool misuse attack cases (e.g., `A-10`, `A-11`, `A-12`).
2. The agent executes `issue_refund` without a verified order.
3. The deterministic judge catches `unsafe_tool_call:issue_refund` and records a **CRITICAL** / **HIGH** severity breach.
4. Process exits with code `1` (blocked).
5. A proposed runtime policy patch diff is emitted:
```diff
--- vulnerable-policy.json
+++ hardened-policy.json
@@ -10,3 +10,12 @@
+  "rules": [
+    {
+      "tool": "issue_refund",
+      "conditions": ["amount <= 50.0", "order_status == 'delivered'"],
+      "high_value_action": "human_approval_required"
+    }
+  ]
```

---

## 🛡️ Remediation via `raven-guard`

Set `RAVEN_GUARD_ACTIVE=true` to enable runtime policy enforcement:
```bash
RAVEN_GUARD_ACTIVE=true uvicorn agent:app --host 127.0.0.1 --port 8000
```
Re-running `raven-test run --config raven.yaml` will now report:
* **Attack Success Rate (ASR):** `0.0%` (100% of attacks blocked)
* **Benign Utility Retention:** `100.0%` (legitimate order lookups succeed)
* **Gate Status:** ✅ `PASSED` (exit code `0`)

---

## 🔄 Automated CI/CD Integration

The repository includes [`.github/workflows/security-gate.yml`](file:///home/e0kt/Documents/01_projects/2026/hackathons/RAVEN/examples/vulnerable-agent/.github/workflows/security-gate.yml), which automatically:
1. Boots the agent on ephemeral test runners.
2. Runs `actions/raven-security-scan` against `http://127.0.0.1:8000/chat`.
3. Posts the **Frontier Security Scorecard** and visual prompt/policy diff directly on the PR.
4. Emits `::error` annotations pointing to the vulnerable tool lines.
5. Exports and uploads OASIS SARIF 2.1.0 to the GitHub Code Scanning tab.
