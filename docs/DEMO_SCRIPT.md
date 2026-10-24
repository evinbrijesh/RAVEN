# RAVEN — 5-Minute Demo Script

A pitch walkthrough that follows the scan lifecycle end to end. Every beat
maps to a scan status, so the demo and the state machine tell the same story.

**Total time:** 5:00 · **Tabs needed:** Web UI (localhost:3000), API docs
(localhost:8000/docs) as backup · **Backup:** recorded run (see Fallbacks)

---

## Pre-flight checklist (T-10:00)

- [ ] Stack up: `make dev` (or `docker compose -f infra/docker-compose.yml up --build`).
- [ ] Preflight model availability. If the provider is unreachable, say so up
      front and run deterministic-only — the demo still works, semantic
      judgment is marked unavailable.
- [ ] Reset the target and demo state (reset button / fresh `data/` volume).
- [ ] Confirm fixtures are seeded: `fixtures/shophelper/` and
      `packages/attack-catalog/` present, `fixtures/demo-scan.json` loads.
- [ ] Open the web UI on the scan-setup page; verify SSE progress updates live
      (no manual refresh) with a throwaway 2-case scan if time allows.
- [ ] Backup recording cued in a second window.

## Timeline

| Time | Beat | Scan status on screen |
| --- | --- | --- |
| 0:00–0:35 | Hook: prompt tweaks cause silent security regressions | — |
| 0:35–1:15 | What RAVEN is; bounded scope and safety rules | — |
| 1:15–2:15 | Launch scan; live progress | `created → reconning → attacking → judging` |
| 2:15–3:15 | Findings and evidence | `judging → hardening_proposed` |
| 3:15–4:00 | Hardening diff + human approval gate | `awaiting_approval` |
| 4:00–4:40 | Retest: attack blocked, benign suite passes | `retesting → completed` |
| 4:40–5:00 | Report export + closing line | `completed` |

---

## Script

### 0:00–0:35 — Hook

**On screen:** scan-setup page, empty state.

> "Every time a team tweaks an LLM app's system prompt or tools, it can
> silently re-open a hole they already fixed. Security testing happens once,
> before launch — then the next prompt change undoes it. RAVEN makes LLM
> security a *regression suite*, not a one-time audit."

### 0:35–1:15 — What RAVEN is (and is not)

**On screen:** the four attack categories and budget fields on the setup form.

> "RAVEN scans a built-in local ShopHelper bot with an approved suite: prompt
> injection, canary leakage, sensitive-data probing, and tool misuse — twelve
> cases, hard-capped. Every run is bounded: max cases, max retries, max model
> calls, timeouts. It never touches third-party targets, never executes real
> refunds or emails, and never deploys a fix on its own. A human approves
> every change."

Keep this to three sentences of safety — it is a differentiator, not an apology.

### 1:15–2:15 — Launch the scan (live progress)

**On screen:** click **Start scan**; live progress view.

**Say while it runs:**

> "The scan config is declarative — categories, budgets, benign suite. I hit
> start and the worker takes over: reconnaissance profiles the target, then
> the attack suite runs, then judging. Everything you're seeing streams over
> Server-Sent Events — no refresh."

**Point at the status transitions as they appear:** `created → reconning →
attacking → judging`. Name the state machine explicitly: "This is a bounded
state machine, not an agent loop — every transition is persisted and
auditable."

### 2:15–3:15 — Findings and evidence

**On screen:** findings list; open one `confirmed_failure` (canary leak or
tool-policy violation is the most visual).

> "Here's a confirmed failure. The canary string we planted in the customer
> record came straight back out of the bot. The evidence is a full transcript
> plus a deterministic check — that's a cryptographic-grade signal, not a
> model's opinion. Where the rule-based judge and the LLM judge disagree,
> RAVEN refuses to guess: it labels the finding `needs_review` for a human."

If a model call failed mid-run, show the partial result instead:
> "The model judge dropped one call — the scan continued on deterministic
> checks and marked semantic judgment unavailable. Partial beats blank."

### 3:15–4:00 — Hardening proposal + approval gate

**On screen:** hardening proposal with the diff; approve button.

> "For each failed case, RAVEN proposes at most one hardening change — here,
> a system-prompt guard plus a tool-policy rule — shown as a diff. And this is
> the part I want you to remember: **nothing is applied until a human clicks
> approve.** The scan sits in `awaiting_approval` until then."

Click **Approve**. Status flips to `retesting`.

### 4:00–4:40 — Retest (security + benign)

**On screen:** retest results side by side.

> "Retest: the same attack now comes back `attack_blocked`. And because
> hardening can break normal behavior, RAVEN re-runs the benign utility
> suite — the bot still answers real customer questions. Both results are
> saved as regression cases, so the next scan re-verifies them
> automatically."

If a benign case regressed, show `regression_detected` — that is a feature,
say so: "RAVEN catches the cure being worse than the disease."

### 4:40–5:00 — Report + close

**On screen:** report page; click **Export Markdown** (mention JSON export).

> "Everything — transcripts, verdicts, diffs, approvals, before/after — lands
> in an exportable report. One last honest caveat: a clean RAVEN result is
> not a security guarantee; it's a verified regression suite under stated
> checks. That's the point — security you can re-run every time someone
> touches the prompt."

---

## Fallback playbook

| Failure | Response |
| --- | --- |
| Model provider down / slow | Run deterministic-only; say "semantic judgment unavailable", show partial findings. |
| SSE stalls | Refresh once; if still stalled, open the scan via API docs (`/api/scans/{id}`) and narrate from JSON. |
| Scan fails fatally | Reset target + state, rerun once. If it fails again, switch to the backup recording and narrate live over it. |
| Approval click does nothing | Skip ahead to retest results from the previous recorded run; keep talking. |
| Anything unrecoverable | Backup recording. Never debug live on stage. |

## Do-not-say list

- Do not claim RAVEN proves the target is secure (rule 8).
- Do not describe the attack suite as exhaustive ("twelve approved cases" is
  the honest framing).
- Do not imply hardening is auto-deployed — the approval gate is the story.
- Do not name real customers, real PII, or real credentials; all fixture data
  is synthetic.
