# LangGraph Scan Orchestration Architecture in RAVEN

## 1. Overview

RAVEN incorporates **LangGraph** (`langgraph>=1.2.17`) as the production execution engine for security scan orchestration. The architecture formalizes the closed-loop scanning, judging, hardening, human-supervised approval, retesting, regression promotion, and report generation pipeline as a durable, typed `StateGraph`.

```
START
  │
  ▼
initialize_scan
  │
  ▼
recon
  │
  ▼
plan_attacks
  │
  ▼
execute_security_tests
  │
  ▼
judge_results
  │
  ▼
resolve_verdicts
  │
  ├───[no findings / non-retestable]──► generate_reports ──► END
  ▼
generate_hardening_proposal
  │
  ▼
human_approval_interrupt ◄─── (LangGraph interrupt gate; awaits human review)
  │
  ├───[rejected]──────────────────────► generate_reports (completed_without_retest) ──► END
  ▼ [approved]
retest_security
  │
  ▼
retest_benign_utility
  │
  ▼
calculate_metrics
  │
  ▼
promote_regressions
  │
  ▼
generate_reports
  │
  ▼
END
```

---

## 2. State Model (`RavenScanState`)

The graph uses a strongly-typed state model defined in [`evaluator.orchestration.state`](file:///home/e0kt/Documents/01_projects/2026/hackathons/RAVEN/workers/evaluator/evaluator/orchestration/state.py):

| Field | Type | Description |
|---|---|---|
| `scan_id` | `str` | Unique scan identifier (used as LangGraph `thread_id`). |
| `run_id` | `str` | Idempotent execution run ID (`run_{scan_id}`). |
| `target_id` | `str` | Target system ID (e.g., `shophelper-local`). |
| `target_configuration_hash` | `str` | Deterministic SHA256 hex digest of target configuration. |
| `phase` | `str` | Active lifecycle phase name. |
| `status` | `str` | Scan status matching `ScanStatus` enum. |
| `scan_configuration` | `dict` | Validated scan configuration and budget parameters. |
| `target_profile` | `dict \| None` | Discovered TargetProfile (secrets redacted). |
| `selected_attack_case_ids` | `list[str]` | Filtered and approved attack cases for this scan. |
| `attack_results` | `list[dict]` | Attempt transcripts, execution metadata, and timings. |
| `deterministic_evidence` | `list[dict]` | Deterministic judge signals, leak checks, and rule outputs. |
| `semantic_judgments` | `list[dict]` | LLM judge classifications and confidence values. |
| `resolved_verdicts` | `list[dict]` | Consolidated verdicts produced by VerdictResolver. |
| `confirmed_findings` | `list[dict]` | High/critical findings eligible for hardening. |
| `hardening_proposal` | `dict \| None` | Generated prompt diff and policy candidate. |
| `approval_status` | `str` | `pending`, `awaiting_approval`, `approved`, `rejected`. |
| `approval_metadata` | `dict \| None` | Approver, timestamp, proposal hash, and rationale. |
| `security_retest_results` | `list[dict]` | Results of security cases re-executed against hardened target. |
| `benign_utility_results` | `list[dict]` | Benign utility suite execution results (detects over-refusal). |
| `regression_case_ids` | `list[str]` | Cases promoted to continuous regression tracking. |
| `report_artifact_ids` | `list[str]` | IDs of generated JSON, Markdown, and SARIF 2.1.0 artifacts. |
| `budget_used` | `dict` | Telemetry for model calls, attempts, and token budgets. |
| `errors` | `list[str]` | Error diagnostics captured during execution. |
| `warnings` | `list[str]` | Operational warnings (e.g., fallback judging, over-refusal notes). |

---

## 3. Node Specifications

1. **`initialize_scan`**:
   - Validates scan configuration against limits (`validate_scan_config`).
   - Ensures target exists and loads/creates an idempotent run record.
   - Emits `SCAN_STARTED` SSE event.
2. **`recon`**:
   - Invokes `ReconAgent` on target adapter without aggressive payloads.
   - Persists `TargetProfile` into SQLite repository.
   - Redacts raw canary tokens / credentials before writing to graph state.
3. **`plan_attacks`**:
   - Loads versioned catalog cases (`packages/attack-catalog/catalog.json`).
   - Applies scan category filters, limits, and regression-only mode.
   - Persists selected plan.
4. **`execute_security_tests`**:
   - Runs `SecurityRegressionRunner` bounded by `max_attempts_per_attack`, `max_model_calls`, and timeouts.
   - Captures full transcript messages and tool calls.
   - Persists records into `attack_runs` and `transcripts` tables idempotently.
5. **`judge_results`**:
   - Runs `DeterministicJudge` (canary leakage, unauthorized tool call, order verification).
   - If configured and budget permits, runs `SemanticJudge`.
   - Never converts timeouts or missing evidence into passing verdicts.
6. **`resolve_verdicts`**:
   - Uses `VerdictResolver` to reconcile rule and LLM judge outcomes conservatively.
   - Persists `Verdict` records into `verdicts` table.
7. **`generate_hardening_proposal`**:
   - Synthesizes `PromptHardener` refusal diff and `PolicyCompiler` tool execution policy.
   - Validates fail-closed behavior (`ProposalValidator.validate_or_raise`).
   - Persists `HardeningProposal` to `proposals` table.
8. **`human_approval_interrupt`**:
   - Calls LangGraph `interrupt(...)`.
   - Halts execution and transitions scan to `ScanStatus.AWAITING_APPROVAL`.
   - Resumed by the API/worker via `Command(resume=...)`.
   - Idempotent: duplicate resumes do not re-run tests or duplicate state.
9. **`retest_security`**:
   - Resets temporary target instance and applies approved policy candidate and prompt diff.
   - Reruns affected security cases in `AFTER` phase.
   - Records before/after evidence pairs.
10. **`retest_benign_utility`**:
    - Executes benign customer tasks via `UtilityRegressionRunner`.
    - Detects over-refusal and regressions on utility.
11. **`calculate_metrics`**:
    - Calculates mitigation rate, delta reduction, over-refusal count, and budget consumption.
12. **`promote_regressions`**:
    - Promotes verified mitigated findings into target's continuous regression suite.
    - Idempotently updates `regressions` table.
13. **`generate_reports`**:
    - Idempotently renders JSON, Markdown, and SARIF 2.1.0 via `app.application.report.service.generate`.
    - Updates scan to terminal state and emits `SCAN_COMPLETED`.

---

## 4. Durable SQLite Checkpointing

To eliminate external infrastructure dependencies (such as Redis or PostgreSQL) while ensuring 100% restart durability:
- Implemented `SqliteCheckpointSaver` extending LangGraph's `BaseCheckpointSaver`.
- Backed by dedicated SQLite tables in `data/raven.db`:
  - `checkpoints` (thread ID, checkpoint ID, serialized checkpoint state)
  - `checkpoint_blobs` (channel versions and blobs)
  - `checkpoint_writes` (pending write buffers)
- On worker restarts, passing `config={"configurable": {"thread_id": scan_id}}` enables the graph to resume execution exactly from the last committed node.

---

## 5. Human Approval Interrupt & Worker Integration

- When `ScanEngine.run(scan_id)` is invoked, the compiled StateGraph executes until `human_approval_interrupt`, where `interrupt(...)` pauses the graph.
- The control plane's approval endpoint (`POST /api/scans/:id/approve-hardening`) records the human decision in `repos.approvals` and enqueues a `run_retest` job.
- When the evaluator worker processes `run_retest`, `ScanEngine.run_retest(scan_id)` calls:
  ```python
  await self._graph.ainvoke(Command(resume=resume_data), config=config)
  ```
- If the proposal is approved, execution flows to `retest_security`. If rejected, execution routes directly to `generate_reports` and completes with status `completed_without_retest`.

---

## 6. Terminal Paths

| Terminal State | Condition |
|---|---|
| `completed` | Scan completed all security and utility tests with hardening verified. |
| `completed_without_retest` | No findings discovered, or human approver rejected hardening proposal, or evaluation-only target. |
| `failed_partial` | Reversible operational failure (e.g. missing proposal on retest) with partial evidence preserved. |
| `failed_fatal` | Unrecoverable error (e.g. non-existent scan ID or total recon connectivity failure). |
| `inconclusive` | Zero runnable attack cases (e.g. empty regression suite in regression-only mode). |

---

## 7. Idempotency Strategy

- **Scans & Runs**: Graph uses `scan_id` as `thread_id` and checks existing records before creating new ones.
- **Node Execution**: Every node verifies whether domain entities (profile, findings, proposals, test runs, report artifacts) are already present in the SQLite database before performing repeated operations.
- **Reporting**: Report generation computes canonical SHA256 hashes and uses `INSERT OR IGNORE` on `report_artifacts`.
