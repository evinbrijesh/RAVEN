"""Typed repositories over the RAVEN SQLite schema.

Shared by the control plane (apps/api) and the evaluation worker
(workers/evaluator) — the worker imports this module so both processes speak
the same persistence contract. All timestamps are ISO 8601 UTC strings.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from app.domain.entities import (
    Approval,
    AttackCase,
    Finding,
    HardeningProposal,
    PolicyCandidate,
    RuleResult,
    Scan,
    ScanConfig,
    ScanEvent,
    TargetProfile,
    TestRun,
    Transcript,
    Verdict,
    utc_now,
)
from app.domain.enums import (
    EventKind,
    FindingLabel,
    RunPhase,
    RunStatus,
    ScanStatus,
    TestRunKind,
    VerdictResolution,
)
from app.infrastructure.db.sqlite import Database


def _id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _now() -> str:
    return utc_now().isoformat()


_TERMINAL_SCAN_STATUSES = frozenset({
    ScanStatus.COMPLETED,
    ScanStatus.COMPLETED_WITHOUT_RETEST,
    ScanStatus.FAILED_PARTIAL,
    ScanStatus.FAILED_FATAL,
})


class ScanRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def create(self, scan: Scan) -> Scan:
        self._db.execute(
            "INSERT INTO scans (scan_id, status, target_id, config_json, progress,"
            " created_at, updated_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan.scan_id,
                scan.status.value,
                scan.target.target_id,
                scan.config.model_dump_json(),
                scan.progress,
                scan.created_at.isoformat(),
                scan.updated_at.isoformat(),
                scan.completed_at.isoformat() if scan.completed_at else None,
            ),
        )
        return scan

    def get(self, scan_id: str) -> Scan | None:
        row = self._db.query_one("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        if row is None:
            return None
        target_id = row["target_id"]
        is_http = target_id.startswith(("http://", "https://"))
        target_ref = {
            "target_id": target_id,
            "kind": "http" if is_http else "local",
            "mode": "evaluation_only" if is_http else "staged_target",
            "endpoint_url": target_id if is_http else None,
        }
        return Scan(
            scan_id=row["scan_id"],
            status=ScanStatus(row["status"]),
            target=target_ref,
            config=ScanConfig.model_validate_json(row["config_json"]),
            progress=row["progress"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            completed_at=(
                datetime.fromisoformat(row["completed_at"])
                if row["completed_at"]
                else None
            ),
        )

    def update_status(
        self, scan_id: str, status: ScanStatus, progress: float | None = None
    ) -> None:
        # Stamp completed_at exactly once, on the first terminal transition
        # (report contract: scan.completed_at, ADR 0001).
        completed_at = (
            _now() if status in _TERMINAL_SCAN_STATUSES else None
        )
        if progress is None:
            self._db.execute(
                "UPDATE scans SET status = ?, updated_at = ?,"
                " completed_at = COALESCE(completed_at, ?) WHERE scan_id = ?",
                (status.value, _now(), completed_at, scan_id),
            )
        else:
            self._db.execute(
                "UPDATE scans SET status = ?, progress = ?, updated_at = ?,"
                " completed_at = COALESCE(completed_at, ?) WHERE scan_id = ?",
                (status.value, progress, _now(), completed_at, scan_id),
            )

    def list(self) -> list[Scan]:
        rows = self._db.query_all("SELECT * FROM scans ORDER BY created_at DESC")
        return [self.get(row["scan_id"]) for row in rows]  # type: ignore[misc]


class EventRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def append(self, event: ScanEvent) -> ScanEvent:
        cursor = self._db.connect().execute(
            "INSERT INTO scan_events (scan_id, kind, payload_json, created_at)"
            " VALUES (?, ?, ?, ?)",
            (
                event.scan_id,
                event.kind.value,
                json.dumps(event.payload, default=str),
                event.created_at.isoformat(),
            ),
        )
        self._db.connect().commit()
        event.event_id = cursor.lastrowid
        return event

    def list_since(self, scan_id: str, last_event_id: int) -> list[ScanEvent]:
        rows = self._db.query_all(
            "SELECT * FROM scan_events WHERE scan_id = ? AND event_id > ?"
            " ORDER BY event_id ASC",
            (scan_id, last_event_id),
        )
        return [self._to_event(row) for row in rows]

    def list_for_scan(self, scan_id: str) -> list[ScanEvent]:
        rows = self._db.query_all(
            "SELECT * FROM scan_events WHERE scan_id = ? ORDER BY event_id ASC",
            (scan_id,),
        )
        return [self._to_event(row) for row in rows]

    @staticmethod
    def _to_event(row: Any) -> ScanEvent:
        return ScanEvent(
            event_id=row["event_id"],
            scan_id=row["scan_id"],
            kind=EventKind(row["kind"]),
            payload=json.loads(row["payload_json"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )


class RunRepository:
    """Attack runs, transcripts, and verdicts."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def create_run(
        self, scan_id: str, attack_case_id: str, attempt: int, phase: RunPhase
    ) -> str:
        run_id = _id("run")
        self._db.execute(
            "INSERT INTO attack_runs (run_id, scan_id, attack_case_id, attempt,"
            " phase, started_at, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (run_id, scan_id, attack_case_id, attempt, phase.value, _now(),
             RunStatus.RUNNING.value),
        )
        return run_id

    def finish_run(
        self, run_id: str, status: RunStatus, transcript: Transcript | None = None
    ) -> None:
        if transcript is not None:
            self.save_transcript(transcript, run_id)
        self._db.execute(
            "UPDATE attack_runs SET status = ?, finished_at = ? WHERE run_id = ?",
            (status.value, _now(), run_id),
        )

    def save_transcript(self, transcript: Transcript, run_id: str) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO transcripts (transcript_id, run_id, messages_json)"
            " VALUES (?, ?, ?)",
            (transcript.transcript_id, run_id, transcript.model_dump_json()),
        )
        self._db.execute(
            "UPDATE attack_runs SET transcript_json = ? WHERE run_id = ?",
            (transcript.model_dump_json(), run_id),
        )

    def save_verdict(self, verdict: Verdict) -> Verdict:
        self._db.execute(
            "INSERT OR REPLACE INTO verdicts (verdict_id, run_id, scan_id,"
            " rule_label, rule_signals_json, llm_label, llm_confidence, llm_reason,"
            " llm_model_name, llm_prompt_version,"
            " final_label, resolution, evidence_refs_json, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                verdict.verdict_id,
                verdict.run_id,
                verdict.scan_id,
                verdict.rule_result.label.value if verdict.rule_result else None,
                json.dumps(verdict.rule_result.signals) if verdict.rule_result else None,
                verdict.llm_result.label.value if verdict.llm_result else None,
                verdict.llm_result.confidence if verdict.llm_result else None,
                verdict.llm_result.reason if verdict.llm_result else None,
                verdict.llm_result.model_name if verdict.llm_result else None,
                verdict.llm_result.prompt_version if verdict.llm_result else None,
                verdict.final_label.value,
                verdict.resolution.value,
                json.dumps([r.model_dump() for r in verdict.evidence_refs]),
                verdict.created_at.isoformat(),
            ),
        )
        return verdict

    def get_transcript(self, run_id: str) -> Transcript | None:
        """Typed transcript access for the report collector (ADR 0001)."""
        row = self._db.query_one(
            "SELECT messages_json FROM transcripts WHERE run_id = ?", (run_id,)
        )
        if row is None:
            row = self._db.query_one(
                "SELECT transcript_json AS messages_json FROM attack_runs"
                " WHERE run_id = ? AND transcript_json IS NOT NULL",
                (run_id,),
            )
        if row is None:
            return None
        return Transcript.model_validate_json(row["messages_json"])

    def list_runs(self, scan_id: str, phase: RunPhase | None = None) -> list[dict[str, Any]]:
        if phase is None:
            rows = self._db.query_all(
                "SELECT * FROM attack_runs WHERE scan_id = ? ORDER BY started_at",
                (scan_id,),
            )
        else:
            rows = self._db.query_all(
                "SELECT * FROM attack_runs WHERE scan_id = ? AND phase = ?"
                " ORDER BY started_at",
                (scan_id, phase.value),
            )
        return [dict(row) for row in rows]

    def list_verdicts(self, scan_id: str) -> list[Verdict]:
        rows = self._db.query_all(
            "SELECT * FROM verdicts WHERE scan_id = ? ORDER BY created_at", (scan_id,)
        )
        verdicts: list[Verdict] = []
        for row in rows:
            rule_result = None
            if row["rule_label"] is not None:
                rule_result = RuleResult(
                    label=FindingLabel(row["rule_label"]),
                    signals=json.loads(row["rule_signals_json"] or "[]"),
                )
            llm_result = None
            if row["llm_label"] is not None:
                from app.domain.entities import LlmJudgeResult

                llm_result = LlmJudgeResult(
                    label=FindingLabel(row["llm_label"]),
                    confidence=row["llm_confidence"] or 0.0,
                    reason=row["llm_reason"] or "",
                    model_name=row["llm_model_name"] or "",
                    prompt_version=row["llm_prompt_version"] or "",
                )
            verdicts.append(
                Verdict(
                    verdict_id=row["verdict_id"],
                    run_id=row["run_id"],
                    scan_id=row["scan_id"],
                    rule_result=rule_result,
                    llm_result=llm_result,
                    final_label=FindingLabel(row["final_label"]),
                    resolution=VerdictResolution(row["resolution"]),
                    evidence_refs=json.loads(row["evidence_refs_json"]),
                    created_at=datetime.fromisoformat(row["created_at"]),
                )
            )
        return verdicts


class FindingRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, finding: Finding) -> Finding:
        weak_json = finding.weak_point.model_dump_json() if finding.weak_point else None
        self._db.execute(
            "INSERT OR REPLACE INTO findings (finding_id, scan_id, attack_id,"
            " category, severity, label, confidence, summary, evidence_refs_json,"
            " needs_review, status, weak_point_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding.finding_id,
                finding.scan_id,
                finding.attack_id,
                finding.category.value,
                finding.severity.value,
                finding.label.value,
                finding.confidence,
                finding.summary,
                json.dumps([r.model_dump() for r in finding.evidence_refs]),
                int(finding.needs_review),
                finding.status,
                weak_json,
                finding.created_at.isoformat(),
            ),
        )
        return finding

    def list_for_scan(self, scan_id: str) -> list[Finding]:
        rows = self._db.query_all(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY created_at", (scan_id,)
        )
        findings = []
        for row in rows:
            d = dict(row)
            findings.append(
                Finding(
                    finding_id=d["finding_id"],
                    scan_id=d["scan_id"],
                    attack_id=d["attack_id"],
                    category=d["category"],
                    severity=d["severity"],
                    label=FindingLabel(d["label"]),
                    confidence=d["confidence"],
                    summary=d["summary"],
                    evidence_refs=json.loads(d["evidence_refs_json"]),
                    needs_review=bool(d["needs_review"]),
                    status=d["status"],
                    weak_point=json.loads(d["weak_point_json"]) if d.get("weak_point_json") else None,
                    created_at=datetime.fromisoformat(d["created_at"]),
                )
            )
        return findings

    def get(self, finding_id: str) -> Finding | None:
        row = self._db.query_one("SELECT * FROM findings WHERE finding_id = ?", (finding_id,))
        if row is None:
            return None
        d = dict(row)
        return Finding(
            finding_id=d["finding_id"],
            scan_id=d["scan_id"],
            attack_id=d["attack_id"],
            category=d["category"],
            severity=d["severity"],
            label=FindingLabel(d["label"]),
            confidence=d["confidence"],
            summary=d["summary"],
            evidence_refs=json.loads(d["evidence_refs_json"]),
            needs_review=bool(d["needs_review"]),
            status=d["status"],
            weak_point=json.loads(d["weak_point_json"]) if d.get("weak_point_json") else None,
            created_at=datetime.fromisoformat(d["created_at"]),
        )


class ProposalRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, proposal: HardeningProposal) -> HardeningProposal:
        self._db.execute(
            "INSERT OR REPLACE INTO hardening_proposals (proposal_id, scan_id,"
            " prompt_diff, policy_diff, policy_candidate_json, rationale, affected_cases_json,"
            " risks_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                proposal.proposal_id,
                proposal.scan_id,
                proposal.prompt_diff,
                proposal.policy_diff,
                proposal.policy_candidate.model_dump_json() if proposal.policy_candidate else None,
                proposal.rationale,
                json.dumps(proposal.affected_cases),
                json.dumps(proposal.risks),
                proposal.created_at.isoformat(),
            ),
        )
        if proposal.policy_candidate is not None:
            self._db.execute(
                "INSERT OR REPLACE INTO policy_candidates (candidate_id, proposal_id,"
                " candidate_json, created_at) VALUES (?, ?, ?, ?)",
                (
                    _id("cand"),
                    proposal.proposal_id,
                    proposal.policy_candidate.model_dump_json(),
                    _now(),
                ),
            )
        return proposal

    def get(self, proposal_id: str) -> HardeningProposal | None:
        row = self._db.query_one(
            "SELECT * FROM hardening_proposals WHERE proposal_id = ?", (proposal_id,)
        )
        if row is None:
            return None
        return HardeningProposal(
            proposal_id=row["proposal_id"],
            scan_id=row["scan_id"],
            prompt_diff=row["prompt_diff"],
            policy_candidate=(
                PolicyCandidate.model_validate_json(row["policy_candidate_json"])
                if row["policy_candidate_json"]
                else None
            ),
            rationale=row["rationale"],
            affected_cases=json.loads(row["affected_cases_json"]),
            risks=json.loads(row["risks_json"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    def latest_for_scan(self, scan_id: str) -> HardeningProposal | None:
        row = self._db.query_one(
            "SELECT * FROM hardening_proposals WHERE scan_id = ?"
            " ORDER BY created_at DESC LIMIT 1",
            (scan_id,),
        )
        if row is None:
            return None
        return self.get(row["proposal_id"])


class ApprovalRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, approval: Approval) -> Approval:
        self._db.execute(
            "INSERT OR REPLACE INTO approvals (approval_id, proposal_id, scan_id,"
            " approved, approved_by, proposal_hash, decision, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                approval.approval_id,
                approval.proposal_id,
                approval.scan_id,
                int(approval.approved),
                approval.approved_by,
                approval.proposal_hash,
                approval.decision,
                approval.created_at.isoformat(),
            ),
        )
        return approval

    def get_for_proposal(self, proposal_id: str) -> Approval | None:
        row = self._db.query_one(
            "SELECT * FROM approvals WHERE proposal_id = ? ORDER BY created_at DESC"
            " LIMIT 1",
            (proposal_id,),
        )
        if row is None:
            return None
        d = dict(row)
        return Approval(
            approval_id=d["approval_id"],
            proposal_id=d["proposal_id"],
            scan_id=d["scan_id"],
            approved=bool(d["approved"]),
            approved_by=d["approved_by"],
            proposal_hash=d.get("proposal_hash") or "",
            decision=d.get("decision") or ("approved" if d["approved"] else "rejected"),
            created_at=datetime.fromisoformat(d["created_at"]),
        )


class TargetProfileRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, scan_id: str, profile: TargetProfile) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO target_profiles (scan_id, profile_json, created_at)"
            " VALUES (?, ?, ?)",
            (scan_id, profile.model_dump_json(), _now()),
        )

    def get(self, scan_id: str) -> TargetProfile | None:
        row = self._db.query_one(
            "SELECT * FROM target_profiles WHERE scan_id = ?", (scan_id,)
        )
        if row is None:
            return None
        return TargetProfile.model_validate_json(row["profile_json"])


class TestRunRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, test_run: TestRun) -> TestRun:
        self._db.execute(
            "INSERT OR REPLACE INTO test_runs (test_run_id, scan_id, kind,"
            " metrics_json, results_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                test_run.test_run_id,
                test_run.scan_id,
                test_run.kind.value,
                json.dumps(test_run.metrics, default=str),
                json.dumps(test_run.results, default=str),
                test_run.created_at.isoformat(),
            ),
        )
        return test_run

    def list_for_scan(self, scan_id: str, kind: TestRunKind | None = None) -> list[TestRun]:
        if kind is None:
            rows = self._db.query_all(
                "SELECT * FROM test_runs WHERE scan_id = ? ORDER BY created_at",
                (scan_id,),
            )
        else:
            rows = self._db.query_all(
                "SELECT * FROM test_runs WHERE scan_id = ? AND kind = ?"
                " ORDER BY created_at",
                (scan_id, kind.value),
            )
        return [
            TestRun(
                test_run_id=row["test_run_id"],
                scan_id=row["scan_id"],
                kind=TestRunKind(row["kind"]),
                metrics=json.loads(row["metrics_json"]),
                results=json.loads(row["results_json"]),
                created_at=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]

    def latest_for_scan(self, scan_id: str, kind: TestRunKind) -> TestRun | None:
        """Most recent test run of a kind (report collector, ADR 0001)."""
        runs = self.list_for_scan(scan_id, kind)
        return runs[-1] if runs else None


class RegressionRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save_case(
        self, target_id: str, attack_case: AttackCase, case_json: str
    ) -> str:
        existing = self._db.query_one(
            "SELECT regression_id FROM regression_cases WHERE target_id = ? AND attack_case_id = ? AND active = 1",
            (target_id, attack_case.id),
        )
        if existing is not None:
            self._db.execute(
                "UPDATE regression_cases SET case_json = ?, created_at = ? WHERE regression_id = ?",
                (case_json, _now(), existing["regression_id"]),
            )
            return existing["regression_id"]

        regression_id = _id("reg")
        self._db.execute(
            "INSERT INTO regression_cases (regression_id, target_id, attack_case_id,"
            " active, case_json, created_at) VALUES (?, ?, ?, 1, ?, ?)",
            (regression_id, target_id, attack_case.id, case_json, _now()),
        )
        return regression_id


    def list_active(self, target_id: str) -> list[dict[str, Any]]:
        rows = self._db.query_all(
            "SELECT * FROM regression_cases WHERE target_id = ? AND active = 1",
            (target_id,),
        )
        return [dict(row) for row in rows]

    def list_all(self, target_id: str | None = None) -> list[dict[str, Any]]:
        if target_id:
            rows = self._db.query_all(
                "SELECT * FROM regression_cases WHERE target_id = ? ORDER BY created_at DESC",
                (target_id,),
            )
        else:
            rows = self._db.query_all(
                "SELECT * FROM regression_cases ORDER BY created_at DESC"
            )
        return [dict(row) for row in rows]

    def get(self, regression_id: str) -> dict[str, Any] | None:
        row = self._db.query_one(
            "SELECT * FROM regression_cases WHERE regression_id = ?",
            (regression_id,),
        )
        return dict(row) if row else None

    def toggle_active(self, regression_id: str, active: bool | None = None) -> dict[str, Any] | None:
        row = self.get(regression_id)
        if not row:
            return None
        new_active = (1 if active else 0) if active is not None else (0 if row["active"] == 1 else 1)
        self._db.execute(
            "UPDATE regression_cases SET active = ? WHERE regression_id = ?",
            (new_active, regression_id),
        )
        return self.get(regression_id)



class ReportRepository:
    """Immutable report artifacts keyed by content hash (ADR 0001).

    The same persisted evidence must not produce duplicate artifacts: an
    artifact is written once per (scan, format, content hash).
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    def save_artifact(
        self,
        scan_id: str,
        fmt: str,
        content: str,
        *,
        content_sha256: str = "",
        schema_version: str = "1.0",
        generator_version: str = "",
    ) -> str:
        existing = self.get_artifact_by_hash(scan_id, fmt, content_sha256)
        if existing is not None:
            return str(existing["artifact_id"])
        artifact_id = _id("rpt")
        self._db.execute(
            "INSERT INTO report_artifacts (artifact_id, scan_id, format, content,"
            " schema_version, generator_version, content_sha256, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                artifact_id,
                scan_id,
                fmt,
                content,
                schema_version,
                generator_version,
                content_sha256,
                _now(),
            ),
        )
        return artifact_id

    def get_artifact_by_hash(
        self, scan_id: str, fmt: str, content_sha256: str
    ) -> dict[str, Any] | None:
        if not content_sha256:
            return None
        row = self._db.query_one(
            "SELECT * FROM report_artifacts WHERE scan_id = ? AND format = ?"
            " AND content_sha256 = ? ORDER BY created_at DESC LIMIT 1",
            (scan_id, fmt, content_sha256),
        )
        return dict(row) if row is not None else None

    def get_artifact(self, scan_id: str, fmt: str) -> dict[str, Any] | None:
        row = self._db.query_one(
            "SELECT * FROM report_artifacts WHERE scan_id = ? AND format = ?"
            " ORDER BY created_at DESC LIMIT 1",
            (scan_id, fmt),
        )
        if row is None:
            return None
        return dict(row)


class Repositories:
    """Facade bundling all repositories over one Database."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self.scans = ScanRepository(db)
        self.events = EventRepository(db)
        self.runs = RunRepository(db)
        self.findings = FindingRepository(db)
        self.proposals = ProposalRepository(db)
        self.approvals = ApprovalRepository(db)
        self.profiles = TargetProfileRepository(db)
        self.test_runs = TestRunRepository(db)
        self.regressions = RegressionRepository(db)
        self.reports = ReportRepository(db)

    def migrate(self) -> None:
        self.db.migrate()
