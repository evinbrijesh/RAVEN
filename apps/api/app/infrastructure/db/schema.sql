-- RAVEN canonical database schema (SQLite for the MVP profile).
-- Blueprint §7: minimum durable tables + required indexes.
-- The same DDL is versioned in apps/api/migrations/0001_init.sql.
-- PostgreSQL notes: TEXT -> VARCHAR/UUID, REAL -> DOUBLE PRECISION,
-- INTEGER booleans -> BOOLEAN, AUTOINCREMENT -> GENERATED ALWAYS AS IDENTITY.

CREATE TABLE IF NOT EXISTS scans (
    scan_id     TEXT PRIMARY KEY,
    status      TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    config_json TEXT NOT NULL,
    progress    REAL NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS scan_events (
    event_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT NOT NULL,
    kind         TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_events_scan ON scan_events(scan_id, created_at);

CREATE TABLE IF NOT EXISTS target_profiles (
    scan_id            TEXT PRIMARY KEY,
    profile_json       TEXT NOT NULL,
    created_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attack_cases (
    attack_case_id TEXT NOT NULL,
    version        TEXT NOT NULL,
    case_json      TEXT NOT NULL,
    PRIMARY KEY (attack_case_id, version)
);

CREATE TABLE IF NOT EXISTS attack_runs (
    run_id         TEXT PRIMARY KEY,
    scan_id        TEXT NOT NULL,
    attack_case_id TEXT NOT NULL,
    attempt        INTEGER NOT NULL,
    phase          TEXT NOT NULL,
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    status         TEXT NOT NULL,
    transcript_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_attack_runs_scan ON attack_runs(scan_id, attack_case_id);

CREATE TABLE IF NOT EXISTS transcripts (
    transcript_id TEXT PRIMARY KEY,
    run_id        TEXT NOT NULL,
    messages_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verdicts (
    verdict_id         TEXT PRIMARY KEY,
    run_id             TEXT NOT NULL,
    scan_id            TEXT NOT NULL,
    rule_label         TEXT,
    rule_signals_json  TEXT,
    llm_label          TEXT,
    llm_confidence     REAL,
    llm_reason         TEXT,
    llm_model_name     TEXT,
    llm_prompt_version TEXT,
    final_label        TEXT NOT NULL,
    resolution         TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    created_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id         TEXT PRIMARY KEY,
    scan_id            TEXT NOT NULL,
    attack_id          TEXT NOT NULL,
    category           TEXT NOT NULL,
    severity           TEXT NOT NULL,
    label              TEXT NOT NULL,
    confidence         REAL NOT NULL,
    summary            TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    needs_review       INTEGER NOT NULL DEFAULT 0,
    status             TEXT NOT NULL DEFAULT 'open',
    weak_point_json    TEXT,
    created_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_status_sev ON findings(status, severity);

CREATE TABLE IF NOT EXISTS hardening_proposals (
    proposal_id          TEXT PRIMARY KEY,
    scan_id              TEXT NOT NULL,
    prompt_diff          TEXT NOT NULL,
    policy_diff          TEXT NOT NULL DEFAULT '',
    policy_candidate_json TEXT,
    rationale            TEXT NOT NULL,
    affected_cases_json  TEXT NOT NULL,
    risks_json           TEXT NOT NULL,
    created_at           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_candidates (
    candidate_id   TEXT PRIMARY KEY,
    proposal_id    TEXT NOT NULL,
    candidate_json TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL,
    scan_id     TEXT NOT NULL,
    approved    INTEGER NOT NULL,
    approved_by TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS regression_cases (
    regression_id  TEXT PRIMARY KEY,
    target_id      TEXT NOT NULL,
    attack_case_id TEXT NOT NULL,
    active         INTEGER NOT NULL DEFAULT 1,
    case_json      TEXT NOT NULL,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_regression_cases
    ON regression_cases(target_id, attack_case_id, active);
-- The unique active-regression index (uq_regression_cases_active) is created
-- defensively by sqlite.migrate() so dirty pre-existing databases do not
-- crash startup.

CREATE TABLE IF NOT EXISTS test_runs (
    test_run_id  TEXT PRIMARY KEY,
    scan_id      TEXT NOT NULL,
    kind         TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    results_json TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS report_artifacts (
    artifact_id       TEXT PRIMARY KEY,
    scan_id           TEXT NOT NULL,
    format            TEXT NOT NULL,
    content           TEXT NOT NULL,
    schema_version    TEXT NOT NULL DEFAULT '1.0',
    generator_version TEXT NOT NULL DEFAULT '',
    content_sha256    TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_report_artifact_hash
    ON report_artifacts(scan_id, format, content_sha256);

-- Job queue (SQLite-backed so the MVP needs no Redis; swap for Redis later).
CREATE TABLE IF NOT EXISTS jobs (
    job_id       TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'queued',
    attempts     INTEGER NOT NULL DEFAULT 0,
    error        TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status, created_at);
