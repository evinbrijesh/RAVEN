"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import TopBar from "@/components/ui/TopBar";
import { LabelChip } from "@/components/ui/primitives";
import { ErrorBlock, LoadingBlock } from "@/components/ui/StateViews";
import {
  ApiRequestError,
  getReport,
  getReportText,
  reportFilename,
  type ReportFormat,
} from "@/lib/api-client";
import type { Report } from "@/lib/types";
import { pct, VERDICT_META } from "@/components/report/shared";

import { DEMO_REPORT } from "@/lib/demo-report";
import Link from "next/link";

/* ─── Section wrapper ────────────────────────────────────────────────────── */
function ReportSection({
  title,
  id,
  children,
}: {
  title: string;
  id: string;
  children: React.ReactNode;
}) {
  return (
    <section id={id} className="space-y-4">
      <h2 className="border-b border-[var(--border-hairline)] pb-2 text-[var(--text-md)] font-semibold">
        {title}
      </h2>
      {children}
    </section>
  );
}

/* ─── Print-safe stat row ─────────────────────────────────────────────────── */
function StatRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between border-b border-[var(--border-hairline)] py-2 last:border-none">
      <dt className="text-[var(--text-sm)] text-[var(--text-secondary)]">{label}</dt>
      <dd className="font-mono text-[var(--text-sm)] text-[var(--text-primary)]">{value}</dd>
    </div>
  );
}

/* ─── Export panel (hidden in print; PDF = browser print) ────────────────── */
function ExportPanel({ scanId }: { scanId: string }) {
  const [exporting, setExporting] = useState<ReportFormat | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function exportReport(format: ReportFormat): Promise<void> {
    setExporting(format);
    setError(null);
    try {
      const text = await getReportText(scanId, format);
      const mimes: Record<ReportFormat, string> = {
        json: "application/json",
        markdown: "text/markdown",
        sarif: "application/sarif+json",
      };
      const blob = new Blob([text], { type: mimes[format] });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = reportFilename(scanId, format);
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (cause) {
      if (scanId === "scan_123") {
        let fallbackText = "";
        const mimes: Record<ReportFormat, string> = {
          json: "application/json",
          markdown: "text/markdown",
          sarif: "application/sarif+json",
        };
        if (format === "json") fallbackText = JSON.stringify(DEMO_REPORT, null, 2);
        else if (format === "sarif") fallbackText = JSON.stringify({ version: "2.1.0", runs: [] }, null, 2);
        else fallbackText = `# RAVEN Security Regression Report: ${DEMO_REPORT.scan.scan_id}\n\n**Verdict:** ${DEMO_REPORT.summary.verdict}\n\n${DEMO_REPORT.summary.headline}`;
        const blob = new Blob([fallbackText], { type: mimes[format] });
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = reportFilename(scanId, format);
        anchor.click();
        URL.revokeObjectURL(url);
        return;
      }
      setError(
        cause instanceof ApiRequestError
          ? `${cause.code}: ${cause.message}`
          : "Export failed.",
      );
    } finally {
      setExporting(null);
    }
  }

  const options: Array<{ label: string; format: ReportFormat | "print" | "gha"; note?: string }> = [
    { label: "JSON", format: "json" },
    { label: "Markdown", format: "markdown" },
    { label: "SARIF", format: "sarif" },
    { label: "PDF", format: "print", note: "via browser print" },
    { label: "GitHub Action", format: "gha", note: ".yml gate" },
  ];

  function downloadGitHubAction(): void {
    const yaml = `name: RAVEN Security Gate
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  raven-security-regression:
    name: Run Continuous Security Regression Suite
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.13"

      - name: Install uv and Dependencies
        run: |
          curl -LsSf https://astral.sh/uv/install.sh | sh
          uv sync --all-packages

      - name: Execute RAVEN Security Regression Runner
        run: |
          uv run raven-test --target shophelper-local --output json
`;
    const blob = new Blob([yaml], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "raven-security-gate.yml";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <aside className="sticky top-6 space-y-4 print:hidden" aria-label="Export options">
      <div className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-4">
        <p className="mb-3 text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)]">
          Export report
        </p>
        {error && (
          <p role="alert" className="mb-2 text-[11px] text-red-400">
            {error}
          </p>
        )}
        <div className="space-y-2">
          {options.map(({ label, format, note }) => (
            <button
              key={format}
              type="button"
              disabled={exporting !== null}
              onClick={
                format === "print"
                  ? () => window.print()
                  : format === "gha"
                    ? downloadGitHubAction
                    : () => void exportReport(format as ReportFormat)
              }
              className="flex w-full items-center justify-between rounded-[var(--radius-input)] border border-[var(--border-hairline)] bg-[var(--bg-raised)] px-3 py-2 text-[var(--text-sm)] text-[var(--text-secondary)] hover:border-[var(--border-subtle)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-50"
            >
              <span>
                {exporting === format ? "Exporting…" : label}
              </span>
              {note ? (
                <span className="text-[10px] text-[var(--text-muted)]">{note}</span>
              ) : (
                <span className="text-[var(--text-muted)]">↓</span>
              )}
            </button>
          ))}
        </div>
      </div>
    </aside>
  );
}

/* ─── Main screen ─────────────────────────────────────────────────────────── */
export default function ReportPage() {
  const params = useParams<{ id: string }>();
  const scanId = typeof params?.id === "string" ? params.id : "";
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!scanId) return;
    setError(null);
    setReport(null);
    try {
      const result = await getReport(scanId, "json");
      if (typeof result === "string") {
        setError("Report endpoint returned an unexpected format.");
        return;
      }
      setReport(result as Report);
    } catch (cause) {
      if (scanId === "scan_123") {
        // scan_123 is the showcase demo scan: seamlessly load demo report
        setReport(DEMO_REPORT);
        return;
      }
      setError(
        cause instanceof ApiRequestError ? cause.message : "Failed to load report.",
      );
    }
  }, [scanId]);

  useEffect(() => {
    void load();
  }, [load]);

  if (error) {
    const isNetworkError = error.includes("Cannot reach RAVEN API") || error.includes("NETWORK_ERROR");
    return (
      <div className="flex flex-col">
        <TopBar
          breadcrumbs={[
            { label: "Scans", href: "/scans" },
            { label: scanId, href: `/scans/${scanId}` },
            { label: "Report" },
          ]}
        />
        <main className="flex-1 px-6 py-8 max-w-3xl mx-auto w-full space-y-6">
          <ErrorBlock
            title="Report not available"
            message={error}
            onRetry={() => void load()}
          />
          {isNetworkError && (
            <div className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5 space-y-3 font-mono">
              <p className="text-xs text-[var(--text-secondary)]">
                💡 <span className="font-semibold text-[var(--accent)]">Render Free Tier Notice:</span> The backend server sleeps after 15 minutes of inactivity. When awakened, it takes 30-50 seconds to complete its cold-start.
              </p>
              <div className="flex flex-wrap gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setReport(DEMO_REPORT)}
                  className="rounded-[var(--radius-input)] bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[#0A0D12] hover:brightness-110"
                >
                  Load Sample Audit Report (ShopHelper) →
                </button>
                <Link
                  href="/scans/new"
                  className="rounded-[var(--radius-input)] border border-[var(--border-hairline)] bg-[var(--bg-raised)] px-4 py-2 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                >
                  Configure New Scan
                </Link>
              </div>
            </div>
          )}
        </main>
      </div>
    );
  }
  if (!report) {
    return (
      <div className="flex flex-col">
        <TopBar
          breadcrumbs={[
            { label: "Scans", href: "/scans" },
            { label: scanId, href: `/scans/${scanId}` },
            { label: "Report" },
          ]}
        />
        <main className="flex-1 px-6 py-8">
          <LoadingBlock label="Loading report…" />
        </main>
      </div>
    );
  }

  const verdictMeta = VERDICT_META[report.summary.verdict];
  const security = report.before_after.security;
  const utility = report.before_after.utility;

  return (
    <div className="flex flex-col">
      {/* Print stylesheet: clean white document output */}
      <style>{`
        @media print {
          body { background: #fff !important; color: #111 !important; }
          .print-hide { display: none !important; }
        }
      `}</style>

      <TopBar
        breadcrumbs={[
          { label: "Scans", href: "/scans" },
          { label: scanId, href: `/scans/${scanId}` },
          { label: "Report" },
        ]}
        scanStatus={report.scan.status}
      />

      <main className="flex-1 px-6 py-8">
        {/* Report header */}
        <div className="mb-8 border-b border-[var(--border-hairline)] pb-6">
          <div className="flex items-start justify-between">
            <div>
              <p className="font-mono text-[var(--text-xs)] text-[var(--text-muted)]">
                RAVEN Security Regression Report
              </p>
              <h1 className="mt-1 text-[var(--text-xl)] font-semibold tracking-tight">
                {report.scan.scan_id} — {report.scan.target.id}
              </h1>
              <p className="mt-1 font-mono text-[var(--text-sm)] text-[var(--text-secondary)]">
                {report.generated_at} · {report.report_id}
              </p>
            </div>
            <div className="flex flex-col items-end gap-1 text-[var(--text-xs)] text-[var(--text-muted)] font-mono print:hidden">
              <span>schema v{report.schema_version}</span>
              <span>
                raven v{report.generator.version} · target v{report.scan.target.version}
              </span>
              <span>sha256 {report.integrity.content_sha256.slice(0, 16)}…</span>
            </div>
          </div>
        </div>

        {/* Awaiting Approval Banner */}
        {report.scan.status === "awaiting_approval" && (
          <div className="mb-8 flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-[var(--radius-card)] border border-amber-500/40 bg-amber-950/20 p-5">
            <div className="space-y-1">
              <div className="flex items-center gap-2 font-mono text-xs text-amber-400 font-semibold uppercase tracking-wider">
                <span className="h-2 w-2 rounded-full bg-amber-400 animate-ping" />
                Hardening Proposed · Awaiting Operator Approval
              </div>
              <p className="text-xs text-[var(--text-secondary)]">
                Phase 1 baseline attacks identified confirmed vulnerabilities ({pct(security.before_attack_success_rate)} attack success rate). A hardening patch was drafted. To execute Phase 2 (verification retest) and measure remediation deltas, approve the hardening proposal.
              </p>
            </div>
            <Link
              href={`/scans/${scanId}/hardening`}
              className="flex-shrink-0 rounded-[var(--radius-input)] bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[#0A0D12] hover:brightness-110 shadow-sm transition-all text-center"
            >
              Review & Approve Hardening →
            </Link>
          </div>
        )}

        <div className="grid gap-8 lg:grid-cols-[1fr_240px]">
          {/* ── Document content ────────────────────────────────────────── */}
          <div className="max-w-3xl space-y-10">
            {/* 1. Summary */}
            <ReportSection title="1. Summary" id="summary">
              <div className="flex items-center gap-3">
                <span
                  className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-1 text-xs font-semibold ${verdictMeta.cls}`}
                >
                  <span aria-hidden className="font-mono text-[10px]">
                    {verdictMeta.icon}
                  </span>
                  {verdictMeta.label}
                </span>
                <p className="text-[var(--text-sm)] text-[var(--text-primary)]">
                  {report.summary.headline}
                </p>
              </div>
              <dl>
                <StatRow label="Attack cases" value={String(report.summary.counts.attack_cases)} />
                <StatRow label="Evaluated" value={String(report.summary.counts.evaluated)} />
                <StatRow label="Confirmed failures" value={String(report.summary.counts.confirmed_failure)} />
                <StatRow label="Likely failures" value={String(report.summary.counts.likely_failure)} />
                <StatRow label="Attacks blocked" value={String(report.summary.counts.attack_blocked)} />
                <StatRow label="Needs review" value={String(report.summary.counts.needs_review)} />
                <StatRow
                  label="Benign passed"
                  value={`${report.summary.counts.benign_passed}/${report.summary.counts.benign_cases}`}
                />
                <StatRow label="Regressions saved" value={String(report.summary.counts.regressions)} />
              </dl>
            </ReportSection>

            {/* 2. Coverage */}
            <ReportSection title="2. Coverage" id="coverage">
              <dl>
                <StatRow label="Attack cases" value={String(report.coverage.attack_cases)} />
                <StatRow
                  label="Categories"
                  value={report.coverage.categories.map((c) => c.replace(/_/g, " ")).join(", ") || "none"}
                />
                <StatRow label="Benign cases" value={String(report.coverage.benign_cases)} />
                <StatRow
                  label="Catalog versions"
                  value={`attacks ${report.coverage.attack_catalog_version} · benign ${report.coverage.benign_catalog_version}`}
                />
              </dl>
            </ReportSection>

            {/* 3. Findings */}
            <ReportSection title="3. Findings" id="findings-report">
              {report.findings.length === 0 ? (
                <p className="text-[var(--text-sm)] text-[var(--text-secondary)]">
                  No findings recorded for this scan.
                </p>
              ) : (
                <div className="space-y-3">
                  {report.findings.map((finding) => (
                    <div
                      key={finding.finding_id}
                      className="flex items-start gap-3 rounded-[var(--radius-input)] border border-[var(--border-hairline)] bg-[var(--bg-raised)] p-3"
                    >
                      <span className="mt-0.5 w-12 flex-shrink-0 font-mono text-[var(--text-xs)] text-[var(--text-muted)]">
                        {finding.attack_id}
                      </span>
                      <div className="min-w-0 flex-1 space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <LabelChip label={finding.label} />
                          <span className="font-mono text-[10px] text-[var(--text-muted)]">
                            {finding.category.replace(/_/g, " ")}
                          </span>
                          <span className="font-mono text-[10px] uppercase text-[var(--text-muted)]">
                            {finding.severity}
                          </span>
                          {!finding.evidence_complete && (
                            <span className="font-mono text-[10px] text-orange-400">
                              evidence incomplete
                            </span>
                          )}
                        </div>
                        <p className="text-[var(--text-sm)] text-[var(--text-secondary)]">
                          {finding.summary}
                        </p>
                        {finding.attack && (
                          <p className="font-mono text-[10px] text-[var(--text-muted)]">
                            goal: {finding.attack.goal} · rule: {finding.attack.success_rule}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </ReportSection>

            {/* 4. Hardening */}
            <ReportSection title="4. Hardening" id="hardening-report">
              {report.hardening.proposal ? (
                <>
                  <dl>
                    <StatRow label="Proposal" value={report.hardening.proposal.proposal_id} />
                    <StatRow
                      label="Approved"
                      value={
                        report.hardening.approval
                          ? `${report.hardening.approval.approved ? "yes" : "no"} by ${report.hardening.approval.approved_by}`
                          : "not recorded"
                      }
                    />
                    <StatRow label="Applied to" value={report.hardening.applied_to.replace(/_/g, " ")} />
                  </dl>
                  <pre className="overflow-auto rounded-[var(--radius-input)] border border-[var(--border-hairline)] bg-[var(--bg-raised)] p-3 font-mono text-[11px] text-[var(--text-secondary)]">
                    {report.hardening.proposal.prompt_diff}
                  </pre>
                </>
              ) : (
                <p className="text-[var(--text-sm)] text-[var(--text-secondary)]">
                  No hardening proposal was generated for this scan.
                </p>
              )}
            </ReportSection>

            {/* 5. Before & After */}
            <ReportSection title="5. Before & after" id="before-after">
              <dl>
                <StatRow
                  label="Attack success rate (before → after)"
                  value={`${pct(security.before_attack_success_rate)} → ${pct(security.after_attack_success_rate)} (Δ ${pct(security.delta)})`}
                />
                <StatRow
                  label="Blocked rate (before → after)"
                  value={`${pct(security.before_blocked_rate)} → ${pct(security.after_blocked_rate)}`}
                />
                <StatRow
                  label="Benign success rate (before → after)"
                  value={`${pct(utility.before_benign_success_rate)} → ${pct(utility.after_benign_success_rate)} (Δ ${pct(utility.delta)})`}
                />
              </dl>
              {security.after_attack_success_rate === null && (
                <div className="mt-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded-md border border-amber-900/30 bg-amber-950/15 p-3 text-xs font-mono text-amber-300/90">
                  <span>
                    ℹ️ "After" metrics are pending. Approve the hardening proposal to execute Phase 2 retest and calculate remediation efficacy.
                  </span>
                  <Link
                    href={`/scans/${scanId}/hardening`}
                    className="text-[var(--accent)] font-semibold hover:underline whitespace-nowrap"
                  >
                    Approve proposal →
                  </Link>
                </div>
              )}
              {utility.over_refusal_case_ids.length > 0 && (
                <p className="text-[var(--text-sm)] text-amber-300/90">
                  Over-refusal detected after hardening:{" "}
                  <span className="font-mono">{utility.over_refusal_case_ids.join(", ")}</span>
                </p>
              )}
            </ReportSection>

            {/* 6. Evidence */}
            <ReportSection title="6. Evidence" id="evidence">
              <dl>
                <StatRow label="Evidence entries" value={String(report.evidence.length)} />
                <StatRow label="Model calls (judge)" value={String(report.model_usage.calls)} />
                <StatRow
                  label="Redaction"
                  value={
                    report.redaction.applied
                      ? `applied (${report.redaction.redacted_fields.join(", ")})`
                      : "not applied"
                  }
                />
              </dl>
            </ReportSection>

            {/* 7. Limitations (prominent) */}
            <ReportSection title="7. Limitations" id="limitations">
              <div className="rounded-[var(--radius-card)] border border-amber-900/30 bg-amber-950/15 p-4">
                <ul className="space-y-2">
                  {report.limitations.map((limitation, index) => (
                    <li
                      key={index}
                      className="flex items-start gap-2 text-[var(--text-sm)] text-amber-300/90"
                    >
                      <span className="mt-0.5 flex-shrink-0 font-mono text-amber-500">!</span>
                      {limitation}
                    </li>
                  ))}
                </ul>
              </div>
            </ReportSection>

            {/* 8. Versions & integrity */}
            <ReportSection title="8. Versions & integrity" id="versions">
              <dl>
                {Object.entries(report.tool_versions).map(([key, value]) => (
                  <StatRow key={key} label={key} value={value} />
                ))}
                <StatRow label="Generated at" value={report.generated_at} />
                <StatRow label="Content SHA-256" value={report.integrity.content_sha256} />
                <StatRow label="Source" value={report.integrity.source} />
              </dl>
            </ReportSection>
          </div>

          {/* ── Sticky export panel ──────────────────────────────────────── */}
          <ExportPanel scanId={scanId} />
        </div>
      </main>
    </div>
  );
}
