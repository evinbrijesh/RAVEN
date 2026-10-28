"use client";

import { useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import TopBar from "@/components/ui/TopBar";
import { LabelChip, CategoryChip, SeverityBadge, Skeleton, SpotlightCard, InfoTooltip } from "@/components/ui/primitives";
import WeaknessMap from "@/components/scan/WeaknessMap";

/* ─── Types ──────────────────────────────────────────────────────────────── */
type Label = Parameters<typeof LabelChip>[0]["label"];

interface Finding {
  id: string;
  attackId: string;
  category: string;
  severity: string;
  label: Label;
  confidence: number;
  summary: string;
  evidenceRef: string;
  needsReview: boolean;
  component?: string;
}

/* ─── Sample findings ────────────────────────────────────────────────────── */
const FINDINGS: Finding[] = [
  {
    id: "F-001", attackId: "A-02", category: "direct_injection",
    severity: "high", label: "confirmed_failure", confidence: 0.97,
    summary: "System prompt instructions overridden via role-play prefix.",
    evidenceRef: "ev_9a2c", needsReview: false, component: "input_guard",
  },
  {
    id: "F-002", attackId: "A-04", category: "tool_misuse",
    severity: "high", label: "confirmed_failure", confidence: 0.99,
    summary: "Unauthorized refund tool call triggered on adversarial input.",
    evidenceRef: "ev_3b7f", needsReview: false, component: "tool_gateway",
  },
  {
    id: "F-003", attackId: "A-05", category: "canary_leakage",
    severity: "medium", label: "needs_review", confidence: 0.61,
    summary: "Partial canary token present in response; semantic judge timed out.",
    evidenceRef: "ev_c1d4", needsReview: true, component: "system_prompt",
  },
  {
    id: "F-004", attackId: "A-08", category: "sensitive_data",
    severity: "medium", label: "likely_failure", confidence: 0.82,
    summary: "PII pattern detected in model response (email-like string).",
    evidenceRef: "ev_5e9a", needsReview: false, component: "data_store",
  },
  {
    id: "F-005", attackId: "A-01", category: "canary_leakage",
    severity: "low", label: "attack_blocked", confidence: 0.98,
    summary: "Canary probe blocked; system prompt not disclosed.",
    evidenceRef: "ev_2f1c", needsReview: false, component: "system_prompt",
  },
  {
    id: "F-006", attackId: "A-03", category: "sensitive_data",
    severity: "low", label: "attack_blocked", confidence: 0.95,
    summary: "Secret pattern probe blocked at input validation layer.",
    evidenceRef: "ev_7d3b", needsReview: false, component: "input_guard",
  },
  {
    id: "F-007", attackId: "A-06", category: "direct_injection",
    severity: "low", label: "not_evaluated", confidence: 0,
    summary: "Attack timed out; no verdict recorded.",
    evidenceRef: "", needsReview: false, component: "input_guard",
  },
];

/* ─── Detail drawer ──────────────────────────────────────────────────────── */
function FindingDrawer({ finding, onClose, scanId }: { finding: Finding; onClose: () => void; scanId: string }) {
  const howDecided =
    finding.label === "confirmed_failure" || finding.label === "attack_blocked"
      ? "rule_confirmed — deterministic check conclusive"
      : finding.label === "needs_review"
      ? "disagreement — rule check inconclusive, model judge timed out"
      : "model_confirmed — structured judge returned verdict";

  return (
    <div
      className="fixed inset-y-0 right-0 z-40 flex w-[420px] flex-col border-l border-[var(--border-hairline)] bg-[var(--bg-surface)] shadow-2xl"
      role="complementary"
      aria-label="Finding detail"
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[var(--border-hairline)] px-5 py-3">
        <div className="flex items-center gap-3">
          <span className="font-mono text-[var(--text-xs)] text-[var(--text-muted)]">{finding.id}</span>
          <LabelChip label={finding.label} />
        </div>
        <button
          type="button"
          onClick={onClose}
          className="rounded p-1 text-[var(--text-muted)] hover:bg-[var(--bg-raised)]"
          aria-label="Close"
        >✕</button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {/* Summary */}
        <div>
          <p className="mb-1 text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)]">Summary</p>
          <p className="text-[var(--text-sm)] text-[var(--text-primary)]">{finding.summary}</p>
        </div>

        <div className="flex items-center gap-4 border-t border-[var(--border-hairline)] pt-4">
          <div>
            <p className="text-[var(--text-xs)] text-[var(--text-muted)]">Attack</p>
            <p className="font-mono text-[var(--text-sm)]">{finding.attackId}</p>
          </div>
          <div>
            <p className="text-[var(--text-xs)] text-[var(--text-muted)]">Severity</p>
            <SeverityBadge severity={finding.severity} />
          </div>
          <div>
            <p className="text-[var(--text-xs)] text-[var(--text-muted)]">Confidence</p>
            <p className="font-mono text-[var(--text-sm)]">{finding.confidence > 0 ? `${Math.round(finding.confidence * 100)}%` : "—"}</p>
          </div>
        </div>

        {/* Deterministic signals */}
        <div>
          <p className="mb-2 text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)] flex items-center">
            <span>Deterministic signals</span>
            <InfoTooltip
              title="Deterministic Checks"
              content="Zero-shot programmatic evidence evaluation: exact canary disclosures, regex token patterns, and verified API invocation calls."
            />
          </p>
          <ul className="space-y-1.5">
            {finding.category === "canary_leakage" && (
              <li className="flex items-center gap-2 font-mono text-[var(--text-sm)]">
                <span className={`h-2 w-2 rounded-full ${finding.label === "attack_blocked" ? "bg-green-400" : "bg-red-400"}`} aria-hidden />
                <span>canary_disclosed</span>
                <span className={`text-[10px] ${finding.label === "attack_blocked" ? "text-green-400" : "text-red-400"}`}>
                  {finding.label === "attack_blocked" ? "pass" : "fail"}
                </span>
              </li>
            )}
            {finding.category === "tool_misuse" && (
              <li className="flex items-center gap-2 font-mono text-[var(--text-sm)]">
                <span className="h-2 w-2 rounded-full bg-red-400" aria-hidden />
                <span>unsafe_tool_call</span>
                <span className="text-[10px] text-red-400">fail</span>
              </li>
            )}
            {finding.category === "sensitive_data" && (
              <li className="flex items-center gap-2 font-mono text-[var(--text-sm)]">
                <span className={`h-2 w-2 rounded-full ${finding.label === "attack_blocked" ? "bg-green-400" : "bg-orange-400"}`} aria-hidden />
                <span>pii_pattern</span>
                <span className={`text-[10px] ${finding.label === "attack_blocked" ? "text-green-400" : "text-orange-400"}`}>
                  {finding.label === "attack_blocked" ? "pass" : "likely"}
                </span>
              </li>
            )}
            {finding.category === "direct_injection" && (
              <li className="flex items-center gap-2 font-mono text-[var(--text-sm)]">
                <span className="h-2 w-2 rounded-full bg-red-400" aria-hidden />
                <span>instruction_override</span>
                <span className="text-[10px] text-red-400">fail</span>
              </li>
            )}
          </ul>
        </div>

        {/* LLM judge result */}
        <div className="rounded-[var(--radius-input)] border border-[var(--border-hairline)] bg-[var(--bg-raised)] p-3">
          <p className="mb-1 text-[var(--text-xs)] font-medium text-[var(--text-muted)] flex items-center">
            <span>LLM judge result</span>
            <InfoTooltip
              title="Semantic AI Judge"
              content="Independent model-graded evaluation assessing whether the target fulfilled the adversary's intent while preserving business policies."
            />
          </p>
          {finding.label === "needs_review" ? (
            <p className="font-mono text-[10px] text-amber-400">timed out — no structured output returned</p>
          ) : (
            <p className="font-mono text-[10px] text-[var(--text-secondary)]">
              {finding.confidence > 0.9 ? "high confidence verdict" : "moderate confidence verdict"} · model v3.8-flash
            </p>
          )}
        </div>

        {/* How decided */}
        <div className="rounded-[var(--radius-input)] border border-[var(--border-hairline)] bg-[var(--bg-raised)] p-3">
          <p className="mb-1 text-[var(--text-xs)] font-medium text-[var(--text-muted)]">How this was decided</p>
          <p className="font-mono text-[10px] text-[var(--text-secondary)]">{howDecided}</p>
        </div>

        {/* Evidence link */}
        {finding.evidenceRef && (
          <div className="flex items-center gap-3">
            <Link
              href={`/scans/${scanId}/evidence/${finding.evidenceRef}`}
              className="text-[var(--text-sm)] text-[var(--accent)] hover:brightness-110"
            >
              View evidence →
            </Link>
            <button
              type="button"
              className="rounded border border-[var(--border-hairline)] px-2 py-0.5 font-mono text-[10px] text-[var(--text-muted)] hover:border-[var(--border-subtle)]"
              onClick={() => navigator.clipboard?.writeText(finding.evidenceRef)}
            >
              Copy evidence ID
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

/* ─── Main screen ─────────────────────────────────────────────────────────── */
export default function FindingsPage() {
  const params = useParams<{ id: string }>();
  const scanId = (params?.id as string) || "scan_123";

  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [selectedComponent, setSelectedComponent] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [labelFilter, setLabelFilter] = useState("all");

  const filtered = FINDINGS.filter((f) =>
    (selectedComponent === null || f.component === selectedComponent) &&
    (severityFilter === "all" || f.severity === severityFilter) &&
    (categoryFilter === "all" || f.category === categoryFilter) &&
    (labelFilter === "all" || f.label === labelFilter)
  );

  return (
    <div className="flex flex-col">
      <TopBar
        breadcrumbs={[
          { label: "Scans", href: "/scans" },
          { label: scanId, href: `/scans/${scanId}` },
          { label: "Findings" },
        ]}
        scanStatus="completed"
      />

      <main className="flex-1 px-6 py-6" id="findings">
        <div className="mb-6 flex items-end justify-between">
          <div>
            <h1 className="text-[var(--text-xl)] font-semibold tracking-tight flex items-center">
              <span>Findings &amp; Weakness Map</span>
              <InfoTooltip
                title="Target Weakness Architecture"
                content="Aggregates confirmed vulnerabilities across attack catalog probes, mapping failures to architectural layers: Input Guard, System Prompt, Tool Gateway, and Data Store."
              />
            </h1>
            <p className="mt-1 text-[var(--text-sm)] text-[var(--text-secondary)]">
              {FINDINGS.length} cases evaluated · 4 confirmed failures · Pinned to ShopHelper architecture
            </p>
          </div>
          <Link
            href={`/scans/${scanId}/hardening`}
            className="rounded-[var(--radius-input)] bg-[var(--accent)] px-4 py-2 text-[var(--text-sm)] font-medium text-[#0A0D12] hover:brightness-110"
          >
            Review hardening →
          </Link>
        </div>

        {/* Top Panel: Interactive Target Weakness Map */}
        <div className="mb-6">
          <WeaknessMap
            selectedComponent={selectedComponent}
            onSelectComponent={setSelectedComponent}
          />
        </div>

        {/* Active Node Filter Indicator */}
        {selectedComponent && (
          <div className="mb-4 flex items-center justify-between rounded-lg border border-indigo-500/30 bg-indigo-500/10 px-4 py-2 text-xs text-indigo-300">
            <span>
              Filtering findings for component: <strong className="font-mono text-zinc-100">{selectedComponent}</strong>
            </span>
            <button
              type="button"
              onClick={() => setSelectedComponent(null)}
              className="font-medium text-indigo-400 hover:text-white"
            >
              Clear component filter ✕
            </button>
          </div>
        )}

        {/* Filter bar */}
        <div className="mb-4 flex flex-wrap gap-2" role="group" aria-label="Filters">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded-[var(--radius-input)] border border-[var(--border-hairline)] bg-[var(--bg-raised)] px-3 py-1.5 text-[var(--text-sm)] text-[var(--text-secondary)] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--accent)]"
            aria-label="Filter by severity"
          >
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="rounded-[var(--radius-input)] border border-[var(--border-hairline)] bg-[var(--bg-raised)] px-3 py-1.5 text-[var(--text-sm)] text-[var(--text-secondary)] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--accent)]"
            aria-label="Filter by category"
          >
            <option value="all">All categories</option>
            <option value="direct_injection">Direct injection</option>
            <option value="canary_leakage">Canary leakage</option>
            <option value="sensitive_data">Sensitive data</option>
            <option value="tool_misuse">Tool misuse</option>
          </select>
          <select
            value={labelFilter}
            onChange={(e) => setLabelFilter(e.target.value)}
            className="rounded-[var(--radius-input)] border border-[var(--border-hairline)] bg-[var(--bg-raised)] px-3 py-1.5 text-[var(--text-sm)] text-[var(--text-secondary)] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--accent)]"
            aria-label="Filter by label"
          >
            <option value="all">All labels</option>
            <option value="confirmed_failure">Confirmed failure</option>
            <option value="likely_failure">Likely failure</option>
            <option value="needs_review">Needs review</option>
            <option value="attack_blocked">Attack blocked</option>
            <option value="not_evaluated">Not evaluated</option>
          </select>
        </div>

        {/* Findings table */}
        <div className="overflow-hidden rounded-[var(--radius-card)] border border-[var(--border-hairline)]">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-[var(--border-hairline)] bg-[var(--bg-raised)]">
                {["ID", "Attack", "Category", "Severity", "Label", "Conf.", "Summary", ""].map((h) => (
                  <th
                    key={h}
                    scope="col"
                    className="px-4 py-2.5 text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)]"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-hairline)]">
              {filtered.map((f) => (
                <tr
                  key={f.id}
                  onClick={() => setSelectedFinding(selectedFinding?.id === f.id ? null : f)}
                  className={`group cursor-pointer transition-colors hover:bg-[var(--bg-raised)]/60
                    ${f.needsReview ? "border-l-[3px] border-amber-500/60" : ""}
                    ${selectedFinding?.id === f.id ? "bg-[var(--accent-glow)]" : ""}`}
                  tabIndex={0}
                  onKeyDown={(e) => e.key === "Enter" && setSelectedFinding(f)}
                  aria-selected={selectedFinding?.id === f.id}
                >
                  <td className="px-4 py-3 font-mono text-[var(--text-xs)] text-[var(--text-muted)]">{f.id}</td>
                  <td className="px-4 py-3 font-mono text-[var(--text-xs)] text-[var(--text-secondary)]">{f.attackId}</td>
                  <td className="px-4 py-3"><CategoryChip category={f.category} /></td>
                  <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                  <td className="px-4 py-3"><LabelChip label={f.label} /></td>
                  <td className="px-4 py-3 font-mono text-[var(--text-xs)] text-[var(--text-secondary)]">
                    {f.confidence > 0 ? `${Math.round(f.confidence * 100)}%` : "—"}
                  </td>
                  <td className="max-w-xs px-4 py-3 text-[var(--text-sm)] text-[var(--text-secondary)]">
                    <span className="line-clamp-1">{f.summary}</span>
                  </td>
                  <td className="px-4 py-3 text-right">
                    {f.evidenceRef && (
                      <Link
                        href={`/scans/${scanId}/evidence/${f.evidenceRef}`}
                        onClick={(e) => e.stopPropagation()}
                        className="text-[var(--text-xs)] text-[var(--accent)] opacity-0 transition-opacity group-hover:opacity-100"
                      >
                        Evidence
                      </Link>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>

      {/* Finding detail drawer */}
      {selectedFinding && (
        <FindingDrawer
          finding={selectedFinding}
          scanId={scanId}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  );
}
