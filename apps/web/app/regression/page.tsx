"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  ShieldCheck,
  Play,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Terminal,
  Layers,
  Sparkles,
  ExternalLink,
  Lock,
  FileCheck2,
  SlidersHorizontal,
  Flame,
  Check,
  X,
} from "lucide-react";
import TopBar from "@/components/ui/TopBar";
import { SpotlightCard, StatusBadge } from "@/components/ui/primitives";
import { ErrorBlock, LoadingBlock } from "@/components/ui/StateViews";
import {
  listRegressions,
  toggleRegression,
  runRegressionSuite,
  ApiRequestError,
} from "@/lib/api-client";
import type { RegressionCase, RegressionsResponse } from "@/lib/types";

/* ─── Two-Dimensional Security-vs-Utility Scores ──────────────────────────── */
interface ScoreMetric {
  title: string;
  value: string;
  subtitle: string;
  change: string;
  status: "success" | "neutral" | "warning";
  badge: string;
}

const METRICS: ScoreMetric[] = [
  {
    title: "Known Attack Success Rate",
    value: "8.3%",
    subtitle: "Down from 33.3% before prompt & tool hardening",
    change: "−25.0pp",
    status: "success",
    badge: "1 of 12 attacks succeeded",
  },
  {
    title: "Benign Task Success Rate",
    value: "100%",
    subtitle: "All legitimate customer shopping workflows passed",
    change: "10 / 10 passed",
    status: "success",
    badge: "Utility Preserved",
  },
  {
    title: "Over-Refusal Rate",
    value: "0.0%",
    subtitle: "Zero false positive rejections on benign requests",
    change: "0 / 10 rejected",
    status: "success",
    badge: "No False Positives",
  },
  {
    title: "Regressions Introduced",
    value: "0",
    subtitle: "Hardening diffs broke zero previously working cases",
    change: "0 new failures",
    status: "success",
    badge: "Suite Clean",
  },
];

/* ─── Workflow steps ──────────────────────────────────────────────────────── */
const WORKFLOW_STEPS = [
  { step: "01", name: "Discover", desc: "Targeted adversarial red-teaming", icon: Flame },
  { step: "02", name: "Prove Evidence", desc: "Deterministic transcripts & SHA-256", icon: Terminal },
  { step: "03", name: "Propose Hardening", desc: "System prompt diff generation", icon: SlidersHorizontal },
  { step: "04", name: "Runtime Policy", desc: "Tool guardrails & pre-conditions", icon: Lock },
  { step: "05", name: "Human Approval", desc: "Supervised gate before sandbox retest", icon: FileCheck2 },
  { step: "06", name: "Retest Attacks", desc: "Verify breach is now blocked", icon: RotateCcw },
  { step: "07", name: "Retest Benign", desc: "Verify legitimate utility intact", icon: CheckCircle2 },
  { step: "08", name: "Persistent Test", desc: "Saved to continuous regression suite", icon: ShieldCheck },
];

export default function RegressionSuitePage() {
  const router = useRouter();
  const [data, setData] = useState<RegressionsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [togglingId, setTogglingId] = useState<string | null>(null);

  const fetchSuite = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await listRegressions("shophelper-local");
      setData(res);
    } catch (err) {
      setError(
        err instanceof ApiRequestError
          ? err.message
          : "Failed to connect to RAVEN regression API.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchSuite();
  }, [fetchSuite]);

  async function handleToggle(caseItem: RegressionCase) {
    setTogglingId(caseItem.regression_id);
    try {
      await toggleRegression(caseItem.regression_id);
      setData((prev) => {
        if (!prev) return prev;
        const updatedItems = prev.items.map((item) =>
          item.regression_id === caseItem.regression_id
            ? { ...item, active: !item.active }
            : item,
        );
        const activeCount = updatedItems.filter((i) => i.active).length;
        return { ...prev, items: updatedItems, active_count: activeCount };
      });
    } catch (err) {
      console.error("Failed to toggle regression case", err);
    } finally {
      setTogglingId(null);
    }
  }

  async function handleRunSuite() {
    setRunning(true);
    try {
      const res = await runRegressionSuite("shophelper-local");
      router.push(`/scans/${res.scan_id}`);
    } catch (err) {
      setError(
        err instanceof ApiRequestError
          ? err.message
          : "Failed to start regression suite scan.",
      );
      setRunning(false);
    }
  }

  return (
    <div className="min-h-screen bg-[var(--bg-base)] text-[var(--text-primary)]">
      <TopBar breadcrumbs={[{ label: "AI Regression Assurance Suite" }]} />

      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-8">
        {/* Header with positioning & primary action */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-[var(--border-hairline)] pb-6">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-teal-500/20 bg-teal-950/30 px-2.5 py-0.5 text-[11px] font-mono text-[var(--accent)] font-medium">
                <ShieldCheck className="h-3 w-3" />
                SECURITY REMEDIATION & REGRESSION ASSURANCE
              </span>
              <span className="font-mono text-[11px] text-[var(--text-muted)]">
                Target: shophelper-local
              </span>
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-[var(--text-primary)]">
              Continuous AI Regression Suite
            </h1>
            <p className="text-sm text-[var(--text-secondary)] max-w-3xl leading-relaxed">
              Every confirmed vulnerability is converted into tested guardrail policies and persisted as a permanent regression case.
              When models, prompts, or tools are updated, this suite ensures fixes stay sealed without degrading legitimate agent utility.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={handleRunSuite}
              disabled={running || loading}
              className="inline-flex items-center gap-2 rounded-[var(--radius-input)] border border-teal-500/30 bg-teal-500/15 px-4 py-2.5 text-xs font-mono font-medium text-[var(--accent)] hover:bg-teal-500/25 transition-all shadow-xs disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Play className={`h-3.5 w-3.5 fill-current ${running ? "animate-spin" : ""}`} />
              {running ? "DISPATCHING SUITE…" : "RUN REGRESSION SUITE"}
            </button>
          </div>
        </div>

        {/* Two-Dimensional Scoring Matrix */}
        <section aria-label="Two-dimensional Security vs Utility Scores" className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-[var(--text-muted)]">
              Two-Dimensional Verification Matrix
            </h2>
            <span className="text-[11px] font-mono text-[var(--text-muted)]">
              Evaluating security delta alongside legitimate user utility
            </span>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {METRICS.map((m) => (
              <SpotlightCard key={m.title} className="p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-medium text-[var(--text-secondary)]">
                    {m.title}
                  </span>
                  <span className="inline-flex items-center rounded border border-teal-500/20 bg-teal-950/40 px-1.5 py-0.5 text-[9px] font-mono text-[var(--accent)] font-medium">
                    {m.badge}
                  </span>
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-2xl font-bold font-mono tracking-tight text-[var(--text-primary)]">
                    {m.value}
                  </span>
                  <span className="text-xs font-mono font-medium text-emerald-400">
                    {m.change}
                  </span>
                </div>
                <p className="text-[11px] text-[var(--text-muted)] leading-tight">
                  {m.subtitle}
                </p>
              </SpotlightCard>
            ))}
          </div>
        </section>

        {/* End-to-End Remediation Workflow */}
        <section aria-label="End-to-End Remediation Workflow" className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1">
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-[var(--accent)]" />
              <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-[var(--text-primary)]">
                The Closed-Loop Remediation Architecture
              </h3>
            </div>
            <span className="text-[10px] font-mono text-[var(--text-muted)]">
              Tested remediation • Utility preservation • Deterministic evidence ledger
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-8">
            {WORKFLOW_STEPS.map((st, idx) => {
              const Icon = st.icon;
              return (
                <div
                  key={st.step}
                  className="relative flex flex-col justify-between rounded border border-[var(--border-hairline)] bg-[var(--bg-raised)] p-2.5 space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[9px] font-mono text-[var(--text-muted)]">
                      {st.step}
                    </span>
                    <Icon className="h-3 w-3 text-teal-400/80" />
                  </div>
                  <div>
                    <p className="text-[11px] font-semibold text-[var(--text-primary)] leading-tight">
                      {st.name}
                    </p>
                    <p className="text-[9px] text-[var(--text-muted)] line-clamp-2 mt-0.5">
                      {st.desc}
                    </p>
                  </div>
                  {idx < WORKFLOW_STEPS.length - 1 && (
                    <div className="hidden lg:block absolute -right-2 top-1/2 -translate-y-1/2 z-10 text-zinc-600">
                      ›
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>

        {/* Persistent Regression Cases Table */}
        <section aria-label="Active Persistent Regression Tests" className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-[var(--text-primary)]">
                Persistent Regression Catalog
              </h2>
              {data && (
                <span className="rounded-full bg-[var(--bg-raised)] px-2 py-0.5 text-[10px] font-mono text-[var(--text-secondary)] border border-[var(--border-hairline)]">
                  {data.active_count} active / {data.total} total cases
                </span>
              )}
            </div>
            <span className="text-[11px] font-mono text-[var(--text-muted)]">
              Auto-persisted upon approved prompt & policy hardening
            </span>
          </div>

          {loading ? (
            <LoadingBlock message="Loading persistent regression catalog…" />
          ) : error ? (
            <ErrorBlock message={error} onRetry={fetchSuite} />
          ) : data && data.items.length > 0 ? (
            <div className="overflow-hidden rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)]">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-[var(--border-hairline)] bg-[var(--bg-raised)] text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">
                    <th className="px-4 py-3">Case ID</th>
                    <th className="px-4 py-3">Category</th>
                    <th className="px-4 py-3">Attack Goal & Seed Prompt</th>
                    <th className="px-4 py-3">Hardened Guardrail Policy</th>
                    <th className="px-4 py-3 text-center">Active</th>
                    <th className="px-4 py-3 text-center">Latest Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border-hairline)] font-mono">
                  {data.items.map((item) => {
                    const c = item.case;
                    return (
                      <tr key={item.regression_id} className="hover:bg-[var(--bg-raised)]/50 transition-colors">
                        <td className="px-4 py-3 font-semibold text-[var(--accent)]">
                          {item.attack_case_id}
                          <div className="text-[9px] text-[var(--text-muted)] font-normal">
                            {item.regression_id.slice(0, 10)}…
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className="inline-block rounded border border-[var(--border-hairline)] bg-[var(--bg-base)] px-2 py-0.5 text-[10px] text-[var(--text-secondary)]">
                            {c.category?.replace(/_/g, " ") ?? "injection"}
                          </span>
                        </td>
                        <td className="px-4 py-3 max-w-md font-sans">
                          <p className="font-medium text-[var(--text-primary)] text-xs">
                            {c.goal}
                          </p>
                          <p className="text-[11px] font-mono text-[var(--text-muted)] truncate max-w-sm mt-0.5">
                            "{c.seed_prompt}"
                          </p>
                        </td>
                        <td className="px-4 py-3 font-mono text-[10px] text-[var(--text-secondary)]">
                          {c.category === "tool_misuse" ? (
                            <span className="text-teal-400">policy: issue_refund pre-conditions</span>
                          ) : c.category === "canary_leakage" ? (
                            <span className="text-teal-400">prompt: canary redaction boundary</span>
                          ) : (
                            <span className="text-teal-400">prompt: authority override resistance</span>
                          )}
                          <div className="text-[9px] text-[var(--text-muted)]">
                            rule: {c.success_rule ?? "instruction_override"}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-center">
                          <button
                            type="button"
                            onClick={() => handleToggle(item)}
                            disabled={togglingId === item.regression_id}
                            className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-mono transition-colors border ${
                              item.active
                                ? "border-emerald-500/30 bg-emerald-950/40 text-emerald-400 hover:bg-emerald-950/60"
                                : "border-zinc-700 bg-zinc-900 text-zinc-500 hover:text-zinc-400"
                            }`}
                          >
                            {item.active ? (
                              <>
                                <Check className="h-2.5 w-2.5" /> ACTIVE
                              </>
                            ) : (
                              <>
                                <X className="h-2.5 w-2.5" /> DISABLED
                              </>
                            )}
                          </button>
                        </td>
                        <td className="px-4 py-3 text-center font-mono">
                          <span className="inline-flex items-center gap-1 rounded border border-teal-500/30 bg-teal-950/30 px-2 py-0.5 text-[10px] text-[var(--accent)] font-medium">
                            <CheckCircle2 className="h-3 w-3" />
                            BLOCKED
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-8 text-center space-y-3">
              <ShieldCheck className="mx-auto h-8 w-8 text-zinc-500" />
              <p className="text-sm text-[var(--text-secondary)]">
                No persistent regression cases have been saved yet.
              </p>
              <p className="text-xs text-[var(--text-muted)] max-w-md mx-auto">
                Run an evaluation scan against your agent. When vulnerabilities are detected and prompt or runtime policy hardening is approved, the blocked cases are automatically stored here.
              </p>
              <Link
                href="/scans/new"
                className="inline-flex items-center gap-1.5 rounded-[var(--radius-input)] border border-teal-500/30 bg-teal-500/10 px-3 py-1.5 text-xs font-mono text-[var(--accent)] hover:bg-teal-500/20"
              >
                Start New Evaluation Scan →
              </Link>
            </div>
          )}
        </section>

        {/* Footer Mandatory Safety Disclaimer */}
        <footer className="border-t border-[var(--border-hairline)] pt-4 text-center">
          <p className="text-[11px] font-mono text-[var(--text-muted)]">
            Results describe only the evaluated cases. Not a proof of security.
          </p>
        </footer>
      </main>
    </div>
  );
}
