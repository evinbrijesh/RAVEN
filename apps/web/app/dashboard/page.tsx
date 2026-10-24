"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  Play,
  ArrowUpRight,
  ShieldCheck,
  Activity,
  Terminal,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Sparkles,
} from "lucide-react";
import TopBar from "@/components/ui/TopBar";
import { SpotlightCard, MetricCard, LabelChip } from "@/components/ui/primitives";
import { AgentConstellation, type AgentStatus } from "@/components/ui/AgentConstellation";
import { getReadiness, type SystemReadiness } from "@/lib/api-client";
import {
  ApiUnavailableBanner,
  WorkerUnavailableBanner,
  ModelUnavailableNotice,
} from "@/components/ui/StateViews";

/* ─── Telemetry metrics data (21st.dev Stats Bento pattern) ──────────────── */
const METRICS = [
  {
    label: "Total scans",
    value: "14",
    sub: "+3 this week",
    trend: "up" as const,
    telemetry: "PASS_RATE: 92.8%",
  },
  {
    label: "Confirmed failures",
    value: "4",
    sub: "+1 vs last scan",
    trend: "down" as const,
    telemetry: "CANARY + TOOL_CALL",
  },
  {
    label: "Attack success rate",
    value: "33% → 8%",
    sub: "-25pp post-hardening",
    trend: "up" as const,
    telemetry: "EVAL_CASES: 12",
  },
  {
    label: "Benign pass rate",
    value: "100%",
    sub: "10 / 10 cases passed",
    trend: "up" as const,
    telemetry: "OVER_REFUSAL: 0%",
  },
];

const RECENT_SCANS = [
  {
    id: "scan_123",
    date: "2026-10-24 23:41",
    target: "shophelper-local",
    status: "completed",
    cases: 12,
    confirmed: 4,
    blocked: 7,
    review: 1,
    duration: "42s",
  },
  {
    id: "scan_118",
    date: "2026-10-23 18:02",
    target: "shophelper-local",
    status: "completed",
    cases: 12,
    confirmed: 2,
    blocked: 9,
    review: 1,
    duration: "38s",
  },
  {
    id: "scan_111",
    date: "2026-10-22 09:17",
    target: "shophelper-local",
    status: "failed_partial",
    cases: 6,
    confirmed: 0,
    blocked: 0,
    review: 0,
    duration: "12s",
  },
  {
    id: "scan_099",
    date: "2026-10-20 14:55",
    target: "shophelper-local",
    status: "completed",
    cases: 12,
    confirmed: 6,
    blocked: 5,
    review: 1,
    duration: "49s",
  },
];

const EMPTY_AGENTS: AgentStatus[] = [
  { id: "planner",       state: "idle" },
  { id: "recon",         state: "idle" },
  { id: "attacker",      state: "idle" },
  { id: "judge",         state: "idle" },
  { id: "hardener",      state: "idle" },
  { id: "human_approval",state: "idle" },
  { id: "shophelper",    state: "idle" },
];

/* ─── Area Sparkline graphic with gradient fill ─────────────────────────── */
function AreaSparkline({ data, color }: { data: number[]; color: string }) {
  const h = 28;
  const w = 90;
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  const pts = data.map((v, i) => `${(i / (data.length - 1)) * w},${h - ((v - min) / range) * (h - 6)}`).join(" ");
  const areaD = `M 0,${h} L ${pts} L ${w},${h} Z`;

  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden className="overflow-visible">
      <defs>
        <linearGradient id={`grad-${color}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.25" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={areaD} fill={`url(#grad-${color})`} />
      <polyline points={pts} fill="none" stroke={color} strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export default function DashboardPage() {
  const hasScans = RECENT_SCANS.length > 0;
  const [readiness, setReadiness] = useState<SystemReadiness | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);

  const fetchStatus = () => {
    setApiError(null);
    getReadiness()
      .then((res) => setReadiness(res))
      .catch((err) => {
        setApiError(err?.message || "Failed to reach RAVEN API");
      });
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  return (
    <div className="flex flex-col min-h-full">
      <TopBar breadcrumbs={[{ label: "Mission Control" }, { label: "Operations Dashboard" }]} />

      <main className="flex-1 px-6 py-8 space-y-8 max-w-7xl w-full mx-auto">
        {/* Readiness Banners (Item 13) */}
        {apiError && <ApiUnavailableBanner error={apiError} onRetry={fetchStatus} />}
        {readiness && !readiness.queue.ready && <WorkerUnavailableBanner />}
        {readiness && !readiness.model.configured && (
          <ModelUnavailableNotice modelName={readiness.model.name} />
        )}

        {/* Header bar */}
        <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="flex h-2 w-2 rounded-full bg-teal-400" />
              <span className="text-[11px] font-mono tracking-wider uppercase text-[var(--text-muted)]">
                Security Regression Suite
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-[var(--text-primary)]">
              Operations Dashboard
            </h1>
            <p className="mt-1 text-xs text-[var(--text-secondary)]">
              Active target: <span className="font-mono text-teal-400">shophelper-local</span> (sandboxed) · 5 bounded security agents
            </p>
          </div>
          <div className="flex items-center gap-3">
            <Link
              href="/regression"
              className="inline-flex items-center gap-1.5 rounded-[var(--radius-input)] border border-[var(--border-subtle)] bg-[var(--bg-raised)] px-3.5 py-2 text-xs font-mono text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--accent)]/40 transition-colors"
            >
              <ShieldCheck className="h-3.5 w-3.5 text-teal-400" />
              Regression Suite
            </Link>
            <Link
              href="/scans/new"
              className="inline-flex items-center gap-1.5 rounded-[var(--radius-input)] bg-[var(--accent)] px-4 py-2 text-xs font-medium text-[#0A0D12] hover:brightness-110 shadow-sm transition-all focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
            >
              <Play className="h-3.5 w-3.5 fill-[#0A0D12]" />
              Start New Scan
            </Link>
          </div>
        </div>

        {/* 21st.dev Bento Grid Metrics */}
        <section aria-label="Key telemetry metrics">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {METRICS.map((m, i) => (
              <SpotlightCard key={i} className="p-5">
                <div className="flex items-center justify-between text-[11px] text-[var(--text-muted)]">
                  <span className="font-mono tracking-wider uppercase">{m.label}</span>
                  <span className="font-mono text-[9px] text-zinc-500">{m.telemetry}</span>
                </div>
                <div className="mt-2.5 flex items-end justify-between">
                  <p className="text-2xl font-semibold tracking-tight text-[var(--text-primary)] font-mono">
                    {m.value}
                  </p>
                  <AreaSparkline
                    data={[4, 6, 5, 8, 7, 9, 7]}
                    color={m.trend === "up" ? "#2DD4BF" : m.trend === "down" ? "#EF4444" : "#8B95A5"}
                  />
                </div>
                <p className={`mt-2 font-mono text-[11px] ${
                  m.trend === "up" ? "text-emerald-400" : m.trend === "down" ? "text-red-400" : "text-[var(--text-muted)]"
                }`}>
                  {m.sub}
                </p>
              </SpotlightCard>
            ))}
          </div>
        </section>

        {/* 21st.dev System Status Banner & Live Mission Snapshot */}
        <SpotlightCard className="p-4 sm:p-5">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[var(--border-hairline)] pb-4">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-teal-500/20 bg-teal-950/30 text-[var(--accent)]">
                <Activity className="h-5 w-5" />
              </div>
              <div>
                <p className="text-xs font-mono font-medium text-[var(--text-primary)] uppercase tracking-wider">
                  Target Verification Status · Normal Operational State
                </p>
                <p className="text-[11px] text-[var(--text-muted)] font-mono">
                  Target shophelper-local bounded simulation · All deterministic checks active
                </p>
              </div>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono">
              <span className="flex items-center gap-1.5 text-emerald-400">
                <CheckCircle2 className="h-3.5 w-3.5" />
                Canary Guard Active
              </span>
              <span className="flex items-center gap-1.5 text-emerald-400">
                <CheckCircle2 className="h-3.5 w-3.5" />
                Tool Policy Filtered
              </span>
            </div>
          </div>

          <div className="pt-4 grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
            <div>
              <p className="text-[10px] text-[var(--text-muted)] uppercase">Active Agents</p>
              <p className="mt-1 text-sm font-medium text-[var(--text-primary)]">5 Bounded</p>
            </div>
            <div>
              <p className="text-[10px] text-[var(--text-muted)] uppercase">Attack Catalog</p>
              <p className="mt-1 text-sm font-medium text-[var(--text-primary)]">12 Cases (4 Cat)</p>
            </div>
            <div>
              <p className="text-[10px] text-[var(--text-muted)] uppercase">Judge Engine</p>
              <p className="mt-1 text-sm font-medium text-[var(--text-primary)]">Rules + Gemini 3.8</p>
            </div>
            <div>
              <p className="text-[10px] text-[var(--text-muted)] uppercase">Latest Regression</p>
              <p className="mt-1 text-sm font-medium text-emerald-400">0 Regressions</p>
            </div>
          </div>
        </SpotlightCard>

        {/* Recent Scans (21st.dev Data Grid Table pattern) */}
        {hasScans ? (
          <section aria-label="Recent scans" className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-[var(--accent)]" />
                <h2 className="text-sm font-semibold tracking-wide uppercase font-mono text-[var(--text-primary)]">
                  Execution History
                </h2>
              </div>
              <Link
                href="/scans"
                className="text-xs font-mono text-[var(--accent)] hover:underline inline-flex items-center gap-1"
              >
                All scans ({RECENT_SCANS.length}) <ArrowUpRight className="h-3 w-3" />
              </Link>
            </div>

            <div className="overflow-hidden rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-surface)]">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-[var(--border-hairline)] bg-[var(--bg-raised)] text-[10px] text-[var(--text-muted)] uppercase tracking-wider">
                    <th className="px-4 py-3 font-medium">Scan ID</th>
                    <th className="px-4 py-3 font-medium">Timestamp</th>
                    <th className="px-4 py-3 font-medium">Target</th>
                    <th className="px-4 py-3 font-medium">Status</th>
                    <th className="px-4 py-3 font-medium">Failures</th>
                    <th className="px-4 py-3 font-medium">Blocked</th>
                    <th className="px-4 py-3 font-medium">Review</th>
                    <th className="px-4 py-3 text-right font-medium">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border-hairline)] text-[11px]">
                  {RECENT_SCANS.map((scan) => (
                    <tr
                      key={scan.id}
                      className="group hover:bg-[var(--bg-raised)]/70 transition-colors cursor-pointer"
                    >
                      <td className="px-4 py-3 font-semibold text-teal-400">
                        {scan.id}
                      </td>
                      <td className="px-4 py-3 text-[var(--text-muted)]">
                        {scan.date}
                      </td>
                      <td className="px-4 py-3 text-[var(--text-secondary)]">
                        {scan.target}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] font-medium
                          ${scan.status === "completed"
                            ? "bg-emerald-950/30 text-emerald-300 border-emerald-800/40"
                            : "bg-orange-950/30 text-orange-300 border-orange-800/40"
                          }`}
                        >
                          {scan.status.replace(/_/g, " ")}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {scan.confirmed > 0 ? (
                          <span className="text-red-400 font-semibold">{scan.confirmed}</span>
                        ) : (
                          <span className="text-zinc-600">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-emerald-400">
                        {scan.blocked > 0 ? scan.blocked : "—"}
                      </td>
                      <td className="px-4 py-3">
                        {scan.review > 0 ? (
                          <span className="text-amber-400">{scan.review}</span>
                        ) : (
                          <span className="text-zinc-600">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Link
                          href={`/scans/${scan.id}`}
                          className="inline-flex items-center gap-1 text-[var(--accent)] hover:underline opacity-80 group-hover:opacity-100"
                        >
                          inspect <ArrowUpRight className="h-3 w-3" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        ) : (
          /* Empty state */
          <section className="flex flex-col items-center gap-6 py-16">
            <div className="w-full max-w-xl opacity-30">
              <AgentConstellation agents={EMPTY_AGENTS} width={640} height={220} />
            </div>
            <div className="text-center">
              <p className="text-lg font-medium text-[var(--text-primary)] font-mono">No Active Telemetry</p>
              <p className="mt-1 text-xs text-[var(--text-secondary)] max-w-sm">
                Run your first security regression scan against the sandboxed ShopHelper target.
              </p>
              <Link
                href="/scans/new"
                className="mt-5 inline-flex items-center gap-2 rounded-[var(--radius-input)] bg-[var(--accent)] px-5 py-2.5 text-xs font-medium text-[#0A0D12] hover:brightness-110 shadow-sm"
              >
                <Play className="h-3 w-3 fill-[#0A0D12]" />
                Start First Scan
              </Link>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
