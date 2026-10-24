"use client";

import Link from "next/link";
import TopBar from "@/components/ui/TopBar";
import { SpotlightCard, MetricCard, Skeleton } from "@/components/ui/primitives";
import { AgentConstellation, type AgentStatus } from "@/components/ui/AgentConstellation";
import { LabelChip } from "@/components/ui/primitives";

/* ─── Sample data ───────────────────────────────────────────────────────── */
const METRICS = [
  { label: "Total scans",              value: "14",   sub: "+3 this week",  trend: "up"   as const },
  { label: "Confirmed failures",       value: "4",    sub: "+1 vs last scan",trend: "up"  as const },
  { label: "Latest attack success rate", value: "33%",sub: "↓ 8% after hardening", trend: "down" as const },
  { label: "Benign pass rate",         value: "100%", sub: "10 / 10 cases",  trend: "flat" as const },
];

const RECENT_SCANS = [
  { id: "scan_123", date: "2026-10-24 23:41", target: "shophelper-local", status: "completed",        confirmed: 4,  blocked: 7 },
  { id: "scan_118", date: "2026-10-23 18:02", target: "shophelper-local", status: "completed",        confirmed: 2,  blocked: 9 },
  { id: "scan_111", date: "2026-10-22 09:17", target: "shophelper-local", status: "failed_partial",   confirmed: 0,  blocked: 0 },
  { id: "scan_099", date: "2026-10-20 14:55", target: "shophelper-local", status: "completed",        confirmed: 6,  blocked: 5 },
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

const STATUS_CHIP: Record<string, string> = {
  completed:     "text-green-300",
  failed_partial:"text-orange-300",
  attacking:     "text-orange-300",
  reconning:     "text-sky-300",
  awaiting_approval: "text-violet-300",
};

/* ─── Mini sparkline (SVG stub) ─────────────────────────────────────────── */
function Sparkline({ data, color }: { data: number[]; color: string }) {
  const h = 24;
  const w = 64;
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  const pts = data.map((v, i) =>
    `${(i / (data.length - 1)) * w},${h - ((v - min) / range) * h}`
  ).join(" ");
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden>
      <polyline points={pts} fill="none" stroke={color} strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export default function DashboardPage() {
  const hasScans = RECENT_SCANS.length > 0;

  return (
    <div className="flex flex-col">
      <TopBar breadcrumbs={[{ label: "Dashboard" }]} showTarget={false} />

      <main className="flex-1 space-y-8 px-6 py-8">
        {/* Page header */}
        <div className="flex items-end justify-between">
          <div>
            <h1 className="text-[var(--text-xl)] font-semibold tracking-tight">Dashboard</h1>
            <p className="mt-1 text-[var(--text-sm)] text-[var(--text-secondary)]">
              Security regression runs for shophelper-local
            </p>
          </div>
          <Link
            href="/scans/new"
            className="rounded-[var(--radius-input)] bg-[var(--accent)] px-4 py-2 text-[var(--text-sm)] font-medium text-[#0A0D12] hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
          >
            New scan
          </Link>
        </div>

        {/* Metric cards */}
        <section aria-label="Key metrics">
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            {METRICS.map((m, i) => (
              <SpotlightCard
                key={i}
                className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5"
              >
                <p className="text-[var(--text-xs)] text-[var(--text-muted)]">{m.label}</p>
                <div className="mt-2 flex items-end justify-between">
                  <p className="text-[28px] font-semibold leading-none tracking-tight">{m.value}</p>
                  <Sparkline
                    data={[2, 4, 3, 5, 4, 6, 4]}
                    color={m.trend === "up" ? "#2DD4BF" : m.trend === "down" ? "#EF4444" : "#5B6575"}
                  />
                </div>
                <p className={`mt-1.5 font-mono text-[11px] ${
                  m.trend === "up" ? "text-green-400" : m.trend === "down" ? "text-red-400" : "text-[var(--text-muted)]"
                }`}>
                  {m.sub}
                </p>
              </SpotlightCard>
            ))}
          </div>
        </section>

        {/* Recent scans table */}
        {hasScans ? (
          <section aria-label="Recent scans">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-[var(--text-base)] font-medium">Recent scans</h2>
              <Link href="/scans" className="text-[var(--text-sm)] text-[var(--accent)] hover:brightness-110">
                View all →
              </Link>
            </div>

            <div className="overflow-hidden rounded-[var(--radius-card)] border border-[var(--border-hairline)]">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-[var(--border-hairline)] bg-[var(--bg-raised)]">
                    {["Scan ID", "Date", "Target", "Status", "Confirmed", "Blocked", ""].map((h) => (
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
                  {RECENT_SCANS.map((scan) => (
                    <tr key={scan.id} className="group hover:bg-[var(--bg-raised)]/60">
                      <td className="px-4 py-3 font-mono text-[var(--text-xs)] text-[var(--text-secondary)]">
                        {scan.id}
                      </td>
                      <td className="px-4 py-3 font-mono text-[var(--text-xs)] text-[var(--text-muted)]">
                        {scan.date}
                      </td>
                      <td className="px-4 py-3 font-mono text-[var(--text-xs)] text-[var(--text-secondary)]">
                        {scan.target}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`font-mono text-[var(--text-xs)] ${STATUS_CHIP[scan.status] ?? "text-[var(--text-muted)]"}`}>
                          {scan.status.replace(/_/g, " ")}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-[var(--text-xs)]">
                        {scan.confirmed > 0
                          ? <span className="text-red-400">{scan.confirmed}</span>
                          : <span className="text-[var(--text-muted)]">—</span>
                        }
                      </td>
                      <td className="px-4 py-3 font-mono text-[var(--text-xs)] text-green-400">
                        {scan.blocked > 0 ? scan.blocked : "—"}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Link
                          href={`/scans/${scan.id}`}
                          className="text-[var(--text-xs)] text-[var(--accent)] opacity-0 transition-opacity group-hover:opacity-100"
                        >
                          View →
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        ) : (
          /* ─── Empty state ─────────────────────────────────────────────── */
          <section className="flex flex-col items-center gap-8 py-16">
            {/* Faint constellation preview */}
            <div className="w-full max-w-xl opacity-25">
              <AgentConstellation agents={EMPTY_AGENTS} width={640} height={220} />
            </div>
            <div className="text-center">
              <p className="text-[var(--text-lg)] font-medium">No scans yet</p>
              <p className="mt-1.5 text-[var(--text-sm)] text-[var(--text-secondary)]">
                Run your first security regression scan against the ShopHelper demo bot.
              </p>
              <Link
                href="/scans/new"
                className="mt-6 inline-block rounded-[var(--radius-input)] bg-[var(--accent)] px-6 py-2.5 text-[var(--text-sm)] font-medium text-[#0A0D12] hover:brightness-110"
              >
                Start first scan
              </Link>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
