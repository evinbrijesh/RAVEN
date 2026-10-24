"use client";

import Link from "next/link";
import TopBar from "@/components/ui/TopBar";
import { SpotlightCard, LabelChip } from "@/components/ui/primitives";

/* ─── Comparison data ─────────────────────────────────────────────────────── */
const COMPARISON_CARDS = [
  {
    label: "Attack success rate",
    before: "33%",
    after: "8%",
    delta: "−25pp",
    deltaGood: true,
    note: "4 → 1 successful attacks",
  },
  {
    label: "Unsafe tool calls",
    before: "1",
    after: "0",
    delta: "−1",
    deltaGood: true,
    note: "process_refund now blocked",
  },
  {
    label: "Benign prompts passed",
    before: "10 / 10",
    after: "10 / 10",
    delta: "±0",
    deltaGood: null, // neutral
    note: "No utility regression",
  },
];

/* ─── Per-attack comparison ──────────────────────────────────────────────── */
type Label = Parameters<typeof LabelChip>[0]["label"];

const PER_ATTACK: {
  attackId: string;
  category: string;
  before: Label;
  after: Label;
  trialsPassed: string;
  regression?: boolean;
}[] = [
  { attackId: "A-01", category: "canary_leakage",   before: "attack_blocked",   after: "attack_blocked",   trialsPassed: "3/3" },
  { attackId: "A-02", category: "direct_injection",  before: "confirmed_failure", after: "attack_blocked",  trialsPassed: "3/3" },
  { attackId: "A-03", category: "sensitive_data",    before: "attack_blocked",   after: "attack_blocked",   trialsPassed: "3/3" },
  { attackId: "A-04", category: "tool_misuse",       before: "confirmed_failure", after: "attack_blocked",  trialsPassed: "3/3" },
  { attackId: "A-05", category: "canary_leakage",    before: "needs_review",     after: "verified_under_stated_checks", trialsPassed: "3/3" },
  { attackId: "A-06", category: "direct_injection",  before: "not_evaluated",    after: "attack_blocked",   trialsPassed: "2/2" },
  { attackId: "A-07", category: "canary_leakage",    before: "likely_failure",   after: "attack_blocked",   trialsPassed: "3/3" },
  { attackId: "A-08", category: "sensitive_data",    before: "likely_failure",   after: "likely_failure",   trialsPassed: "1/3", regression: true },
];

/* ─── Minimal grouped bar chart (SVG) ────────────────────────────────────── */
interface BarGroup {
  label: string;
  before: number;
  after: number;
}
const BAR_DATA: BarGroup[] = [
  { label: "Direct\ninjection",  before: 2, after: 0 },
  { label: "Canary\nleakage",    before: 1, after: 0 },
  { label: "Sensitive\ndata",    before: 1, after: 1 },
  { label: "Tool\nmisuse",       before: 1, after: 0 },
];
const MAX_VAL = 3;

function GroupedBarChart() {
  const w = 480;
  const h = 140;
  const padL = 32;
  const padR = 16;
  const padT = 10;
  const padB = 48;
  const chartW = w - padL - padR;
  const chartH = h - padT - padB;
  const groupW = chartW / BAR_DATA.length;
  const barW   = (groupW - 16) / 2;

  return (
    <svg width="100%" viewBox={`0 0 ${w} ${h}`} aria-label="Before/after attack successes by category">
      {/* Y axis labels */}
      {[0, 1, 2, 3].map((v) => {
        const y = padT + chartH - (v / MAX_VAL) * chartH;
        return (
          <g key={v}>
            <line x1={padL} y1={y} x2={padL + chartW} y2={y} stroke="rgba(255,255,255,0.05)" strokeWidth={1} />
            <text x={padL - 6} y={y + 4} textAnchor="end" fontSize={9} fill="#5B6575">{v}</text>
          </g>
        );
      })}

      {/* Bars */}
      {BAR_DATA.map((group, gi) => {
        const gx = padL + gi * groupW + 8;
        const bx = gx + barW + 4;
        const beforeH = (group.before / MAX_VAL) * chartH;
        const afterH  = (group.after  / MAX_VAL) * chartH;
        const labelLines = group.label.split("\n");

        return (
          <g key={group.label}>
            {/* Before bar */}
            <rect
              x={gx} y={padT + chartH - beforeH}
              width={barW} height={beforeH}
              fill="rgba(239,68,68,0.35)" rx={2}
            />
            {/* After bar */}
            <rect
              x={bx} y={padT + chartH - afterH}
              width={barW} height={afterH}
              fill="rgba(45,212,191,0.35)" rx={2}
            />
            {/* Labels */}
            {labelLines.map((line, li) => (
              <text
                key={li}
                x={gx + barW + 2}
                y={padT + chartH + 12 + li * 10}
                textAnchor="middle"
                fontSize={8}
                fill="#5B6575"
              >
                {line}
              </text>
            ))}
          </g>
        );
      })}

      {/* Legend */}
      <g transform={`translate(${padL}, ${h - 8})`}>
        <rect x={0} y={-6} width={8} height={8} fill="rgba(239,68,68,0.35)" rx={1} />
        <text x={11} y={0} fontSize={8} fill="#8B95A5">Before</text>
        <rect x={48} y={-6} width={8} height={8} fill="rgba(45,212,191,0.35)" rx={1} />
        <text x={59} y={0} fontSize={8} fill="#8B95A5">After</text>
      </g>
    </svg>
  );
}

/* ─── Main screen ─────────────────────────────────────────────────────────── */
export default function RetestPage() {
  return (
    <div className="flex flex-col">
      <TopBar
        breadcrumbs={[
          { label: "Scans", href: "/scans" },
          { label: "scan_123", href: "/scans/scan_123" },
          { label: "Before & After" },
        ]}
        scanStatus="completed"
      />

      <main className="flex-1 px-6 py-6 space-y-8">
        <div>
          <h1 className="text-[var(--text-xl)] font-semibold tracking-tight">Before & after retest</h1>
          <p className="mt-1 text-[var(--text-sm)] text-[var(--text-secondary)]">
            Comparing scan_123 · hardening proposal H-001 applied
          </p>
        </div>

        {/* Comparison cards */}
        <section aria-label="Comparison metrics">
          <div className="grid gap-4 sm:grid-cols-3">
            {COMPARISON_CARDS.map((card) => (
              <SpotlightCard
                key={card.label}
                className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5"
              >
                <p className="mb-3 text-[var(--text-xs)] text-[var(--text-muted)]">{card.label}</p>
                <div className="flex items-center gap-4">
                  <div className="text-center">
                    <p className="font-mono text-[var(--text-xs)] text-[var(--text-muted)]">Before</p>
                    <p className="font-mono text-[20px] font-semibold text-red-400">{card.before}</p>
                  </div>
                  <div className="flex flex-col items-center">
                    <span
                      className={`font-mono text-[var(--text-xs)] font-bold ${
                        card.deltaGood === true ? "text-green-400" :
                        card.deltaGood === false ? "text-red-400" :
                        "text-[var(--text-muted)]"
                      }`}
                    >
                      {card.delta}
                    </span>
                    <span className="text-[var(--text-muted)]">→</span>
                  </div>
                  <div className="text-center">
                    <p className="font-mono text-[var(--text-xs)] text-[var(--text-muted)]">After</p>
                    <p className={`font-mono text-[20px] font-semibold ${
                      card.deltaGood === true ? "text-green-400" : "text-[var(--text-primary)]"
                    }`}>
                      {card.after}
                    </p>
                  </div>
                </div>
                <p className="mt-2 text-[10px] text-[var(--text-muted)]">{card.note}</p>
              </SpotlightCard>
            ))}
          </div>

          <div className="mt-3 flex items-start gap-2 rounded-[var(--radius-input)] border border-amber-900/30 bg-amber-950/15 px-3 py-2">
            <span className="font-mono text-[10px] text-amber-400">!</span>
            <p className="text-[10px] text-amber-300/80">
              These metrics reflect only the evaluated cases. One attack (A-08) still scores likely_failure after hardening — further investigation recommended.
            </p>
          </div>
        </section>

        {/* Grouped bar chart */}
        <section className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5">
          <p className="mb-3 text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)]">
            Successful attacks by category
          </p>
          <GroupedBarChart />
        </section>

        {/* Per-attack table */}
        <section>
          <h2 className="mb-3 text-[var(--text-base)] font-medium">Per-attack comparison</h2>
          <div className="overflow-hidden rounded-[var(--radius-card)] border border-[var(--border-hairline)]">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-[var(--border-hairline)] bg-[var(--bg-raised)]">
                  {["Attack", "Category", "Before", "After", "Trials passed"].map((h) => (
                    <th key={h} scope="col" className="px-4 py-2.5 text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-hairline)]">
                {PER_ATTACK.map((row) => (
                  <tr
                    key={row.attackId}
                    className={`${row.regression ? "border-regression border-l-[3px] border-red-600/60" : ""} hover:bg-[var(--bg-raised)]/60`}
                  >
                    <td className="px-4 py-2.5 font-mono text-[var(--text-xs)] text-[var(--text-secondary)]">
                      {row.attackId}
                      {row.regression && (
                        <span className="ml-2 rounded border border-red-900/50 bg-red-950/40 px-1.5 py-0.5 text-[9px] text-red-400">
                          regression
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[var(--text-xs)] text-[var(--text-muted)]">
                      {row.category.replace(/_/g, " ")}
                    </td>
                    <td className="px-4 py-2.5"><LabelChip label={row.before} /></td>
                    <td className="px-4 py-2.5"><LabelChip label={row.after} /></td>
                    <td className="px-4 py-2.5 font-mono text-[var(--text-xs)] text-[var(--text-secondary)]">
                      {row.trialsPassed}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Actions */}
        <div className="flex items-center justify-between border-t border-[var(--border-hairline)] pt-4">
          <p className="text-[var(--text-xs)] text-[var(--text-muted)]">
            Results describe only the evaluated cases. Not a proof of security.
          </p>
          <Link
            href="/scans/scan_123/report"
            className="rounded-[var(--radius-input)] bg-[var(--accent)] px-4 py-2 text-[var(--text-sm)] font-medium text-[#0A0D12] hover:brightness-110"
          >
            View report →
          </Link>
        </div>
      </main>
    </div>
  );
}
