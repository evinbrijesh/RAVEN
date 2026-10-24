"use client";

import type { Report } from "@/lib/types";
import { VERDICT_META } from "./shared";

/** Verdict headline, counts, and judge availability (report §summary). */
export default function ReportSummary({ report }: { report: Report }) {
  const meta = VERDICT_META[report.summary.verdict];
  const counts = report.summary.counts;
  const judge = report.summary.judge;

  const cells: Array<[string, string | number]> = [
    ["Attack cases", counts.attack_cases],
    ["Evaluated", counts.evaluated],
    ["Not evaluated", counts.not_evaluated],
    ["Confirmed failures", counts.confirmed_failure],
    ["Likely failures", counts.likely_failure],
    ["Attacks blocked", counts.attack_blocked],
    ["Needs review", counts.needs_review],
    ["Benign passed", `${counts.benign_passed}/${counts.benign_cases}`],
    ["Regressions saved", counts.regressions],
  ];

  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <span
          className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-1 text-xs font-semibold ${meta.cls}`}
        >
          <span aria-hidden className="font-mono text-[10px]">
            {meta.icon}
          </span>
          {meta.label}
        </span>
        <p className="text-sm font-medium text-zinc-100">{report.summary.headline}</p>
      </div>

      <div className="mt-4 grid grid-cols-3 gap-2 sm:grid-cols-5 lg:grid-cols-9">
        {cells.map(([label, value]) => (
          <div key={label} className="rounded-md bg-zinc-900 px-2.5 py-2">
            <p className="text-[11px] text-zinc-500">{label}</p>
            <p className="mt-0.5 font-mono text-sm font-medium text-zinc-200">{value}</p>
          </div>
        ))}
      </div>

      <p className="mt-3 text-xs text-zinc-500">
        Judges: deterministic {judge.deterministic_available ? "available" : "unavailable"}
        {" · "}semantic {judge.semantic_available ? "available" : "unavailable"}
        {judge.model_name ? ` (${judge.model_name}, prompt ${judge.prompt_version})` : ""}
        {" · "}disagreements: {judge.disagreements}
      </p>
    </section>
  );
}
