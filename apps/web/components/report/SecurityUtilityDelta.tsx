"use client";

import type { Report } from "@/lib/types";
import { deltaColor, pct } from "./shared";

function DeltaTable({
  rows,
}: {
  rows: Array<{ label: string; before: string; after: string; delta: string; deltaRaw: number | null }>;
}) {
  return (
    <table className="w-full text-left text-xs">
      <thead>
        <tr className="border-b border-zinc-800 text-zinc-500">
          <th className="py-1.5 pr-3 font-medium">Metric</th>
          <th className="py-1.5 pr-3 font-medium">Before</th>
          <th className="py-1.5 pr-3 font-medium">After</th>
          <th className="py-1.5 font-medium">Delta</th>
        </tr>
      </thead>
      <tbody className="font-mono">
        {rows.map((row) => (
          <tr key={row.label} className="border-b border-zinc-800/50 last:border-0">
            <td className="py-1.5 pr-3 font-sans text-zinc-300">{row.label}</td>
            <td className="py-1.5 pr-3 text-zinc-400">{row.before}</td>
            <td className="py-1.5 pr-3 text-zinc-400">{row.after}</td>
            <td className={`py-1.5 ${deltaColor(row.deltaRaw)}`}>{row.delta}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** Security and utility before/after deltas, including over-refusal (report §before_after). */
export default function SecurityUtilityDelta({ report }: { report: Report }) {
  const security = report.before_after.security;
  const utility = report.before_after.utility;

  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
      <h3 className="text-sm font-medium text-zinc-300">Before / after</h3>

      <div className="mt-3 grid gap-4 lg:grid-cols-2">
        <div>
          <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-zinc-500">
            Security
          </p>
          <DeltaTable
            rows={[
              {
                label: "Attack success rate",
                before: pct(security.before_attack_success_rate),
                after: pct(security.after_attack_success_rate),
                delta: pct(security.delta),
                deltaRaw: security.delta,
              },
              {
                label: "Blocked rate",
                before: pct(security.before_blocked_rate),
                after: pct(security.after_blocked_rate),
                delta: "—",
                deltaRaw: null,
              },
            ]}
          />
          {security.per_category.length > 0 && (
            <table className="mt-3 w-full text-left text-xs">
              <thead>
                <tr className="border-b border-zinc-800 text-zinc-500">
                  <th className="py-1.5 pr-3 font-medium">Category</th>
                  <th className="py-1.5 pr-3 font-medium">Before</th>
                  <th className="py-1.5 pr-3 font-medium">After</th>
                  <th className="py-1.5 font-medium">Delta</th>
                </tr>
              </thead>
              <tbody className="font-mono">
                {security.per_category.map((category) => (
                  <tr
                    key={category.category}
                    className="border-b border-zinc-800/50 last:border-0"
                  >
                    <td className="py-1.5 pr-3 font-sans text-zinc-300">
                      {category.category.replace(/_/g, " ")}
                    </td>
                    <td className="py-1.5 pr-3 text-zinc-400">
                      {pct(category.before_success_rate)}
                    </td>
                    <td className="py-1.5 pr-3 text-zinc-400">
                      {pct(category.after_success_rate)}
                    </td>
                    <td className={`py-1.5 ${deltaColor(category.delta)}`}>
                      {pct(category.delta)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div>
          <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-zinc-500">
            Benign utility
          </p>
          <DeltaTable
            rows={[
              {
                label: "Benign success rate",
                before: pct(utility.before_benign_success_rate),
                after: pct(utility.after_benign_success_rate),
                delta: pct(utility.delta),
                deltaRaw: utility.delta,
              },
            ]}
          />
          {utility.cases.length > 0 && (
            <table className="mt-3 w-full text-left text-xs">
              <thead>
                <tr className="border-b border-zinc-800 text-zinc-500">
                  <th className="py-1.5 pr-3 font-medium">Case</th>
                  <th className="py-1.5 pr-3 font-medium">Before</th>
                  <th className="py-1.5 pr-3 font-medium">After</th>
                  <th className="py-1.5 font-medium">Over-refusal</th>
                </tr>
              </thead>
              <tbody className="font-mono">
                {utility.cases.map((entry) => (
                  <tr key={entry.case_id} className="border-b border-zinc-800/50 last:border-0">
                    <td className="py-1.5 pr-3 text-zinc-300">{entry.case_id}</td>
                    <td className="py-1.5 pr-3 text-zinc-400">
                      {entry.passed_before === null ? "n/a" : entry.passed_before ? "pass" : "fail"}
                    </td>
                    <td className="py-1.5 pr-3 text-zinc-400">
                      {entry.passed_after === null ? "n/a" : entry.passed_after ? "pass" : "fail"}
                    </td>
                    <td
                      className={`py-1.5 ${entry.over_refusal ? "text-amber-400" : "text-zinc-500"}`}
                    >
                      {entry.over_refusal ? "yes" : "no"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </section>
  );
}
