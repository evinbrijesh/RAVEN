"use client";

import type { Report } from "@/lib/types";
import { CategoryChip, LabelChip, SeverityBadge } from "@/components/ui/primitives";
import { EmptyBlock } from "@/components/ui/StateViews";

/** Findings list with judge detail and evidence completeness (report §findings). */
export default function ReportFindings({ report }: { report: Report }) {
  if (report.findings.length === 0) {
    return (
      <EmptyBlock
        title="No findings"
        message="This scan produced no findings under the stated checks."
      />
    );
  }

  return (
    <section className="space-y-3">
      {report.findings.map((finding) => (
        <article
          key={finding.finding_id}
          className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4"
        >
          <header className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-zinc-400">{finding.attack_id}</span>
            <LabelChip label={finding.label} />
            <CategoryChip category={finding.category} />
            <SeverityBadge severity={finding.severity} />
            {finding.needs_review && (
              <span className="rounded border border-amber-800/50 bg-amber-950/40 px-2 py-0.5 text-[11px] text-amber-300">
                needs review
              </span>
            )}
            {!finding.evidence_complete && (
              <span className="rounded border border-orange-800/50 bg-orange-950/40 px-2 py-0.5 text-[11px] text-orange-300">
                evidence incomplete
              </span>
            )}
            <span className="ml-auto font-mono text-[11px] text-zinc-600">
              confidence {finding.confidence.toFixed(2)}
            </span>
          </header>

          <p className="mt-2 text-sm text-zinc-200">{finding.summary}</p>

          {finding.attack && (
            <dl className="mt-2 grid gap-x-6 gap-y-1 text-xs sm:grid-cols-2">
              <div className="flex gap-2">
                <dt className="text-zinc-500">Goal</dt>
                <dd className="text-zinc-300">{finding.attack.goal}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="text-zinc-500">Success rule</dt>
                <dd className="text-zinc-300">{finding.attack.success_rule}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="text-zinc-500">Attack version</dt>
                <dd className="font-mono text-zinc-400">{finding.attack.version}</dd>
              </div>
              {finding.attack.references.length > 0 && (
                <div className="flex gap-2">
                  <dt className="text-zinc-500">References</dt>
                  <dd className="font-mono text-zinc-400">
                    {finding.attack.references.join(", ")}
                  </dd>
                </div>
              )}
            </dl>
          )}

          <div className="mt-3 grid gap-3 text-xs sm:grid-cols-2">
            <div className="rounded-md bg-zinc-950/60 p-2.5">
              <p className="mb-1 font-medium uppercase tracking-wide text-zinc-500">
                Deterministic check
              </p>
              {finding.deterministic ? (
                <>
                  <p className="text-zinc-300">
                    {finding.deterministic.label
                      ? finding.deterministic.label.replace(/_/g, " ")
                      : "no label"}
                  </p>
                  {finding.deterministic.signals.length > 0 && (
                    <ul className="mt-1 list-inside list-disc font-mono text-[11px] text-zinc-500">
                      {finding.deterministic.signals.map((signal) => (
                        <li key={signal}>{signal}</li>
                      ))}
                    </ul>
                  )}
                </>
              ) : (
                <p className="text-zinc-500">unavailable</p>
              )}
            </div>
            <div className="rounded-md bg-zinc-950/60 p-2.5">
              <p className="mb-1 font-medium uppercase tracking-wide text-zinc-500">
                Semantic judge
              </p>
              {finding.semantic.available ? (
                <>
                  <p className="text-zinc-300">
                    {finding.semantic.label
                      ? finding.semantic.label.replace(/_/g, " ")
                      : "no label"}
                    {finding.semantic.confidence !== null &&
                      ` · ${finding.semantic.confidence.toFixed(2)}`}
                  </p>
                  {finding.semantic.reason && (
                    <p className="mt-1 text-[11px] text-zinc-500">{finding.semantic.reason}</p>
                  )}
                  <p className="mt-1 font-mono text-[10px] text-zinc-600">
                    {finding.semantic.model_name} · {finding.semantic.prompt_version}
                  </p>
                </>
              ) : (
                <p className="text-zinc-500">unavailable</p>
              )}
            </div>
          </div>

          <footer className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-zinc-600">
            {finding.run && (
              <span className="font-mono">
                run {finding.run.run_id} · attempt {finding.run.attempt} ·{" "}
                {finding.run.phase} · {finding.run.status}
              </span>
            )}
            {finding.resolution && <span>resolution: {finding.resolution}</span>}
            {finding.evidence_refs.length > 0 && (
              <span className="font-mono">
                evidence: {finding.evidence_refs.map((ref) => ref.ref_id).join(", ")}
              </span>
            )}
          </footer>
        </article>
      ))}
    </section>
  );
}
