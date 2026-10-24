"use client";

import type { Report } from "@/lib/types";

/** Limitations, model usage, redaction, and integrity (report tail sections). */
export default function ReportLimitations({ report }: { report: Report }) {
  const usage = report.model_usage;
  return (
    <section className="space-y-3">
      <div className="rounded-md border border-amber-900/50 bg-amber-950/20 p-3">
        <p className="text-xs font-medium text-amber-300">Limitations</p>
        <ul className="mt-1 list-inside list-disc text-xs text-amber-200/80">
          {report.limitations.map((limitation) => (
            <li key={limitation}>{limitation}</li>
          ))}
        </ul>
      </div>

      <div className="grid gap-2 text-xs text-zinc-500 sm:grid-cols-2">
        <div className="rounded-md bg-zinc-900 px-3 py-2">
          <p className="font-medium text-zinc-400">Model usage</p>
          <p className="mt-0.5">
            semantic judge {usage.semantic_judge_available ? "available" : "unavailable"}
            {usage.model_name ? ` (${usage.model_name}, prompt ${usage.prompt_version})` : ""}
            {" · "}calls: {usage.calls}
          </p>
        </div>
        <div className="rounded-md bg-zinc-900 px-3 py-2">
          <p className="font-medium text-zinc-400">Redaction</p>
          <p className="mt-0.5">
            {report.redaction.applied ? "applied" : "not applied"} at render time ·
            fields: {report.redaction.redacted_fields.join(", ")} · excerpt limit{" "}
            {report.redaction.transcript_excerpt_chars} chars
          </p>
        </div>
        <div className="rounded-md bg-zinc-900 px-3 py-2">
          <p className="font-medium text-zinc-400">Tool versions</p>
          <p className="mt-0.5 font-mono">
            {Object.entries(report.tool_versions)
              .map(([key, value]) => `${key} ${value}`)
              .join(" · ")}
          </p>
        </div>
        <div className="rounded-md bg-zinc-900 px-3 py-2">
          <p className="font-medium text-zinc-400">Integrity</p>
          <p className="mt-0.5 break-all font-mono">
            sha256 {report.integrity.content_sha256} ({report.integrity.source})
          </p>
        </div>
      </div>

      <p className="text-xs text-zinc-500">
        A clean report is not a security guarantee — results cover only the
        selected cases and target configuration.
      </p>
    </section>
  );
}
