"use client";

import type { Report } from "@/lib/types";

/** Hardening proposal, policy candidate, and approval state (report §hardening). */
export default function ReportHardening({ report }: { report: Report }) {
  const proposal = report.hardening.proposal;
  const approval = report.hardening.approval;

  if (!proposal) {
    return (
      <p className="text-xs text-zinc-500">
        No hardening proposal was generated for this scan.
      </p>
    );
  }

  return (
    <section className="space-y-3">
      <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
        <header className="flex flex-wrap items-center gap-2 text-xs">
          <span className="font-mono text-zinc-400">{proposal.proposal_id}</span>
          <span className="text-zinc-600">·</span>
          <span className="text-zinc-400">rationale: {proposal.rationale}</span>
          {approval && (
            <span
              className={`ml-auto rounded border px-2 py-0.5 text-[11px] font-medium ${
                approval.approved
                  ? "border-green-800/50 bg-green-950/40 text-green-300"
                  : "border-red-800/50 bg-red-950/40 text-red-300"
              }`}
            >
              {approval.approved ? "approved" : "rejected"} by {approval.approved_by}
            </span>
          )}
        </header>

        {proposal.affected_cases.length > 0 && (
          <p className="mt-2 text-xs text-zinc-500">
            Affected cases:{" "}
            <span className="font-mono text-zinc-400">
              {proposal.affected_cases.join(", ")}
            </span>
          </p>
        )}
        {proposal.risks.length > 0 && (
          <p className="mt-1 text-xs text-amber-300/80">
            Risks: {proposal.risks.join("; ")}
          </p>
        )}

        <pre className="mt-3 max-h-64 overflow-auto rounded-md border border-zinc-800 bg-zinc-950 p-3 font-mono text-[11px] text-zinc-300">
          {proposal.prompt_diff}
        </pre>

        {proposal.policy_candidate && (
          <div className="mt-3 rounded-md bg-zinc-950/60 p-2.5 text-xs">
            <p className="font-medium text-zinc-300">
              Policy candidate:{" "}
              <span className="font-mono text-indigo-300">
                {proposal.policy_candidate.tool}
              </span>
            </p>
            <p className="mt-1 text-zinc-500">
              high-value action:{" "}
              <span className="font-mono text-zinc-400">
                {proposal.policy_candidate.high_value_action}
              </span>{" "}
              · on violation:{" "}
              <span className="font-mono text-zinc-400">
                {proposal.policy_candidate.on_violation}
              </span>
            </p>
            {proposal.policy_candidate.conditions.length > 0 && (
              <ul className="mt-1 list-inside list-disc font-mono text-[11px] text-zinc-500">
                {proposal.policy_candidate.conditions.map((condition) => (
                  <li key={condition}>{condition}</li>
                ))}
              </ul>
            )}
          </div>
        )}

        <p className="mt-3 text-[11px] text-zinc-600">
          Applied to: {report.hardening.applied_to.replace(/_/g, " ")} — generated
          hardening is never auto-deployed; approval is explicit and human.
        </p>
      </div>
    </section>
  );
}
