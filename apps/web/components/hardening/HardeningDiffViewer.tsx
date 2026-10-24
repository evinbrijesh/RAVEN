"use client";

import { useCallback, useEffect, useState } from "react";
import {
  ApiRequestError,
  approveHardening,
  getProposal,
} from "@/lib/api-client";
import type { HardeningProposal } from "@/lib/types";
import { EmptyBlock, ErrorBlock, LoadingBlock } from "@/components/ui/StateViews";

type DiffLine = { type: "add" | "remove" | "hunk" | "context" | "meta"; text: string };

/** Minimal unified-diff line classifier — no extra dependency. */
function parseDiff(diffText: string): DiffLine[] {
  return diffText.split("\n").map((line) => {
    if (line.startsWith("+++") || line.startsWith("---") || line.startsWith("diff ")) {
      return { type: "meta", text: line };
    }
    if (line.startsWith("@@")) return { type: "hunk", text: line };
    if (line.startsWith("+")) return { type: "add", text: line };
    if (line.startsWith("-")) return { type: "remove", text: line };
    return { type: "context", text: line };
  });
}

const LINE_STYLES: Record<DiffLine["type"], string> = {
  add: "bg-emerald-950/50 text-emerald-200",
  remove: "bg-red-950/50 text-red-200",
  hunk: "bg-sky-950/50 text-sky-300",
  context: "text-zinc-400",
  meta: "text-zinc-500",
};

/**
 * Hardening proposal diff viewer with human approve/reject controls.
 * Approval only affects the temporary demo target — never a real deployment.
 */
export default function HardeningDiffViewer({
  scanId,
  onDecision,
}: {
  scanId: string;
  /** Called after an approve/reject so the page can refresh the scan view. */
  onDecision?: () => void;
}) {
  const [proposal, setProposal] = useState<HardeningProposal | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [deciding, setDeciding] = useState<"approve" | "reject" | null>(null);
  const [decisionError, setDecisionError] = useState<string | null>(null);
  const [decided, setDecided] = useState<"approved" | "rejected" | null>(null);

  const load = useCallback(async () => {
    setLoadError(null);
    setProposal(null);
    try {
      const result = await getProposal(scanId);
      setProposal(result);
    } catch (cause) {
      setLoadError(
        cause instanceof ApiRequestError ? cause.message : "Failed to load proposal.",
      );
    }
  }, [scanId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function decide(approved: boolean): Promise<void> {
    if (!proposal) return;
    setDeciding(approved ? "approve" : "reject");
    setDecisionError(null);
    try {
      await approveHardening(scanId, proposal.proposal_id, approved);
      setDecided(approved ? "approved" : "rejected");
      onDecision?.();
    } catch (cause) {
      setDecisionError(
        cause instanceof ApiRequestError
          ? `${cause.code}: ${cause.message}`
          : "Failed to record decision.",
      );
    } finally {
      setDeciding(null);
    }
  }

  if (loadError) {
    return (
      <ErrorBlock
        title="Could not load hardening proposal"
        message={loadError}
        onRetry={() => void load()}
      />
    );
  }
  if (proposal === null) {
    return <LoadingBlock label="Loading hardening proposal…" />;
  }

  const diffLines = parseDiff(proposal.prompt_diff);

  return (
    <section className="rounded-lg border border-violet-900/60 bg-zinc-900/50">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800 px-4 py-2.5">
        <h2 className="text-sm font-medium text-zinc-300">
          Hardening proposal{" "}
          <span className="font-mono text-xs text-zinc-500">
            {proposal.proposal_id}
          </span>
        </h2>
        {decided ? (
          <span
            className={`rounded px-2 py-0.5 text-xs font-medium ${
              decided === "approved"
                ? "bg-emerald-950 text-emerald-300"
                : "bg-zinc-800 text-zinc-300"
            }`}
          >
            {decided === "approved"
              ? "Approved — retest in progress"
              : "Rejected — no changes applied"}
          </span>
        ) : (
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => void decide(true)}
              disabled={deciding !== null}
              className="rounded-md bg-emerald-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-emerald-600 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {deciding === "approve" ? "Approving…" : "Approve & retest"}
            </button>
            <button
              type="button"
              onClick={() => void decide(false)}
              disabled={deciding !== null}
              className="rounded-md border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {deciding === "reject" ? "Rejecting…" : "Reject"}
            </button>
          </div>
        )}
      </header>

      {decisionError && (
        <div className="px-4 pt-3">
          <ErrorBlock title="Decision not recorded" message={decisionError} />
        </div>
      )}

      <div className="space-y-4 p-4">
        <p className="text-sm text-zinc-300">{proposal.rationale}</p>

        {proposal.policy_candidate && (
          <div className="rounded-md border border-zinc-800 bg-zinc-900 p-3 text-xs text-zinc-400">
            <p className="mb-1 font-medium text-zinc-300">
              Policy candidate:{" "}
              <span className="font-mono">{proposal.policy_candidate.tool}</span>
            </p>
            <p>conditions: {proposal.policy_candidate.conditions.join("; ") || "—"}</p>
            <p>
              high-value action: {proposal.policy_candidate.high_value_action} · on
              violation: {proposal.policy_candidate.on_violation}
            </p>
          </div>
        )}

        <div className="overflow-x-auto rounded-md border border-zinc-800 bg-zinc-950">
          <pre className="min-w-0 p-3 font-mono text-xs leading-5">
            {diffLines.map((line, index) => (
              <div key={index} className={`px-2 ${LINE_STYLES[line.type]}`}>
                {line.text || " "}
              </div>
            ))}
          </pre>
        </div>

        <div className="grid gap-3 text-xs sm:grid-cols-2">
          <div className="rounded-md bg-zinc-900 p-3">
            <p className="mb-1 font-medium text-zinc-300">Affected cases</p>
            <p className="font-mono text-zinc-400">
              {proposal.affected_cases.join(", ") || "—"}
            </p>
          </div>
          <div className="rounded-md bg-zinc-900 p-3">
            <p className="mb-1 font-medium text-zinc-300">Risks</p>
            <ul className="list-inside list-disc text-zinc-400">
              {proposal.risks.length === 0 ? (
                <li>None stated</li>
              ) : (
                proposal.risks.map((risk) => <li key={risk}>{risk}</li>)
              )}
            </ul>
          </div>
        </div>

        <p className="text-xs text-zinc-500">
          Approval loads the change into the temporary evaluation target only. It
          is never deployed to an external system.
        </p>
      </div>
    </section>
  );
}
