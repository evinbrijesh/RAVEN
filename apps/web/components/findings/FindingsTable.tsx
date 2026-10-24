"use client";

import { useCallback, useEffect, useState } from "react";
import { ApiRequestError, getFindings } from "@/lib/api-client";
import type { Finding } from "@/lib/types";
import {
  EmptyBlock,
  ErrorBlock,
  LabelBadge,
  LoadingBlock,
  SeverityBadge,
} from "@/components/ui/StateViews";

/** Findings table for a scan, with loading / error / empty states. */
export default function FindingsTable({ scanId }: { scanId: string }) {
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    setFindings(null);
    try {
      const result = await getFindings(scanId);
      setFindings(result.items);
    } catch (cause) {
      setError(
        cause instanceof ApiRequestError ? cause.message : "Failed to load findings.",
      );
    }
  }, [scanId]);

  useEffect(() => {
    void load();
  }, [load]);

  if (error) {
    return (
      <ErrorBlock
        title="Could not load findings"
        message={error}
        onRetry={() => void load()}
      />
    );
  }
  if (findings === null) {
    return <LoadingBlock label="Loading findings…" />;
  }
  if (findings.length === 0) {
    return (
      <EmptyBlock
        title="No findings yet"
        message="Findings appear here as verdicts are produced during the scan."
      />
    );
  }

  const [filter, setFilter] = useState<"all" | "review">("all");
  const [promotedMap, setPromotedMap] = useState<Record<string, boolean>>({});
  const [promotingId, setPromotingId] = useState<string | null>(null);

  const displayedFindings = findings?.filter((f) =>
    filter === "review" ? f.needs_review || f.label === "needs_review" : true,
  );

  async function handlePromote(findingId: string) {
    setPromotingId(findingId);
    try {
      const { promoteFindingToRegression } = await import("@/lib/api-client");
      await promoteFindingToRegression(scanId, findingId);
      setPromotedMap((prev) => ({ ...prev, [findingId]: true }));
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to promote finding");
    } finally {
      setPromotingId(null);
    }
  }

  const reviewCount = findings?.filter((f) => f.needs_review || f.label === "needs_review").length ?? 0;

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 border-b border-zinc-800 pb-2 text-xs">
        <button
          type="button"
          onClick={() => setFilter("all")}
          className={`rounded px-2.5 py-1 font-medium transition ${
            filter === "all"
              ? "bg-zinc-800 text-zinc-100"
              : "text-zinc-400 hover:text-zinc-200"
          }`}
        >
          All findings ({findings.length})
        </button>
        <button
          type="button"
          onClick={() => setFilter("review")}
          className={`rounded px-2.5 py-1 font-medium transition ${
            filter === "review"
              ? "bg-amber-950/40 text-amber-300 border border-amber-800/50"
              : "text-zinc-400 hover:text-zinc-200"
          }`}
        >
          Judge Audit / Needs Review ({reviewCount})
        </button>
      </div>

      <div className="overflow-x-auto rounded-lg border border-zinc-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-zinc-900 text-xs uppercase tracking-wide text-zinc-500">
            <tr>
              <th className="px-4 py-3">Attack</th>
              <th className="px-4 py-3">Category</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Verdict</th>
              <th className="px-4 py-3">Confidence</th>
              <th className="px-4 py-3">Summary</th>
              <th className="px-4 py-3 text-right">Regression</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {displayedFindings?.map((finding) => (
              <tr key={finding.finding_id} className="align-top hover:bg-zinc-900/60">
                <td className="px-4 py-3 font-mono text-xs text-zinc-300">
                  {finding.attack_id}
                </td>
                <td className="px-4 py-3 text-zinc-400">{finding.category}</td>
                <td className="px-4 py-3">
                  <SeverityBadge severity={finding.severity} />
                </td>
                <td className="px-4 py-3">
                  <LabelBadge label={finding.label} />
                  {finding.needs_review && (
                    <span className="ml-2 inline-flex items-center rounded bg-amber-950/60 px-1.5 py-0.5 text-[11px] font-medium text-amber-300 border border-amber-800/40">
                      Disagreement / Audit
                    </span>
                  )}
                </td>
                <td className="px-4 py-3 text-zinc-400">
                  {Math.round(finding.confidence * 100)}%
                </td>
                <td className="max-w-md px-4 py-3 text-zinc-300">
                  <div>{finding.summary}</div>
                  {finding.evidence_refs?.length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1 text-[11px] text-zinc-500 font-mono">
                      evidence: {finding.evidence_refs.join(", ")}
                    </div>
                  )}
                </td>
                <td className="px-4 py-3 text-right">
                  {promotedMap[finding.finding_id] ? (
                    <span className="inline-flex items-center text-xs text-emerald-400">
                      ✓ Saved to Suite
                    </span>
                  ) : (
                    <button
                      type="button"
                      disabled={promotingId === finding.finding_id}
                      onClick={() => void handlePromote(finding.finding_id)}
                      className="rounded border border-indigo-700/60 bg-indigo-950/20 px-2 py-1 text-xs font-medium text-indigo-300 hover:bg-indigo-900/30 disabled:opacity-50"
                      title="Promote this finding into continuous regression test suite"
                    >
                      {promotingId === finding.finding_id ? "Saving…" : "+ Save as Test"}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
