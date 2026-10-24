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

  return (
    <div className="overflow-x-auto rounded-lg border border-zinc-800">
      <table className="w-full text-left text-sm">
        <thead className="bg-zinc-900 text-xs uppercase tracking-wide text-zinc-500">
          <tr>
            <th className="px-4 py-3">Attack</th>
            <th className="px-4 py-3">Category</th>
            <th className="px-4 py-3">Severity</th>
            <th className="px-4 py-3">Label</th>
            <th className="px-4 py-3">Confidence</th>
            <th className="px-4 py-3">Summary</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800">
          {findings.map((finding) => (
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
                {finding.needs_review && finding.label !== "needs_review" && (
                  <span className="ml-2 text-xs text-amber-300">needs review</span>
                )}
              </td>
              <td className="px-4 py-3 text-zinc-400">
                {Math.round(finding.confidence * 100)}%
              </td>
              <td className="max-w-md px-4 py-3 text-zinc-300">{finding.summary}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
