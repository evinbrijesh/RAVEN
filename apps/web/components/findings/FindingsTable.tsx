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
  const [viewingFinding, setViewingFinding] = useState<Finding | null>(null);
  const [transcriptData, setTranscriptData] = useState<{
    messages: Array<{ role: string; content: string; tool_name?: string; tool_args_json?: string }>;
    evidence_refs: Array<{ ref_id: string; kind: string; locator: string; hash_sha256: string }>;
    timeline?: Array<{ time_ms: number; stage: string; badge: string; detail: string }>;
  } | null>(null);
  const [loadingTranscript, setLoadingTranscript] = useState(false);

  async function openTranscript(finding: Finding) {
    setViewingFinding(finding);
    setLoadingTranscript(true);
    setTranscriptData(null);
    try {
      const { getFindingTranscript } = await import("@/lib/api-client");
      const res = await getFindingTranscript(scanId, finding.finding_id);
      setTranscriptData(res);
    } catch {
      setTranscriptData({ messages: [], evidence_refs: [] });
    } finally {
      setLoadingTranscript(false);
    }
  }

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

  const [modalTab, setModalTab] = useState<"timeline" | "transcript">("timeline");
  const [redactView, setRedactView] = useState(true);

  function maskSensitiveText(text: string): string {
    if (!redactView || !text) return text;
    return text
      .replace(/RAVEN-CANARY-[A-Za-z0-9_-]+/g, "[REDACTED_CANARY]")
      .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]")
      .replace(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, "[REDACTED_PHONE]")
      .replace(/\b(?:\d{4}[ -]?){3}\d{4}\b/g, "[REDACTED_CARD]");
  }

  const BADGE_STYLES: Record<string, string> = {
    breach: "bg-red-950/80 text-red-300 border-red-800",
    warning: "bg-amber-950/80 text-amber-300 border-amber-800",
    blocked: "bg-emerald-950/80 text-emerald-300 border-emerald-800",
    info: "bg-zinc-800 text-zinc-300 border-zinc-700",
  };

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
                  <div className="mt-1 flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => void openTranscript(finding)}
                      className="text-xs text-indigo-400 hover:text-indigo-300 underline underline-offset-2"
                    >
                      View Evidence & Transcript →
                    </button>
                    {finding.evidence_refs?.length > 0 && (
                      <span className="text-[11px] text-zinc-500 font-mono">
                        ({finding.evidence_refs.length} refs)
                      </span>
                    )}
                  </div>
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

      {viewingFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4">
          <div className="max-h-[85vh] w-full max-w-2xl overflow-y-auto rounded-lg border border-zinc-800 bg-zinc-900 p-5 shadow-2xl">
            <div className="flex items-start justify-between border-b border-zinc-800 pb-3">
              <div>
                <h3 className="font-semibold text-zinc-200">
                  Evidence Ledger: {viewingFinding.attack_id}
                </h3>
                <p className="mt-0.5 text-xs text-zinc-400">{viewingFinding.summary}</p>
              </div>
              <button
                type="button"
                onClick={() => setViewingFinding(null)}
                className="text-sm text-zinc-400 hover:text-zinc-200"
              >
                ✕
              </button>
            </div>

            <div className="mt-4 space-y-3">
              <div className="flex items-center gap-2 text-xs">
                <span className="text-zinc-500">Verdict:</span>
                <LabelBadge label={viewingFinding.label} />
                <span className="text-zinc-500 ml-2">Confidence:</span>
                <span className="text-zinc-300">{Math.round(viewingFinding.confidence * 100)}%</span>
              </div>

              <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setModalTab("timeline")}
                    className={`rounded px-2.5 py-1 text-xs font-medium transition ${
                      modalTab === "timeline"
                        ? "bg-violet-900/60 text-violet-200 border border-violet-700"
                        : "bg-zinc-800 text-zinc-400 hover:text-zinc-200"
                    }`}
                  >
                    Exploit Replay Timeline
                  </button>
                  <button
                    type="button"
                    onClick={() => setModalTab("transcript")}
                    className={`rounded px-2.5 py-1 text-xs font-medium transition ${
                      modalTab === "transcript"
                        ? "bg-violet-900/60 text-violet-200 border border-violet-700"
                        : "bg-zinc-800 text-zinc-400 hover:text-zinc-200"
                    }`}
                  >
                    Raw Transcript
                  </button>
                </div>
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setRedactView((prev) => !prev)}
                    className={`rounded border px-2 py-0.5 text-[10px] font-mono transition ${
                      redactView
                        ? "border-emerald-700/60 bg-emerald-950/40 text-emerald-300"
                        : "border-amber-700/60 bg-amber-950/40 text-amber-300"
                    }`}
                    title="Toggle simulated privacy masking for canary tokens and customer PII"
                  >
                    {redactView ? "🔒 Redaction Active" : "🔓 Raw Privacy Exposure"}
                  </button>
                  <span className="text-[11px] text-zinc-500 font-mono">
                    {modalTab === "timeline" ? "Deterministic State Trace" : "Wire Messages"}
                  </span>
                </div>
              </div>

              {loadingTranscript ? (
                <p className="text-xs text-zinc-400 py-4 text-center">Loading execution trace…</p>
              ) : modalTab === "timeline" ? (
                <div className="space-y-3 py-2">
                  {transcriptData?.timeline && transcriptData.timeline.length > 0 ? (
                    <div className="relative pl-6 space-y-4 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-zinc-800">
                      {transcriptData.timeline.map((item, idx) => (
                        <div key={idx} className="relative group">
                          {/* Dot */}
                          <div
                            className={`absolute -left-[22px] top-1.5 h-3 w-3 rounded-full border-2 bg-zinc-950 ${
                              item.badge === "breach"
                                ? "border-red-500 bg-red-950"
                                : item.badge === "warning"
                                  ? "border-amber-500 bg-amber-950"
                                  : item.badge === "blocked"
                                    ? "border-emerald-500 bg-emerald-950"
                                    : "border-zinc-500"
                            }`}
                          />
                          <div className="rounded border border-zinc-800 bg-zinc-950/70 p-3 text-xs">
                            <div className="flex items-center justify-between gap-2 mb-1.5">
                              <span className="font-semibold text-zinc-200">{item.stage}</span>
                              <div className="flex items-center gap-2">
                                <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase border ${BADGE_STYLES[item.badge] || BADGE_STYLES.info}`}>
                                  {item.badge}
                                </span>
                                <span className="font-mono text-[10px] text-zinc-500">T+{item.time_ms}ms</span>
                              </div>
                            </div>
                            <div className="font-mono text-[11px] text-zinc-400 whitespace-pre-wrap break-words bg-zinc-900/60 rounded p-2 border border-zinc-800/60">
                              {maskSensitiveText(item.detail)}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-zinc-500 italic py-2">
                      No replay trace available for this attack run.
                    </p>
                  )}
                </div>
              ) : (
                <div className="space-y-2 py-2">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-500">
                    Prompt & Tool Execution Transcript
                  </h4>
                  {transcriptData?.messages && transcriptData.messages.length > 0 ? (
                    <div className="space-y-2">
                      {transcriptData.messages.map((m, idx) => (
                        <div
                          key={idx}
                          className={`rounded p-2.5 text-xs font-mono ${
                            m.role === "user"
                              ? "bg-zinc-800 text-zinc-200 border-l-2 border-indigo-500"
                              : m.role === "assistant"
                                ? "bg-zinc-950 text-emerald-300 border-l-2 border-emerald-500"
                                : "bg-zinc-950/60 text-amber-300 border-l-2 border-amber-500"
                          }`}
                        >
                          <div className="text-[10px] uppercase font-bold text-zinc-500 mb-1">
                            [{m.role}] {m.tool_name ? `(tool: ${m.tool_name})` : ""}
                          </div>
                          <div className="whitespace-pre-wrap">{maskSensitiveText(m.content)}</div>
                          {m.tool_args_json && (
                            <pre className="mt-1 text-[11px] text-zinc-400">
                              {maskSensitiveText(m.tool_args_json)}
                            </pre>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-zinc-500 italic">
                      No raw transcript recorded for this run.
                    </p>
                  )}
                </div>
              )}
            </div>

            <div className="mt-5 border-t border-zinc-800 pt-3 text-right">
              <button
                type="button"
                onClick={() => setViewingFinding(null)}
                className="rounded bg-zinc-800 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-700"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
