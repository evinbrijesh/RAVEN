"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { ApiRequestError, getScan } from "@/lib/api-client";
import { isTerminalStatus, type ScanEvent, type ScanView } from "@/lib/types";
import ScanProgress from "@/components/scan/ScanProgress";
import EventFeed from "@/components/scan/EventFeed";
import FindingsTable from "@/components/findings/FindingsTable";
import HardeningDiffViewer from "@/components/hardening/HardeningDiffViewer";
import ReportView from "@/components/report/ReportView";
import { ErrorBlock, LoadingBlock } from "@/components/ui/StateViews";

/** Statuses where a hardening proposal awaits a human decision. */
const PROPOSAL_STATUSES = new Set(["hardening_proposed", "awaiting_approval"]);

export default function ScanDetailPage() {
  const params = useParams<{ id: string }>();
  const scanId = typeof params.id === "string" ? params.id : "";

  const [scan, setScan] = useState<ScanView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showProposal, setShowProposal] = useState(false);
  const [findingsKey, setFindingsKey] = useState(0);

  const refreshScan = useCallback(async () => {
    try {
      const view = await getScan(scanId);
      setScan(view);
      setError(null);
      if (PROPOSAL_STATUSES.has(view.status)) {
        setShowProposal(true);
      }
    } catch (cause) {
      setError(
        cause instanceof ApiRequestError ? cause.message : "Failed to load scan.",
      );
    }
  }, [scanId]);

  // Initial load.
  useEffect(() => {
    if (scanId) void refreshScan();
  }, [scanId, refreshScan]);

  const bumpFindings = useCallback(() => setFindingsKey((k) => k + 1), []);

  // SSE events drive refreshes: scan view on every event, findings on verdicts.
  const lastRefreshRef = useRef(0);
  const handleEvent = useCallback(
    (event: ScanEvent) => {
      const now = Date.now();
      if (now - lastRefreshRef.current > 500) {
        lastRefreshRef.current = now;
        void refreshScan();
      }
      if (event.kind === "verdict_created") bumpFindings();
    },
    [refreshScan, bumpFindings],
  );

  // Fallback polling while the scan is active, in case the SSE stream is down
  // (the stream reconnects independently; this keeps progress visible).
  useEffect(() => {
    const active =
      scan !== null &&
      !isTerminalStatus(scan.status) &&
      scan.status !== "created";
    if (!active) return;
    const interval = setInterval(() => void refreshScan(), 10_000);
    return () => clearInterval(interval);
  }, [scan, refreshScan]);

  if (error) {
    return (
      <div className="space-y-4">
        <Link href="/" className="text-sm text-indigo-400 hover:text-indigo-300">
          ← All scans
        </Link>
        <ErrorBlock
          title={error.includes("not found") ? "Scan not found" : "Could not load scan"}
          message={error}
          onRetry={() => void refreshScan()}
        />
      </div>
    );
  }
  if (scan === null) {
    return <LoadingBlock label="Loading scan…" />;
  }

  const terminal = isTerminalStatus(scan.status);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <Link href="/" className="text-sm text-indigo-400 hover:text-indigo-300">
            ← All scans
          </Link>
          <h1 className="mt-1 font-mono text-xl font-semibold">{scan.scan_id}</h1>
        </div>
        <span className="text-xs text-zinc-500">target: {scan.target_id}</span>
      </div>

      <ScanProgress scan={scan} />

      <EventFeed scanId={scanId} onEvent={handleEvent} />

      <section className="space-y-2">
        <h2 className="text-sm font-medium text-zinc-300">Findings</h2>
        <FindingsTable key={findingsKey} scanId={scanId} />
      </section>

      {showProposal && (
        <HardeningDiffViewer scanId={scanId} onDecision={() => void refreshScan()} />
      )}

      {terminal && <ReportView scanId={scanId} />}
    </div>
  );
}
