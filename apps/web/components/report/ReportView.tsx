"use client";

import { useCallback, useEffect, useState } from "react";
import { ApiRequestError, getReport } from "@/lib/api-client";
import type { Report } from "@/lib/types";
import { ErrorBlock, LoadingBlock } from "@/components/ui/StateViews";
import ReportSummary from "./ReportSummary";
import SecurityUtilityDelta from "./SecurityUtilityDelta";
import ReportFindings from "./ReportFindings";
import ReportEvidence from "./ReportEvidence";
import ReportHardening from "./ReportHardening";
import ReportLimitations from "./ReportLimitations";
import ReportActions from "./ReportActions";

/** Report view composed from the report primitives (ADR 0001 UI contract). */
export default function ReportView({ scanId }: { scanId: string }) {
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    setReport(null);
    try {
      const result = await getReport(scanId, "json");
      if (typeof result === "string") {
        setError("Report endpoint returned an unexpected format.");
        return;
      }
      setReport(result as Report);
    } catch (cause) {
      setError(
        cause instanceof ApiRequestError ? cause.message : "Failed to load report.",
      );
    }
  }, [scanId]);

  useEffect(() => {
    void load();
  }, [load]);

  if (error) {
    return (
      <ErrorBlock
        title="Report not available"
        message={error}
        onRetry={() => void load()}
      />
    );
  }
  if (report === null) {
    return <LoadingBlock label="Loading report…" />;
  }

  return (
    <section className="space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-medium text-zinc-300">
          Report{" "}
          <span className="text-xs text-zinc-500">
            schema v{report.schema_version} · {report.report_id} · generated{" "}
            {new Date(report.generated_at).toLocaleString()}
          </span>
        </h2>
        <ReportActions scanId={scanId} />
      </header>

      <ReportSummary report={report} />
      <SecurityUtilityDelta report={report} />

      <div>
        <h3 className="mb-2 text-sm font-medium text-zinc-300">Findings</h3>
        <ReportFindings report={report} />
      </div>

      <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
        <h3 className="mb-2 text-sm font-medium text-zinc-300">Hardening</h3>
        <ReportHardening report={report} />
      </div>

      <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
        <h3 className="mb-2 text-sm font-medium text-zinc-300">Evidence</h3>
        <ReportEvidence report={report} />
      </div>

      <ReportLimitations report={report} />
    </section>
  );
}
