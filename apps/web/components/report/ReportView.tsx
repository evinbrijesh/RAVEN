"use client";

import { useCallback, useEffect, useState } from "react";
import { ApiRequestError, getReport } from "@/lib/api-client";
import type { Report } from "@/lib/types";
import { ErrorBlock, LoadingBlock } from "@/components/ui/StateViews";

function download(filename: string, content: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

/** Report view with JSON / Markdown export. */
export default function ReportView({ scanId }: { scanId: string }) {
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState<"json" | "markdown" | "sarif" | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

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

  async function exportReport(format: "json" | "markdown" | "sarif"): Promise<void> {
    setExporting(format);
    setExportError(null);
    try {
      if (format === "json") {
        const result = await getReport(scanId, "json");
        const text =
          typeof result === "string" ? result : JSON.stringify(result, null, 2);
        download(`raven-report-${scanId}.json`, text, "application/json");
      } else if (format === "sarif") {
        const result = await getReport(scanId, "sarif");
        const text =
          typeof result === "string" ? result : JSON.stringify(result, null, 2);
        download(`raven-report-${scanId}.sarif`, text, "application/sarif+json");
      } else {
        const markdown = await getReport(scanId, "markdown");
        download(
          `raven-report-${scanId}.md`,
          typeof markdown === "string" ? markdown : "",
          "text/markdown",
        );
      }
    } catch (cause) {
      setExportError(
        cause instanceof ApiRequestError
          ? `${cause.code}: ${cause.message}`
          : "Export failed.",
      );
    } finally {
      setExporting(null);
    }
  }

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
    <section className="rounded-lg border border-zinc-800 bg-zinc-900/50">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800 px-4 py-2.5">
        <h2 className="text-sm font-medium text-zinc-300">
          Report{" "}
          <span className="text-xs text-zinc-500">
            schema v{report.schema_version} · generated{" "}
            {new Date(report.generated_at).toLocaleString()}
          </span>
        </h2>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void exportReport("sarif")}
            disabled={exporting !== null}
            className="rounded-md border border-indigo-700/60 bg-indigo-950/30 px-3 py-1.5 text-xs font-medium text-indigo-300 hover:bg-indigo-900/40 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {exporting === "sarif" ? "Exporting…" : "Export SARIF"}
          </button>
          <button
            type="button"
            onClick={() => void exportReport("json")}
            disabled={exporting !== null}
            className="rounded-md border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {exporting === "json" ? "Exporting…" : "Export JSON"}
          </button>
          <button
            type="button"
            onClick={() => void exportReport("markdown")}
            disabled={exporting !== null}
            className="rounded-md border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {exporting === "markdown" ? "Exporting…" : "Export Markdown"}
          </button>
        </div>
      </header>

      {exportError && (
        <div className="px-4 pt-3">
          <ErrorBlock title="Export failed" message={exportError} />
        </div>
      )}

      <div className="space-y-4 p-4 text-sm">
        <div className="grid gap-3 sm:grid-cols-3">
          <Fact label="Target" value={`${report.target.id} (${report.target.version})`} />
          <Fact
            label="Coverage"
            value={`${report.coverage.attack_cases} cases · ${report.coverage.categories} categories`}
          />
          <Fact
            label="Hardening approved"
            value={
              report.hardening.approved === null
                ? "—"
                : report.hardening.approved
                  ? "yes"
                  : "no"
            }
          />
        </div>

        {report.limitations.length > 0 && (
          <div className="rounded-md border border-amber-900/50 bg-amber-950/20 p-3">
            <p className="text-xs font-medium text-amber-300">Limitations</p>
            <ul className="mt-1 list-inside list-disc text-xs text-amber-200/80">
              {report.limitations.map((limitation) => (
                <li key={limitation}>{limitation}</li>
              ))}
            </ul>
          </div>
        )}

        <details className="rounded-md border border-zinc-800 bg-zinc-950">
          <summary className="cursor-pointer px-3 py-2 text-xs text-zinc-400 hover:text-zinc-200">
            Raw report JSON
          </summary>
          <pre className="max-h-96 overflow-auto p-3 font-mono text-xs text-zinc-400">
            {JSON.stringify(report, null, 2)}
          </pre>
        </details>

        <p className="text-xs text-zinc-500">
          A clean report is not a security guarantee — results cover only the
          selected cases and target configuration.
        </p>
      </div>
    </section>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md bg-zinc-900 px-3 py-2">
      <p className="text-xs text-zinc-500">{label}</p>
      <p className="mt-0.5 font-medium text-zinc-200">{value}</p>
    </div>
  );
}
