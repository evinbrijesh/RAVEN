"use client";

import Link from "next/link";
import { useState } from "react";
import {
  ApiRequestError,
  getReportText,
  reportFilename,
  type ReportFormat,
} from "@/lib/api-client";

/** Export actions: JSON / Markdown / SARIF downloads + printable view link. */
export default function ReportActions({ scanId }: { scanId: string }) {
  const [exporting, setExporting] = useState<ReportFormat | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function exportReport(format: ReportFormat): Promise<void> {
    setExporting(format);
    setError(null);
    try {
      const text = await getReportText(scanId, format);
      const mimes: Record<ReportFormat, string> = {
        json: "application/json",
        markdown: "text/markdown",
        sarif: "application/sarif+json",
      };
      const blob = new Blob([text], { type: mimes[format] });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = reportFilename(scanId, format);
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (cause) {
      setError(
        cause instanceof ApiRequestError
          ? `${cause.code}: ${cause.message}`
          : "Export failed.",
      );
    } finally {
      setExporting(null);
    }
  }

  function downloadGitHubAction(): void {
    const yaml = `name: RAVEN Security Gate
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  raven-security-regression:
    name: Run Continuous Security Regression Suite
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.13"

      - name: Install uv and Dependencies
        run: |
          curl -LsSf https://astral.sh/uv/install.sh | sh
          uv sync --all-packages

      - name: Execute RAVEN Security Regression Runner
        run: |
          uv run raven-test --target shophelper-local --output json
`;
    const blob = new Blob([yaml], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "raven-security-gate.yml";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  const buttonCls =
    "rounded-md border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50";

  return (
    <div className="flex flex-wrap items-center gap-2">
      {error && (
        <span role="alert" className="text-xs text-red-400">
          {error}
        </span>
      )}
      <Link
        href={`/scans/${encodeURIComponent(scanId)}/report`}
        className="rounded-md border border-indigo-700/60 bg-indigo-950/30 px-3 py-1.5 text-xs font-medium text-indigo-300 hover:bg-indigo-900/40"
      >
        Printable report
      </Link>
      {(["json", "markdown", "sarif"] as const).map((format) => (
        <button
          key={format}
          type="button"
          onClick={() => void exportReport(format)}
          disabled={exporting !== null}
          className={buttonCls}
        >
          {exporting === format
            ? "Exporting…"
            : `Export ${format === "markdown" ? "Markdown" : format.toUpperCase()}`}
        </button>
      ))}
      <button
        type="button"
        onClick={downloadGitHubAction}
        className="rounded-md border border-teal-700/60 bg-teal-950/30 px-3 py-1.5 text-xs font-medium text-teal-300 hover:bg-teal-900/40"
        title="Download ready-to-run GitHub Actions workflow (.github/workflows/raven-security-gate.yml)"
      >
        Export GitHub Action (.yml)
      </button>
    </div>
  );
}
