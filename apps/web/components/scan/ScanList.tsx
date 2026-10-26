"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { ApiRequestError, listScans } from "@/lib/api-client";
import type { ScanListItem } from "@/lib/types";
import { ErrorBlock, LoadingBlock, StatusBadge } from "@/components/ui/StateViews";
import { useProject } from "@/lib/project-context";

export default function ScanList() {
  const { currentProject } = useProject();
  const [scans, setScans] = useState<ScanListItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    setScans(null);
    try {
      const items = await listScans(currentProject.project_id);
      setScans(items);
    } catch (cause) {
      setError(
        cause instanceof ApiRequestError
          ? cause.message
          : "Failed to load scans.",
      );
    }
  }, [currentProject.project_id]);

  useEffect(() => {
    void load();
  }, [load]);

  if (error) {
    return <ErrorBlock title="Could not load scans" message={error} onRetry={() => void load()} />;
  }
  if (scans === null) {
    return <LoadingBlock label="Loading scans…" />;
  }
  if (scans.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-zinc-700 bg-zinc-900/30 p-10 text-center">
        <p className="font-medium text-zinc-300">No scans yet</p>
        <p className="mt-1 text-sm text-zinc-500">
          Run your first security regression scan against the ShopHelper demo bot.
        </p>
        <Link
          href="/scans/new"
          className="mt-4 inline-block rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
        >
          Create a scan
        </Link>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-lg border border-zinc-800">
      <table className="w-full text-left text-sm">
        <thead className="bg-zinc-900 text-xs uppercase tracking-wide text-zinc-500">
          <tr>
            <th className="px-4 py-3">Scan ID</th>
            <th className="px-4 py-3">Target</th>
            <th className="px-4 py-3">Status</th>
            <th className="px-4 py-3 text-right">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800">
          {scans.map((scan) => (
            <tr key={scan.scan_id} className="hover:bg-zinc-900/60">
              <td className="px-4 py-3 font-mono text-xs text-zinc-300">
                {scan.scan_id}
              </td>
              <td className="px-4 py-3 text-zinc-400">{scan.target_id}</td>
              <td className="px-4 py-3">
                <StatusBadge status={scan.status} />
              </td>
              <td className="px-4 py-3 text-right">
                <Link
                  href={`/scans/${encodeURIComponent(scan.scan_id)}`}
                  className="text-indigo-400 hover:text-indigo-300"
                >
                  View →
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
