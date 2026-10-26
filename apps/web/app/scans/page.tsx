"use client";

import Link from "next/link";
import { Plus, History, Shield, Play } from "lucide-react";
import TopBar from "@/components/ui/TopBar";
import ScanList from "@/components/scan/ScanList";
import { useProject } from "@/lib/project-context";

export default function ScansHistoryPage() {
  const { currentProject } = useProject();

  return (
    <div className="flex flex-col min-h-full">
      <TopBar
        breadcrumbs={[
          { label: "Mission Control", href: "/dashboard" },
          { label: "Scans" },
        ]}
      />

      <main className="flex-1 px-4 sm:px-6 lg:px-8 py-8 space-y-6 max-w-7xl w-full mx-auto font-mono">
        {/* Header bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[var(--border-hairline)] pb-5">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <History className="h-4 w-4 text-teal-400" />
              <span className="text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
                Audit Trail & History
              </span>
              <span className="text-[10px] text-teal-400 border border-teal-800/40 bg-teal-950/40 px-2 py-0.5 rounded">
                Workspace: {currentProject.name}
              </span>
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-[var(--text-primary)]">
              Security Regression Scans
            </h1>
            <p className="mt-1 text-xs text-[var(--text-secondary)]">
              History of bounded multi-agent security scans and automated regression verifications for{" "}
              <span className="text-teal-400 font-medium">{currentProject.name}</span>.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <Link
              href="/scans/new"
              className="inline-flex items-center gap-2 rounded-[var(--radius-input)] bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[#0A0D12] hover:brightness-110 shadow-sm transition-all"
            >
              <Play className="h-3.5 w-3.5 fill-[#0A0D12]" />
              Start New Scan
            </Link>
          </div>
        </div>

        {/* Scan List Scoped to Active Project */}
        <div className="space-y-4">
          <ScanList />
        </div>
      </main>
    </div>
  );
}
