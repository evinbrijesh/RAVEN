"use client";

import { useState, useCallback, useEffect } from "react";
import Link from "next/link";
import {
  Search,
  Terminal,
  Shield,
  Layers,
  FileText,
  Activity,
  ArrowRight,
  Sparkles,
  Command,
} from "lucide-react";

interface BreadcrumbItem {
  label: string;
  href?: string;
}

interface TopBarProps {
  breadcrumbs?: BreadcrumbItem[];
  scanStatus?: string;
  showTarget?: boolean;
}

/* ─── Command palette (21st.dev modal pattern) ─────────────────────────── */
function CommandPalette({ onClose }: { onClose: () => void }) {
  const commands = [
    { label: "Go to Operations Dashboard", kbd: "⌘ D", href: "/dashboard", icon: Activity },
    { label: "Start new security scan", kbd: "⌘ N", href: "/scans/new", icon: Shield },
    { label: "Jump to findings & triage", kbd: "⌘ F", href: "/scans/scan_123/findings", icon: Layers },
    { label: "Review hardening diff", kbd: "⌘ H", href: "/scans/scan_123/hardening", icon: Terminal },
    { label: "Export compliance report", kbd: "⌘ E", href: "/scans/scan_123/report", icon: FileText },
    { label: "Live regression telemetry", kbd: "⌘ R", href: "/scans/scan_123", icon: Activity },
  ];

  const [query, setQuery] = useState("");
  const filtered = commands.filter((c) => c.label.toLowerCase().includes(query.toLowerCase()));

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh]"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
      role="dialog"
      aria-modal
      aria-label="Command palette"
    >
      <div className="absolute inset-0 bg-black/70 backdrop-blur-md" aria-hidden />

      <div className="relative w-full max-w-lg overflow-hidden rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-overlay)] shadow-2xl animate-fade-in">
        {/* Search header */}
        <div className="flex items-center gap-3 border-b border-[var(--border-hairline)] px-4 py-3 bg-[var(--bg-surface)]">
          <Search className="h-4 w-4 text-[var(--accent)]" />
          <input
            type="text"
            placeholder="Type a command or jump to screen..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="flex-1 bg-transparent text-xs text-[var(--text-primary)] placeholder-[var(--text-muted)] outline-none font-mono"
            autoFocus
          />
          <kbd className="rounded border border-[var(--border-subtle)] px-1.5 py-0.5 font-mono text-[9px] text-[var(--text-muted)]">
            ESC
          </kbd>
        </div>

        {/* Results */}
        <ul className="max-h-72 overflow-y-auto py-2" role="listbox">
          {filtered.map((cmd) => {
            const Icon = cmd.icon;
            return (
              <li key={cmd.label} role="option" aria-selected={false}>
                <Link
                  href={cmd.href}
                  onClick={onClose}
                  className="group flex items-center justify-between px-4 py-2.5 text-xs text-[var(--text-secondary)] hover:bg-[var(--bg-raised)] hover:text-[var(--text-primary)] transition-colors"
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className="h-3.5 w-3.5 text-zinc-500 group-hover:text-[var(--accent)]" />
                    <span>{cmd.label}</span>
                  </div>
                  <kbd className="rounded border border-[var(--border-hairline)] px-1.5 py-0.5 font-mono text-[9px] text-[var(--text-muted)] bg-[var(--bg-base)]">
                    {cmd.kbd}
                  </kbd>
                </Link>
              </li>
            );
          })}
          {filtered.length === 0 && (
            <li className="px-4 py-8 text-center text-xs text-[var(--text-muted)] font-mono">
              No matching commands
            </li>
          )}
        </ul>

        {/* Footer tip */}
        <div className="flex items-center justify-between border-t border-[var(--border-hairline)] bg-[var(--bg-surface)]/60 px-4 py-2 text-[10px] font-mono text-[var(--text-muted)]">
          <span>RAVEN Mission Control</span>
          <span className="flex items-center gap-1">
            <Command className="h-3 w-3" /> Navigation
          </span>
        </div>
      </div>
    </div>
  );
}

const STATUS_CHIP: Record<string, { cls: string; dot: string }> = {
  created:                  { cls: "bg-zinc-800/60 text-zinc-400 border-zinc-700", dot: "bg-zinc-400" },
  reconning:                { cls: "bg-sky-950/60 text-sky-300 border-sky-800/40", dot: "bg-sky-400" },
  attacking:                { cls: "bg-orange-950/60 text-orange-300 border-orange-800/40", dot: "bg-orange-400 animate-ping" },
  judging:                  { cls: "bg-amber-950/60 text-amber-300 border-amber-800/40", dot: "bg-amber-400" },
  hardening_proposed:       { cls: "bg-violet-950/60 text-violet-300 border-violet-800/40", dot: "bg-violet-400" },
  awaiting_approval:        { cls: "bg-violet-950/60 text-violet-300 border-violet-800/40", dot: "bg-violet-400 animate-pulse" },
  retesting:                { cls: "bg-sky-950/60 text-sky-300 border-sky-800/40", dot: "bg-sky-400" },
  completed:                { cls: "bg-emerald-950/60 text-emerald-300 border-emerald-800/40", dot: "bg-emerald-400" },
  completed_without_retest: { cls: "bg-emerald-950/60 text-emerald-300 border-emerald-800/40", dot: "bg-emerald-400" },
  failed_partial:           { cls: "bg-orange-950/60 text-orange-300 border-orange-800/40", dot: "bg-orange-400" },
  failed_fatal:             { cls: "bg-red-950/60 text-red-300 border-red-800/40", dot: "bg-red-400" },
};

export default function TopBar({ breadcrumbs = [], scanStatus, showTarget = true }: TopBarProps) {
  const [paletteOpen, setPaletteOpen] = useState(false);

  const openPalette = useCallback(() => setPaletteOpen(true), []);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setPaletteOpen(true);
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, []);

  const statusMeta = scanStatus ? STATUS_CHIP[scanStatus] : null;

  return (
    <>
      <header className="flex h-14 items-center justify-between gap-4 border-b border-[var(--border-hairline)] bg-[var(--bg-surface)]/80 px-6 backdrop-blur-md sticky top-0 z-10">
        {/* Breadcrumb Path */}
        <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-xs font-mono">
          {breadcrumbs.map((crumb, i) => (
            <span key={i} className="flex items-center gap-2">
              {i > 0 && <span aria-hidden className="text-zinc-600">/</span>}
              {crumb.href ? (
                <Link
                  href={crumb.href}
                  className="text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
                >
                  {crumb.label}
                </Link>
              ) : (
                <span className="text-[var(--text-primary)] font-medium text-teal-400">
                  {crumb.label}
                </span>
              )}
            </span>
          ))}
        </nav>

        {/* Right controls: target badge + status + command palette */}
        <div className="flex items-center gap-3">
          {/* Target telemetry badge */}
          {showTarget && (
            <div className="flex items-center gap-2 rounded-md border border-[var(--border-hairline)] bg-[var(--bg-base)] px-2.5 py-1 font-mono text-[11px] text-[var(--text-secondary)]">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span>shophelper-local</span>
              <span className="text-[9px] text-[var(--text-muted)] border-l border-[var(--border-hairline)] pl-2">
                SANDBOXED
              </span>
            </div>
          )}

          {/* Scan status chip */}
          {scanStatus && statusMeta && (
            <span
              className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-0.5 font-mono text-[10px] font-medium tracking-tight ${statusMeta.cls}`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${statusMeta.dot}`} />
              {scanStatus.replace(/_/g, " ")}
            </span>
          )}

          {/* Command palette search trigger */}
          <button
            type="button"
            onClick={openPalette}
            className="flex items-center gap-2 rounded-[var(--radius-input)] border border-[var(--border-hairline)] bg-[var(--bg-raised)] px-2.5 py-1 text-xs text-[var(--text-muted)] hover:border-[var(--border-subtle)] hover:text-[var(--text-secondary)] transition-colors"
            aria-label="Open command palette (Cmd+K)"
          >
            <Search className="h-3 w-3" />
            <span className="hidden sm:inline font-mono text-[11px]">Command</span>
            <kbd className="rounded border border-[var(--border-hairline)] px-1 py-0.2 font-mono text-[9px] bg-[var(--bg-base)]">
              ⌘K
            </kbd>
          </button>
        </div>
      </header>

      {paletteOpen && <CommandPalette onClose={() => setPaletteOpen(false)} />}
    </>
  );
}
