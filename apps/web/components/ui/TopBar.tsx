"use client";

import { useState, useCallback, useEffect } from "react";
import Link from "next/link";

interface BreadcrumbItem {
  label: string;
  href?: string;
}

interface TopBarProps {
  breadcrumbs?: BreadcrumbItem[];
  scanStatus?: string;
  showTarget?: boolean;
}

/* ─── Command palette ────────────────────────────────────────────────────── */
function CommandPalette({ onClose }: { onClose: () => void }) {
  const commands = [
    { label: "Start new scan",      kbd: "⌘ N", href: "/scans/new" },
    { label: "Jump to findings",    kbd: "⌘ F", href: "#findings" },
    { label: "Export report",       kbd: "⌘ E", href: "#export" },
    { label: "Toggle dark/light",   kbd: "⌘ T", href: "#theme" },
    { label: "View regression suite",kbd: "⌘ R",href: "/regression" },
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
      className="fixed inset-0 z-50 flex items-start justify-center pt-[12vh]"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
      role="dialog"
      aria-modal
      aria-label="Command palette"
    >
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" aria-hidden />

      {/* Palette */}
      <div className="relative w-full max-w-lg rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-overlay)] shadow-2xl">
        {/* Search input */}
        <div className="flex items-center gap-3 border-b border-[var(--border-hairline)] px-4 py-3">
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="var(--text-muted)" strokeWidth={1.5} aria-hidden>
            <circle cx="6" cy="6" r="4.5" />
            <line x1="9.5" y1="9.5" x2="13" y2="13" />
          </svg>
          <input
            type="text"
            placeholder="Type a command…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="flex-1 bg-transparent text-[var(--text-sm)] text-[var(--text-primary)] placeholder-[var(--text-muted)] outline-none"
            autoFocus
          />
          <kbd className="rounded border border-[var(--border-subtle)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--text-muted)]">Esc</kbd>
        </div>

        {/* Results */}
        <ul className="max-h-64 overflow-y-auto py-2" role="listbox">
          {filtered.map((cmd) => (
            <li key={cmd.label} role="option" aria-selected={false}>
              <Link
                href={cmd.href}
                onClick={onClose}
                className="flex items-center justify-between px-4 py-2.5 text-[var(--text-sm)] text-[var(--text-secondary)] hover:bg-[var(--bg-raised)] hover:text-[var(--text-primary)]"
              >
                <span>{cmd.label}</span>
                <kbd className="rounded border border-[var(--border-hairline)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--text-muted)]">
                  {cmd.kbd}
                </kbd>
              </Link>
            </li>
          ))}
          {filtered.length === 0 && (
            <li className="px-4 py-6 text-center text-[var(--text-sm)] text-[var(--text-muted)]">
              No commands found
            </li>
          )}
        </ul>
      </div>
    </div>
  );
}

const STATUS_CHIP: Record<string, string> = {
  created:              "bg-zinc-800/60 text-zinc-400 border-zinc-700",
  reconning:            "bg-sky-950/60 text-sky-300 border-sky-800/40",
  attacking:            "bg-orange-950/60 text-orange-300 border-orange-800/40",
  judging:              "bg-amber-950/60 text-amber-300 border-amber-800/40",
  hardening_proposed:   "bg-violet-950/60 text-violet-300 border-violet-800/40",
  awaiting_approval:    "bg-violet-950/60 text-violet-300 border-violet-800/40",
  retesting:            "bg-sky-950/60 text-sky-300 border-sky-800/40",
  completed:            "bg-green-950/60 text-green-300 border-green-800/40",
  completed_without_retest: "bg-green-950/60 text-green-300 border-green-800/40",
  failed_partial:       "bg-orange-950/60 text-orange-300 border-orange-800/40",
  failed_fatal:         "bg-red-950/60 text-red-300 border-red-800/40",
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

  return (
    <>
      <header className="flex h-14 items-center gap-4 border-b border-[var(--border-hairline)] bg-[var(--bg-surface)]/80 px-5 backdrop-blur-sm">
        {/* Breadcrumbs */}
        <nav aria-label="Breadcrumb" className="flex flex-1 items-center gap-1.5 text-[var(--text-sm)]">
          {breadcrumbs.map((crumb, i) => (
            <span key={i} className="flex items-center gap-1.5">
              {i > 0 && <span aria-hidden className="text-[var(--text-muted)]">/</span>}
              {crumb.href ? (
                <Link href={crumb.href} className="text-[var(--text-secondary)] hover:text-[var(--text-primary)]">
                  {crumb.label}
                </Link>
              ) : (
                <span className="text-[var(--text-primary)]">{crumb.label}</span>
              )}
            </span>
          ))}
        </nav>

        {/* Target badge */}
        {showTarget && (
          <span className="flex items-center gap-1.5 rounded border border-[var(--border-hairline)] bg-[var(--bg-raised)] px-2.5 py-1 font-mono text-[11px] text-[var(--text-secondary)]">
            <span className="h-1.5 w-1.5 rounded-full bg-green-400" aria-hidden />
            shophelper-local
          </span>
        )}

        {/* Scan status chip */}
        {scanStatus && (
          <span
            className={`rounded border px-2.5 py-0.5 text-[11px] font-medium ${STATUS_CHIP[scanStatus] ?? "bg-zinc-800 text-zinc-400 border-zinc-700"}`}
          >
            {scanStatus.replace(/_/g, " ")}
          </span>
        )}

        {/* Command palette trigger */}
        <button
          type="button"
          onClick={openPalette}
          className="flex items-center gap-2 rounded-[var(--radius-input)] border border-[var(--border-hairline)] bg-[var(--bg-raised)] px-3 py-1.5 text-[var(--text-sm)] text-[var(--text-muted)] hover:border-[var(--border-subtle)] hover:text-[var(--text-secondary)]"
          aria-label="Open command palette (Cmd+K)"
        >
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth={1.5} aria-hidden>
            <circle cx="5" cy="5" r="3.5" />
            <line x1="8" y1="8" x2="11" y2="11" />
          </svg>
          <span>Search</span>
          <kbd className="rounded border border-[var(--border-hairline)] px-1 py-0.5 font-mono text-[9px]">⌘K</kbd>
        </button>
      </header>

      {paletteOpen && <CommandPalette onClose={() => setPaletteOpen(false)} />}
    </>
  );
}
