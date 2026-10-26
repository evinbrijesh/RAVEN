"use client";

import { useState, useCallback, useEffect, useRef } from "react";
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
  ChevronDown,
  Check,
  Plus,
  FolderGit2,
} from "lucide-react";
import { useProject } from "@/lib/project-context";

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

function ProjectSelector() {
  const { currentProject, projects, setProjectId, createAndSelectProject } = useProject();
  const [open, setOpen] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [newId, setNewId] = useState("");
  const [newName, setNewName] = useState("");
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setOpen(false);
        setShowNew(false);
      }
    };
    if (open) {
      document.addEventListener("mousedown", handleClickOutside);
      return () => document.removeEventListener("mousedown", handleClickOutside);
    }
  }, [open]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newId.trim() || !newName.trim()) return;
    await createAndSelectProject(newId.trim(), newName.trim());
    setNewId("");
    setNewName("");
    setShowNew(false);
    setOpen(false);
  };

  return (
    <div className="relative" ref={menuRef}>
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        className="flex items-center gap-2 rounded-md border border-[var(--border-hairline)] bg-[var(--bg-raised)] px-2.5 py-1 text-xs text-[var(--text-secondary)] hover:border-[var(--border-subtle)] hover:text-[var(--text-primary)] transition-colors"
        aria-label="Select Project Workspace"
      >
        <FolderGit2 className="h-3.5 w-3.5 text-teal-400" />
        <span className="font-mono text-[11px] font-medium text-[var(--text-primary)] max-w-[130px] truncate">
          {currentProject.name}
        </span>
        <ChevronDown className={`h-3 w-3 text-zinc-500 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-1.5 w-72 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-overlay)] p-2 shadow-2xl backdrop-blur-xl z-50 animate-fade-in font-mono">
          <div className="flex items-center justify-between border-b border-[var(--border-hairline)] px-2 pb-2 mb-1">
            <span className="text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
              Project Workspace
            </span>
            <span className="text-[9px] text-teal-400 bg-teal-950/60 border border-teal-800/40 px-1.5 py-0.2 rounded">
              Multi-Tenant
            </span>
          </div>

          <div className="max-h-52 overflow-y-auto space-y-1 py-1">
            {projects.map((proj) => {
              const isActive = proj.project_id === currentProject.project_id;
              return (
                <button
                  key={proj.project_id}
                  type="button"
                  onClick={() => {
                    setProjectId(proj.project_id);
                    setOpen(false);
                  }}
                  className={`w-full flex items-start justify-between gap-2 rounded px-2 py-1.5 text-left text-xs transition-colors ${
                    isActive
                      ? "bg-teal-950/40 text-teal-300 border border-teal-800/30"
                      : "text-[var(--text-secondary)] hover:bg-[var(--bg-raised)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span className="font-medium truncate">{proj.name}</span>
                      <span className="text-[9px] text-zinc-500">({proj.project_id})</span>
                    </div>
                    {proj.description && (
                      <p className="text-[10px] text-zinc-500 truncate mt-0.5">{proj.description}</p>
                    )}
                  </div>
                  {isActive && <Check className="h-3.5 w-3.5 text-teal-400 shrink-0 mt-0.5" />}
                </button>
              );
            })}
          </div>

          <div className="border-t border-[var(--border-hairline)] pt-1.5 mt-1">
            {!showNew ? (
              <button
                type="button"
                onClick={() => setShowNew(true)}
                className="w-full flex items-center gap-1.5 rounded px-2 py-1.5 text-xs text-[var(--text-muted)] hover:text-[var(--accent)] hover:bg-[var(--bg-raised)] transition-colors"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>New Project Workspace</span>
              </button>
            ) : (
              <form onSubmit={handleCreate} className="p-2 space-y-2 bg-[var(--bg-surface)] rounded border border-[var(--border-hairline)]">
                <p className="text-[10px] font-semibold text-[var(--text-primary)]">Add Workspace</p>
                <input
                  type="text"
                  placeholder="Project ID (e.g. proj_sec)"
                  value={newId}
                  onChange={(e) => setNewId(e.target.value)}
                  className="w-full rounded border border-[var(--border-subtle)] bg-[var(--bg-base)] px-2 py-1 text-[11px] text-[var(--text-primary)] placeholder-zinc-600 outline-none"
                  autoFocus
                />
                <input
                  type="text"
                  placeholder="Project Name"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  className="w-full rounded border border-[var(--border-subtle)] bg-[var(--bg-base)] px-2 py-1 text-[11px] text-[var(--text-primary)] placeholder-zinc-600 outline-none"
                />
                <div className="flex items-center justify-end gap-1.5 pt-1">
                  <button
                    type="button"
                    onClick={() => setShowNew(false)}
                    className="rounded px-2 py-0.5 text-[10px] text-zinc-400 hover:text-white"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="rounded bg-teal-500 px-2.5 py-0.5 text-[10px] font-medium text-black hover:bg-teal-400"
                  >
                    Create
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
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

        {/* Right controls: project selector + target badge + status + command palette */}
        <div className="flex items-center gap-3">
          {/* Project Workspace Selector */}
          <ProjectSelector />

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
