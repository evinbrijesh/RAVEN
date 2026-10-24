"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  PlusCircle,
  History,
  ShieldCheck,
  BookOpen,
  PanelLeftClose,
  PanelLeftOpen,
  Terminal,
  RotateCcw,
  Activity,
  Cpu,
} from "lucide-react";
import { MiniConstellation, type AgentStatus } from "@/components/ui/AgentConstellation";

/* ─── Static demo agents for sidebar mini-constellation ─────────────────── */
const DEMO_AGENTS: AgentStatus[] = [
  { id: "planner",       state: "done" },
  { id: "recon",         state: "done" },
  { id: "attacker",      state: "active" },
  { id: "judge",         state: "idle" },
  { id: "hardener",      state: "idle" },
  { id: "human_approval",state: "idle" },
  { id: "shophelper",    state: "idle" },
];

/* ─── Nav items with 21st.dev style icons & badges ─────────────────────── */
const NAV = [
  { href: "/",           label: "Dashboard",       icon: LayoutDashboard, kbd: "1" },
  { href: "/scans/new",  label: "New Scan",        icon: PlusCircle,      kbd: "N" },
  { href: "/scans",      label: "Scans",           icon: History,         kbd: "S" },
  { href: "/regression", label: "Regression Suite",icon: ShieldCheck,     kbd: "R" },
  { href: "/docs",       label: "Docs",            icon: BookOpen,        kbd: "?" },
];

export default function Sidebar({
  collapsed = false,
  onToggle,
}: {
  collapsed?: boolean;
  onToggle?: () => void;
}) {
  const pathname = usePathname();
  const w = collapsed ? "w-16" : "w-[240px]";

  return (
    <aside
      className={`${w} flex-shrink-0 flex flex-col border-r border-[var(--border-hairline)] bg-[var(--bg-surface)] transition-[width] duration-200 ease-out z-20`}
      aria-label="Main navigation"
    >
      {/* Brand & Wordmark */}
      <div className="flex h-14 items-center justify-between border-b border-[var(--border-hairline)] px-4">
        {!collapsed ? (
          <Link href="/" className="flex items-center gap-2.5 group">
            {/* Geometric raven emblem */}
            <div className="flex h-7 w-7 items-center justify-center rounded-md border border-teal-500/20 bg-teal-950/30 text-[var(--accent)] shadow-sm">
              <svg width="16" height="16" viewBox="0 0 20 20" fill="none" aria-hidden>
                <polygon points="10,2 18,16 10,12 2,16" fill="#2DD4BF" opacity={0.9} />
                <polygon points="10,12 14,9 10,6" fill="#0A0D12" opacity={0.6} />
              </svg>
            </div>
            <div className="flex flex-col">
              <span className="text-[13px] font-semibold tracking-wider text-[var(--text-primary)] font-mono">
                RAVEN
              </span>
              <span className="text-[9px] font-mono text-[var(--text-muted)] tracking-tight">
                SEC_REGRESSION v0.1
              </span>
            </div>
          </Link>
        ) : (
          <Link href="/" className="mx-auto" aria-label="RAVEN home">
            <div className="flex h-7 w-7 items-center justify-center rounded-md border border-teal-500/20 bg-teal-950/30 text-[var(--accent)]">
              <svg width="16" height="16" viewBox="0 0 20 20" fill="none" aria-hidden>
                <polygon points="10,2 18,16 10,12 2,16" fill="#2DD4BF" opacity={0.9} />
                <polygon points="10,12 14,9 10,6" fill="#0A0D12" opacity={0.6} />
              </svg>
            </div>
          </Link>
        )}
        <button
          type="button"
          onClick={onToggle}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="ml-auto rounded p-1 text-[var(--text-muted)] hover:bg-[var(--bg-raised)] hover:text-[var(--text-secondary)] transition-colors"
        >
          {collapsed ? (
            <PanelLeftOpen className="h-4 w-4" />
          ) : (
            <PanelLeftClose className="h-4 w-4" />
          )}
        </button>
      </div>

      {/* Nav links */}
      <nav className="flex-1 px-2.5 py-3 space-y-1" aria-label="Primary navigation">
        {NAV.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`group flex items-center justify-between rounded-[var(--radius-input)] px-2.5 py-2 text-xs transition-colors
                ${isActive
                  ? "bg-teal-950/25 text-[var(--accent)] border border-teal-500/20 shadow-xs"
                  : "text-[var(--text-secondary)] hover:bg-[var(--bg-raised)] hover:text-[var(--text-primary)]"
                }`}
              aria-current={isActive ? "page" : undefined}
            >
              <div className="flex items-center gap-3">
                <Icon className={`h-4 w-4 flex-shrink-0 ${isActive ? "text-[var(--accent)]" : "text-zinc-500 group-hover:text-zinc-300"}`} />
                {!collapsed && <span className="font-medium">{item.label}</span>}
              </div>
              {!collapsed && (
                <kbd className="hidden group-hover:inline-block rounded border border-[var(--border-hairline)] px-1 font-mono text-[9px] text-[var(--text-muted)] bg-[var(--bg-base)]">
                  {item.kbd}
                </kbd>
              )}
            </Link>
          );
        })}
      </nav>

      {/* Mini Constellation & Mission Telemetry */}
      {!collapsed && (
        <div className="border-t border-[var(--border-hairline)] px-3 py-3 space-y-3">
          <div className="flex items-center justify-between text-[10px] font-mono text-[var(--text-muted)] px-1">
            <span className="flex items-center gap-1.5">
              <Cpu className="h-3 w-3 text-teal-400" />
              CONSTELLATION
            </span>
            <span className="flex items-center gap-1 text-[var(--accent)]">
              <span className="h-1.5 w-1.5 rounded-full bg-[var(--accent)] animate-ping" />
              LIVE
            </span>
          </div>

          <MiniConstellation agents={DEMO_AGENTS} />

          {/* Target telemetry card */}
          <div className="rounded border border-[var(--border-hairline)] bg-[var(--bg-base)] p-2 space-y-1.5">
            <div className="flex items-center justify-between text-[10px] font-mono">
              <span className="text-[var(--text-secondary)]">TARGET</span>
              <span className="inline-flex items-center gap-1 text-emerald-400">
                <span className="h-1 w-1 rounded-full bg-emerald-400" />
                sandboxed
              </span>
            </div>
            <p className="font-mono text-[11px] text-[var(--text-primary)] truncate">
              shophelper-local
            </p>
            <div className="flex items-center justify-between pt-1 border-t border-[var(--border-hairline)] text-[9px] font-mono text-[var(--text-muted)]">
              <span className="flex items-center gap-1">
                <Terminal className="h-2.5 w-2.5 text-zinc-500" />
                port: 8080
              </span>
              <button
                type="button"
                className="hover:text-red-400 flex items-center gap-0.5 transition-colors"
                title="Reset local demo container"
              >
                <RotateCcw className="h-2.5 w-2.5" />
                reset
              </button>
            </div>
          </div>
        </div>
      )}
    </aside>
  );
}
