"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
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

/* ─── Nav items ─────────────────────────────────────────────────────────── */
const NAV = [
  { href: "/",           label: "Dashboard",      icon: "⊟" },
  { href: "/scans/new",  label: "New Scan",        icon: "+" },
  { href: "/scans",      label: "Scans",           icon: "≡" },
  { href: "/regression", label: "Regression Suite",icon: "⊛" },
  { href: "/docs",       label: "Docs",            icon: "?" },
];

export default function Sidebar({
  collapsed = false,
  onToggle,
}: {
  collapsed?: boolean;
  onToggle?: () => void;
}) {
  const pathname = usePathname();
  const w = collapsed ? "w-16" : "w-[232px]";

  return (
    <aside
      className={`${w} flex-shrink-0 flex flex-col border-r border-[var(--border-hairline)] bg-[var(--bg-surface)] transition-[width] duration-200 ease-out`}
      aria-label="Main navigation"
    >
      {/* Wordmark */}
      <div className="flex h-14 items-center justify-between border-b border-[var(--border-hairline)] px-4">
        {!collapsed && (
          <Link href="/" className="flex items-center gap-2 group">
            {/* Geometric raven mark */}
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none" aria-hidden>
              <polygon points="10,2 18,16 10,12 2,16" fill="#2DD4BF" opacity={0.9} />
              <polygon points="10,12 14,9 10,6" fill="#0A0D12" opacity={0.6} />
            </svg>
            <span className="text-[var(--text-sm)] font-semibold tracking-[0.06em] text-[var(--text-primary)]">
              RAVEN
            </span>
          </Link>
        )}
        {collapsed && (
          <Link href="/" className="mx-auto" aria-label="RAVEN home">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none" aria-hidden>
              <polygon points="10,2 18,16 10,12 2,16" fill="#2DD4BF" opacity={0.9} />
              <polygon points="10,12 14,9 10,6" fill="#0A0D12" opacity={0.6} />
            </svg>
          </Link>
        )}
        <button
          type="button"
          onClick={onToggle}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="ml-auto rounded p-1 text-[var(--text-muted)] hover:bg-[var(--bg-raised)] hover:text-[var(--text-secondary)]"
        >
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth={1.5}>
            {collapsed
              ? <path d="M2 4h10M2 7h10M2 10h10" />
              : <path d="M2 4h10M2 7h6M2 10h10" />}
          </svg>
        </button>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-2 py-3 space-y-0.5" aria-label="Primary navigation">
        {NAV.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 rounded-[var(--radius-input)] px-3 py-2 text-[var(--text-sm)] transition-colors
                ${isActive
                  ? "bg-[var(--accent-glow)] text-[var(--accent)]"
                  : "text-[var(--text-secondary)] hover:bg-[var(--bg-raised)] hover:text-[var(--text-primary)]"
                }`}
              aria-current={isActive ? "page" : undefined}
            >
              <span
                aria-hidden
                className={`w-4 text-center font-mono text-[13px] ${isActive ? "text-[var(--accent)]" : "text-[var(--text-muted)]"}`}
              >
                {item.icon}
              </span>
              {!collapsed && <span>{item.label}</span>}
            </Link>
          );
        })}
      </nav>

      {/* Bottom: mini constellation + pills */}
      {!collapsed && (
        <div className="border-t border-[var(--border-hairline)] px-3 py-3 space-y-3">
          <MiniConstellation agents={DEMO_AGENTS} />
          <div className="flex flex-col gap-1.5">
            <span className="inline-flex items-center gap-1.5 self-start rounded border border-[var(--accent)]/30 bg-[var(--accent-glow)] px-2 py-0.5 text-[10px] font-medium text-[var(--accent)]">
              Demo mode
            </span>
            <button
              type="button"
              className="self-start rounded border border-[var(--border-subtle)] px-2 py-0.5 text-[10px] text-[var(--text-muted)] hover:border-red-900/50 hover:text-red-400"
            >
              Reset target
            </button>
          </div>
        </div>
      )}
    </aside>
  );
}
