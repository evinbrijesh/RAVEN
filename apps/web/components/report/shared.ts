/** Shared helpers for report components (ADR 0001 UI contract). */

import type { ReportVerdict } from "@/lib/types";

/** Format a 0..1 rate as a percentage string; null → "n/a". */
export function pct(value: number | null | undefined): string {
  if (value === null || value === undefined) return "n/a";
  return `${Math.round(value * 100)}%`;
}

export const VERDICT_META: Record<
  ReportVerdict,
  { label: string; cls: string; icon: string }
> = {
  improved: {
    label: "Improved",
    cls: "bg-green-950/60 text-green-300 border-green-800/40",
    icon: "✓",
  },
  confirmed_vulnerable: {
    label: "Confirmed vulnerable",
    cls: "bg-red-950/60 text-red-300 border-red-800/40",
    icon: "✕",
  },
  no_confirmed_findings: {
    label: "No confirmed findings",
    cls: "bg-green-950/60 text-green-300 border-green-800/40",
    icon: "✓",
  },
  inconclusive: {
    label: "Inconclusive",
    cls: "bg-amber-950/60 text-amber-300 border-amber-800/40",
    icon: "?",
  },
  partial: {
    label: "Partial",
    cls: "bg-orange-950/60 text-orange-300 border-orange-800/40",
    icon: "~",
  },
};

export function deltaColor(delta: number | null): string {
  if (delta === null) return "text-zinc-500";
  if (delta < 0) return "text-green-400";
  if (delta > 0) return "text-red-400";
  return "text-zinc-400";
}
