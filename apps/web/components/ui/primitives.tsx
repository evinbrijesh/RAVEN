"use client";

import { useEffect, useRef } from "react";

/** Spotlight card — cursor-following radial glow on hover */
export function SpotlightCard({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const card = ref.current;
    if (!card) return;
    const onMove = (e: MouseEvent) => {
      const rect = card.getBoundingClientRect();
      card.style.setProperty("--mouse-x", `${e.clientX - rect.left}px`);
      card.style.setProperty("--mouse-y", `${e.clientY - rect.top}px`);
    };
    card.addEventListener("mousemove", onMove);
    return () => card.removeEventListener("mousemove", onMove);
  }, []);

  return (
    <div ref={ref} className={`spotlight-card ${className}`}>
      {children}
    </div>
  );
}

/** Skeleton loader block */
export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`skeleton ${className}`} aria-hidden />;
}

/** Three-dot AI loader for model-pending states */
export function AiLoader({ label = "Model thinking" }: { label?: string }) {
  return (
    <span role="status" aria-label={label} className="inline-flex items-center gap-1">
      {[0, 150, 300].map((delay) => (
        <span
          key={delay}
          className="inline-block h-1 w-1 rounded-full bg-[var(--accent)]"
          style={{ animation: `breathe 1.2s ease-in-out ${delay}ms infinite` }}
          aria-hidden
        />
      ))}
    </span>
  );
}

/** Teal accent budget ring (SVG) */
export function BudgetRing({
  used,
  total,
  size = 40,
  label,
  warn = false,
}: {
  used: number;
  total: number;
  size?: number;
  label?: string;
  warn?: boolean;
}) {
  const r = (size - 6) / 2;
  const circ = 2 * Math.PI * r;
  const pct = Math.min(1, used / total);
  const stroke = warn ? "#F59E0B" : "var(--accent)";

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-label={label}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={3} />
      <circle
        cx={size / 2} cy={size / 2} r={r}
        fill="none" stroke={stroke} strokeWidth={3}
        strokeDasharray={circ}
        strokeDashoffset={circ * (1 - pct)}
        strokeLinecap="round"
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
        style={{ transition: "stroke-dashoffset 600ms ease" }}
      />
    </svg>
  );
}

/** Status/finding label chip — always has an icon + text, never color alone */
type LabelKey =
  | "confirmed_failure" | "likely_failure" | "needs_review"
  | "partial_mitigation" | "attack_blocked" | "not_evaluated"
  | "verified_under_stated_checks" | "regression_detected";

const LABEL_META: Record<LabelKey, { cls: string; icon: string; text: string }> = {
  confirmed_failure:          { cls: "label-confirmed-failure",  icon: "✕", text: "Confirmed failure" },
  likely_failure:             { cls: "label-likely-failure",     icon: "!", text: "Likely failure" },
  needs_review:               { cls: "label-needs-review",       icon: "?", text: "Needs review" },
  partial_mitigation:         { cls: "label-partial-mitigation", icon: "~", text: "Partial mitigation" },
  attack_blocked:             { cls: "label-attack-blocked",     icon: "✓", text: "Attack blocked" },
  not_evaluated:              { cls: "label-not-evaluated",      icon: "–", text: "Not evaluated" },
  verified_under_stated_checks:{ cls: "label-verified-under",   icon: "✓", text: "Verified" },
  regression_detected:        { cls: "label-regression-detected",icon: "↺", text: "Regression" },
};

export function LabelChip({ label }: { label: LabelKey }) {
  const meta = LABEL_META[label] ?? LABEL_META.not_evaluated;
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] font-medium ${meta.cls}`}
    >
      <span aria-hidden className="font-mono text-[10px]">{meta.icon}</span>
      {meta.text}
    </span>
  );
}

/** Category chip */
const CATEGORY_META: Record<string, string> = {
  direct_injection: "bg-purple-950/60 text-purple-300 border-purple-800/40",
  canary_leakage:   "bg-orange-950/60 text-orange-300 border-orange-800/40",
  sensitive_data:   "bg-blue-950/60 text-blue-300 border-blue-800/40",
  tool_misuse:      "bg-red-950/60 text-red-300 border-red-800/40",
};
export function CategoryChip({ category }: { category: string }) {
  const cls = CATEGORY_META[category] ?? "bg-zinc-800 text-zinc-300 border-zinc-700";
  const label = category.replace(/_/g, " ");
  return (
    <span className={`inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-medium ${cls}`}>
      {label}
    </span>
  );
}

/** Severity badge */
const SEV_META: Record<string, string> = {
  low: "text-[var(--text-muted)]",
  medium: "text-yellow-400",
  high: "text-orange-400",
  critical: "text-red-400",
};
export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`text-[11px] font-semibold uppercase tracking-wide ${SEV_META[severity] ?? ""}`}>
      {severity}
    </span>
  );
}

/** Toast notification */
export function Toast({
  message,
  variant = "info",
}: {
  message: string;
  variant?: "info" | "success" | "warn" | "error";
}) {
  const colors = {
    info:    "border-[var(--border-subtle)] bg-[var(--bg-raised)]",
    success: "border-green-900/50 bg-green-950/60",
    warn:    "border-amber-900/50 bg-amber-950/60",
    error:   "border-red-900/50 bg-red-950/60",
  };
  const icons = { info: "·", success: "✓", warn: "!", error: "✕" };
  return (
    <div
      role="status"
      aria-live="polite"
      className={`animate-toast-in flex items-center gap-3 rounded-lg border px-4 py-3 text-sm shadow-xl ${colors[variant]}`}
    >
      <span aria-hidden className="font-mono text-[var(--accent)]">{icons[variant]}</span>
      {message}
    </div>
  );
}

/** Phase step indicator */
type Phase = "done" | "active" | "pending";
export function PhaseDot({ phase }: { phase: Phase }) {
  const cls =
    phase === "done"    ? "bg-[var(--accent)]" :
    phase === "active"  ? "bg-[var(--accent)] animate-breathe shadow-[0_0_0_3px_rgba(45,212,191,0.2)]" :
                          "bg-[var(--bg-raised)] border border-[var(--border-subtle)]";
  return <span className={`inline-block h-2 w-2 rounded-full ${cls}`} aria-hidden />;
}

/** Metric card value with optional sparkline stub */
export function MetricCard({
  label,
  value,
  sub,
  trend,
}: {
  label: string;
  value: string | number;
  sub?: string;
  trend?: "up" | "down" | "flat";
}) {
  const trendIcon = trend === "up" ? "↑" : trend === "down" ? "↓" : "→";
  const trendColor = trend === "up" ? "text-green-400" : trend === "down" ? "text-red-400" : "text-[var(--text-muted)]";

  return (
    <SpotlightCard className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5">
      <p className="text-[var(--text-muted)] text-[var(--text-xs)]">{label}</p>
      <p className="mt-1 text-[var(--text-xl)] font-semibold tracking-tight">{value}</p>
      {sub && (
        <p className={`mt-0.5 text-[var(--text-xs)] ${trendColor} font-mono`}>
          {trend && <span aria-hidden>{trendIcon} </span>}{sub}
        </p>
      )}
    </SpotlightCard>
  );
}

/** Inline error block */
export function ErrorBlock({
  code,
  message,
  onRetry,
}: {
  code?: string;
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div role="alert" className="rounded-[var(--radius-card)] border border-red-900/40 bg-red-950/20 p-6">
      {code && (
        <p className="mb-1 font-mono text-[var(--text-xs)] text-red-400">{code}</p>
      )}
      <p className="text-sm text-red-300">{message}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-3 rounded-[var(--radius-input)] border border-red-800/60 px-3 py-1.5 text-[var(--text-sm)] text-red-300 hover:bg-red-950/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500"
        >
          Retry
        </button>
      )}
    </div>
  );
}

/** Partial failure banner */
export function PartialFailureBanner({ message }: { message: string }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-3 rounded-[var(--radius-card)] border border-amber-900/40 bg-amber-950/20 px-4 py-3 text-sm text-amber-300"
    >
      <span aria-hidden className="mt-0.5 font-mono text-amber-400">!</span>
      {message}
    </div>
  );
}
