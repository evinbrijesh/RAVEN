"use client";

import { useEffect, useRef } from "react";
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  HelpCircle,
  RefreshCw,
  MinusCircle,
  ShieldCheck,
  TrendingDown,
  TrendingUp,
  ArrowRight,
  Sparkles,
} from "lucide-react";

/**
 * 21st.dev Spotlight Card (easemize-spotlight-card pattern)
 * Interactive radial glow that tracks cursor coordinates
 */
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
    <div
      ref={ref}
      className={`spotlight-card relative rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-surface)] transition-all duration-200 hover:border-[var(--border-subtle)] ${className}`}
    >
      {/* Corner crosshairs for technical mission-control feel */}
      <span className="pointer-events-none absolute -top-1 -left-1 text-[8px] font-mono text-zinc-700 select-none">+</span>
      <span className="pointer-events-none absolute -top-1 -right-1 text-[8px] font-mono text-zinc-700 select-none">+</span>
      <span className="pointer-events-none absolute -bottom-1 -left-1 text-[8px] font-mono text-zinc-700 select-none">+</span>
      <span className="pointer-events-none absolute -bottom-1 -right-1 text-[8px] font-mono text-zinc-700 select-none">+</span>
      {children}
    </div>
  );
}

/** Skeleton loader block */
export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`skeleton ${className}`} aria-hidden />;
}

/** 21st.dev AI Loader (beratberkayg-ai-loader pattern) for model thinking */
export function AiLoader({ label = "Evaluating model" }: { label?: string }) {
  return (
    <span role="status" aria-label={label} className="inline-flex items-center gap-1.5 font-mono text-xs text-[var(--accent)]">
      <span className="relative flex h-2 w-2">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--accent)] opacity-75"></span>
        <span className="relative inline-flex rounded-full h-2 w-2 bg-[var(--accent)]"></span>
      </span>
      <span className="text-[11px] uppercase tracking-wider text-[var(--text-muted)]">{label}</span>
      <span className="inline-flex gap-0.5">
        {[0, 150, 300].map((delay) => (
          <span
            key={delay}
            className="inline-block h-1 w-1 rounded-full bg-[var(--accent)]"
            style={{ animation: `breathe 1.2s ease-in-out ${delay}ms infinite` }}
            aria-hidden
          />
        ))}
      </span>
    </span>
  );
}

/** 21st.dev Rate Limit & Budget Gauge (astralyxdev-rate-limit-meter) */
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
    <div className="relative inline-flex items-center justify-center">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-label={label}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={3} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={stroke}
          strokeWidth={3}
          strokeDasharray={circ}
          strokeDashoffset={circ * (1 - pct)}
          strokeLinecap="round"
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: "stroke-dashoffset 600ms ease" }}
        />
      </svg>
      <span className="absolute font-mono text-[9px] text-[var(--text-muted)]">
        {Math.round(pct * 100)}%
      </span>
    </div>
  );
}

/** Status/finding label chip — always has an icon + text, never color alone */
export type LabelKey =
  | "confirmed_failure"
  | "likely_failure"
  | "needs_review"
  | "partial_mitigation"
  | "attack_blocked"
  | "not_evaluated"
  | "verified_under_stated_checks"
  | "regression_detected";

export function LabelChip({ label }: { label: LabelKey }) {
  switch (label) {
    case "confirmed_failure":
      return (
        <span className="inline-flex items-center gap-1.5 rounded border border-red-500/25 bg-red-950/20 px-2 py-0.5 text-[11px] font-medium text-red-400">
          <XCircle className="h-3 w-3 text-red-400" />
          Confirmed failure
        </span>
      );
    case "likely_failure":
      return (
        <span className="inline-flex items-center gap-1.5 rounded border border-orange-500/25 bg-orange-950/20 px-2 py-0.5 text-[11px] font-medium text-orange-400">
          <AlertTriangle className="h-3 w-3 text-orange-400" />
          Likely failure
        </span>
      );
    case "needs_review":
      return (
        <span className="inline-flex items-center gap-1.5 rounded border border-amber-500/25 bg-amber-950/20 px-2 py-0.5 text-[11px] font-medium text-amber-400">
          <HelpCircle className="h-3 w-3 text-amber-400" />
          Needs review
        </span>
      );
    case "partial_mitigation":
      return (
        <span className="inline-flex items-center gap-1.5 rounded border border-yellow-500/25 bg-yellow-950/20 px-2 py-0.5 text-[11px] font-medium text-yellow-300">
          <MinusCircle className="h-3 w-3 text-yellow-300" />
          Partial mitigation
        </span>
      );
    case "attack_blocked":
      return (
        <span className="inline-flex items-center gap-1.5 rounded border border-emerald-500/25 bg-emerald-950/20 px-2 py-0.5 text-[11px] font-medium text-emerald-400">
          <CheckCircle2 className="h-3 w-3 text-emerald-400" />
          Attack blocked
        </span>
      );
    case "verified_under_stated_checks":
      return (
        <span className="inline-flex items-center gap-1.5 rounded border border-[var(--accent)] bg-transparent px-2 py-0.5 text-[11px] font-medium text-[var(--accent)]">
          <ShieldCheck className="h-3 w-3 text-[var(--accent)]" />
          Verified
        </span>
      );
    case "regression_detected":
      return (
        <span className="inline-flex items-center gap-1.5 rounded border border-red-500/30 bg-red-950/30 px-2 py-0.5 text-[11px] font-medium text-red-400">
          <RefreshCw className="h-3 w-3 text-red-400" />
          Regression
        </span>
      );
    case "not_evaluated":
    default:
      return (
        <span className="inline-flex items-center gap-1.5 rounded border border-zinc-700/40 bg-zinc-800/30 px-2 py-0.5 text-[11px] font-medium text-zinc-400">
          <MinusCircle className="h-3 w-3 text-zinc-500" />
          Not evaluated
        </span>
      );
  }
}

/** Category chip */
const CATEGORY_META: Record<string, string> = {
  direct_injection: "bg-purple-950/30 text-purple-300 border-purple-800/40",
  canary_leakage:   "bg-orange-950/30 text-orange-300 border-orange-800/40",
  sensitive_data:   "bg-blue-950/30 text-blue-300 border-blue-800/40",
  tool_misuse:      "bg-rose-950/30 text-rose-300 border-rose-800/40",
};

export function CategoryChip({ category }: { category: string }) {
  const cls = CATEGORY_META[category] ?? "bg-zinc-800/40 text-zinc-300 border-zinc-700/40";
  const label = category.replace(/_/g, " ");
  return (
    <span className={`inline-flex items-center rounded border px-2 py-0.5 text-[10px] font-mono tracking-tight ${cls}`}>
      {label}
    </span>
  );
}

/** Severity badge */
const SEV_META: Record<string, string> = {
  low: "text-[var(--text-muted)]",
  medium: "text-amber-400",
  high: "text-orange-400",
  critical: "text-red-400",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`text-[10px] font-mono font-semibold uppercase tracking-wider ${SEV_META[severity] ?? ""}`}>
      {severity}
    </span>
  );
}

/** 21st.dev Bento Metric Card with Sparkline & Micro-telemetry */
export function MetricCard({
  label,
  value,
  sub,
  trend,
  telemetry,
}: {
  label: string;
  value: string | number;
  sub?: string;
  trend?: "up" | "down" | "flat";
  telemetry?: string;
}) {
  return (
    <SpotlightCard className="p-4 sm:p-5">
      <div className="flex items-center justify-between text-[11px] text-[var(--text-muted)]">
        <span className="font-medium tracking-wide uppercase">{label}</span>
        {telemetry && <span className="font-mono text-[9px] text-zinc-500">{telemetry}</span>}
      </div>
      <div className="mt-2 flex items-baseline justify-between">
        <p className="text-2xl sm:text-3xl font-semibold tracking-tight text-[var(--text-primary)] font-mono">{value}</p>
        {trend && (
          <span
            className={`flex items-center gap-1 font-mono text-[11px] ${
              trend === "up" ? "text-emerald-400" : trend === "down" ? "text-red-400" : "text-zinc-500"
            }`}
          >
            {trend === "up" ? <TrendingUp className="h-3 w-3" /> : trend === "down" ? <TrendingDown className="h-3 w-3" /> : <ArrowRight className="h-3 w-3" />}
            {sub}
          </span>
        )}
      </div>
      {!trend && sub && (
        <p className="mt-1 font-mono text-[11px] text-[var(--text-muted)]">{sub}</p>
      )}
    </SpotlightCard>
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
    info:    "border-[var(--border-subtle)] bg-[var(--bg-raised)] text-[var(--text-secondary)]",
    success: "border-emerald-900/50 bg-emerald-950/60 text-emerald-300",
    warn:    "border-amber-900/50 bg-amber-950/60 text-amber-300",
    error:   "border-red-900/50 bg-red-950/60 text-red-300",
  };
  return (
    <div
      role="status"
      aria-live="polite"
      className={`animate-toast-in flex items-center gap-3 rounded-lg border px-4 py-3 text-xs font-mono shadow-2xl ${colors[variant]}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-[var(--accent)]" />
      {message}
    </div>
  );
}

/** Inline error block with technical details */
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
    <div role="alert" className="rounded-lg border border-red-900/40 bg-red-950/20 p-5">
      {code && (
        <div className="mb-2 flex items-center gap-2 font-mono text-[11px] text-red-400">
          <XCircle className="h-3.5 w-3.5" />
          <span>ERR_CODE: {code}</span>
        </div>
      )}
      <p className="text-sm text-red-300/90">{message}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-3 inline-flex items-center gap-1.5 rounded-[var(--radius-input)] border border-red-800/60 bg-red-950/40 px-3 py-1.5 font-mono text-[11px] text-red-300 hover:bg-red-900/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500"
        >
          <RefreshCw className="h-3 w-3" />
          Retry operation
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
      className="flex items-start gap-3 rounded-lg border border-amber-900/40 bg-amber-950/20 px-4 py-3 text-xs text-amber-300/90"
    >
      <AlertTriangle className="h-4 w-4 text-amber-400 flex-shrink-0 mt-0.5" />
      <span className="font-mono">{message}</span>
    </div>
  );
}
