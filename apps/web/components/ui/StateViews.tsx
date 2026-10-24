import type { FindingLabel, ScanStatus, Severity } from "@/lib/types";

/** Shared loading / error / empty state blocks — every view uses these. */

export function LoadingBlock({ label = "Loading…" }: { label?: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900/50 p-6 text-zinc-400"
    >
      <span
        aria-hidden
        className="h-4 w-4 animate-spin rounded-full border-2 border-zinc-600 border-t-indigo-400"
      />
      {label}
    </div>
  );
}

export function ErrorBlock({
  title = "Something went wrong",
  message,
  onRetry,
}: {
  title?: string;
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div
      role="alert"
      className="rounded-lg border border-red-900/60 bg-red-950/30 p-6"
    >
      <p className="font-medium text-red-300">{title}</p>
      <p className="mt-1 text-sm text-red-200/80">{message}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-3 rounded-md border border-red-800 px-3 py-1.5 text-sm text-red-200 hover:bg-red-950/60"
        >
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyBlock({
  title,
  message,
  children,
}: {
  title: string;
  message: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-dashed border-zinc-700 bg-zinc-900/30 p-10 text-center">
      <p className="font-medium text-zinc-300">{title}</p>
      <p className="mt-1 text-sm text-zinc-500">{message}</p>
      {children && <div className="mt-4">{children}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Badges
// ---------------------------------------------------------------------------

const STATUS_STYLES: Record<ScanStatus, string> = {
  created: "bg-zinc-800 text-zinc-300",
  reconning: "bg-sky-950 text-sky-300",
  attacking: "bg-amber-950 text-amber-300",
  judging: "bg-amber-950 text-amber-300",
  hardening_proposed: "bg-violet-950 text-violet-300",
  awaiting_approval: "bg-violet-950 text-violet-300",
  retesting: "bg-sky-950 text-sky-300",
  completed: "bg-emerald-950 text-emerald-300",
  completed_without_retest: "bg-emerald-950 text-emerald-300",
  failed_partial: "bg-orange-950 text-orange-300",
  failed_fatal: "bg-red-950 text-red-300",
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${STATUS_STYLES[status] ?? "bg-zinc-800 text-zinc-300"}`}
    >
      {status}
    </span>
  );
}

const LABEL_STYLES: Record<FindingLabel, string> = {
  confirmed_failure: "bg-red-950 text-red-300 border-red-900",
  likely_failure: "bg-orange-950 text-orange-300 border-orange-900",
  attack_blocked: "bg-emerald-950 text-emerald-300 border-emerald-900",
  needs_review: "bg-amber-950 text-amber-300 border-amber-900",
  partial_mitigation: "bg-sky-950 text-sky-300 border-sky-900",
  regression_detected: "bg-red-950 text-red-300 border-red-900",
  not_evaluated: "bg-zinc-800 text-zinc-400 border-zinc-700",
  verified_under_stated_checks: "bg-emerald-950 text-emerald-300 border-emerald-900",
};

export function LabelBadge({ label }: { label: FindingLabel }) {
  return (
    <span
      className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${LABEL_STYLES[label] ?? "bg-zinc-800 text-zinc-300 border-zinc-700"}`}
    >
      {label.replaceAll("_", " ")}
    </span>
  );
}

const SEVERITY_STYLES: Record<Severity, string> = {
  low: "text-zinc-400",
  medium: "text-amber-300",
  high: "text-orange-300",
  critical: "text-red-300",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`text-xs font-semibold uppercase ${SEVERITY_STYLES[severity]}`}>
      {severity}
    </span>
  );
}
