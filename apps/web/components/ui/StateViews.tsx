/**
 * Shared loading / error / empty state blocks — every view uses these.
 * Updated to use the RAVEN design token system.
 */
import type { FindingLabel, ScanStatus, Severity } from "@/lib/types";

export function LoadingBlock({ label = "Loading…" }: { label?: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex items-center gap-3 rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-6 text-[var(--text-secondary)]"
    >
      {/* Three-dot AI loader */}
      <span className="inline-flex items-center gap-1" aria-hidden>
        {[0, 150, 300].map((delay) => (
          <span
            key={delay}
            className="inline-block h-1 w-1 rounded-full bg-[var(--accent)]"
            style={{ animation: `breathe 1.2s ease-in-out ${delay}ms infinite` }}
          />
        ))}
      </span>
      <span className="text-[var(--text-sm)]">{label}</span>
    </div>
  );
}

export function ErrorBlock({
  title = "Something went wrong",
  message,
  code,
  onRetry,
}: {
  title?: string;
  message: string;
  code?: string;
  onRetry?: () => void;
}) {
  return (
    <div
      role="alert"
      className="rounded-lg border border-red-900/40 bg-red-950/20 p-6"
    >
      {code && (
        <p className="mb-1 font-mono text-[var(--text-xs)] text-red-400">{code}</p>
      )}
      <p className="font-medium text-red-300">{title}</p>
      <p className="mt-1 text-[var(--text-sm)] text-red-200/80">{message}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-3 rounded-[var(--radius-input)] border border-red-800/60 px-3 py-1.5 text-[var(--text-sm)] text-red-200 hover:bg-red-950/40"
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
    <div className="rounded-lg border border-dashed border-[var(--border-subtle)] bg-[var(--bg-surface)]/30 p-10 text-center">
      <p className="font-medium text-[var(--text-primary)]">{title}</p>
      <p className="mt-1 text-[var(--text-sm)] text-[var(--text-secondary)]">{message}</p>
      {children && <div className="mt-4">{children}</div>}
    </div>
  );
}

// ─── Status badge ────────────────────────────────────────────────────────────

const STATUS_STYLES: Record<ScanStatus, string> = {
  created:                  "bg-zinc-800/60 text-zinc-400 border-zinc-700",
  reconning:                "bg-sky-950/60 text-sky-300 border-sky-800/40",
  attacking:                "bg-orange-950/60 text-orange-300 border-orange-800/40",
  judging:                  "bg-amber-950/60 text-amber-300 border-amber-800/40",
  hardening_proposed:       "bg-violet-950/60 text-violet-300 border-violet-800/40",
  awaiting_approval:        "bg-violet-950/60 text-violet-300 border-violet-800/40",
  retesting:                "bg-sky-950/60 text-sky-300 border-sky-800/40",
  completed:                "bg-green-950/60 text-green-300 border-green-800/40",
  completed_without_retest: "bg-green-950/60 text-green-300 border-green-800/40",
  completed_with_limitations: "bg-amber-950/60 text-amber-300 border-amber-800/40",
  inconclusive:             "bg-amber-950/60 text-amber-300 border-amber-800/40",
  failed_partial:           "bg-orange-950/60 text-orange-300 border-orange-800/40",
  failed_fatal:             "bg-red-950/60 text-red-300 border-red-800/40",
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span
      className={`inline-block rounded border px-2 py-0.5 text-[11px] font-medium ${STATUS_STYLES[status] ?? "bg-zinc-800 text-zinc-300 border-zinc-700"}`}
    >
      {status.replace(/_/g, " ")}
    </span>
  );
}

export function ApiUnavailableBanner({ error, onRetry }: { error?: string; onRetry?: () => void }) {
  return (
    <div className="rounded-lg border border-red-900/50 bg-red-950/20 p-4 font-mono">
      <div className="flex items-center gap-2 text-red-400 font-semibold text-xs">
        <span className="h-2 w-2 rounded-full bg-red-500 animate-pulse" />
        RAVEN CONTROL PLANE DISCONNECTED
      </div>
      <p className="mt-1 text-xs text-red-200/80">
        {error || "Cannot reach API server at localhost:8000. Start it with `make dev`."}
      </p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-2 rounded border border-red-800/60 bg-red-900/30 px-2 py-1 text-[11px] text-red-200 hover:bg-red-900/50"
        >
          Retry Connection
        </button>
      )}
    </div>
  );
}

export function WorkerUnavailableBanner() {
  return (
    <div className="rounded-lg border border-amber-900/50 bg-amber-950/20 p-4 font-mono">
      <div className="flex items-center gap-2 text-amber-400 font-semibold text-xs">
        <span className="h-2 w-2 rounded-full bg-amber-500 animate-pulse" />
        EVALUATION WORKER OFFLINE
      </div>
      <p className="mt-1 text-xs text-amber-200/80">
        Background worker is offline. Queued jobs will process when `evaluator.worker` starts.
      </p>
    </div>
  );
}

export function ModelUnavailableNotice({ modelName }: { modelName?: string }) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3 font-mono text-xs">
      <div className="flex items-center gap-2 text-zinc-400 font-medium">
        <span className="h-1.5 w-1.5 rounded-full bg-zinc-500" />
        SEMANTIC JUDGE OFFLINE: DETERMINISTIC CHECK FALLBACK ACTIVE
      </div>
      <p className="mt-1 text-[11px] text-zinc-500">
        No model API key ({modelName || "unconfigured"}). Running conservative offline deterministic checks.
      </p>
    </div>
  );
}

export function ScanStateBanner({ status, limitations = [] }: { status: ScanStatus; limitations?: string[] }) {
  const isIncomplete = [
    "created", "reconning", "attacking", "judging", "awaiting_approval",
    "hardening_proposed", "retesting", "failed_partial", "failed_fatal",
    "completed_with_limitations", "inconclusive"
  ].includes(status);

  if (isIncomplete) {
    return (
      <div className="rounded-lg border border-amber-900/40 bg-amber-950/15 p-4 font-mono text-xs">
        <div className="flex items-center gap-2 font-semibold text-amber-400">
          <span className="h-2 w-2 rounded-full bg-amber-400 animate-pulse" />
          SCAN INCOMPLETE — {status.toUpperCase().replace(/_/g, " ")}
        </div>
        <p className="mt-1 text-amber-200/80 text-[11px]">
          Results represent partial evidence only. Cannot receive a clean security verdict while evaluations are incomplete or limited.
        </p>
        {limitations.length > 0 && (
          <ul className="mt-2 list-disc list-inside space-y-0.5 text-[10px] text-amber-300/70">
            {limitations.map((lim, idx) => (
              <li key={idx}>{lim}</li>
            ))}
          </ul>
        )}
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-teal-900/40 bg-teal-950/15 p-4 font-mono text-xs">
      <div className="flex items-center gap-2 font-semibold text-teal-400">
        <span className="h-2 w-2 rounded-full bg-teal-400" />
        SCAN COMPLETED — FULL EVALUATION EVIDENCE PRESERVED
      </div>
      <p className="mt-1 text-teal-200/80 text-[11px]">
        All planned attacks and benign regression tests executed. Canonical evidence ledger verified.
      </p>
    </div>
  );
}


// ─── Finding label badge ─────────────────────────────────────────────────────

const LABEL_STYLES: Record<FindingLabel, string> = {
  confirmed_failure:           "bg-red-950/40 text-red-300 border-red-900/50",
  likely_failure:              "bg-orange-950/40 text-orange-300 border-orange-900/50",
  attack_blocked:              "bg-green-950/40 text-green-300 border-green-900/50",
  needs_review:                "bg-amber-950/40 text-amber-300 border-amber-900/50",
  partial_mitigation:          "bg-yellow-950/40 text-yellow-300 border-yellow-900/50",
  regression_detected:         "bg-red-950/40 text-red-300 border-red-900/50",
  not_evaluated:               "bg-zinc-800/60 text-zinc-400 border-zinc-700",
  verified_under_stated_checks:"bg-transparent text-[var(--accent)] border-[var(--accent)]",
};

const LABEL_ICONS: Record<FindingLabel, string> = {
  confirmed_failure:           "✕",
  likely_failure:              "!",
  attack_blocked:              "✓",
  needs_review:                "?",
  partial_mitigation:          "~",
  regression_detected:         "↺",
  not_evaluated:               "–",
  verified_under_stated_checks:"✓",
};

export function LabelBadge({ label }: { label: FindingLabel }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] font-medium ${LABEL_STYLES[label] ?? "bg-zinc-800 text-zinc-300 border-zinc-700"}`}
    >
      <span aria-hidden className="font-mono text-[10px]">{LABEL_ICONS[label]}</span>
      {label.replace(/_/g, " ")}
    </span>
  );
}

// ─── Severity badge ──────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<Severity, string> = {
  low:      "text-[var(--text-muted)]",
  medium:   "text-yellow-400",
  high:     "text-orange-400",
  critical: "text-red-400",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`text-[11px] font-semibold uppercase tracking-wide ${SEVERITY_STYLES[severity]}`}>
      {severity}
    </span>
  );
}
