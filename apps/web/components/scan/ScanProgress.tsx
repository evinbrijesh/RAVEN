import type { ScanView } from "@/lib/types";
import { StatusBadge } from "@/components/ui/StateViews";

/** Live scan header: status, progress bar, counts, and security metrics. */
export default function ScanProgress({ scan }: { scan: ScanView }) {
  const pct = Math.round(Math.min(1, Math.max(0, scan.progress)) * 100);
  const active = !["completed", "completed_without_retest", "failed_partial", "failed_fatal"].includes(
    scan.status,
  );

  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <StatusBadge status={scan.status} />
        {scan.phase && (
          <span className="text-xs text-zinc-500">phase: {scan.phase}</span>
        )}
        {active && (
          <span className="text-xs text-zinc-400" aria-live="polite">
            {pct}%
          </span>
        )}
      </div>

      <div
        className="mt-3 h-2 overflow-hidden rounded-full bg-zinc-800"
        role="progressbar"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Scan progress"
      >
        <div
          className="h-full rounded-full bg-indigo-500 transition-all duration-500"
          style={{ width: `${pct}%` }}
        />
      </div>

      <dl className="mt-4 grid grid-cols-2 gap-3 text-sm sm:grid-cols-5">
        <Metric label="Cases" value={scan.counts.total} />
        <Metric
          label="Confirmed failures"
          value={scan.counts.confirmed_failures}
          tone={scan.counts.confirmed_failures > 0 ? "bad" : "ok"}
        />
        <Metric label="Blocked" value={scan.counts.blocked} tone="ok" />
        <Metric
          label="Needs review"
          value={scan.counts.needs_review}
          tone={scan.counts.needs_review > 0 ? "warn" : undefined}
        />
        <Metric label="Not evaluated" value={scan.counts.not_evaluated} />
      </dl>

      {(scan.security_metrics.before_attack_success_rate !== null ||
        scan.security_metrics.after_attack_success_rate !== null ||
        scan.security_metrics.benign_success_rate !== null) && (
        <dl className="mt-4 grid grid-cols-1 gap-3 border-t border-zinc-800 pt-4 text-sm sm:grid-cols-3">
          <RateMetric
            label="Attack success (before)"
            value={scan.security_metrics.before_attack_success_rate}
          />
          <RateMetric
            label="Attack success (after hardening)"
            value={scan.security_metrics.after_attack_success_rate}
          />
          <RateMetric
            label="Benign success"
            value={scan.security_metrics.benign_success_rate}
          />
        </dl>
      )}
    </section>
  );
}

function Metric({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone?: "ok" | "bad" | "warn";
}) {
  const color =
    tone === "bad"
      ? "text-red-300"
      : tone === "warn"
        ? "text-amber-300"
        : tone === "ok"
          ? "text-emerald-300"
          : "text-zinc-200";
  return (
    <div className="rounded-md bg-zinc-900 px-3 py-2">
      <dt className="text-xs text-zinc-500">{label}</dt>
      <dd className={`mt-0.5 text-lg font-semibold ${color}`}>{value}</dd>
    </div>
  );
}

function RateMetric({
  label,
  value,
}: {
  label: string;
  value: number | null;
}) {
  return (
    <div>
      <dt className="text-xs text-zinc-500">{label}</dt>
      <dd className="mt-0.5 font-semibold text-zinc-200">
        {value === null ? "—" : `${Math.round(value * 100)}%`}
      </dd>
    </div>
  );
}
