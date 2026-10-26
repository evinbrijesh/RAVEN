"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { ApiRequestError, createScan } from "@/lib/api-client";
import {
  ATTACK_CATEGORIES,
  type AttackCategory,
  type ScanConfig,
} from "@/lib/types";
import { ErrorBlock } from "@/components/ui/StateViews";
import { useProject } from "@/lib/project-context";

const CATEGORY_LABELS: Record<AttackCategory, string> = {
  direct_injection: "Direct injection",
  canary_leakage: "Canary leakage",
  sensitive_data: "Sensitive data",
  tool_misuse: "Tool misuse",
};

const CATEGORY_HINTS: Record<AttackCategory, string> = {
  direct_injection: "Prompt-injection attempts against the bot's instructions.",
  canary_leakage: "Tries to make the bot reveal its embedded canary token.",
  sensitive_data: "Probes for secrets or PII in responses.",
  tool_misuse: "Attempts unsafe tool calls (e.g. refunds without verification).",
};

const DEFAULT_CONFIG: ScanConfig = {
  target_id: "shophelper-local",
  attack_categories: [...ATTACK_CATEGORIES],
  max_attempts_per_attack: 2,
  enable_mutation: true,
  run_benign_suite: true,
  budget: {
    max_attack_cases: 12,
    max_attempts_per_attack: 2,
    max_model_calls: 40,
    max_total_tokens: 200_000,
    per_call_timeout_seconds: 30,
    scan_timeout_seconds: 600,
    concurrency_limit: 2,
  },
};

export default function NewScanForm() {
  const router = useRouter();
  const { currentProject } = useProject();
  const [targetMode, setTargetMode] = useState<"local" | "http">("local");
  const [externalUrl, setExternalUrl] = useState("");
  const [categories, setCategories] = useState<AttackCategory[]>([
    ...ATTACK_CATEGORIES,
  ]);
  const [maxAttempts, setMaxAttempts] = useState(2);
  const [enableMutation, setEnableMutation] = useState(true);
  const [runBenignSuite, setRunBenignSuite] = useState(true);
  const [regressionOnly, setRegressionOnly] = useState(false);
  const [maxAttackCases, setMaxAttackCases] = useState(12);
  const [maxModelCalls, setMaxModelCalls] = useState(40);
  const [maxTotalTokens, setMaxTotalTokens] = useState(200_000);
  const [perCallTimeout, setPerCallTimeout] = useState(30);
  const [scanTimeout, setScanTimeout] = useState(600);
  const [concurrency, setConcurrency] = useState(2);

  const [submitting, setSubmitting] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);

  function toggleCategory(category: AttackCategory): void {
    setCategories((prev) =>
      prev.includes(category)
        ? prev.filter((c) => c !== category)
        : [...prev, category],
    );
  }

  function validate(): string | null {
    if (targetMode === "http") {
      const trimmed = externalUrl.trim();
      if (!trimmed) {
        return "Please enter a valid HTTP(S) endpoint URL.";
      }
      if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
        return "External target URL must start with http:// or https://.";
      }
    }
    if (categories.length === 0) {
      return "Select at least one attack category.";
    }
    if (maxAttackCases < 1 || maxAttackCases > 12) {
      return "Attack case budget must be between 1 and 12.";
    }
    if (maxAttempts !== 1 && maxAttempts !== 2) {
      return "Attempts per attack must be 1 or 2.";
    }
    if (concurrency < 1 || concurrency > 8) {
      return "Concurrency limit must be between 1 and 8.";
    }
    if (maxModelCalls < 0) {
      return "Model call budget cannot be negative.";
    }
    if (perCallTimeout <= 0 || scanTimeout <= 0) {
      return "Timeouts must be greater than zero.";
    }
    return null;
  }

  async function handleSubmit(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    setSubmitError(null);
    const problem = validate();
    if (problem) {
      setValidationError(problem);
      return;
    }
    setValidationError(null);
    setSubmitting(true);
    const config: ScanConfig = {
      target_id: targetMode === "local" ? "shophelper-local" : externalUrl.trim(),
      project_id: currentProject.project_id,
      attack_categories: categories,
      max_attempts_per_attack: maxAttempts,
      enable_mutation: enableMutation,
      run_benign_suite: runBenignSuite,
      regression_only_mode: regressionOnly,
      budget: {
        max_attack_cases: maxAttackCases,
        max_attempts_per_attack: maxAttempts,
        max_model_calls: maxModelCalls,
        max_total_tokens: maxTotalTokens,
        per_call_timeout_seconds: perCallTimeout,
        scan_timeout_seconds: scanTimeout,
        concurrency_limit: concurrency,
      },
    };
    try {
      const result = await createScan(config);
      router.push(`/scans/${encodeURIComponent(result.scan_id)}`);
    } catch (cause) {
      setSubmitting(false);
      setSubmitError(
        cause instanceof ApiRequestError
          ? `${cause.code}: ${cause.message}`
          : "Failed to create scan.",
      );
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-6" noValidate>
      {/* Target selection */}
      <fieldset className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
        <legend className="px-1 text-sm font-medium text-zinc-300">Target Selection</legend>
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <label
              className={`flex cursor-pointer items-start gap-3 rounded-md border p-3 transition-colors ${
                targetMode === "local"
                  ? "border-indigo-500 bg-indigo-500/10 text-zinc-100"
                  : "border-zinc-800 bg-zinc-950/40 text-zinc-400 hover:border-zinc-700"
              }`}
            >
              <input
                type="radio"
                name="targetMode"
                value="local"
                checked={targetMode === "local"}
                onChange={() => setTargetMode("local")}
                className="mt-0.5 h-4 w-4 accent-indigo-600"
              />
              <div className="space-y-1">
                <span className="block font-medium text-sm text-zinc-200">
                  Built-in Demo Bot (Simulated)
                </span>
                <span className="block text-xs text-zinc-400">
                  <code className="rounded bg-zinc-800 px-1 py-0.5 text-zinc-300">shophelper-local</code> — In-memory vulnerable e-commerce assistant with canary and refund tool.
                </span>
              </div>
            </label>

            <label
              className={`flex cursor-pointer items-start gap-3 rounded-md border p-3 transition-colors ${
                targetMode === "http"
                  ? "border-indigo-500 bg-indigo-500/10 text-zinc-100"
                  : "border-zinc-800 bg-zinc-950/40 text-zinc-400 hover:border-zinc-700"
              }`}
            >
              <input
                type="radio"
                name="targetMode"
                value="http"
                checked={targetMode === "http"}
                onChange={() => setTargetMode("http")}
                className="mt-0.5 h-4 w-4 accent-indigo-600"
              />
              <div className="space-y-1">
                <span className="block font-medium text-sm text-zinc-200">
                  External HTTP Endpoint (Mode A)
                </span>
                <span className="block text-xs text-zinc-400">
                  Public JSON chat API. Protected by strict SSRF guardrails and target consent verification.
                </span>
              </div>
            </label>
          </div>

          {targetMode === "http" && (
            <div className="rounded-md border border-zinc-800/80 bg-zinc-950/60 p-3 space-y-2">
              <label htmlFor="externalUrl" className="block text-xs font-semibold uppercase tracking-wider text-zinc-400">
                Target Endpoint URL
              </label>
              <input
                id="externalUrl"
                type="url"
                value={externalUrl}
                onChange={(e) => setExternalUrl(e.target.value)}
                placeholder="https://api.your-org.com/v1/chat"
                className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 font-mono text-sm text-zinc-100 placeholder-zinc-500 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              />
              <div className="flex items-start gap-2 text-xs text-amber-400/90">
                <span className="font-semibold">SSRF Protection:</span>
                <span className="text-zinc-400">
                  Private IPv4/IPv6 (RFC 1918), loopback, link-local, and cloud metadata (169.254.169.254) are rejected by RAVEN. Scan requests send <code className="rounded bg-zinc-800 px-1 text-zinc-300">X-Raven-Scan-Consent: true</code>.
                </span>
              </div>
            </div>
          )}
        </div>
      </fieldset>

      {/* Attack categories */}
      <fieldset className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
        <legend className="px-1 text-sm font-medium text-zinc-300">
          Attack categories
        </legend>
        <div className="grid gap-3 sm:grid-cols-2">
          {ATTACK_CATEGORIES.map((category) => (
            <label
              key={category}
              className="flex cursor-pointer items-start gap-3 rounded-md border border-zinc-800 p-3 hover:border-zinc-600"
            >
              <input
                type="checkbox"
                checked={categories.includes(category)}
                onChange={() => toggleCategory(category)}
                className="mt-0.5 h-4 w-4 accent-indigo-600"
              />
              <span>
                <span className="block text-sm font-medium text-zinc-200">
                  {CATEGORY_LABELS[category]}
                </span>
                <span className="mt-0.5 block text-xs text-zinc-500">
                  {CATEGORY_HINTS[category]}
                </span>
              </span>
            </label>
          ))}
        </div>
        {validationError && (
          <p role="alert" className="mt-3 text-sm text-red-400">
            {validationError}
          </p>
        )}
      </fieldset>

      {/* Budgets */}
      <fieldset className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
        <legend className="px-1 text-sm font-medium text-zinc-300">
          Budgets &amp; limits
        </legend>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <NumberField
            label="Attack case budget"
            hint="1–12 cases"
            value={maxAttackCases}
            min={1}
            max={12}
            onChange={setMaxAttackCases}
          />
          <NumberField
            label="Attempts per attack"
            hint="1 or 2"
            value={maxAttempts}
            min={1}
            max={2}
            onChange={(v) => setMaxAttempts(Math.min(2, Math.max(1, v)))}
          />
          <NumberField
            label="Model call budget"
            hint="Total LLM calls allowed"
            value={maxModelCalls}
            min={0}
            onChange={setMaxModelCalls}
          />
          <NumberField
            label="Total token budget"
            hint="Across all model calls"
            value={maxTotalTokens}
            min={0}
            onChange={setMaxTotalTokens}
          />
          <NumberField
            label="Per-call timeout (s)"
            hint="Each model call"
            value={perCallTimeout}
            min={1}
            onChange={setPerCallTimeout}
          />
          <NumberField
            label="Scan timeout (s)"
            hint="Whole scan"
            value={scanTimeout}
            min={1}
            onChange={setScanTimeout}
          />
          <NumberField
            label="Concurrency limit"
            hint="1–8 parallel runs"
            value={concurrency}
            min={1}
            max={8}
            onChange={setConcurrency}
          />
        </div>
      </fieldset>

      {/* Options */}
      <fieldset className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
        <legend className="px-1 text-sm font-medium text-zinc-300">Options</legend>
        <div className="space-y-3">
          <label className="flex items-center gap-3 text-sm text-zinc-300">
            <input
              type="checkbox"
              checked={enableMutation}
              onChange={(e) => setEnableMutation(e.target.checked)}
              className="h-4 w-4 accent-indigo-600"
            />
            Enable mutation (one mutated retry per failed case, within budget)
          </label>
          <label className="flex items-center gap-3 text-sm text-zinc-300">
            <input
              type="checkbox"
              checked={runBenignSuite}
              onChange={(e) => setRunBenignSuite(e.target.checked)}
              className="h-4 w-4 accent-indigo-600"
            />
            Run benign utility suite (regression check after hardening)
          </label>
          <label className="flex items-center gap-3 text-sm text-indigo-300 font-medium">
            <input
              type="checkbox"
              checked={regressionOnly}
              onChange={(e) => setRegressionOnly(e.target.checked)}
              className="h-4 w-4 accent-indigo-600"
            />
            Regression-only mode (re-test saved failure cases for this target)
          </label>
        </div>
      </fieldset>

      {submitError && (
        <ErrorBlock title="Scan could not be created" message={submitError} />
      )}

      <div className="flex items-center gap-3">
        <button
          type="submit"
          disabled={submitting}
          className="rounded-md bg-indigo-600 px-5 py-2.5 text-sm font-medium text-white hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {submitting ? "Creating scan…" : "Start scan"}
        </button>
        <span className="text-xs text-zinc-500">
          The scan runs with bounded budgets; hardening is never auto-deployed.
        </span>
      </div>
    </form>
  );
}

function NumberField({
  label,
  hint,
  value,
  min,
  max,
  onChange,
}: {
  label: string;
  hint: string;
  value: number;
  min?: number;
  max?: number;
  onChange: (value: number) => void;
}) {
  return (
    <label className="block">
      <span className="block text-sm font-medium text-zinc-300">{label}</span>
      <input
        type="number"
        value={value}
        min={min}
        max={max}
        onChange={(e) => {
          const parsed = Number(e.target.value);
          if (!Number.isNaN(parsed)) onChange(parsed);
        }}
        className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 focus:border-indigo-500 focus:outline-none"
      />
      <span className="mt-1 block text-xs text-zinc-500">{hint}</span>
    </label>
  );
}
