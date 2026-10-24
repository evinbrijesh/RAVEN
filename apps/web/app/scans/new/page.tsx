"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import TopBar from "@/components/ui/TopBar";
import { SpotlightCard } from "@/components/ui/primitives";

/* ─── Sample budget summary data ─────────────────────────────────────────── */
const AGENT_ROSTER = [
  { name: "Planner",  icon: "⊞", desc: "Selects cases from catalog" },
  { name: "Recon",    icon: "⊙", desc: "Profiles target capabilities" },
  { name: "Attacker", icon: "⊗", desc: "Executes attack cases" },
  { name: "Judge",    icon: "⊘", desc: "Rule + model verdict" },
  { name: "Hardener", icon: "⊕", desc: "Proposes system prompt fix" },
];

type Category = "direct_injection" | "canary_leakage" | "sensitive_data" | "tool_misuse";

const CATEGORIES: { id: Category; label: string; desc: string }[] = [
  { id: "direct_injection", label: "Direct injection",   desc: "Prompt injection via user turn" },
  { id: "canary_leakage",   label: "Canary leakage",     desc: "System-prompt canary disclosure" },
  { id: "sensitive_data",   label: "Sensitive data",     desc: "PII and secrets probing" },
  { id: "tool_misuse",      label: "Tool misuse",        desc: "Unauthorized tool invocation" },
];

export default function NewScanPage() {
  const router = useRouter();

  const [categories, setCategories] = useState<Set<Category>>(
    new Set(["direct_injection", "canary_leakage", "sensitive_data", "tool_misuse"])
  );
  const [attempts, setAttempts] = useState<1 | 2>(1);
  const [mutation, setMutation] = useState(true);
  const [benign,   setBenign]   = useState(true);
  const [consent,  setConsent]  = useState(false);
  const [starting, setStarting] = useState(false);

  const toggleCategory = (id: Category) => {
    setCategories((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const maxAttacks   = categories.size * 3;
  const modelCalls   = maxAttacks * attempts * (mutation ? 2 : 1) + (benign ? 10 : 0);
  const timeEstimate = Math.ceil(modelCalls * 0.4);

  const handleStart = async () => {
    if (!consent) return;
    setStarting(true);
    // Navigate to a demo scan
    await new Promise((r) => setTimeout(r, 800));
    router.push("/scans/scan_123");
  };

  return (
    <div className="flex flex-col">
      <TopBar breadcrumbs={[{ label: "Scans", href: "/scans" }, { label: "New scan" }]} />

      <main className="flex-1 px-6 py-8">
        <div className="mb-8">
          <h1 className="text-[var(--text-xl)] font-semibold tracking-tight">New scan</h1>
          <p className="mt-1 text-[var(--text-sm)] text-[var(--text-secondary)]">
            Configure an attack suite, then approve to run.
          </p>
        </div>

        <div className="grid gap-8 lg:grid-cols-[1fr_340px]">
          {/* ── Left column: configuration ─────────────────────────────── */}
          <div className="space-y-6">
            {/* Target (locked) */}
            <SpotlightCard className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5">
              <p className="mb-3 text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)]">Target</p>
              <div className="flex items-center gap-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-[var(--radius-input)] border border-[var(--border-hairline)] bg-[var(--bg-raised)]">
                  <span className="font-mono text-[11px] text-[var(--accent)]">SH</span>
                </div>
                <div>
                  <p className="font-mono text-[var(--text-sm)] text-[var(--text-primary)]">shophelper-local</p>
                  <p className="text-[var(--text-xs)] text-[var(--text-muted)]">Built-in sandboxed demo target · locked</p>
                </div>
                <span className="ml-auto rounded border border-[var(--border-hairline)] bg-[var(--bg-raised)] px-2 py-0.5 font-mono text-[10px] text-[var(--text-muted)]">
                  locked
                </span>
              </div>
            </SpotlightCard>

            {/* Attack categories */}
            <SpotlightCard className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5">
              <p className="mb-3 text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)]">Attack categories</p>
              <div className="grid gap-2 sm:grid-cols-2">
                {CATEGORIES.map((cat) => {
                  const on = categories.has(cat.id);
                  return (
                    <button
                      key={cat.id}
                      type="button"
                      onClick={() => toggleCategory(cat.id)}
                      aria-pressed={on}
                      className={`flex items-start gap-3 rounded-[var(--radius-input)] border px-3 py-3 text-left transition-colors
                        ${on
                          ? "border-[var(--accent)]/40 bg-[var(--accent-glow)]"
                          : "border-[var(--border-hairline)] bg-[var(--bg-raised)] hover:border-[var(--border-subtle)]"
                        }`}
                    >
                      <span
                        className={`mt-0.5 flex h-4 w-4 flex-shrink-0 items-center justify-center rounded border
                          ${on ? "border-[var(--accent)] bg-[var(--accent)]" : "border-[var(--border-subtle)]"}`}
                        aria-hidden
                      >
                        {on && <svg viewBox="0 0 10 8" fill="none" className="w-2.5" stroke="#0A0D12" strokeWidth={2}><polyline points="1,4 3.5,7 9,1"/></svg>}
                      </span>
                      <div>
                        <p className={`text-[var(--text-sm)] font-medium ${on ? "text-[var(--text-primary)]" : "text-[var(--text-secondary)]"}`}>
                          {cat.label}
                        </p>
                        <p className="text-[var(--text-xs)] text-[var(--text-muted)]">{cat.desc}</p>
                      </div>
                    </button>
                  );
                })}
              </div>
            </SpotlightCard>

            {/* Attempts per attack */}
            <SpotlightCard className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5">
              <p className="mb-3 text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                Attempts per attack
              </p>
              <div className="inline-flex rounded-[var(--radius-input)] border border-[var(--border-hairline)] bg-[var(--bg-raised)]">
                {([1, 2] as const).map((n) => (
                  <button
                    key={n}
                    type="button"
                    onClick={() => setAttempts(n)}
                    className={`px-6 py-1.5 text-[var(--text-sm)] transition-colors first:rounded-l-[var(--radius-input)] last:rounded-r-[var(--radius-input)]
                      ${attempts === n
                        ? "bg-[var(--bg-overlay)] text-[var(--text-primary)]"
                        : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
                      }`}
                    aria-pressed={attempts === n}
                  >
                    {n}
                  </button>
                ))}
              </div>
            </SpotlightCard>

            {/* Switches */}
            <SpotlightCard className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5">
              <p className="mb-3 text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)]">Options</p>
              <div className="space-y-3">
                {[
                  { label: "Mutation", sub: "Try one variant of each failed attack", value: mutation, set: setMutation },
                  { label: "Benign suite", sub: "Run 10 benign cases after hardening", value: benign, set: setBenign },
                ].map(({ label, sub, value, set }) => (
                  <label key={label} className="flex cursor-pointer items-center justify-between gap-4">
                    <div>
                      <p className="text-[var(--text-sm)] text-[var(--text-primary)]">{label}</p>
                      <p className="text-[var(--text-xs)] text-[var(--text-muted)]">{sub}</p>
                    </div>
                    <button
                      type="button"
                      role="switch"
                      aria-checked={value}
                      onClick={() => set((v) => !v)}
                      className={`relative h-5 w-9 rounded-full transition-colors
                        ${value ? "bg-[var(--accent)]" : "bg-[var(--bg-raised)] border border-[var(--border-subtle)]"}`}
                    >
                      <span
                        className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-transform ${value ? "translate-x-4" : "translate-x-0.5"}`}
                        aria-hidden
                      />
                    </button>
                  </label>
                ))}
              </div>
            </SpotlightCard>

            {/* Budget summary */}
            <div className="rounded-[var(--radius-input)] border border-[var(--border-hairline)] bg-[var(--bg-raised)] px-4 py-3">
              <p className="mb-2 text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)]">Budget</p>
              <dl className="grid grid-cols-3 gap-4 font-mono">
                {[
                  { label: "Max attacks",   value: maxAttacks },
                  { label: "Model calls",   value: `≤ ${modelCalls}` },
                  { label: "Time limit",    value: `~${timeEstimate}min` },
                ].map(({ label, value }) => (
                  <div key={label}>
                    <dt className="text-[10px] text-[var(--text-muted)]">{label}</dt>
                    <dd className="text-[var(--text-sm)] text-[var(--text-primary)]">{value}</dd>
                  </div>
                ))}
              </dl>
            </div>
          </div>

          {/* ── Right column: authorization ────────────────────────────── */}
          <div className="space-y-6">
            <SpotlightCard className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5">
              <p className="mb-1 text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                Authorization required
              </p>
              <p className="mb-4 text-[var(--text-xs)] text-[var(--text-muted)]">
                Only the built-in demo target can be scanned. No real systems are affected.
              </p>

              <label className="flex cursor-pointer items-start gap-3 rounded-[var(--radius-input)] border border-[var(--border-hairline)] bg-[var(--bg-raised)] p-4 hover:border-[var(--border-subtle)]">
                <input
                  type="checkbox"
                  checked={consent}
                  onChange={(e) => setConsent(e.target.checked)}
                  className="mt-0.5 accent-[var(--accent)]"
                />
                <span className="text-[var(--text-sm)] leading-snug text-[var(--text-secondary)]">
                  I own this target and authorize testing against the sandboxed ShopHelper demo.
                </span>
              </label>

              <div className="mt-4 rounded border border-amber-900/30 bg-amber-950/20 px-3 py-2 text-[var(--text-xs)] text-amber-300">
                Only the built-in demo target (shophelper-local) can be scanned.
                Approval changes only the temporary demo target. Nothing is deployed.
              </div>
            </SpotlightCard>

            {/* Agent roster preview */}
            <SpotlightCard className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5">
              <div className="mb-3 flex items-center justify-between">
                <p className="text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                  Agent roster
                </p>
                <span className="rounded border border-[var(--accent)]/30 bg-[var(--accent-glow)] px-2 py-0.5 text-[10px] font-medium text-[var(--accent)]">
                  5 agents · all bounded
                </span>
              </div>
              <ul className="space-y-2">
                {AGENT_ROSTER.map((a) => (
                  <li key={a.name} className="flex items-center gap-3">
                    <span className="w-4 font-mono text-[13px] text-[var(--text-muted)]">{a.icon}</span>
                    <div>
                      <p className="text-[var(--text-sm)] text-[var(--text-primary)]">{a.name}</p>
                      <p className="text-[var(--text-xs)] text-[var(--text-muted)]">{a.desc}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </SpotlightCard>

            {/* Start button */}
            <button
              type="button"
              onClick={handleStart}
              disabled={!consent || starting}
              className={`w-full rounded-[var(--radius-input)] px-6 py-3 text-[var(--text-sm)] font-medium transition-all
                ${consent && !starting
                  ? "bg-[var(--accent)] text-[#0A0D12] hover:brightness-110 focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
                  : "cursor-not-allowed bg-[var(--bg-raised)] text-[var(--text-muted)]"
                }`}
              aria-disabled={!consent || starting}
            >
              {starting ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-[#0A0D12]/30 border-t-[#0A0D12]" aria-hidden />
                  Starting…
                </span>
              ) : "Start scan"}
            </button>
            {!consent && (
              <p className="text-center text-[var(--text-xs)] text-[var(--text-muted)]">
                Check the authorization box to enable.
              </p>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
