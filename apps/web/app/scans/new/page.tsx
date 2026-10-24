"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  ShieldAlert,
  Play,
  Lock,
  Globe,
  Server,
  Key,
  Code2,
  CheckCircle2,
  AlertTriangle,
  Layers,
  HelpCircle,
  ExternalLink,
} from "lucide-react";
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

  // Target mode: built-in demo vs custom enterprise target
  const [targetType, setTargetType] = useState<"demo" | "custom">("demo");

  // Custom target fields
  const [customEndpoint, setCustomEndpoint] = useState("http://localhost:8080/v1/chat/completions");
  const [customTargetId, setCustomTargetId] = useState("my-customer-bot-staging");
  const [customAuthKey, setCustomAuthKey] = useState("env:TARGET_API_KEY");
  const [customCanary, setCustomCanary] = useState("CANARY-SECRET-TOKEN-99");
  const [toolSandboxMode, setToolSandboxMode] = useState<"mock" | "proxy">("mock");

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
    await new Promise((r) => setTimeout(r, 600));
    router.push("/scans/scan_123");
  };

  return (
    <div className="flex flex-col min-h-full">
      <TopBar breadcrumbs={[{ label: "Scans", href: "/scans" }, { label: "New scan" }]} />

      <main className="flex-1 px-4 sm:px-6 py-8 max-w-7xl w-full mx-auto space-y-8">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="flex h-2 w-2 rounded-full bg-teal-400" />
            <span className="text-[11px] font-mono tracking-wider uppercase text-[var(--text-muted)]">
              Scan Configuration
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-[var(--text-primary)]">
            Configure Security Scan
          </h1>
          <p className="mt-1 text-xs sm:text-sm text-[var(--text-secondary)]">
            Select target environment, attack categories, and runtime boundaries.
          </p>
        </div>

        <div className="grid gap-8 lg:grid-cols-[1fr_360px]">
          {/* ── Left column: configuration ─────────────────────────────── */}
          <div className="space-y-6">
            {/* Target Selection & Custom Input Scheme */}
            <SpotlightCard className="p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--border-hairline)] pb-3">
                <div className="flex items-center gap-2">
                  <Server className="h-4 w-4 text-[var(--accent)]" />
                  <p className="text-xs font-mono font-medium uppercase tracking-wider text-[var(--text-primary)]">
                    Target Environment
                  </p>
                </div>
                {/* Target Switcher */}
                <div className="inline-flex rounded-md border border-[var(--border-hairline)] bg-[var(--bg-base)] p-0.5 text-xs font-mono">
                  <button
                    type="button"
                    onClick={() => setTargetType("demo")}
                    className={`px-3 py-1 rounded transition-colors ${
                      targetType === "demo"
                        ? "bg-[var(--accent)] text-[#0A0D12] font-semibold"
                        : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
                    }`}
                  >
                    Built-in Sandbox
                  </button>
                  <button
                    type="button"
                    onClick={() => setTargetType("custom")}
                    className={`px-3 py-1 rounded transition-colors ${
                      targetType === "custom"
                        ? "bg-[var(--accent)] text-[#0A0D12] font-semibold"
                        : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
                    }`}
                  >
                    Custom Project (BYO)
                  </button>
                </div>
              </div>

              {/* A. Built-in Sandbox Mode */}
              {targetType === "demo" ? (
                <div className="space-y-3">
                  <div className="flex items-center gap-3 rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-base)] p-3.5">
                    <div className="flex h-9 w-9 items-center justify-center rounded-md border border-teal-500/20 bg-teal-950/40 text-[var(--accent)] font-mono font-semibold text-xs">
                      SH
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <p className="font-mono text-sm font-semibold text-[var(--text-primary)]">
                          shophelper-local
                        </p>
                        <span className="rounded border border-teal-500/30 bg-teal-950/30 px-1.5 py-0.2 text-[9px] font-mono text-teal-400">
                          SANDBOXED FIXTURE
                        </span>
                      </div>
                      <p className="text-xs text-[var(--text-muted)] font-mono mt-0.5">
                        ShopHelper v1.2 demo bot · Seeded with tools: refund, inventory, order lookup
                      </p>
                    </div>
                    <span className="ml-auto inline-flex items-center gap-1 rounded border border-[var(--border-hairline)] bg-[var(--bg-raised)] px-2 py-0.5 font-mono text-[10px] text-zinc-400">
                      <Lock className="h-2.5 w-2.5 text-amber-400" />
                      locked
                    </span>
                  </div>

                  {/* Why locked explanatory alert */}
                  <div className="rounded-lg border border-amber-900/30 bg-amber-950/15 p-3 text-xs text-amber-300/80 leading-relaxed font-sans flex items-start gap-2.5">
                    <HelpCircle className="h-4 w-4 text-amber-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <span className="font-medium text-amber-300">Why is this target locked by default?</span>
                      <p className="mt-1 text-[11px] text-amber-300/70">
                        Autonomous AI red-teaming agents execute multi-turn adversarial payloads. To guarantee safety and prevent unintended third-party traffic, the standard demo profile locks to this local sandboxed fixture where all actions (e.g. refunds) are virtual simulations.
                      </p>
                    </div>
                  </div>
                </div>
              ) : (
                /* B. Custom Project Input Scheme (For customer's individual LLM app) */
                <div className="space-y-4 pt-1 animate-fade-in font-mono text-xs">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div>
                      <label className="block text-[10px] text-[var(--text-muted)] uppercase mb-1">
                        Target Name / Identifier
                      </label>
                      <input
                        type="text"
                        value={customTargetId}
                        onChange={(e) => setCustomTargetId(e.target.value)}
                        className="w-full rounded border border-[var(--border-subtle)] bg-[var(--bg-base)] px-3 py-2 text-xs text-[var(--text-primary)] outline-none focus:border-teal-400"
                        placeholder="e.g. support-bot-staging"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-[var(--text-muted)] uppercase mb-1">
                        API Protocol / Format
                      </label>
                      <select className="w-full rounded border border-[var(--border-subtle)] bg-[var(--bg-base)] px-3 py-2 text-xs text-[var(--text-primary)] outline-none focus:border-teal-400">
                        <option>OpenAI ChatCompletions API</option>
                        <option>LangChain / LangGraph REST</option>
                        <option>Anthropic Messages API</option>
                        <option>Custom Webhook / Agent Endpoint</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-[10px] text-[var(--text-muted)] uppercase mb-1">
                      Target Endpoint URL
                    </label>
                    <div className="relative">
                      <Globe className="absolute left-3 top-2.5 h-3.5 w-3.5 text-zinc-500" />
                      <input
                        type="url"
                        value={customEndpoint}
                        onChange={(e) => setCustomEndpoint(e.target.value)}
                        className="w-full rounded border border-[var(--border-subtle)] bg-[var(--bg-base)] pl-9 pr-3 py-2 text-xs text-[var(--text-primary)] outline-none focus:border-teal-400 font-mono"
                        placeholder="http://localhost:8080/v1/chat/completions"
                      />
                    </div>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2">
                    <div>
                      <label className="block text-[10px] text-[var(--text-muted)] uppercase mb-1">
                        Auth Token / Header
                      </label>
                      <div className="relative">
                        <Key className="absolute left-3 top-2.5 h-3.5 w-3.5 text-zinc-500" />
                        <input
                          type="text"
                          value={customAuthKey}
                          onChange={(e) => setCustomAuthKey(e.target.value)}
                          className="w-full rounded border border-[var(--border-subtle)] bg-[var(--bg-base)] pl-9 pr-3 py-2 text-xs text-[var(--text-primary)] outline-none focus:border-teal-400 font-mono"
                          placeholder="Bearer sk-... or env var"
                        />
                      </div>
                    </div>
                    <div>
                      <label className="block text-[10px] text-[var(--text-muted)] uppercase mb-1">
                        Canary Token (For Proof Oracle)
                      </label>
                      <input
                        type="text"
                        value={customCanary}
                        onChange={(e) => setCustomCanary(e.target.value)}
                        className="w-full rounded border border-[var(--border-subtle)] bg-[var(--bg-base)] px-3 py-2 text-xs text-[var(--text-primary)] outline-none focus:border-teal-400 font-mono"
                        placeholder="CANARY-SECRET-TOKEN"
                      />
                    </div>
                  </div>

                  {/* Tool execution sandbox mode */}
                  <div>
                    <label className="block text-[10px] text-[var(--text-muted)] uppercase mb-1.5">
                      Tool Execution Policy
                    </label>
                    <div className="grid grid-cols-2 gap-2">
                      <button
                        type="button"
                        onClick={() => setToolSandboxMode("mock")}
                        className={`p-2.5 rounded border text-left transition-colors ${
                          toolSandboxMode === "mock"
                            ? "border-teal-500/50 bg-teal-950/20 text-teal-300"
                            : "border-[var(--border-hairline)] bg-[var(--bg-base)] text-[var(--text-muted)]"
                        }`}
                      >
                        <p className="font-semibold text-xs">Mock Dry-Run (Recommended)</p>
                        <p className="text-[10px] opacity-80 mt-0.5">Intercepts tool calls in sandbox; no side-effects</p>
                      </button>
                      <button
                        type="button"
                        onClick={() => setToolSandboxMode("proxy")}
                        className={`p-2.5 rounded border text-left transition-colors ${
                          toolSandboxMode === "proxy"
                            ? "border-teal-500/50 bg-teal-950/20 text-teal-300"
                            : "border-[var(--border-hairline)] bg-[var(--bg-base)] text-[var(--text-muted)]"
                        }`}
                      >
                        <p className="font-semibold text-xs">Staging Proxy</p>
                        <p className="text-[10px] opacity-80 mt-0.5">Forwards calls to customer testbed</p>
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </SpotlightCard>

            {/* Attack categories */}
            <SpotlightCard className="p-5">
              <p className="mb-3 text-[var(--text-xs)] font-medium font-mono uppercase tracking-wider text-[var(--text-muted)]">
                Attack categories
              </p>
              <div className="grid gap-2.5 sm:grid-cols-2">
                {CATEGORIES.map((cat) => {
                  const on = categories.has(cat.id);
                  return (
                    <button
                      key={cat.id}
                      type="button"
                      onClick={() => toggleCategory(cat.id)}
                      aria-pressed={on}
                      className={`flex items-start gap-3 rounded-[var(--radius-input)] border p-3 text-left transition-colors
                        ${on
                          ? "border-teal-500/40 bg-teal-950/20"
                          : "border-[var(--border-hairline)] bg-[var(--bg-raised)] hover:border-[var(--border-subtle)]"
                        }`}
                    >
                      <span
                        className={`mt-0.5 flex h-4 w-4 flex-shrink-0 items-center justify-center rounded border
                          ${on ? "border-teal-400 bg-teal-400" : "border-[var(--border-subtle)]"}`}
                        aria-hidden
                      >
                        {on && (
                          <svg viewBox="0 0 10 8" fill="none" className="w-2.5" stroke="#0A0D12" strokeWidth={2}>
                            <polyline points="1,4 3.5,7 9,1"/>
                          </svg>
                        )}
                      </span>
                      <div>
                        <p className={`text-xs font-semibold ${on ? "text-[var(--text-primary)]" : "text-[var(--text-secondary)]"}`}>
                          {cat.label}
                        </p>
                        <p className="text-[11px] text-[var(--text-muted)] mt-0.5">{cat.desc}</p>
                      </div>
                    </button>
                  );
                })}
              </div>
            </SpotlightCard>

            {/* Attempts per attack */}
            <SpotlightCard className="p-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium font-mono uppercase tracking-wider text-[var(--text-primary)]">
                    Attempts per attack case
                  </p>
                  <p className="text-xs text-[var(--text-muted)] font-mono mt-0.5">
                    Determines trial repetitions for flakiness detection
                  </p>
                </div>
                <div className="inline-flex rounded-md border border-[var(--border-hairline)] bg-[var(--bg-base)] p-0.5 font-mono text-xs">
                  {([1, 2] as const).map((n) => (
                    <button
                      key={n}
                      type="button"
                      onClick={() => setAttempts(n)}
                      className={`px-4 py-1 rounded transition-colors ${
                        attempts === n
                          ? "bg-[var(--accent)] text-[#0A0D12] font-semibold"
                          : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
                      }`}
                    >
                      {n} {n === 1 ? "trial" : "trials"}
                    </button>
                  ))}
                </div>
              </div>
            </SpotlightCard>

            {/* Switches */}
            <SpotlightCard className="p-5 space-y-3">
              <p className="text-xs font-medium font-mono uppercase tracking-wider text-[var(--text-muted)]">
                Runtime Options
              </p>
              <div className="space-y-3 font-mono text-xs">
                {[
                  { label: "Adversarial Mutation", sub: "Attacker tries mutation variant if trial fails", value: mutation, set: setMutation },
                  { label: "Benign Suite Non-Regression", sub: "Run 10 standard shopping queries to verify utility is preserved", value: benign, set: setBenign },
                ].map(({ label, sub, value, set }) => (
                  <label key={label} className="flex cursor-pointer items-center justify-between gap-4 p-2 rounded hover:bg-[var(--bg-raised)] transition-colors">
                    <div>
                      <p className="text-[var(--text-primary)] font-medium">{label}</p>
                      <p className="text-[10px] text-[var(--text-muted)]">{sub}</p>
                    </div>
                    <input
                      type="checkbox"
                      checked={value}
                      onChange={(e) => set(e.target.checked)}
                      className="h-4 w-4 accent-teal-400 rounded cursor-pointer"
                    />
                  </label>
                ))}
              </div>
            </SpotlightCard>
          </div>

          {/* ── Right column: Authorization & Consent ─────────────────── */}
          <div className="space-y-5">
            {/* Authorization Panel */}
            <SpotlightCard className="p-5 space-y-4 border border-teal-500/25">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-[var(--accent)]" />
                <p className="text-xs font-mono font-semibold uppercase tracking-wider text-[var(--text-primary)]">
                  Authorization & Governance
                </p>
              </div>

              <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                {targetType === "demo"
                  ? "You are scanning the local sandboxed ShopHelper fixture. No real-world networks or production resources are contacted."
                  : `Target: ${customTargetId} at ${customEndpoint}. Ensure you own this endpoint and have staging isolation enabled.`}
              </p>

              {/* Consent checkbox */}
              <label className="flex items-start gap-3 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-base)] p-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={consent}
                  onChange={(e) => setConsent(e.target.checked)}
                  className="mt-0.5 h-4 w-4 accent-teal-400 rounded cursor-pointer"
                />
                <span className="text-xs text-[var(--text-primary)] leading-snug">
                  I own or have explicit authorization to execute bounded security testing against this target.
                </span>
              </label>

              {/* Scope notice */}
              <div className="rounded border border-amber-900/30 bg-amber-950/20 p-3 text-[11px] font-mono text-amber-300/80 leading-relaxed">
                Approval changes only the sandboxed session prompt and temporary policy candidate. Nothing is auto-deployed to production.
              </div>

              {/* Start Button */}
              <button
                type="button"
                onClick={handleStart}
                disabled={!consent || starting}
                className="w-full rounded-lg bg-[var(--accent)] py-3 text-xs font-bold font-mono text-[#0A0D12] hover:brightness-110 disabled:opacity-35 disabled:cursor-not-allowed shadow-md transition-all flex items-center justify-center gap-2"
              >
                <Play className="h-4 w-4 fill-[#0A0D12]" />
                {starting ? "Initializing Bounded Agents..." : "Start Security Scan →"}
              </button>
            </SpotlightCard>

            {/* Agent Roster Preview */}
            <SpotlightCard className="p-4 space-y-3">
              <div className="flex items-center justify-between border-b border-[var(--border-hairline)] pb-2 text-xs font-mono">
                <span className="text-[var(--text-muted)] uppercase">Agent Roster</span>
                <span className="text-teal-400 text-[10px]">5 Bounded Agents</span>
              </div>
              <ul className="space-y-2 text-xs font-mono">
                {AGENT_ROSTER.map((agent) => (
                  <li key={agent.name} className="flex items-center justify-between">
                    <span className="text-[var(--text-secondary)]">{agent.name}</span>
                    <span className="text-[10px] text-[var(--text-muted)]">{agent.desc}</span>
                  </li>
                ))}
              </ul>
            </SpotlightCard>

            {/* Budget summary */}
            <div className="rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-4 font-mono text-xs space-y-2">
              <div className="flex items-center justify-between text-[10px] text-[var(--text-muted)] uppercase">
                <span>Budget Boundary</span>
                <span>Hard Capped</span>
              </div>
              <div className="flex items-center justify-between text-[var(--text-secondary)]">
                <span>Max Attacks:</span>
                <span className="text-[var(--text-primary)] font-semibold">{maxAttacks} cases</span>
              </div>
              <div className="flex items-center justify-between text-[var(--text-secondary)]">
                <span>Est. Model Calls:</span>
                <span className="text-[var(--text-primary)] font-semibold">{modelCalls} calls</span>
              </div>
              <div className="flex items-center justify-between text-[var(--text-secondary)]">
                <span>Est. Duration:</span>
                <span className="text-[var(--text-primary)] font-semibold">~{timeEstimate}s</span>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
