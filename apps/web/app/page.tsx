"use client";

import Link from "next/link";
import {
  ShieldAlert,
  Play,
  ArrowRight,
  ShieldCheck,
  Activity,
  Terminal,
  Cpu,
  CheckCircle2,
  Lock,
  Layers,
  FileCheck,
  Sparkles,
} from "lucide-react";
import TopBar from "@/components/ui/TopBar";
import { SpotlightCard } from "@/components/ui/primitives";
import InkOrbitFeatures from "@/components/ui/ink-orbit-features";

export default function LandingPage() {
  return (
    <div className="flex flex-col min-h-full">
      <TopBar
        breadcrumbs={[{ label: "RAVEN Security" }, { label: "Overview" }]}
        showTarget={true}
      />

      <main className="flex-1 px-4 sm:px-6 lg:px-8 py-10 space-y-16 max-w-7xl w-full mx-auto">
        {/* ─── Hero Section ──────────────────────────────────────────────── */}
        <section className="text-center space-y-6 pt-6 pb-2 max-w-4xl mx-auto">
          <div className="inline-flex items-center gap-2 rounded-full border border-teal-500/30 bg-teal-950/40 px-3.5 py-1 text-xs font-mono text-[var(--accent)] shadow-xs">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-teal-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-teal-400"></span>
            </span>
            <span>BOUNDED SECURITY REGRESSION PLATFORM</span>
          </div>

          <h1 className="text-3xl sm:text-5xl lg:text-6xl font-bold tracking-tight text-[var(--text-primary)] leading-[1.12]">
            Security Regression for <br className="hidden sm:inline" />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-teal-300 via-teal-400 to-emerald-400">
              LLM Applications
            </span>
          </h1>

          <p className="text-sm sm:text-base text-[var(--text-secondary)] max-w-2xl mx-auto leading-relaxed">
            Prompt tweaks silently re-open fixed security holes. RAVEN bounds an autonomous team of AI agents to attack your app, proves which attacks succeeded with deterministic evidence, proposes guardrail diffs, and re-tests before you deploy.
          </p>

          {/* Action CTAs */}
          <div className="flex flex-wrap items-center justify-center gap-4 pt-2">
            <Link
              href="/scans/new"
              className="inline-flex items-center gap-2 rounded-lg bg-[var(--accent)] px-5 py-3 text-xs sm:text-sm font-semibold text-[#0A0D12] hover:brightness-110 shadow-md transition-all focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
            >
              <Play className="h-4 w-4 fill-[#0A0D12]" />
              Start First Scan
            </Link>
            <Link
              href="/dashboard"
              className="inline-flex items-center gap-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-raised)] px-5 py-3 text-xs sm:text-sm font-medium font-mono text-[var(--text-primary)] hover:border-[var(--accent)]/40 hover:bg-[var(--bg-surface)] transition-all"
            >
              <Activity className="h-4 w-4 text-[var(--accent)]" />
              Open Mission Control Dashboard
              <ArrowRight className="h-3.5 w-3.5 text-zinc-500" />
            </Link>
          </div>
        </section>

        {/* ─── 21st.dev Interactive Attack Architecture (Bento) ─────────── */}
        <section aria-label="Interactive Architecture Showcase" className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[var(--border-hairline)] pb-3">
            <div>
              <h2 className="text-sm font-semibold tracking-wide uppercase font-mono text-[var(--text-primary)]">
                Autonomous Attack & Verification Architecture
              </h2>
              <p className="text-xs text-[var(--text-muted)] font-mono">
                Interactive demonstration: probe vectors, deterministic reporting, and guardrail verification
              </p>
            </div>
            <span className="self-start sm:self-auto text-[10px] font-mono text-[var(--accent)] border border-teal-500/30 bg-teal-950/40 px-2.5 py-1 rounded">
              INTERACTIVE · HOVER & SCRUB
            </span>
          </div>

          <InkOrbitFeatures
            theme="dark"
            brand="RAVEN Hub"
            tag="Architecture Showcase"
            title="Bounded *Multi-Agent* Attack Simulation"
            collaboration={{
              title: "Autonomous Red-Team Vectors",
              description: "Attacker and Recon agents dispatch prompt injections, canary extraction, and tool-abuse payloads to test boundaries.",
            }}
            reports={{
              title: "Deterministic Verification Reports",
              description: "Every attack run produces verifiable evidence: canary token leaks, unauthorized refunds, and diff proposals.",
            }}
            integrations={{
              title: "Target Tool Sandbox Policy",
              description: "Intercepts and evaluates LLM tool-calling policies on ShopHelper (process_refund, lookup_order, verify_auth, get_catalog).",
              tools: ["Refund", "Order", "Auth", "Catalog"],
            }}
            insights={{
              title: "Regression & Utility Frontier",
              description: "Scans compare attack failure rate against benign utility pass rate to ensure security without over-refusal.",
              values: [33, 31, 28, 25, 20, 16, 14, 12, 10, 8, 8, 8],
              forecastFrom: 8,
            }}
          />
        </section>

        {/* ─── Feature Pillars (Bento Grid) ─────────────────────────────── */}
        <section aria-label="Core Capabilities" className="grid grid-cols-1 md:grid-cols-3 gap-5">
          <SpotlightCard className="p-6 space-y-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-teal-500/20 bg-teal-950/30 text-[var(--accent)]">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <h3 className="text-base font-semibold text-[var(--text-primary)]">
              Deterministic Proof
            </h3>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
              No fuzzy evaluations or hallucinations. Attacks are verified via exact canary token extraction, unauthorized function argument inspection, and regex matching.
            </p>
            <div className="pt-2 flex items-center gap-1.5 font-mono text-[10px] text-teal-400">
              <CheckCircle2 className="h-3 w-3" />
              <span>Regex + AST Tool Tracing</span>
            </div>
          </SpotlightCard>

          <SpotlightCard className="p-6 space-y-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-teal-500/20 bg-teal-950/30 text-[var(--accent)]">
              <Lock className="h-5 w-5" />
            </div>
            <h3 className="text-base font-semibold text-[var(--text-primary)]">
              Human-in-the-Loop Gate
            </h3>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
              Zero autonomous deployment. When vulnerabilities are confirmed, the Hardener agent drafts at most one prompt diff and guardrail rule, waiting for your approval.
            </p>
            <div className="pt-2 flex items-center gap-1.5 font-mono text-[10px] text-teal-400">
              <CheckCircle2 className="h-3 w-3" />
              <span>Monaco Side-by-Side Diff</span>
            </div>
          </SpotlightCard>

          <SpotlightCard className="p-6 space-y-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-teal-500/20 bg-teal-950/30 text-[var(--accent)]">
              <FileCheck className="h-5 w-5" />
            </div>
            <h3 className="text-base font-semibold text-[var(--text-primary)]">
              Utility Non-Regression
            </h3>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
              Fixes that over-refuse customer queries are useless. Retesting simultaneously runs our 10-case Benign Suite to guarantee 100% legitimate utility preservation.
            </p>
            <div className="pt-2 flex items-center gap-1.5 font-mono text-[10px] text-teal-400">
              <CheckCircle2 className="h-3 w-3" />
              <span>10/10 Benign Pass Guarantee</span>
            </div>
          </SpotlightCard>
        </section>

        {/* ─── Start Now Section (Conversion Banner to Dashboard) ────────── */}
        <section aria-label="Start Now" className="pt-4">
          <SpotlightCard className="p-8 sm:p-10 border border-teal-500/30 bg-gradient-to-b from-[#11151C] to-[#0D1219]">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-8">
              <div className="space-y-3 max-w-2xl">
                <div className="flex items-center gap-2">
                  <span className="flex h-2 w-2 rounded-full bg-teal-400" />
                  <span className="text-[11px] font-mono tracking-wider uppercase text-teal-400">
                    Ready to Test Your LLM Application
                  </span>
                </div>
                <h2 className="text-2xl sm:text-3xl font-semibold tracking-tight text-[var(--text-primary)]">
                  Launch Your First Security Regression Scan
                </h2>
                <p className="text-xs sm:text-sm text-[var(--text-secondary)] leading-relaxed">
                  Evaluate the sandboxed <span className="text-teal-300 font-mono">shophelper-local</span> target against prompt injection, canary leakage, sensitive data probing, and tool misuse in less than 60 seconds.
                </p>

                <div className="flex flex-wrap items-center gap-4 pt-2 text-xs font-mono text-[var(--text-muted)]">
                  <span className="flex items-center gap-1.5 text-zinc-300">
                    <CheckCircle2 className="h-3.5 w-3.5 text-teal-400" /> 12 Attack Cases
                  </span>
                  <span className="flex items-center gap-1.5 text-zinc-300">
                    <CheckCircle2 className="h-3.5 w-3.5 text-teal-400" /> 5 Bounded Agents
                  </span>
                  <span className="flex items-center gap-1.5 text-zinc-300">
                    <CheckCircle2 className="h-3.5 w-3.5 text-teal-400" /> SARIF + PDF Reports
                  </span>
                </div>
              </div>

              <div className="flex flex-col sm:flex-row lg:flex-col gap-3 flex-shrink-0">
                <Link
                  href="/dashboard"
                  className="inline-flex items-center justify-center gap-2 rounded-lg bg-[var(--accent)] px-6 py-3.5 text-xs sm:text-sm font-semibold text-[#0A0D12] hover:brightness-110 shadow-lg transition-all"
                >
                  <Activity className="h-4 w-4" />
                  Go to Operations Dashboard
                </Link>
                <Link
                  href="/scans/new"
                  className="inline-flex items-center justify-center gap-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-raised)] px-6 py-3 text-xs sm:text-sm font-mono text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--accent)]/40 transition-colors"
                >
                  <Play className="h-3.5 w-3.5 text-teal-400" />
                  Configure New Scan
                </Link>
              </div>
            </div>
          </SpotlightCard>
        </section>
      </main>
    </div>
  );
}
