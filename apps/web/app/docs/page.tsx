"use client";

import Link from "next/link";
import {
  BookOpen,
  Shield,
  Layers,
  Terminal,
  Cpu,
  Lock,
  CheckCircle2,
  AlertTriangle,
  Play,
  ArrowRight,
  ShieldCheck,
  FileCode2,
} from "lucide-react";
import TopBar from "@/components/ui/TopBar";
import { SpotlightCard } from "@/components/ui/primitives";

export default function DocsPage() {
  return (
    <div className="flex flex-col min-h-full">
      <TopBar
        breadcrumbs={[
          { label: "Overview", href: "/" },
          { label: "Documentation" },
        ]}
      />

      <main className="flex-1 px-4 sm:px-6 lg:px-8 py-8 space-y-12 max-w-5xl w-full mx-auto font-mono">
        {/* Header */}
        <div className="border-b border-[var(--border-hairline)] pb-6 space-y-2">
          <div className="flex items-center gap-2">
            <BookOpen className="h-4 w-4 text-teal-400" />
            <span className="text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
              Architecture & Runbook
            </span>
            <span className="text-[9px] text-teal-400 bg-teal-950/60 border border-teal-800/40 px-2 py-0.5 rounded">
              v0.1.0
            </span>
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-[var(--text-primary)]">
            RAVEN System Architecture
          </h1>
          <p className="text-sm text-[var(--text-secondary)] leading-relaxed max-w-3xl">
            Bounded, human-supervised security regression testing for agentic LLM applications.
            RAVEN autonomously attacks targets, verifies failures deterministically, proposes diffs,
            guards operator approvals against race conditions, and persists regression suites to prevent vulnerability regressions.
          </p>
        </div>

        {/* 1. Autonomous Agent Constellation */}
        <section className="space-y-4">
          <div className="flex items-center gap-2 border-b border-[var(--border-hairline)] pb-2">
            <Cpu className="h-4 w-4 text-teal-400" />
            <h2 className="text-base font-semibold text-[var(--text-primary)]">
              1. Bounded Multi-Agent Lifecycle
            </h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <SpotlightCard className="p-4 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-teal-300">Recon Agent</span>
                <span className="text-[10px] text-zinc-500">PHASE 1</span>
              </div>
              <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                Probes the target application to identify system prompt fingerprint, tools, parameter signatures, and active canary tokens.
              </p>
            </SpotlightCard>

            <SpotlightCard className="p-4 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-orange-300">Attacker Agent</span>
                <span className="text-[10px] text-zinc-500">PHASE 2</span>
              </div>
              <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                Dispatches targeted evasion attempts across 4 attack categories using adaptive prompt mutations and role-play injection payloads.
              </p>
            </SpotlightCard>

            <SpotlightCard className="p-4 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-amber-300">Dual-Judge Engine</span>
                <span className="text-[10px] text-zinc-500">PHASE 3</span>
              </div>
              <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                Combines deterministic regex/token signal checks with an LLM judge to classify verdicts (confirmed failure, attack blocked, or needs review).
              </p>
            </SpotlightCard>

            <SpotlightCard className="p-4 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-violet-300">Hardener & Gatekeeper</span>
                <span className="text-[10px] text-zinc-500">PHASE 4</span>
              </div>
              <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                Synthesizes minimal system prompt diffs and tool authorization policies. Gated behind atomic human approval with HTTP 409 concurrency guards.
              </p>
            </SpotlightCard>
          </div>
        </section>

        {/* 2. Attack Taxonomy */}
        <section className="space-y-4">
          <div className="flex items-center gap-2 border-b border-[var(--border-hairline)] pb-2">
            <Shield className="h-4 w-4 text-teal-400" />
            <h2 className="text-base font-semibold text-[var(--text-primary)]">
              2. Evaluated Threat Vectors
            </h2>
          </div>
          <div className="space-y-3 text-xs">
            <div className="rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-3 space-y-1">
              <p className="font-semibold text-teal-300">Direct Injection (OWASP LLM01)</p>
              <p className="text-[var(--text-secondary)]">
                Payloads designed to hijack control flow, override safety guidelines, or force compliance via adversarial roleplay or developer mode bypasses.
              </p>
            </div>
            <div className="rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-3 space-y-1">
              <p className="font-semibold text-teal-300">Canary Leakage (OWASP LLM06)</p>
              <p className="text-[var(--text-secondary)]">
                Probes seeking disclosure of embedded system canary tokens, revealing unredacted system prompt instructions or internal deployment configurations.
              </p>
            </div>
            <div className="rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-3 space-y-1">
              <p className="font-semibold text-teal-300">Sensitive Data & PII (OWASP LLM02)</p>
              <p className="text-[var(--text-secondary)]">
                Extraction attempts targeting customer payment details, credentials, session tokens, or unredacted personal identifiers.
              </p>
            </div>
            <div className="rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-3 space-y-1">
              <p className="font-semibold text-teal-300">Tool Misuse & Unsafe Execution (OWASP LLM08)</p>
              <p className="text-[var(--text-secondary)]">
                Coercing the assistant into executing unauthorized state-changing tool calls (such as processing refunds or changing shipping addresses without customer verification).
              </p>
            </div>
          </div>
        </section>

        {/* 3. Cryptographic Verification & Concurrency */}
        <section className="space-y-4">
          <div className="flex items-center gap-2 border-b border-[var(--border-hairline)] pb-2">
            <Lock className="h-4 w-4 text-teal-400" />
            <h2 className="text-base font-semibold text-[var(--text-primary)]">
              3. Enterprise Idempotency & Tamper-Proof Audit
            </h2>
          </div>
          <div className="rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-4 space-y-3 text-xs">
            <div>
              <p className="font-semibold text-[var(--text-primary)]">Atomic Approval Concurrency Guard (HTTP 409)</p>
              <p className="text-[var(--text-secondary)] mt-1">
                When multiple operators or automated CI triggers simultaneously click approve on hardening proposals, the control plane uses an atomic compare-and-swap transition (`status = 'awaiting_approval'`). Only the winning call initiates the retest pipeline; all racing duplicate requests return HTTP 409 Conflict.
              </p>
            </div>
            <div className="border-t border-[var(--border-hairline)] pt-3">
              <p className="font-semibold text-[var(--text-primary)]">Cryptographic SHA-256 Audit Endpoint</p>
              <p className="text-[var(--text-secondary)] mt-1">
                Auditors can query <code className="text-teal-400 bg-teal-950/40 px-1 py-0.5 rounded">GET /api/scans/:id/artifacts/:artifact_id/verify</code> to cryptographically verify that report artifacts (SARIF, JSON, Markdown) and transcripts exactly match their runtime execution digests.
              </p>
            </div>
          </div>
        </section>

        {/* Action CTAs */}
        <div className="flex items-center justify-between border-t border-[var(--border-hairline)] pt-6">
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-2 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          >
            ← Return to Dashboard
          </Link>
          <Link
            href="/scans/new"
            className="inline-flex items-center gap-2 rounded-lg bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[#0A0D12] hover:brightness-110 shadow-sm"
          >
            <Play className="h-3.5 w-3.5 fill-[#0A0D12]" />
            Launch New Scan
          </Link>
        </div>
      </main>
    </div>
  );
}
