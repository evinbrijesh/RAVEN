"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import TopBar from "@/components/ui/TopBar";
import { AgentConstellation, AgentTrace, type AgentStatus, type AgentId, type TraceStep } from "@/components/ui/AgentConstellation";
import { LabelChip, CategoryChip, PartialFailureBanner } from "@/components/ui/primitives";
import ReconProfileCard from "@/components/scan/ReconProfileCard";
import { getScan } from "@/lib/api-client";
import type { TargetProfile } from "@/lib/types";

/* ─── Phase stepper ──────────────────────────────────────────────────────── */
const PHASES = ["Recon", "Attack", "Judge", "Hardening", "Approval", "Retest", "Report"] as const;
type PhaseLabel = typeof PHASES[number];

function PhaseStepper({ current }: { current: PhaseLabel }) {
  const currentIdx = PHASES.indexOf(current);

  return (
    <div className="relative flex items-center" role="list" aria-label="Scan phases">
      {/* Base line */}
      <div className="absolute inset-y-1/2 left-0 right-0 h-px bg-[var(--border-hairline)]" aria-hidden />

      {/* Teal progress line */}
      <div
        className="absolute inset-y-1/2 left-0 h-px bg-[var(--accent)] transition-all duration-700"
        style={{ width: `${(currentIdx / (PHASES.length - 1)) * 100}%` }}
        aria-hidden
      />

      {PHASES.map((phase, i) => {
        const state = i < currentIdx ? "done" : i === currentIdx ? "active" : "pending";
        return (
          <div
            key={phase}
            role="listitem"
            className="relative flex flex-1 flex-col items-center"
            aria-current={state === "active" ? "step" : undefined}
          >
            <div
              className={`z-10 h-2 w-2 rounded-full transition-all duration-300
                ${state === "done"   ? "bg-[var(--accent)]" :
                  state === "active" ? "bg-[var(--accent)] animate-breathe shadow-[0_0_0_3px_rgba(45,212,191,0.2)]" :
                                       "border border-[var(--border-subtle)] bg-[var(--bg-base)]"}`}
              aria-hidden
            />
            <span
              className={`mt-2 whitespace-nowrap text-[10px] ${
                state === "active" ? "font-medium text-[var(--accent)]" :
                state === "done"   ? "text-[var(--text-secondary)]" :
                                     "text-[var(--text-muted)]"
              }`}
            >
              {phase}
            </span>
          </div>
        );
      })}
    </div>
  );
}

/* ─── Live event feed entry ──────────────────────────────────────────────── */
interface EventEntry {
  id: string;
  ts: string;
  attackId: string;
  category: string;
  label?: string;
  message: string;
}

function EventFeedEntry({ ev }: { ev: EventEntry }) {
  return (
    <div className="animate-fade-in flex items-baseline gap-3 border-b border-[var(--border-hairline)] py-2 last:border-none">
      <span className="flex-shrink-0 font-mono text-[10px] text-[var(--text-muted)]">{ev.ts}</span>
      <span className="flex-shrink-0 font-mono text-[10px] text-[var(--text-secondary)]">{ev.attackId}</span>
      <CategoryChip category={ev.category} />
      <span className="flex-1 font-mono text-[11px] text-[var(--text-secondary)]">{ev.message}</span>
      {ev.label && <LabelChip label={ev.label as Parameters<typeof LabelChip>[0]["label"]} />}
    </div>
  );
}

/* ─── Live counters ─────────────────────────────────────────────────────── */
function LiveCounters({ counts }: {
  counts: { total: number; failures: number; blocked: number; review: number; notEval: number };
}) {
  const items = [
    { label: "Total",           value: counts.total,    color: "text-[var(--text-primary)]" },
    { label: "Confirmed fail",  value: counts.failures, color: "text-red-400" },
    { label: "Blocked",         value: counts.blocked,  color: "text-green-400" },
    { label: "Needs review",    value: counts.review,   color: "text-amber-400" },
    { label: "Not evaluated",   value: counts.notEval,  color: "text-[var(--text-muted)]" },
  ];

  return (
    <div className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-4">
      <p className="mb-3 text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)]">
        Live counters
      </p>
      <dl className="space-y-2">
        {items.map(({ label, value, color }) => (
          <div key={label} className="flex items-center justify-between">
            <dt className="text-[var(--text-xs)] text-[var(--text-secondary)]">{label}</dt>
            <dd className={`font-mono text-[var(--text-sm)] font-semibold ${color}`}>{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

/* ─── Budget meter ──────────────────────────────────────────────────────── */
function BudgetMeter({ used, total }: { used: number; total: number }) {
  const pct = Math.min(1, used / total);
  const warn = pct > 0.8;
  return (
    <div className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-4">
      <div className="mb-2 flex items-center justify-between">
        <p className="text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)]">Budget</p>
        <span className={`font-mono text-[11px] ${warn ? "text-amber-400" : "text-[var(--text-secondary)]"}`}>
          {used} / {total} model calls
        </span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-[var(--bg-raised)]" role="meter" aria-valuenow={used} aria-valuemin={0} aria-valuemax={total} aria-label="Budget">
        <div
          className={`h-full rounded-full transition-all duration-500 ${warn ? "bg-amber-500" : "bg-[var(--accent)]"}`}
          style={{ width: `${pct * 100}%` }}
        />
      </div>
    </div>
  );
}

/* ─── Sample data ─────────────────────────────────────────────────────────── */
const DEMO_AGENTS: AgentStatus[] = [
  { id: "planner",       state: "done",   stepsUsed: 2, stepsBudget: 3, tokensUsed: 1200, tokensBudget: 4000 },
  { id: "recon",         state: "done",   stepsUsed: 3, stepsBudget: 4, tokensUsed: 2100, tokensBudget: 4000 },
  { id: "attacker",      state: "active", stepsUsed: 6, stepsBudget: 12, tokensUsed: 3800, tokensBudget: 8000,
    caption: "trying encoded canary request", mutationCount: 1, mutationTotal: 1 },
  { id: "judge",         state: "idle",   stepsUsed: 0, stepsBudget: 12, tokensUsed: 0, tokensBudget: 8000 },
  { id: "hardener",      state: "idle",   stepsUsed: 0, stepsBudget: 6, tokensUsed: 0, tokensBudget: 4000 },
  { id: "human_approval",state: "idle" },
  { id: "shophelper",    state: "active", caption: "evaluating attack A-07" },
];

const ACTIVE_EDGES: [AgentId, AgentId][] = [["attacker", "shophelper"]];

const EVENTS: EventEntry[] = [
  { id: "e1", ts: "23:41:02", attackId: "A-01", category: "canary_leakage", message: "attack dispatched → 3 trials", label: "attack_blocked" },
  { id: "e2", ts: "23:41:08", attackId: "A-02", category: "direct_injection", message: "attack dispatched → 3 trials", label: "confirmed_failure" },
  { id: "e3", ts: "23:41:15", attackId: "A-03", category: "sensitive_data", message: "attack dispatched → 2 trials", label: "attack_blocked" },
  { id: "e4", ts: "23:41:22", attackId: "A-04", category: "tool_misuse", message: "attack dispatched → 3 trials", label: "confirmed_failure" },
  { id: "e5", ts: "23:41:30", attackId: "A-05", category: "canary_leakage", message: "mutation variant dispatched", label: "needs_review" },
  { id: "e6", ts: "23:41:38", attackId: "A-06", category: "direct_injection", message: "attack dispatched → 1 trial" },
  { id: "e7", ts: "23:41:44", attackId: "A-07", category: "canary_leakage", message: "running…" },
];

const TRACE_STEPS: TraceStep[] = [
  { id: "t1", kind: "thought",   summary: "Selecting encoded variant from catalog based on prior recon" },
  { id: "t2", kind: "tool_call", tool: "select_cases", args: { category: "canary_leakage", variant: "base64" }, result: "3 cases selected", durationMs: 42, tokensUsed: 180 },
  { id: "t3", kind: "thought",   summary: "Preparing trial sequence for case C-07b" },
  { id: "t4", kind: "tool_call", tool: "invoke_target", args: { attack_id: "A-07", payload: "[REDACTED]" }, result: "response_id: r_9a2c", durationMs: 1240, tokensUsed: 340 },
  { id: "t5", kind: "result",    summary: "Trial 1/3 dispatched, awaiting judge verdict" },
];

/* ─── Agent trace drawer ─────────────────────────────────────────────────── */
function AgentDrawer({ agentId, onClose }: { agentId: AgentId; onClose: () => void }) {
  const agent = DEMO_AGENTS.find((a) => a.id === agentId);

  return (
    <div
      className="fixed inset-y-0 right-0 z-40 flex w-80 flex-col border-l border-[var(--border-hairline)] bg-[var(--bg-surface)] shadow-2xl"
      role="complementary"
      aria-label="Agent trace"
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[var(--border-hairline)] px-4 py-3">
        <p className="text-[var(--text-sm)] font-semibold">Agent trace</p>
        <button
          type="button"
          onClick={onClose}
          className="rounded p-1 text-[var(--text-muted)] hover:bg-[var(--bg-raised)]"
          aria-label="Close trace panel"
        >
          ✕
        </button>
      </div>

      <AgentTrace
        agentId={agentId}
        steps={TRACE_STEPS}
        budget={agent ? {
          stepsUsed: agent.stepsUsed ?? 0,
          stepsTotal: agent.stepsBudget ?? 12,
          tokensUsed: agent.tokensUsed ?? 0,
          tokensTotal: agent.tokensBudget ?? 8000,
        } : undefined}
      />
    </div>
  );
}

/* ─── Main screen ─────────────────────────────────────────────────────────── */
export default function LiveScanPage() {
  const params = useParams<{ id: string }>();
  const scanId = (params?.id as string) || "scan_123";
  const [traceAgent, setTraceAgent] = useState<AgentId | null>(null);
  const [profile, setProfile] = useState<TargetProfile | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let mounted = true;
    async function loadScanProfile() {
      try {
        const scan = await getScan(scanId);
        if (mounted && scan.profile) {
          setProfile(scan.profile);
        }
      } catch {
        // Fallback for demo scan_123 preview
        if (mounted) {
          setProfile({
            target_id: "shophelper-local",
            version: "v1.2-sandbox",
            system_prompt_hash: "3a8f9c1b7e4d2085fe7b6d194c5029a738491c2b5d6e7f8a90123456789abcdef",
            tools: ["lookup_order", "check_inventory", "issue_refund"],
            canary_token: "RAVEN-CANARY-DEMO",
            notes: ["Isolated ShopHelper fixture runtime", "Deterministic refund amount validation active"],
          });
        }
      }
    }
    void loadScanProfile();
    return () => {
      mounted = false;
    };
  }, [scanId]);

  // Auto-scroll feed
  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  });

  return (
    <div className="flex flex-col">
      <TopBar
        breadcrumbs={[{ label: "Scans", href: "/scans" }, { label: scanId }]}
        scanStatus="attacking"
      />

      <main className="flex-1 px-6 py-6 space-y-6">
        {/* Partial failure banner */}
        <PartialFailureBanner
          message="Semantic judge timed out on A-05. Deterministic checks are still available and will be used for verdict."
        />

        {/* Phase stepper */}
        <section aria-label="Scan phases">
          <PhaseStepper current="Attack" />
        </section>

        {/* Target Recon Profile Inspector */}
        <section aria-label="Target recon profile">
          <ReconProfileCard profile={profile} targetId="shophelper-local" />
        </section>

        {/* Hero: Agent Constellation */}
        <section
          className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] px-4 py-6"
          aria-label="Agent constellation"
        >
          <div className="mb-3 flex items-center justify-between">
            <p className="text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)]">
              Live agent graph
            </p>
            <div className="flex items-center gap-1.5 text-[var(--text-xs)] text-[var(--text-muted)]">
              <span className="h-1.5 w-1.5 animate-breathe rounded-full bg-[var(--accent)]" aria-hidden />
              Attacker active
            </div>
          </div>
          <AgentConstellation
            agents={DEMO_AGENTS}
            activeEdges={ACTIVE_EDGES}
            onNodeClick={(id) => setTraceAgent(traceAgent === id ? null : id)}
            width={820}
            height={280}
          />
          <p className="mt-3 text-center font-mono text-[10px] text-[var(--text-muted)]">
            Click any node to open its trace
          </p>
        </section>

        {/* Two-column: event feed + counters */}
        <div className="grid gap-4 lg:grid-cols-[1fr_240px]">
          {/* Event feed */}
          <section className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)]">
            <div className="border-b border-[var(--border-hairline)] px-4 py-2.5">
              <p className="text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                Event feed
              </p>
            </div>
            <div ref={feedRef} className="h-64 overflow-y-auto px-4">
              {EVENTS.map((ev) => <EventFeedEntry key={ev.id} ev={ev} />)}
            </div>
          </section>

          {/* Counters + budget */}
          <div className="space-y-3">
            <LiveCounters
              counts={{ total: 7, failures: 2, blocked: 3, review: 1, notEval: 1 }}
            />
            <BudgetMeter used={11} total={36} />
          </div>
        </div>

        {/* Navigation to findings */}
        <div className="flex items-center justify-end gap-3 border-t border-[var(--border-hairline)] pt-4">
          <Link
            href="/scans/scan_123/findings"
            className="rounded-[var(--radius-input)] border border-[var(--border-subtle)] px-4 py-2 text-[var(--text-sm)] text-[var(--text-secondary)] hover:border-[var(--accent)]/40 hover:text-[var(--text-primary)]"
          >
            View findings →
          </Link>
        </div>
      </main>

      {/* Trace drawer */}
      {traceAgent && (
        <AgentDrawer agentId={traceAgent} onClose={() => setTraceAgent(null)} />
      )}
    </div>
  );
}
