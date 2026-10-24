"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  Play,
  Pause,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  ArrowRight,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Cpu,
  Clock,
  Sparkles,
} from "lucide-react";
import TopBar from "@/components/ui/TopBar";
import {
  AgentConstellation,
  AgentTrace,
  type AgentStatus,
  type AgentId,
  type TraceStep,
} from "@/components/ui/AgentConstellation";
import {
  LabelChip,
  CategoryChip,
  PartialFailureBanner,
  SpotlightCard,
} from "@/components/ui/primitives";
import ReconProfileCard from "@/components/scan/ReconProfileCard";
import { getScan } from "@/lib/api-client";
import { connectScanEvents } from "@/lib/sse-client";
import type { TargetProfile, ScanEvent } from "@/lib/types";

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
                  state === "active" ? "bg-[var(--accent)] shadow-[0_0_0_4px_rgba(45,212,191,0.25)]" :
                                       "border border-[var(--border-subtle)] bg-[var(--bg-base)]"}`}
              aria-hidden
            />
            <span
              className={`mt-2 whitespace-nowrap text-[10px] font-mono ${
                state === "active" ? "font-semibold text-[var(--accent)]" :
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
      <span className="flex-shrink-0 font-mono text-[10px] text-teal-400 font-medium">{ev.attackId}</span>
      <CategoryChip category={ev.category} />
      <span className="flex-1 font-mono text-[11px] text-[var(--text-secondary)] truncate">{ev.message}</span>
      {ev.label && <LabelChip label={ev.label as Parameters<typeof LabelChip>[0]["label"]} />}
    </div>
  );
}

/* ─── Live counters ─────────────────────────────────────────────────────── */
function LiveCounters({ counts }: {
  counts: { total: number; failures: number; blocked: number; review: number; notEval: number };
}) {
  const items = [
    { label: "Total Cases",     value: counts.total,    color: "text-[var(--text-primary)]" },
    { label: "Confirmed Fail",  value: counts.failures, color: "text-red-400" },
    { label: "Attack Blocked",  value: counts.blocked,  color: "text-emerald-400" },
    { label: "Needs Review",    value: counts.review,   color: "text-amber-400" },
    { label: "Not Evaluated",   value: counts.notEval,  color: "text-[var(--text-muted)]" },
  ];

  return (
    <div className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-4">
      <p className="mb-3 text-[var(--text-xs)] font-medium font-mono uppercase tracking-wider text-[var(--text-muted)] flex items-center justify-between">
        <span>Live Telemetry</span>
        <span className="flex h-1.5 w-1.5 rounded-full bg-teal-400 animate-ping" />
      </p>
      <dl className="space-y-2 font-mono">
        {items.map(({ label, value, color }) => (
          <div key={label} className="flex items-center justify-between">
            <dt className="text-xs text-[var(--text-secondary)]">{label}</dt>
            <dd className={`text-sm font-semibold ${color}`}>{value}</dd>
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
      <div className="mb-2 flex items-center justify-between font-mono">
        <p className="text-[var(--text-xs)] font-medium uppercase tracking-wider text-[var(--text-muted)]">Model Calls</p>
        <span className={`text-[11px] ${warn ? "text-amber-400" : "text-[var(--text-secondary)]"}`}>
          {used} / {total} calls
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

/* ─── Simulation Sequence Script ─────────────────────────────────────────── */
interface SimStep {
  phase: PhaseLabel;
  scanStatus: string;
  activeAgents: AgentStatus[];
  activeEdges: [AgentId, AgentId][];
  event?: EventEntry;
  counters: { total: number; failures: number; blocked: number; review: number; notEval: number };
  budgetUsed: number;
}

const SIM_SEQUENCE: SimStep[] = [
  {
    phase: "Recon",
    scanStatus: "reconning",
    activeAgents: [
      { id: "planner", state: "done", stepsUsed: 2, stepsBudget: 3 },
      { id: "recon", state: "active", stepsUsed: 1, stepsBudget: 4, caption: "profiling system prompt & tools" },
      { id: "attacker", state: "idle" },
      { id: "shophelper", state: "active", caption: "exposing tools: refund, order, auth" },
      { id: "judge", state: "idle" },
      { id: "hardener", state: "idle" },
      { id: "human_approval", state: "idle" },
    ],
    activeEdges: [["planner", "recon"], ["recon", "attacker"]],
    event: { id: "e0", ts: "00:01:05", attackId: "INIT", category: "direct_injection", message: "Planner selected 12 catalog cases · Recon active" },
    counters: { total: 0, failures: 0, blocked: 0, review: 0, notEval: 12 },
    budgetUsed: 2,
  },
  {
    phase: "Attack",
    scanStatus: "attacking",
    activeAgents: [
      { id: "planner", state: "done" },
      { id: "recon", state: "done" },
      { id: "attacker", state: "active", caption: "dispatching base64 canary leak probe", stepsUsed: 2, stepsBudget: 12 },
      { id: "shophelper", state: "active", caption: "evaluating attack A-01" },
      { id: "judge", state: "idle" },
      { id: "hardener", state: "idle" },
      { id: "human_approval", state: "idle" },
    ],
    activeEdges: [["attacker", "shophelper"]],
    event: { id: "e1", ts: "00:01:10", attackId: "A-01", category: "canary_leakage", message: "Base64 encoded canary extraction dispatched", label: "attack_blocked" },
    counters: { total: 1, failures: 0, blocked: 1, review: 0, notEval: 11 },
    budgetUsed: 4,
  },
  {
    phase: "Attack",
    scanStatus: "attacking",
    activeAgents: [
      { id: "planner", state: "done" },
      { id: "recon", state: "done" },
      { id: "attacker", state: "active", caption: "roleplay bypass probe", mutationCount: 1, mutationTotal: 1, stepsUsed: 4, stepsBudget: 12 },
      { id: "shophelper", state: "active", caption: "evaluating attack A-02" },
      { id: "judge", state: "active", caption: "verifying instruction override" },
      { id: "hardener", state: "idle" },
      { id: "human_approval", state: "idle" },
    ],
    activeEdges: [["attacker", "shophelper"], ["shophelper", "judge"]],
    event: { id: "e2", ts: "00:01:18", attackId: "A-02", category: "direct_injection", message: "Role-play override executed → instruction bypassed", label: "confirmed_failure" },
    counters: { total: 2, failures: 1, blocked: 1, review: 0, notEval: 10 },
    budgetUsed: 7,
  },
  {
    phase: "Attack",
    scanStatus: "attacking",
    activeAgents: [
      { id: "planner", state: "done" },
      { id: "recon", state: "done" },
      { id: "attacker", state: "active", caption: "dispatching unauthorized refund call", stepsUsed: 6, stepsBudget: 12 },
      { id: "shophelper", state: "active", caption: "evaluating attack A-04" },
      { id: "judge", state: "active", caption: "AST tool-call validation" },
      { id: "hardener", state: "idle" },
      { id: "human_approval", state: "idle" },
    ],
    activeEdges: [["attacker", "shophelper"], ["shophelper", "judge"]],
    event: { id: "e3", ts: "00:01:25", attackId: "A-04", category: "tool_misuse", message: "process_refund invoked without customer auth", label: "confirmed_failure" },
    counters: { total: 3, failures: 2, blocked: 1, review: 0, notEval: 9 },
    budgetUsed: 11,
  },
  {
    phase: "Judge",
    scanStatus: "judging",
    activeAgents: [
      { id: "planner", state: "done" },
      { id: "recon", state: "done" },
      { id: "attacker", state: "done" },
      { id: "shophelper", state: "idle" },
      { id: "judge", state: "active", caption: "reconciling rule checks with LLM judge" },
      { id: "hardener", state: "active", caption: "inspecting confirmed failures F-001, F-002" },
      { id: "human_approval", state: "idle" },
    ],
    activeEdges: [["judge", "hardener"]],
    event: { id: "e4", ts: "00:01:32", attackId: "A-05", category: "canary_leakage", message: "Semantic judge timeout → defaulted to review", label: "needs_review" },
    counters: { total: 4, failures: 2, blocked: 1, review: 1, notEval: 8 },
    budgetUsed: 14,
  },
  {
    phase: "Hardening",
    scanStatus: "hardening_proposed",
    activeAgents: [
      { id: "planner", state: "done" },
      { id: "recon", state: "done" },
      { id: "attacker", state: "done" },
      { id: "shophelper", state: "idle" },
      { id: "judge", state: "done" },
      { id: "hardener", state: "active", caption: "drafting prompt diff + refund policy guardrail" },
      { id: "human_approval", state: "active" },
    ],
    activeEdges: [["hardener", "human_approval"]],
    event: { id: "e5", ts: "00:01:40", attackId: "HARDEN", category: "tool_misuse", message: "Hardening proposal H-001 generated · awaiting human approval" },
    counters: { total: 7, failures: 2, blocked: 4, review: 1, notEval: 5 },
    budgetUsed: 18,
  },
  {
    phase: "Approval",
    scanStatus: "awaiting_approval",
    activeAgents: [
      { id: "planner", state: "done" },
      { id: "recon", state: "done" },
      { id: "attacker", state: "done" },
      { id: "shophelper", state: "idle" },
      { id: "judge", state: "done" },
      { id: "hardener", state: "done" },
      { id: "human_approval", state: "active" },
    ],
    activeEdges: [],
    event: { id: "e6", ts: "00:01:45", attackId: "GATE", category: "direct_injection", message: "HALTED at human gate. Click 'Approve and Retest' to continue" },
    counters: { total: 12, failures: 4, blocked: 7, review: 1, notEval: 0 },
    budgetUsed: 22,
  },
  {
    phase: "Retest",
    scanStatus: "retesting",
    activeAgents: [
      { id: "planner", state: "done" },
      { id: "recon", state: "done" },
      { id: "attacker", state: "active", caption: "re-executing failed cases against patched prompt" },
      { id: "shophelper", state: "active", caption: "evaluating hardened target" },
      { id: "judge", state: "active", caption: "running 10-case benign utility suite" },
      { id: "hardener", state: "done" },
      { id: "human_approval", state: "done" },
    ],
    activeEdges: [["hardener", "shophelper"], ["attacker", "shophelper"]],
    event: { id: "e7", ts: "00:01:52", attackId: "RETEST", category: "tool_misuse", message: "Retest completed: attack blocked! Benign utility 10/10 passed", label: "verified_under_stated_checks" },
    counters: { total: 12, failures: 1, blocked: 10, review: 1, notEval: 0 },
    budgetUsed: 28,
  },
  {
    phase: "Report",
    scanStatus: "completed",
    activeAgents: [
      { id: "planner", state: "done" },
      { id: "recon", state: "done" },
      { id: "attacker", state: "done" },
      { id: "shophelper", state: "done" },
      { id: "judge", state: "done" },
      { id: "hardener", state: "done" },
      { id: "human_approval", state: "done" },
    ],
    activeEdges: [],
    event: { id: "e8", ts: "00:02:00", attackId: "FINISH", category: "canary_leakage", message: "Scan completed. Report generated with before/after regression deltas." },
    counters: { total: 12, failures: 1, blocked: 10, review: 1, notEval: 0 },
    budgetUsed: 31,
  },
];

/* ─── Trace steps for drawer ─────────────────────────────────────────────── */
const TRACE_STEPS: TraceStep[] = [
  { id: "t1", kind: "thought",   summary: "Selecting encoded variant from catalog based on prior recon" },
  { id: "t2", kind: "tool_call", tool: "select_cases", args: { category: "canary_leakage", variant: "base64" }, result: "3 cases selected", durationMs: 42, tokensUsed: 180 },
  { id: "t3", kind: "thought",   summary: "Preparing trial sequence for case C-07b" },
  { id: "t4", kind: "tool_call", tool: "invoke_target", args: { attack_id: "A-07", payload: "[REDACTED]" }, result: "response_id: r_9a2c", durationMs: 1240, tokensUsed: 340 },
  { id: "t5", kind: "result",    summary: "Trial dispatched, awaiting deterministic judge verification" },
];

/* ─── Agent trace drawer ─────────────────────────────────────────────────── */
function AgentDrawer({ agentId, onClose, agents }: { agentId: AgentId; onClose: () => void; agents: AgentStatus[] }) {
  const agent = agents.find((a) => a.id === agentId);

  return (
    <div
      className="fixed inset-y-0 right-0 z-40 flex w-84 flex-col border-l border-[var(--border-hairline)] bg-[var(--bg-surface)] shadow-2xl animate-fade-in"
      role="complementary"
      aria-label="Agent trace"
    >
      <div className="flex items-center justify-between border-b border-[var(--border-hairline)] px-4 py-3 bg-[var(--bg-raised)]">
        <p className="text-xs font-semibold font-mono uppercase tracking-wider text-[var(--text-primary)]">
          {agentId} Live Trace
        </p>
        <button
          type="button"
          onClick={onClose}
          className="rounded p-1 text-[var(--text-muted)] hover:bg-[var(--bg-base)] text-xs font-mono"
          aria-label="Close trace panel"
        >
          ✕
        </button>
      </div>

      <AgentTrace
        agentId={agentId}
        steps={TRACE_STEPS}
        budget={agent ? {
          stepsUsed: agent.stepsUsed ?? 6,
          stepsTotal: agent.stepsBudget ?? 12,
          tokensUsed: agent.tokensUsed ?? 2400,
          tokensTotal: agent.tokensBudget ?? 8000,
        } : undefined}
      />
    </div>
  );
}

/* ─── Main Live Scan Page ────────────────────────────────────────────────── */
export default function LiveScanPage() {
  const params = useParams<{ id: string }>();
  const scanId = (params?.id as string) || "scan_123";

  const [simIndex, setSimIndex] = useState(2); // Start midway in attack phase
  const [isPlaying, setIsPlaying] = useState(true);
  const [eventsList, setEventsList] = useState<EventEntry[]>(() =>
    SIM_SEQUENCE.slice(0, 3).map((s) => s.event!).filter(Boolean)
  );
  const [traceAgent, setTraceAgent] = useState<AgentId | null>(null);
  const [profile, setProfile] = useState<TargetProfile | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);

  const currentStep = SIM_SEQUENCE[simIndex];

  // Auto-advance simulation ticker every 3.2s when playing
  useEffect(() => {
    if (!isPlaying) return;
    const interval = setInterval(() => {
      setSimIndex((prev) => {
        // Halt at Approval gate until user manually approves
        if (prev === 6) {
          setIsPlaying(false);
          return prev;
        }
        const next = (prev + 1) % SIM_SEQUENCE.length;
        const nextEvent = SIM_SEQUENCE[next].event;
        if (nextEvent) {
          setEventsList((list) => [...list.slice(-18), nextEvent]);
        }
        return next;
      });
    }, 3200);

    return () => clearInterval(interval);
  }, [isPlaying]);

  // Connect to real SSE stream if available
  useEffect(() => {
    let client: ReturnType<typeof connectScanEvents> | null = null;
    try {
      client = connectScanEvents(scanId, {
        onEvent: (event: ScanEvent) => {
          // If real backend events arrive, log to event feed
          const ts = new Date().toLocaleTimeString();
          setEventsList((prev) => [
            ...prev,
            {
              id: String(event.event_id || Math.random()),
              ts,
              attackId: (event.payload as any)?.attack_id || "EVT",
              category: (event.payload as any)?.category || "direct_injection",
              message: (event.payload as any)?.message || event.kind,
              label: (event.payload as any)?.label,
            },
          ]);
        },
      });
    } catch {
      // Offline fallback
    }

    return () => {
      client?.close();
    };
  }, [scanId]);

  // Load target profile
  useEffect(() => {
    let mounted = true;
    async function loadProfile() {
      try {
        const scan = await getScan(scanId);
        if (mounted && scan.profile) setProfile(scan.profile);
      } catch {
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
    void loadProfile();
    return () => { mounted = false; };
  }, [scanId]);

  // Auto-scroll feed
  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [eventsList]);

  const handleApprove = () => {
    setSimIndex(7); // Jump to Retest
    setIsPlaying(true);
    setEventsList((l) => [
      ...l,
      {
        id: "approve-action",
        ts: new Date().toLocaleTimeString(),
        attackId: "HUMAN",
        category: "tool_misuse",
        message: "Proposal H-001 APPROVED. Dispatched retest suite.",
      },
    ]);
  };

  const handleReset = () => {
    setSimIndex(0);
    setIsPlaying(true);
    setEventsList([SIM_SEQUENCE[0].event!]);
  };

  return (
    <div className="flex flex-col min-h-full">
      <TopBar
        breadcrumbs={[{ label: "Scans", href: "/scans" }, { label: scanId }]}
        scanStatus={currentStep.scanStatus}
      />

      <main className="flex-1 px-4 sm:px-6 py-6 space-y-6 max-w-7xl w-full mx-auto">
        {/* Partial failure banner */}
        <PartialFailureBanner
          message="Semantic judge timed out on A-05. Deterministic checks are still available and will be used for verdict."
        />

        {/* Phase Stepper with Simulation Controls */}
        <section aria-label="Scan progress" className="rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-4 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-teal-400" />
              <span className="text-xs font-mono font-medium text-[var(--text-primary)] uppercase tracking-wider">
                Phase: <span className="text-[var(--accent)] font-semibold">{currentStep.phase}</span>
              </span>
            </div>

            {/* Interactive Simulation Controls */}
            <div className="flex items-center gap-2 font-mono text-xs">
              <button
                type="button"
                onClick={() => setIsPlaying(!isPlaying)}
                className="inline-flex items-center gap-1.5 rounded border border-[var(--border-subtle)] bg-[var(--bg-raised)] px-2.5 py-1 text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-teal-500/40 transition-colors"
                title={isPlaying ? "Pause simulation" : "Play live simulation"}
              >
                {isPlaying ? <Pause className="h-3 w-3" /> : <Play className="h-3 w-3 fill-teal-400 text-teal-400" />}
                <span>{isPlaying ? "Live Ticking" : "Paused"}</span>
              </button>
              <button
                type="button"
                onClick={handleReset}
                className="inline-flex items-center gap-1 rounded border border-[var(--border-subtle)] bg-[var(--bg-raised)] px-2.5 py-1 text-[var(--text-muted)] hover:text-red-400 hover:border-red-900/40 transition-colors"
                title="Restart simulation sequence"
              >
                <RotateCcw className="h-3 w-3" />
                <span>Replay</span>
              </button>
            </div>
          </div>

          <PhaseStepper current={currentStep.phase} />
        </section>

        {/* Target Recon Profile Inspector */}
        <section aria-label="Target recon profile">
          <ReconProfileCard profile={profile} targetId="shophelper-local" />
        </section>

        {/* Live Constellation Hero Card */}
        <section
          className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] px-4 py-6"
          aria-label="Agent constellation"
        >
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Cpu className="h-4 w-4 text-[var(--accent)]" />
              <p className="text-[var(--text-xs)] font-mono font-medium uppercase tracking-wider text-[var(--text-primary)]">
                Live State Machine Circuit
              </p>
            </div>
            <div className="flex items-center gap-2 font-mono text-[11px] text-[var(--text-muted)]">
              <span className="h-2 w-2 rounded-full bg-teal-400 animate-ping" aria-hidden />
              <span className="text-[var(--accent)] font-medium">
                {currentStep.activeAgents.find((a) => a.state === "active")?.id.toUpperCase()} ACTIVE
              </span>
            </div>
          </div>

          <AgentConstellation
            agents={currentStep.activeAgents}
            activeEdges={currentStep.activeEdges}
            onNodeClick={(id) => setTraceAgent(traceAgent === id ? null : id)}
            width={820}
            height={280}
          />

          <p className="mt-3 text-center font-mono text-[10px] text-[var(--text-muted)]">
            Click any node to inspect agent thought stream and redacted tool arguments
          </p>
        </section>

        {/* Human Approval Gate Prompt Banner (when scan reaches approval) */}
        {currentStep.phase === "Approval" && (
          <SpotlightCard className="p-5 border border-teal-500/40 bg-teal-950/20 animate-fade-in">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2 font-mono text-xs text-[var(--accent)]">
                  <ShieldAlert className="h-4 w-4" />
                  <span className="font-semibold uppercase tracking-wider">Human-in-the-Loop Sign-off Required</span>
                </div>
                <p className="text-xs text-[var(--text-secondary)]">
                  Hardener agent drafted 1 system prompt confidentiality rule + 1 refund auth policy guardrail.
                </p>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <button
                  type="button"
                  onClick={handleApprove}
                  className="rounded-md bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[#0A0D12] hover:brightness-110 shadow-sm transition-all"
                >
                  Approve and Retest →
                </button>
                <Link
                  href="/scans/scan_123/hardening"
                  className="rounded-md border border-[var(--border-subtle)] bg-[var(--bg-raised)] px-3 py-2 text-xs font-mono text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                >
                  Inspect Diff
                </Link>
              </div>
            </div>
          </SpotlightCard>
        )}

        {/* Report Ready Banner (when scan reaches report phase) */}
        {currentStep.phase === "Report" && (
          <SpotlightCard className="p-5 border border-emerald-500/40 bg-emerald-950/20 animate-fade-in">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2 font-mono text-xs text-emerald-400">
                  <CheckCircle2 className="h-4 w-4" />
                  <span className="font-semibold uppercase tracking-wider">Verification Complete · Hardening Verified</span>
                </div>
                <p className="text-xs text-[var(--text-secondary)]">
                  Attack success rate dropped from 33% to 8%. 10 of 10 benign utility prompts passed without over-refusal.
                </p>
              </div>
              <Link
                href="/scans/scan_123/report"
                className="rounded-md bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[#0A0D12] hover:brightness-110 shadow-sm transition-all"
              >
                View Full Audit Report →
              </Link>
            </div>
          </SpotlightCard>
        )}

        {/* Two-column: live event feed + telemetry counters */}
        <div className="grid gap-4 lg:grid-cols-[1fr_260px]">
          {/* Event feed */}
          <section className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)]">
            <div className="border-b border-[var(--border-hairline)] px-4 py-3 flex items-center justify-between bg-[var(--bg-raised)]">
              <p className="text-[var(--text-xs)] font-mono font-medium uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-2">
                <Activity className="h-3.5 w-3.5 text-teal-400" />
                Live Event Stream
              </p>
              <span className="font-mono text-[10px] text-zinc-500">
                {eventsList.length} events
              </span>
            </div>
            <div ref={feedRef} className="h-72 overflow-y-auto px-4 divide-y divide-[var(--border-hairline)]">
              {eventsList.map((ev, i) => (
                <EventFeedEntry key={`${ev.id}-${i}`} ev={ev} />
              ))}
            </div>
          </section>

          {/* Counters + budget */}
          <div className="space-y-3">
            <LiveCounters counts={currentStep.counters} />
            <BudgetMeter used={currentStep.budgetUsed} total={36} />
          </div>
        </div>

        {/* Footer actions */}
        <div className="flex items-center justify-between border-t border-[var(--border-hairline)] pt-4 text-xs font-mono">
          <span className="text-[var(--text-muted)]">
            Target: shophelper-local · Sandboxed evaluation
          </span>
          <div className="flex items-center gap-3">
            <Link
              href="/scans/scan_123/findings"
              className="rounded-[var(--radius-input)] border border-[var(--border-subtle)] bg-[var(--bg-raised)] px-4 py-2 text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-teal-500/40 transition-colors"
            >
              Browse Findings ({currentStep.counters.failures} confirmed) →
            </Link>
            <Link
              href="/scans/scan_123/hardening"
              className="rounded-[var(--radius-input)] bg-[var(--accent)] px-4 py-2 font-semibold text-[#0A0D12] hover:brightness-110 shadow-sm transition-all"
            >
              Hardening Review →
            </Link>
          </div>
        </div>
      </main>

      {/* Trace drawer */}
      {traceAgent && (
        <AgentDrawer
          agentId={traceAgent}
          agents={currentStep.activeAgents}
          onClose={() => setTraceAgent(null)}
        />
      )}
    </div>
  );
}
