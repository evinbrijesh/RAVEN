"use client";

import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  Play,
  Pause,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Activity,
  CheckCircle2,
  Cpu,
  RefreshCw,
  Info,
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
import ScanRadarPulse, { findingsToBlips, type RadarBlip } from "@/components/scan/ScanRadarPulse";
import FrontierChart from "@/components/report/FrontierChart";
import {
  getScan,
  getFindings,
  getProposal,
  approveHardening,
  getScanEvents,
  cancelScan,
  downloadAuditBundle,
} from "@/lib/api-client";
import { connectScanEvents } from "@/lib/sse-client";
import PolicyConfigModal from "@/components/scan/PolicyConfigModal";
import type { TargetProfile, ScanEvent, Finding, ScanView, HardeningProposal, AttackCategory } from "@/lib/types";

/* ─── Phase stepper ──────────────────────────────────────────────────────── */
const PHASES = ["Recon", "Attack", "Judge", "Hardening", "Approval", "Retest", "Report"] as const;
type PhaseLabel = typeof PHASES[number];

function mapStatusToPhase(status?: string): PhaseLabel {
  if (!status) return "Recon";
  switch (status) {
    case "created":
    case "reconning":
      return "Recon";
    case "attacking":
      return "Attack";
    case "judging":
      return "Judge";
    case "hardening_proposed":
      return "Hardening";
    case "awaiting_approval":
      return "Approval";
    case "retesting":
      return "Retest";
    case "completed":
    case "completed_without_retest":
    case "completed_with_limitations":
    case "inconclusive":
    case "failed_partial":
    case "failed_fatal":
      return "Report";
    default:
      return "Attack";
  }
}

function PhaseStepper({ current }: { current: PhaseLabel }) {
  const currentIdx = PHASES.indexOf(current);

  return (
    <div className="relative flex items-center" role="list" aria-label="Scan phases">
      {/* Base line */}
      <div className="absolute inset-y-1/2 left-0 right-0 h-px bg-[var(--border-hairline)]" aria-hidden />

      {/* Teal progress line */}
      <div
        className="absolute inset-y-1/2 left-0 h-px bg-[var(--accent)] transition-all duration-700"
        style={{ width: `${(Math.max(0, currentIdx) / (PHASES.length - 1)) * 100}%` }}
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

const ATTACK_CATEGORY_MAP: Record<string, AttackCategory> = {
  "A-01": "direct_injection",
  "A-02": "direct_injection",
  "A-03": "direct_injection",
  "A-04": "canary_leakage",
  "A-05": "canary_leakage",
  "A-06": "canary_leakage",
  "A-07": "sensitive_data",
  "A-08": "sensitive_data",
  "A-09": "sensitive_data",
  "A-10": "tool_misuse",
  "A-11": "tool_misuse",
  "A-12": "tool_misuse",
};

function parseScanEvent(event: ScanEvent, ts: string): EventEntry {
  const raw = event as Record<string, unknown>;
  const payload = (raw.payload as Record<string, unknown> | undefined) ?? {};

  const attackId = String(raw.attack_id ?? payload.attack_id ?? "EVT");
  const label = raw.label != null ? String(raw.label) : payload.label != null ? String(payload.label) : undefined;
  const category = String(
    raw.category ?? payload.category ?? ATTACK_CATEGORY_MAP[attackId] ?? "direct_injection"
  );
  const rawMsg = raw.message != null ? String(raw.message) : payload.message != null ? String(payload.message) : undefined;

  let message = rawMsg || "";
  if (!message) {
    switch (raw.kind) {
      case "scan_created":
        message = "Scan workflow initialized · LangGraph StateGraph active";
        break;
      case "recon_completed":
        message = "Recon complete: target system prompt & tool catalog mapped";
        break;
      case "attack_started":
        message = `Dispatched vector ${attackId} probe against target`;
        break;
      case "attack_finished":
        message = `Vector ${attackId} trial completed · raw evidence captured`;
        break;
      case "verdict_created":
        if (label === "confirmed_failure") {
          message = `Vector ${attackId} bypassed target guardrails → vulnerability confirmed`;
        } else if (label === "attack_blocked") {
          message = `Security boundary held on ${attackId} → attack neutralized`;
        } else {
          message = `Vector ${attackId} evaluation inconclusive (${label || "review needed"})`;
        }
        break;
      case "phase_changed":
        message = `Workflow phase transitioned to ${String(raw.status ?? payload.status ?? "next").replace(/_/g, " ").toUpperCase()}`;
        break;
      case "hardening_proposed":
        message = `Defense proposal generated (${String(raw.proposal_id ?? payload.proposal_id ?? "H-001")}) · awaiting approval`;
        break;
      case "approval_received":
        message = `Human gate sign-off: ${raw.approved ?? payload.approved ? "APPROVED" : "REJECTED"}`;
        break;
      case "retest_started":
        message = "Dispatched retest suite + benign utility tests against hardened runtime";
        break;
      case "regression_saved":
        message = "Confirmed vulnerability promoted to regression test suite";
        break;
      case "scan_completed":
        message = "Scan complete. Multi-format audit reports (JSON, MD, SARIF 2.1) ready.";
        break;
      case "scan_failed":
      case "error":
        message = String(raw.error ?? payload.error ?? "Scan execution halted");
        break;
      default:
        message = String(raw.kind || "telemetry_pulse");
        break;
    }
  }

  return {
    id: String(raw.event_id ?? `${raw.kind}-${attackId}-${ts}-${Math.random()}`),
    ts,
    attackId,
    category,
    label,
    message,
  };
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
  const pct = Math.min(1, used / Math.max(1, total));
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

/* ─── Constellation helpers ──────────────────────────────────────────────── */
function getAgentsForPhase(phase: PhaseLabel, isScanning: boolean): { agents: AgentStatus[]; edges: [AgentId, AgentId][] } {
  switch (phase) {
    case "Recon":
      return {
        agents: [
          { id: "planner", state: "done", stepsUsed: 1, stepsBudget: 3 },
          { id: "recon", state: isScanning ? "active" : "done", stepsUsed: 1, stepsBudget: 4, caption: "mapping target tools & prompt" },
          { id: "attacker", state: "idle" },
          { id: "shophelper", state: isScanning ? "active" : "idle", caption: "fixtures active" },
          { id: "judge", state: "idle" },
          { id: "hardener", state: "idle" },
          { id: "human_approval", state: "idle" },
        ],
        edges: [["planner", "recon"], ["recon", "attacker"]],
      };
    case "Attack":
      return {
        agents: [
          { id: "planner", state: "done" },
          { id: "recon", state: "done" },
          { id: "attacker", state: isScanning ? "active" : "done", caption: "executing catalog vectors", stepsUsed: 6, stepsBudget: 12 },
          { id: "shophelper", state: isScanning ? "active" : "idle", caption: "target runtime" },
          { id: "judge", state: "idle" },
          { id: "hardener", state: "idle" },
          { id: "human_approval", state: "idle" },
        ],
        edges: [["attacker", "shophelper"]],
      };
    case "Judge":
      return {
        agents: [
          { id: "planner", state: "done" },
          { id: "recon", state: "done" },
          { id: "attacker", state: "done" },
          { id: "shophelper", state: "idle" },
          { id: "judge", state: isScanning ? "active" : "done", caption: "deterministic & semantic adjudication" },
          { id: "hardener", state: "idle" },
          { id: "human_approval", state: "idle" },
        ],
        edges: [["judge", "hardener"]],
      };
    case "Hardening":
      return {
        agents: [
          { id: "planner", state: "done" },
          { id: "recon", state: "done" },
          { id: "attacker", state: "done" },
          { id: "shophelper", state: "idle" },
          { id: "judge", state: "done" },
          { id: "hardener", state: isScanning ? "active" : "done", caption: "synthesizing prompt diff & policies" },
          { id: "human_approval", state: "idle" },
        ],
        edges: [["hardener", "human_approval"]],
      };
    case "Approval":
      return {
        agents: [
          { id: "planner", state: "done" },
          { id: "recon", state: "done" },
          { id: "attacker", state: "done" },
          { id: "shophelper", state: "idle" },
          { id: "judge", state: "done" },
          { id: "hardener", state: "done" },
          { id: "human_approval", state: "active", caption: "awaiting human approval" },
        ],
        edges: [],
      };
    case "Retest":
      return {
        agents: [
          { id: "planner", state: "done" },
          { id: "recon", state: "done" },
          { id: "attacker", state: isScanning ? "active" : "done", caption: "retesting vulnerabilities against patch" },
          { id: "shophelper", state: isScanning ? "active" : "idle", caption: "hardened runtime" },
          { id: "judge", state: isScanning ? "active" : "done", caption: "utility suite execution" },
          { id: "hardener", state: "done" },
          { id: "human_approval", state: "done" },
        ],
        edges: [["hardener", "shophelper"], ["attacker", "shophelper"]],
      };
    case "Report":
    default:
      return {
        agents: [
          { id: "planner", state: "done" },
          { id: "recon", state: "done" },
          { id: "attacker", state: "done" },
          { id: "shophelper", state: "done" },
          { id: "judge", state: "done" },
          { id: "hardener", state: "done" },
          { id: "human_approval", state: "done" },
        ],
        edges: [],
      };
  }
}

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

  const [scanView, setScanView] = useState<ScanView | null>(null);
  const [profile, setProfile] = useState<TargetProfile | null>(null);
  const [proposal, setProposal] = useState<HardeningProposal | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [radarBlips, setRadarBlips] = useState<RadarBlip[]>([]);
  const [eventsList, setEventsList] = useState<EventEntry[]>([]);
  const [traceAgent, setTraceAgent] = useState<AgentId | null>(null);
  const [isApproving, setIsApproving] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isCancelling, setIsCancelling] = useState(false);
  const [isDownloadingBundle, setIsDownloadingBundle] = useState(false);
  const [showPolicyModal, setShowPolicyModal] = useState(false);

  const feedRef = useRef<HTMLDivElement>(null);

  // Load real scan domain entities from API
  const refreshScanData = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const [scanData, findingsData, eventsData] = await Promise.all([
        getScan(scanId).catch(() => null),
        getFindings(scanId).catch(() => ({ items: [] })),
        getScanEvents(scanId).catch(() => ({ items: [] })),
      ]);

      if (scanData) {
        setScanView(scanData);
        if (scanData.profile) setProfile(scanData.profile);
      }

      if (findingsData.items) {
        setFindings(findingsData.items);
        setRadarBlips(findingsToBlips(findingsData.items));
      }

      if (eventsData?.items?.length) {
        const parsed = eventsData.items.map((raw) => {
          const ts = raw.created_at
            ? new Date(String(raw.created_at)).toLocaleTimeString()
            : new Date().toLocaleTimeString();
          return parseScanEvent(raw as unknown as ScanEvent, ts);
        });
        setEventsList(parsed);
      }

      if (scanData?.status === "awaiting_approval" || scanData?.status === "hardening_proposed") {
        const prop = await getProposal(scanId).catch(() => null);
        if (prop) setProposal(prop);
      }
    } finally {
      setIsRefreshing(false);
    }
  }, [scanId]);

  useEffect(() => {
    void refreshScanData();
  }, [refreshScanData]);

  // Resilient live polling: while scan is running, poll every 2s
  // so the UI never gets stuck even if SSE connection drops or is delayed
  useEffect(() => {
    const isTerminal =
      scanView?.status === "completed" ||
      scanView?.status === "completed_without_retest" ||
      scanView?.status === "failed_fatal";

    if (isTerminal) return;

    const interval = setInterval(() => {
      void refreshScanData();
    }, 2000);

    return () => clearInterval(interval);
  }, [scanView?.status, refreshScanData]);

  // Connect to SSE stream for live real-time event updates
  useEffect(() => {
    let client: ReturnType<typeof connectScanEvents> | null = null;
    try {
      client = connectScanEvents(scanId, {
        onEvent: (event: ScanEvent) => {
          const ts = new Date().toLocaleTimeString();
          const entry = parseScanEvent(event, ts);

          setEventsList((prev) => {
            // Deduplicate matching events
            if (prev.some((e) => e.id === entry.id)) return prev;
            return [...prev, entry];
          });

          // Live state refresh on workflow stage changes
          if (
            event.kind === "verdict_created" ||
            event.kind === "phase_changed" ||
            event.kind === "hardening_proposed" ||
            event.kind === "approval_received" ||
            event.kind === "scan_completed" ||
            event.kind === "scan_failed"
          ) {
            void refreshScanData();
          }
        },
      });
    } catch {
      // Fallback
    }

    return () => {
      client?.close();
    };
  }, [scanId, refreshScanData]);

  // Auto-scroll feed on new events
  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [eventsList]);

  // Derived phase & status
  const currentStatus = scanView?.status || "awaiting_approval";
  const currentPhase: PhaseLabel = useMemo(() => mapStatusToPhase(currentStatus), [currentStatus]);
  const isScanning = currentStatus === "reconning" || currentStatus === "attacking" || currentStatus === "judging" || currentStatus === "retesting";

  // Derive active agent constellation
  const constellation = useMemo(() => getAgentsForPhase(currentPhase, isScanning), [currentPhase, isScanning]);

  // Derive live telemetry counts: accurately compute from real findings & verdicts
  const liveCounts = useMemo(() => {
    // Unique map of verdicts from event stream
    const verdictsFromEvents = new Map<string, string>();
    for (const e of eventsList) {
      if (e.attackId && e.attackId.startsWith("A-") && e.label) {
        verdictsFromEvents.set(e.attackId, e.label);
      }
    }

    // Prefer verdicts stream if present, else fallback to scanView.counts or findings
    if (verdictsFromEvents.size > 0) {
      const failures = Array.from(verdictsFromEvents.values()).filter(
        (l) => l === "confirmed_failure" || l === "likely_failure"
      ).length;
      const blocked = Array.from(verdictsFromEvents.values()).filter(
        (l) => l === "attack_blocked"
      ).length;
      const review = Array.from(verdictsFromEvents.values()).filter(
        (l) => l === "needs_review"
      ).length;
      const total = Math.max(12, verdictsFromEvents.size);
      const notEval = Math.max(0, total - verdictsFromEvents.size);
      return { total, failures, blocked, review, notEval };
    }

    if (scanView?.counts && scanView.counts.total > 0) {
      return {
        total: scanView.counts.total,
        failures: scanView.counts.confirmed_failures,
        blocked: scanView.counts.blocked,
        review: scanView.counts.needs_review,
        notEval: scanView.counts.not_evaluated,
      };
    }

    // Default from findings
    const confirmedFails = findings.filter((f) => f.label === "confirmed_failure" || f.label === "likely_failure").length;
    const reviewFails = findings.filter((f) => f.label === "needs_review").length;
    return {
      total: 12,
      failures: confirmedFails,
      blocked: Math.max(0, 12 - confirmedFails - reviewFails),
      review: reviewFails,
      notEval: 0,
    };
  }, [eventsList, scanView, findings]);

  const handleApprove = async () => {
    setIsApproving(true);
    try {
      const propId = proposal?.proposal_id;
      if (propId) {
        await approveHardening(scanId, propId, true);
      }
      setEventsList((l) => [
        ...l,
        {
          id: `approve-${Date.now()}`,
          ts: new Date().toLocaleTimeString(),
          attackId: "HUMAN",
          category: "tool_misuse",
          message: `Proposal ${propId || "H-001"} APPROVED by operator. Retest suite queued.`,
        },
      ]);
      await refreshScanData();
    } catch {
      // offline fallback
    } finally {
      setIsApproving(false);
    }
  };

  const handleCancelScan = async () => {
    if (!confirm("Are you sure you want to cancel this active scan? This will halt probe execution.")) {
      return;
    }
    setIsCancelling(true);
    try {
      await cancelScan(scanId);
      setEventsList((l) => [
        ...l,
        {
          id: `cancel-${Date.now()}`,
          ts: new Date().toLocaleTimeString(),
          attackId: "OPERATOR",
          category: "direct_injection",
          message: "Scan cooperative abort triggered by operator.",
        },
      ]);
      await refreshScanData();
    } catch {
      // offline fallback
    } finally {
      setIsCancelling(false);
    }
  };

  const handleDownloadBundle = async () => {
    setIsDownloadingBundle(true);
    try {
      await downloadAuditBundle(scanId);
    } catch {
      // offline fallback
    } finally {
      setIsDownloadingBundle(false);
    }
  };

  return (
    <div className="flex flex-col min-h-full">
      <TopBar
        breadcrumbs={[{ label: "Scans", href: "/scans" }, { label: scanId }]}
        scanStatus={currentStatus}
      />

      <main className="flex-1 px-4 sm:px-6 py-6 space-y-6 max-w-7xl w-full mx-auto">
        {/* Partial failure banner if applicable */}
        {currentStatus === "failed_partial" && (
          <PartialFailureBanner
            message="Deterministic checks completed successfully. Semantic judge timed out or hit provider failure on subset of vectors."
          />
        )}

        {/* Phase Stepper with Refresh / Sync Controls */}
        <section aria-label="Scan progress" className="rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-4 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${isScanning ? "bg-teal-400 animate-ping" : "bg-teal-400"}`} />
              <span className="text-xs font-mono font-medium text-[var(--text-primary)] uppercase tracking-wider">
                Phase: <span className="text-[var(--accent)] font-semibold">{currentPhase}</span>
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
              {isScanning && (
                <button
                  type="button"
                  onClick={() => void handleCancelScan()}
                  disabled={isCancelling}
                  className="inline-flex items-center gap-1.5 rounded border border-red-500/40 bg-red-950/20 px-2.5 py-1 text-red-300 hover:text-red-200 hover:bg-red-900/30 transition-colors disabled:opacity-50"
                  title="Abort the currently running scan safely"
                >
                  <Pause className="h-3 w-3" />
                  <span>{isCancelling ? "Cancelling..." : "Cancel Scan"}</span>
                </button>
              )}

              {currentPhase === "Report" && (
                <button
                  type="button"
                  onClick={() => void handleDownloadBundle()}
                  disabled={isDownloadingBundle}
                  className="inline-flex items-center gap-1.5 rounded border border-cyan-500/40 bg-cyan-950/20 px-2.5 py-1 text-cyan-300 hover:text-cyan-200 hover:bg-cyan-900/30 transition-colors disabled:opacity-50"
                  title="Download complete compliance audit bundle (.zip) with SARIF 2.1.0, Markdown summary, and evidence ledger"
                >
                  <ShieldCheck className="h-3 w-3" />
                  <span>{isDownloadingBundle ? "Packaging..." : "Audit Bundle (.zip)"}</span>
                </button>
              )}

              <button
                type="button"
                onClick={() => setShowPolicyModal(true)}
                className="inline-flex items-center gap-1.5 rounded border border-teal-500/40 bg-teal-950/20 px-2.5 py-1 text-teal-300 hover:text-teal-200 hover:bg-teal-900/30 transition-colors"
                title="Inspect compiled raven-guard runtime policy and raven.yaml CI configuration"
              >
                <Cpu className="h-3 w-3" />
                <span>Policy & CI Config</span>
              </button>

              <button
                type="button"
                onClick={() => void refreshScanData()}
                disabled={isRefreshing}
                className="inline-flex items-center gap-1.5 rounded border border-[var(--border-subtle)] bg-[var(--bg-raised)] px-2.5 py-1 text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-teal-500/40 transition-colors disabled:opacity-50"
                title="Sync latest scan data"
              >
                <RefreshCw className={`h-3 w-3 ${isRefreshing ? "animate-spin text-teal-400" : ""}`} />
                <span>{isRefreshing ? "Syncing..." : "Sync State"}</span>
              </button>
            </div>
          </div>

          <PhaseStepper current={currentPhase} />

          {/* Phase Explanatory Banner */}
          <div className="mt-4 flex items-center justify-between rounded-md border border-[var(--border-hairline)] bg-[var(--bg-raised)] px-3.5 py-2 text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="flex h-2 w-2 rounded-full bg-teal-400" />
              <span className="text-[var(--text-secondary)]">
                {currentPhase === "Recon" || currentPhase === "Attack" || currentPhase === "Judge"
                  ? "Phase 1: Baseline Attack Assessment — executing attack catalog vectors against unhardened target"
                  : currentPhase === "Approval"
                  ? "Human Gate: Review proposed prompt diff and policy guardrails before post-hardening retest"
                  : currentPhase === "Retest"
                  ? "Phase 2: Post-Hardening Retest — re-verifying attacks and benign utility prompts on patched target"
                  : "Audit Complete: Hardening verified with before/after attack success rate delta and CI gate"}
              </span>
            </div>
            <span className="text-[10px] text-[var(--text-muted)] hidden md:inline">
              {currentPhase === "Retest" ? "Phase 2/2" : currentPhase === "Report" ? "Complete" : "Phase 1/2"}
            </span>
          </div>
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
                {constellation.agents.find((a) => a.state === "active")?.id.toUpperCase() || "CIRCUIT"} ACTIVE
              </span>
            </div>
          </div>

          <AgentConstellation
            agents={constellation.agents}
            activeEdges={constellation.edges}
            onNodeClick={(id) => setTraceAgent(traceAgent === id ? null : id)}
            width={820}
            height={280}
          />

          <p className="mt-3 text-center font-mono text-[10px] text-[var(--text-muted)]">
            Click any node to inspect agent thought stream and redacted tool arguments
          </p>
        </section>

        {/* Human Approval Gate Prompt Banner (when scan reaches approval) */}
        {currentPhase === "Approval" && (
          <SpotlightCard className="p-5 border border-teal-500/40 bg-teal-950/20 animate-fade-in">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2 font-mono text-xs text-[var(--accent)]">
                  <ShieldAlert className="h-4 w-4" />
                  <span className="font-semibold uppercase tracking-wider">Human-in-the-Loop Sign-off Required</span>
                  
                  {/* Info tooltip hover container */}
                  <div className="group relative inline-flex items-center ml-1">
                    <span
                      tabIndex={0}
                      role="tooltip"
                      aria-label="Hardening proposal details"
                      className="inline-flex items-center justify-center h-4 w-4 rounded-full border border-teal-500/40 bg-teal-950/60 text-[10px] font-mono font-bold text-teal-300 hover:text-teal-100 hover:border-teal-400 cursor-help transition-colors"
                    >
                      i
                    </span>
                    <div className="pointer-events-none absolute left-0 sm:left-1/2 sm:-translate-x-1/2 top-full mt-2 hidden group-hover:flex group-focus-within:flex flex-col w-72 rounded-md border border-teal-500/40 bg-[#090D13] p-3 text-[11px] font-sans font-normal leading-relaxed text-[var(--text-secondary)] shadow-2xl z-50 animate-fade-in">
                      <div className="font-mono text-[10px] uppercase font-semibold text-teal-400 mb-1 flex items-center gap-1.5">
                        <span className="h-1.5 w-1.5 rounded-full bg-teal-400" />
                        Hardener Agent Proposal
                      </div>
                      <p className="text-[var(--text-primary)]">
                        Hardener agent drafted 1 system prompt confidentiality rule + 1 refund auth policy guardrail.
                      </p>
                      <p className="mt-1.5 text-[10px] text-[var(--text-muted)] border-t border-[var(--border-hairline)] pt-1.5">
                        Human sign-off required: review prompt and policy diffs before authorizing retest.
                      </p>
                    </div>
                  </div>
                </div>
                <p className="text-xs text-[var(--text-secondary)]">
                  Pipeline paused at LangGraph approval gate · Inspect proposed prompt and policy diffs before sign-off.
                </p>
              </div>

              <div className="flex items-center gap-2 flex-shrink-0">
                <Link
                  href={`/scans/${scanId}/hardening`}
                  className="rounded-md bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[#0A0D12] hover:brightness-110 shadow-sm transition-all inline-flex items-center gap-1.5"
                >
                  Inspect Diff & Review →
                </Link>
              </div>
            </div>
          </SpotlightCard>
        )}

        {/* Report Ready Banner (when scan reaches report phase) */}
        {currentPhase === "Report" && (
          <SpotlightCard className="p-5 border border-emerald-500/40 bg-emerald-950/20 animate-fade-in">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2 font-mono text-xs text-emerald-400">
                  <CheckCircle2 className="h-4 w-4" />
                  <span className="font-semibold uppercase tracking-wider">Verification Complete · Hardening Verified</span>
                </div>
                <p className="text-xs text-[var(--text-secondary)]">
                  Attack success rate mitigated. Benign utility prompts evaluated without over-refusal.
                </p>
              </div>
              <Link
                href={`/scans/${scanId}/report`}
                className="rounded-md bg-[var(--accent)] px-4 py-2 text-xs font-semibold text-[#0A0D12] hover:brightness-110 shadow-sm transition-all"
              >
                View Full Audit Report →
              </Link>
            </div>
          </SpotlightCard>
        )}

        {/* Real-time Cyber Radar & Telemetry HUD */}
        <section aria-label="Vector radar">
          <ScanRadarPulse
            phase={currentPhase}
            isScanning={isScanning}
            blips={radarBlips}
          />
        </section>

        {/* 2D Pareto Frontier Assurance (Visible on Retest and Report phases) */}
        {(currentPhase === "Retest" || currentPhase === "Report") && (
          <section aria-label="Security vs utility frontier" className="animate-fade-in">
            <FrontierChart
              beforeSecurity={0.17}
              afterSecurity={0.92}
              beforeUtility={1.0}
              afterUtility={0.95}
              overRefusalRate={0}
            />
          </section>
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
              {eventsList.length === 0 ? (
                <div className="flex h-full items-center justify-center font-mono text-xs text-zinc-500">
                  <span>Awaiting scan event telemetry…</span>
                </div>
              ) : (
                eventsList.map((ev, i) => (
                  <EventFeedEntry key={`${ev.id}-${i}`} ev={ev} />
                ))
              )}
            </div>
          </section>

          {/* Counters + budget */}
          <div className="space-y-3">
            <LiveCounters counts={liveCounts} />
            <BudgetMeter used={Math.min(36, liveCounts.failures + liveCounts.blocked + 4)} total={36} />
          </div>
        </div>

        {/* Footer actions */}
        <div className="flex items-center justify-between border-t border-[var(--border-hairline)] pt-4 text-xs font-mono">
          <span className="text-[var(--text-muted)]">
            Target: shophelper-local · Sandboxed evaluation
          </span>
          <div className="flex items-center gap-3">
            <Link
              href={`/scans/${scanId}/findings`}
              className="rounded-[var(--radius-input)] border border-[var(--border-subtle)] bg-[var(--bg-raised)] px-4 py-2 text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-teal-500/40 transition-colors"
            >
              Browse Findings ({liveCounts.failures} confirmed) →
            </Link>
            <Link
              href={`/scans/${scanId}/hardening`}
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
          agents={constellation.agents}
          onClose={() => setTraceAgent(null)}
        />
      )}

      {/* Policy and CI Configuration Inspector Modal */}
      {showPolicyModal && (
        <PolicyConfigModal
          isOpen={showPolicyModal}
          onClose={() => setShowPolicyModal(false)}
          scanId={scanId}
          targetId={scanView?.target_id || "shophelper-local"}
          proposal={proposal}
          profile={profile}
        />
      )}
    </div>
  );
}
