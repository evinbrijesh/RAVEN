"use client";

import { useEffect, useRef, useState } from "react";
import {
  BrainCircuit,
  Radar,
  Crosshair,
  Scale,
  ShieldCheck,
  UserCheck,
  Bot,
  Check,
  Clock,
  Sparkles,
} from "lucide-react";

/* ─── Types ───────────────────────────────────────────────────────────────── */
export type AgentId =
  | "planner" | "recon" | "attacker" | "judge" | "hardener"
  | "human_approval" | "shophelper";

export type AgentState = "idle" | "active" | "done" | "warn" | "pending";

export interface AgentStatus {
  id: AgentId;
  state: AgentState;
  caption?: string;
  stepsBudget?: number;
  stepsUsed?: number;
  tokensBudget?: number;
  tokensUsed?: number;
  mutationCount?: number;
  mutationTotal?: number;
}

/* ─── Layout positions (normalized 0..1 for SVG viewBox) ─────────────────── */
const POSITIONS: Record<AgentId, [number, number]> = {
  planner:       [0.08, 0.48],
  recon:         [0.22, 0.22],
  attacker:      [0.38, 0.48],
  shophelper:    [0.55, 0.22],
  judge:         [0.70, 0.48],
  hardener:      [0.84, 0.22],
  human_approval:[0.92, 0.65],
};

/* ─── Edges: [from, to, curved] ─────────────────────────────────────────── */
const EDGES: { from: AgentId; to: AgentId; isLoop?: boolean }[] = [
  { from: "planner",   to: "recon" },
  { from: "recon",     to: "attacker" },
  { from: "attacker",  to: "shophelper" },
  { from: "shophelper",to: "judge" },
  { from: "judge",     to: "hardener" },
  { from: "hardener",  to: "human_approval" },
  // Mutation loop: Judge back to Attacker
  { from: "judge",     to: "attacker", isLoop: true },
  // Retest loop: Hardener to ShopHelper
  { from: "hardener",  to: "shophelper", isLoop: true },
];

const AGENT_META: Record<AgentId, { label: string; sub: string; isSquare?: boolean }> = {
  planner:       { label: "Planner",        sub: "Catalog Selection" },
  recon:         { label: "Recon",          sub: "Surface Mapping" },
  attacker:      { label: "Attacker",       sub: "Bounded Execution" },
  shophelper:    { label: "ShopHelper",     sub: "Target (Sandboxed)" },
  judge:         { label: "Judge",          sub: "Rules + LLM" },
  hardener:      { label: "Hardener",       sub: "Policy Diffing" },
  human_approval:{ label: "Human Approval", sub: "Required Gate", isSquare: true },
};

/* ─── Single Agent Node ───────────────────────────────────────────────────── */
function AgentNodeSvg({
  agent,
  cx,
  cy,
  r = 24,
  onClick,
  compact = false,
}: {
  agent: AgentStatus;
  cx: number;
  cy: number;
  r?: number;
  onClick?: () => void;
  compact?: boolean;
}) {
  const meta = AGENT_META[agent.id];
  const isActive  = agent.state === "active";
  const isDone    = agent.state === "done";
  const isWarn    = agent.state === "warn";
  const isPending = agent.state === "idle" || agent.state === "pending";

  const fillColor   = isActive ? "#0F1F1D" : isDone ? "#0D1816" : isPending ? "#13171F" : "#161B24";
  const strokeColor = isActive ? "#2DD4BF" : isDone ? "#2DD4BF" : isWarn ? "#F59E0B" : "rgba(255,255,255,0.12)";
  const strokeWidth = isActive ? 1.75 : 1;
  const iconColor   = isActive ? "#2DD4BF" : isDone ? "#2DD4BF" : isPending ? "#5B6575" : "#8B95A5";
  const labelColor  = isActive ? "#E6EAF0" : isPending ? "#5B6575" : "#8B95A5";
  const opacity     = isPending ? 0.4 : 1;

  const isHuman = meta.isSquare;
  const halfR   = r;

  return (
    <g
      onClick={onClick}
      style={{ cursor: onClick ? "pointer" : "default", opacity }}
      role="button"
      aria-label={meta.label}
      className="group transition-opacity duration-200"
    >
      {/* 2s ease-in-out breathing ring for active agent */}
      {isActive && (
        <circle
          cx={cx}
          cy={cy}
          r={r + 8}
          fill="none"
          stroke="#2DD4BF"
          strokeWidth={1.5}
          className="agent-ring-active animate-breathe"
        />
      )}

      {/* Node shape (Circle or Square for Human) */}
      {isHuman ? (
        <rect
          x={cx - halfR}
          y={cy - halfR}
          width={halfR * 2}
          height={halfR * 2}
          rx={6}
          fill={fillColor}
          stroke={strokeColor}
          strokeWidth={strokeWidth}
        />
      ) : (
        <circle
          cx={cx}
          cy={cy}
          r={r}
          fill={fillColor}
          stroke={strokeColor}
          strokeWidth={strokeWidth}
        />
      )}

      {/* Budget ring overlay */}
      {(agent.stepsBudget ?? 0) > 0 && !compact && (
        <circle
          cx={cx}
          cy={cy}
          r={r + 4}
          fill="none"
          stroke={isWarn ? "#F59E0B" : "#2DD4BF"}
          strokeWidth={2}
          strokeDasharray={`${2 * Math.PI * (r + 4)}`}
          strokeDashoffset={`${2 * Math.PI * (r + 4) * (1 - (agent.stepsUsed ?? 0) / (agent.stepsBudget ?? 1))}`}
          strokeLinecap="round"
          opacity={0.65}
          transform={`rotate(-90 ${cx} ${cy})`}
        />
      )}

      {/* Center symbol / abbreviation */}
      <text
        x={cx}
        y={cy + 1}
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize={compact ? 9 : 11}
        fontWeight="600"
        fill={iconColor}
        style={{ userSelect: "none", fontFamily: "var(--font-mono, monospace)" }}
      >
        {agent.id === "planner" && "PLN"}
        {agent.id === "recon" && "RCN"}
        {agent.id === "attacker" && "ATK"}
        {agent.id === "shophelper" && "SHP"}
        {agent.id === "judge" && "JDG"}
        {agent.id === "hardener" && "HRD"}
        {agent.id === "human_approval" && "HUM"}
      </text>

      {/* Finished check badge */}
      {isDone && !compact && (
        <g>
          <circle cx={cx + r - 4} cy={cy - r + 4} r={6} fill="#0A0D12" stroke="#2DD4BF" strokeWidth={1} />
          <text
            x={cx + r - 4}
            y={cy - r + 4}
            textAnchor="middle"
            dominantBaseline="middle"
            fontSize={7}
            fill="#2DD4BF"
            style={{ userSelect: "none" }}
          >
            ✓
          </text>
        </g>
      )}

      {/* Loop counter badge on Attacker (e.g. mutation 1 of 1) */}
      {agent.id === "attacker" && agent.mutationCount !== undefined && !compact && (
        <g>
          <rect
            x={cx - r - 16}
            y={cy - r - 6}
            width={34}
            height={14}
            rx={3}
            fill="#161B24"
            stroke="rgba(45,212,191,0.4)"
            strokeWidth={1}
          />
          <text
            x={cx - r + 1}
            y={cy - r + 1}
            textAnchor="middle"
            dominantBaseline="middle"
            fontSize={7}
            fill="#2DD4BF"
            style={{ userSelect: "none", fontFamily: "var(--font-mono, monospace)" }}
          >
            mut {agent.mutationCount}/{agent.mutationTotal}
          </text>
        </g>
      )}

      {/* Budget reached warning tag */}
      {isWarn && !compact && (
        <text
          x={cx}
          y={cy - r - 6}
          textAnchor="middle"
          fontSize={8}
          fill="#F59E0B"
          style={{ fontFamily: "var(--font-mono, monospace)" }}
        >
          budget reached
        </text>
      )}

      {/* Label and Subtitle */}
      {!compact && (
        <g>
          <text
            x={cx}
            y={cy + r + 13}
            textAnchor="middle"
            fontSize={11}
            fontWeight="500"
            fill={labelColor}
            style={{ userSelect: "none" }}
          >
            {meta.label}
          </text>
          <text
            x={cx}
            y={cy + r + 24}
            textAnchor="middle"
            fontSize={9}
            fill="#5B6575"
            style={{ userSelect: "none", fontFamily: "var(--font-mono, monospace)" }}
          >
            {meta.sub}
          </text>
        </g>
      )}
    </g>
  );
}

/* ─── 600ms traveling pulse dot along edge ───────────────────────────────── */
function PulseDot({
  x1, y1, x2, y2, active, isCurve,
}: {
  x1: number; y1: number; x2: number; y2: number; active: boolean; isCurve?: boolean;
}) {
  if (!active) return null;
  const pathD = isCurve
    ? `M ${x1} ${y1} Q ${(x1 + x2) / 2} ${Math.min(y1, y2) - 40} ${x2} ${y2}`
    : `M ${x1} ${y1} L ${x2} ${y2}`;

  return (
    <circle r={3} fill="#2DD4BF" opacity={0.9} filter="drop-shadow(0 0 3px #2DD4BF)">
      <animateMotion
        dur="0.6s"
        repeatCount="indefinite"
        path={pathD}
        calcMode="spline"
        keySplines="0.25 0.1 0.25 1"
      />
      <animate attributeName="opacity" values="0;1;1;0" dur="0.6s" repeatCount="indefinite" />
    </circle>
  );
}

/* ─── Main Constellation component ────────────────────────────────────────── */
export function AgentConstellation({
  agents,
  activeEdges = [],
  onNodeClick,
  compact = false,
  width = 820,
  height = 290,
}: {
  agents: AgentStatus[];
  activeEdges?: [AgentId, AgentId][];
  onNodeClick?: (id: AgentId) => void;
  compact?: boolean;
  width?: number;
  height?: number;
}) {
  const nodeR = compact ? 12 : 22;
  const padX  = compact ? 15 : 44;
  const padY  = compact ? 15 : 40;

  const px = (nx: number) => padX + nx * (width - 2 * padX);
  const py = (ny: number) => padY + ny * (height - 2 * padY);

  const agentMap = Object.fromEntries(agents.map((a) => [a.id, a])) as Record<AgentId, AgentStatus>;

  return (
    <div className="relative w-full overflow-hidden select-none">
      <svg
        width="100%"
        viewBox={`0 0 ${width} ${height}`}
        aria-label="Agent Constellation — State Machine Topology"
        role="img"
        className="overflow-visible"
      >
        <defs>
          <linearGradient id="edgeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="rgba(45,212,191,0.6)" />
            <stop offset="100%" stopColor="rgba(45,212,191,0.1)" />
          </linearGradient>
        </defs>

        {/* State Machine Edges */}
        {EDGES.map(({ from, to, isLoop }) => {
          const [fx, fy] = POSITIONS[from];
          const [tx, ty] = POSITIONS[to];
          const x1 = px(fx); const y1 = py(fy);
          const x2 = px(tx); const y2 = py(ty);
          const isActive = activeEdges.some(([ef, et]) => ef === from && et === to);

          const pathD = isLoop
            ? `M ${x1} ${y1} Q ${(x1 + x2) / 2} ${Math.min(y1, y2) - (compact ? 20 : 40)} ${x2} ${y2}`
            : `M ${x1} ${y1} L ${x2} ${y2}`;

          return (
            <g key={`${from}-${to}`}>
              <path
                d={pathD}
                fill="none"
                stroke={isActive ? "rgba(45,212,191,0.4)" : "rgba(255,255,255,0.07)"}
                strokeWidth={isActive ? 1.5 : 1}
                strokeDasharray={isLoop ? "4 4" : undefined}
              />
              <PulseDot x1={x1} y1={y1} x2={x2} y2={y2} active={isActive} isCurve={isLoop} />
            </g>
          );
        })}

        {/* Agent Nodes */}
        {(Object.entries(POSITIONS) as [AgentId, [number, number]][]).map(([id, [nx, ny]]) => {
          const agent = agentMap[id] ?? { id, state: "pending" };
          return (
            <AgentNodeSvg
              key={id}
              agent={agent}
              cx={px(nx)}
              cy={py(ny)}
              r={nodeR}
              compact={compact}
              onClick={onNodeClick ? () => onNodeClick(id) : undefined}
            />
          );
        })}

        {/* Live Mono Caption under Active Node */}
        {!compact && agents
          .filter((a) => a.state === "active" && a.caption)
          .map((a) => {
            const [nx, ny] = POSITIONS[a.id];
            return (
              <g key={a.id} className="animate-fade-in">
                <rect
                  x={px(nx) - 130}
                  y={py(ny) + nodeR + 34}
                  width={260}
                  height={18}
                  rx={4}
                  fill="#0A0D12"
                  stroke="rgba(45,212,191,0.3)"
                  strokeWidth={1}
                />
                <text
                  x={px(nx)}
                  y={py(ny) + nodeR + 46}
                  textAnchor="middle"
                  fontSize={9}
                  fill="#2DD4BF"
                  style={{ fontFamily: "var(--font-mono, monospace)" }}
                >
                  {a.id}: {a.caption}
                </text>
              </g>
            );
          })}
      </svg>
    </div>
  );
}

/* ─── Compact Mini Constellation for Sidebar ────────────────────────────── */
export function MiniConstellation({ agents }: { agents: AgentStatus[] }) {
  return (
    <div className="overflow-hidden rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-base)] p-1.5">
      <AgentConstellation
        agents={agents}
        compact
        width={180}
        height={85}
      />
    </div>
  );
}

/* ─── Agent Trace Side Panel (21st.dev Drawer Pattern) ───────────────────── */
export interface TraceStep {
  id: string;
  kind: "thought" | "tool_call" | "result";
  summary?: string;
  tool?: string;
  args?: Record<string, unknown>;
  result?: string;
  durationMs?: number;
  tokensUsed?: number;
}

export function AgentTrace({
  agentId,
  steps,
  budget,
}: {
  agentId: AgentId;
  steps: TraceStep[];
  budget?: { stepsUsed: number; stepsTotal: number; tokensUsed: number; tokensTotal: number };
}) {
  const meta = AGENT_META[agentId];

  return (
    <div className="flex h-full flex-col font-sans">
      {/* Header */}
      <div className="border-b border-[var(--border-hairline)] bg-[var(--bg-surface)] px-4 py-3">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs font-semibold text-[var(--text-primary)] font-mono uppercase tracking-wider">
              {meta.label} Trace
            </p>
            <p className="text-[10px] text-[var(--text-muted)] font-mono">{meta.sub}</p>
          </div>
          {budget && (
            <div className="text-right font-mono text-[10px] text-[var(--text-muted)]">
              <span className="text-[var(--accent)] font-medium">{budget.stepsUsed}</span>/{budget.stepsTotal} steps ·{" "}
              <span className="text-[var(--text-secondary)]">{(budget.tokensUsed / 1000).toFixed(1)}k</span> tok
            </div>
          )}
        </div>
      </div>

      {/* Timeline Steps */}
      <div className="flex-1 overflow-y-auto px-4 py-3 bg-[var(--bg-base)]">
        <div className="relative border-l border-[var(--border-hairline)] pl-4 space-y-4">
          {steps.map((step) => (
            <div key={step.id} className="relative animate-fade-in group">
              {/* Timeline marker */}
              <div
                className={`absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full border
                  ${step.kind === "tool_call" ? "border-[var(--accent)] bg-teal-950 shadow-xs" :
                    step.kind === "result"    ? "border-emerald-500 bg-emerald-950" :
                                               "border-zinc-700 bg-zinc-900"}`}
              />

              {/* Tool invocation badge */}
              {step.kind === "tool_call" && step.tool && (
                <div className="mb-1.5 flex items-center gap-1.5">
                  <span className="inline-flex items-center gap-1 rounded border border-teal-500/30 bg-teal-950/40 px-2 py-0.5 font-mono text-[10px] font-medium text-[var(--accent)]">
                    <Sparkles className="h-2.5 w-2.5" />
                    {step.tool}
                  </span>
                  {step.durationMs !== undefined && (
                    <span className="font-mono text-[9px] text-[var(--text-muted)] flex items-center gap-0.5">
                      <Clock className="h-2.5 w-2.5" />
                      {step.durationMs}ms
                    </span>
                  )}
                </div>
              )}

              {/* Thought Summary */}
              {step.summary && (
                <p className="text-xs text-[var(--text-secondary)] leading-relaxed">{step.summary}</p>
              )}

              {/* Redacted Args Pre Block */}
              {step.args && step.kind === "tool_call" && (
                <div className="mt-1.5 overflow-hidden rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)]">
                  <div className="bg-[var(--bg-raised)] px-2 py-0.5 text-[9px] font-mono text-[var(--text-muted)] border-b border-[var(--border-hairline)]">
                    arguments (redacted)
                  </div>
                  <pre className="p-2 font-mono text-[10px] text-zinc-400 overflow-x-auto">
                    {JSON.stringify(step.args, null, 2)}
                  </pre>
                </div>
              )}

              {/* Result output */}
              {step.result && (
                <div className="mt-1 flex items-center gap-1.5 font-mono text-[10px] text-emerald-400">
                  <Check className="h-3 w-3" />
                  <span>{step.result}</span>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
