"use client";

import { useEffect, useRef, useState } from "react";

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
  planner:       [0.08, 0.50],
  recon:         [0.24, 0.20],
  attacker:      [0.42, 0.50],
  judge:         [0.60, 0.20],
  hardener:      [0.76, 0.50],
  human_approval:[0.90, 0.80],
  shophelper:    [0.90, 0.20],
};

/* ─── Edges: [from, to] ───────────────────────────────────────────────────── */
const EDGES: [AgentId, AgentId][] = [
  ["planner",  "recon"],
  ["recon",    "attacker"],
  ["attacker", "shophelper"],
  ["shophelper","judge"],
  ["judge",    "hardener"],
  ["hardener", "human_approval"],
  // Mutation loop
  ["judge",    "attacker"],
  // Retest loop
  ["hardener", "shophelper"],
];

const AGENT_META: Record<AgentId, { label: string; icon: string; isSquare?: boolean }> = {
  planner:       { label: "Planner",     icon: "⊞" },
  recon:         { label: "Recon",       icon: "⊙" },
  attacker:      { label: "Attacker",    icon: "⊗" },
  judge:         { label: "Judge",       icon: "⊘" },
  hardener:      { label: "Hardener",    icon: "⊕" },
  human_approval:{ label: "Approval",   icon: "⊡", isSquare: true },
  shophelper:    { label: "ShopHelper", icon: "⊚" },
};

/* ─── Single Agent Node ───────────────────────────────────────────────────── */
function AgentNodeSvg({
  agent,
  cx,
  cy,
  r = 22,
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

  const fillColor     = isActive ? "#0F1F1D" : isPending ? "var(--bg-raised)" : "#0F1F1D";
  const strokeColor   = isActive ? "#2DD4BF" : isDone ? "#2DD4BF" : isWarn ? "#F59E0B" : "rgba(255,255,255,0.1)";
  const strokeWidth   = isActive ? 1.5 : 1;
  const iconColor     = isActive ? "#2DD4BF" : isDone ? "#2DD4BF" : isPending ? "#5B6575" : "#8B95A5";
  const labelColor    = isActive ? "#E6EAF0" : isPending ? "#5B6575" : "#8B95A5";
  const opacity       = isPending ? 0.4 : 1;

  const isHuman  = meta.isSquare;
  const halfR    = r;

  return (
    <g
      onClick={onClick}
      style={{ cursor: onClick ? "pointer" : "default", opacity }}
      role="button"
      aria-label={meta.label}
    >
      {/* Breathing ring for active agent */}
      {isActive && (
        <circle
          cx={cx} cy={cy} r={r + 8}
          fill="none"
          stroke="#2DD4BF"
          strokeWidth={1.5}
          opacity={0}
          style={{ animation: "breathe 2s ease-in-out infinite" }}
          className="agent-ring-active"
        />
      )}

      {/* Node body */}
      {isHuman ? (
        <rect
          x={cx - halfR} y={cy - halfR}
          width={halfR * 2} height={halfR * 2}
          rx={6}
          fill={fillColor}
          stroke={strokeColor}
          strokeWidth={strokeWidth}
        />
      ) : (
        <circle
          cx={cx} cy={cy} r={r}
          fill={fillColor}
          stroke={strokeColor}
          strokeWidth={strokeWidth}
        />
      )}

      {/* Budget ring overlay */}
      {(agent.stepsBudget ?? 0) > 0 && !compact && (
        <circle
          cx={cx} cy={cy} r={r + 3}
          fill="none"
          stroke={isWarn ? "#F59E0B" : "#2DD4BF"}
          strokeWidth={2}
          strokeDasharray={`${2 * Math.PI * (r + 3)}`}
          strokeDashoffset={`${2 * Math.PI * (r + 3) * (1 - (agent.stepsUsed ?? 0) / (agent.stepsBudget ?? 1))}`}
          strokeLinecap="round"
          opacity={0.5}
          transform={`rotate(-90 ${cx} ${cy})`}
        />
      )}

      {/* Icon */}
      <text
        x={cx} y={cy + 1}
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize={compact ? 10 : 13}
        fill={iconColor}
        style={{ userSelect: "none", fontFamily: "monospace" }}
      >
        {meta.icon}
      </text>

      {/* Done checkmark */}
      {isDone && !compact && (
        <circle cx={cx + r - 4} cy={cy - r + 4} r={6} fill="#161B24" stroke="#2DD4BF" strokeWidth={1} />
      )}
      {isDone && !compact && (
        <text x={cx + r - 4} y={cy - r + 4} textAnchor="middle" dominantBaseline="middle" fontSize={7} fill="#2DD4BF" style={{ userSelect: "none" }}>✓</text>
      )}

      {/* Mutation badge */}
      {agent.id === "attacker" && agent.mutationCount !== undefined && !compact && (
        <g>
          <circle cx={cx - r + 4} cy={cy - r + 4} r={8} fill="#1C1A2C" stroke="rgba(139,99,210,0.5)" strokeWidth={1} />
          <text x={cx - r + 4} y={cy - r + 4} textAnchor="middle" dominantBaseline="middle" fontSize={6} fill="#C4B5FD" style={{ userSelect: "none" }}>
            {agent.mutationCount}/{agent.mutationTotal}
          </text>
        </g>
      )}

      {/* Label */}
      {!compact && (
        <text
          x={cx} y={cy + r + 12}
          textAnchor="middle"
          fontSize={10}
          fill={labelColor}
          style={{ userSelect: "none", fontFamily: "var(--font-mono, monospace)" }}
        >
          {meta.label}
        </text>
      )}
    </g>
  );
}

/* ─── Pulse dot traveling along an edge ──────────────────────────────────── */
function PulseDot({
  x1, y1, x2, y2, active,
}: {
  x1: number; y1: number; x2: number; y2: number; active: boolean;
}) {
  if (!active) return null;

  return (
    <circle r={4} fill="#2DD4BF" opacity={0.9}>
      <animateMotion
        dur="0.6s"
        repeatCount="indefinite"
        path={`M ${x1} ${y1} L ${x2} ${y2}`}
        calcMode="spline"
        keySplines="0.4 0 0.2 1"
      />
      <animate attributeName="opacity" values="0;1;1;0" dur="0.6s" repeatCount="indefinite" />
    </circle>
  );
}

/* ─── Main constellation component ────────────────────────────────────────── */
export function AgentConstellation({
  agents,
  activeEdges = [],
  onNodeClick,
  compact = false,
  width = 800,
  height = 280,
}: {
  agents: AgentStatus[];
  activeEdges?: [AgentId, AgentId][];
  onNodeClick?: (id: AgentId) => void;
  compact?: boolean;
  width?: number;
  height?: number;
}) {
  const nodeR = compact ? 14 : 22;
  const pad   = compact ? 20 : 40;

  // Map agent IDs to positions in pixels
  const px = (nx: number) => pad + nx * (width - 2 * pad);
  const py = (ny: number) => pad + ny * (height - 2 * pad);

  const agentMap = Object.fromEntries(agents.map((a) => [a.id, a])) as Record<AgentId, AgentStatus>;

  return (
    <svg
      width="100%"
      viewBox={`0 0 ${width} ${height}`}
      aria-label="Agent constellation — live scan state diagram"
      role="img"
      style={{ overflow: "visible" }}
    >
      {/* Edge lines */}
      {EDGES.map(([from, to]) => {
        const [fx, fy] = POSITIONS[from];
        const [tx, ty] = POSITIONS[to];
        const x1 = px(fx); const y1 = py(fy);
        const x2 = px(tx); const y2 = py(ty);
        const isActive = activeEdges.some(([ef, et]) => ef === from && et === to);

        return (
          <g key={`${from}-${to}`}>
            <line
              x1={x1} y1={y1} x2={x2} y2={y2}
              stroke={isActive ? "rgba(45,212,191,0.35)" : "rgba(255,255,255,0.06)"}
              strokeWidth={isActive ? 1.5 : 1}
              strokeDasharray={isActive ? undefined : "4 4"}
            />
            <PulseDot x1={x1} y1={y1} x2={x2} y2={y2} active={isActive} />
          </g>
        );
      })}

      {/* Agent nodes */}
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

      {/* Live captions */}
      {!compact && agents
        .filter((a) => a.state === "active" && a.caption)
        .map((a) => {
          const [nx, ny] = POSITIONS[a.id];
          return (
            <text
              key={a.id}
              x={px(nx)}
              y={py(ny) + nodeR + 26}
              textAnchor="middle"
              fontSize={9}
              fill="#2DD4BF"
              opacity={0.9}
              style={{ fontFamily: "JetBrains Mono, monospace" }}
            >
              {a.caption}
            </text>
          );
        })}
    </svg>
  );
}

/* ─── Mini constellation for sidebar ─────────────────────────────────────── */
export function MiniConstellation({ agents }: { agents: AgentStatus[] }) {
  return (
    <div className="overflow-hidden rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-2">
      <AgentConstellation
        agents={agents}
        compact
        width={160}
        height={90}
      />
    </div>
  );
}

/* ─── Agent Trace side panel ─────────────────────────────────────────────── */
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
    <div className="flex h-full flex-col">
      {/* Header */}
      <div className="border-b border-[var(--border-hairline)] px-4 py-3">
        <div className="flex items-center justify-between">
          <p className="text-sm font-semibold">{meta.label} trace</p>
          {budget && (
            <div className="flex items-center gap-3 text-[var(--text-xs)] text-[var(--text-muted)] font-mono">
              <span>{budget.stepsUsed}/{budget.stepsTotal} steps</span>
              <span>{(budget.tokensUsed / 1000).toFixed(1)}k/{(budget.tokensTotal / 1000).toFixed(0)}k tok</span>
            </div>
          )}
        </div>
      </div>

      {/* Timeline */}
      <div className="flex-1 overflow-y-auto px-4 py-3">
        <div className="relative border-l border-[var(--border-hairline)] pl-4 space-y-4">
          {steps.map((step) => (
            <div key={step.id} className="relative animate-fade-in">
              {/* Timeline dot */}
              <div
                className={`absolute -left-[17px] top-1 h-2 w-2 rounded-full border
                  ${step.kind === "tool_call" ? "border-[var(--accent)] bg-[var(--accent-dim)]" :
                    step.kind === "result"    ? "border-green-600 bg-green-950" :
                                               "border-[var(--border-subtle)] bg-[var(--bg-raised)]"}`}
              />

              {/* Tool call chip */}
              {step.kind === "tool_call" && step.tool && (
                <div className="mb-1">
                  <span className="inline-flex items-center gap-1 rounded border border-[var(--accent)]/30 bg-[var(--accent-glow)] px-2 py-0.5 font-mono text-[10px] text-[var(--accent)]">
                    {step.tool}
                  </span>
                </div>
              )}

              {/* Summary / thought */}
              {step.summary && (
                <p className="text-[var(--text-sm)] text-[var(--text-secondary)]">{step.summary}</p>
              )}

              {/* Args (redacted) */}
              {step.args && step.kind === "tool_call" && (
                <pre className="mt-1 overflow-x-auto rounded bg-[var(--bg-raised)] p-2 font-mono text-[10px] text-[var(--text-muted)]">
                  {JSON.stringify(step.args, null, 2)}
                </pre>
              )}

              {/* Result */}
              {step.result && (
                <p className="mt-1 font-mono text-[10px] text-[var(--text-muted)]">→ {step.result}</p>
              )}

              {/* Meta */}
              {(step.durationMs !== undefined || step.tokensUsed !== undefined) && (
                <div className="mt-1 flex gap-3 font-mono text-[10px] text-[var(--text-muted)]">
                  {step.durationMs !== undefined && <span>{step.durationMs}ms</span>}
                  {step.tokensUsed !== undefined && <span>{step.tokensUsed} tok</span>}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
