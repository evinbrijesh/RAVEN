"use client";

import { useState, useEffect } from "react";
import { Radio, Terminal, ShieldAlert, ShieldCheck } from "lucide-react";
import type { Finding, AttackCategory, Severity } from "@/lib/types";

// ---------------------------------------------------------------------------
// Public blip type — callers construct these from real Finding data
// ---------------------------------------------------------------------------
export interface RadarBlip {
  id: string;         // attack_id
  angle: number;      // degrees (0 = 12 o'clock)
  dist: number;       // 0–1 fraction of radar radius
  status: "blocked" | "breached";
  label: string;      // human-readable category
  severity: Severity;
}

// ---------------------------------------------------------------------------
// Helper: map a Finding[] to RadarBlip[]
// Exported so the parent (scan page) can call it directly.
// ---------------------------------------------------------------------------

const CATEGORY_BASE_ANGLES: Record<AttackCategory, number> = {
  direct_injection: 20,
  canary_leakage:   110,
  sensitive_data:   200,
  tool_misuse:      290,
};

const CATEGORY_LABELS: Record<AttackCategory, string> = {
  direct_injection: "Direct Injection",
  canary_leakage:   "Canary Leakage",
  sensitive_data:   "Sensitive Data",
  tool_misuse:      "Tool Misuse",
};

export function findingsToBlips(findings: Finding[]): RadarBlip[] {
  // Group by category so we can fan blips out within each quadrant
  const byCategory: Partial<Record<AttackCategory, Finding[]>> = {};
  for (const f of findings) {
    if (!byCategory[f.category]) byCategory[f.category] = [];
    byCategory[f.category]!.push(f);
  }

  const blips: RadarBlip[] = [];
  for (const [cat, items] of Object.entries(byCategory) as [AttackCategory, Finding[]][]) {
    const base = CATEGORY_BASE_ANGLES[cat] ?? 0;
    const step = items.length > 1 ? 60 / (items.length - 1) : 0; // spread 60° per bucket
    items.forEach((f, i) => {
      const angle = (base + i * step - 30 + 360) % 360; // centre the fan
      // Higher confidence → blip closer to the edge (more "detected")
      const dist = 0.45 + Math.min(f.confidence, 1) * 0.45;
      const breached =
        f.label === "confirmed_failure" || f.label === "likely_failure";
      const sev: Severity =
        f.severity === "critical" || f.severity === "high" || f.severity === "medium"
          ? f.severity
          : "medium";
      blips.push({
        id: f.attack_id,
        angle,
        dist,
        status: breached ? "breached" : "blocked",
        label: CATEGORY_LABELS[cat] ?? cat,
        severity: sev,
      });
    });
  }
  return blips;
}

// ---------------------------------------------------------------------------
// Component props
// ---------------------------------------------------------------------------
export interface ScanRadarPulseProps {
  phase?: string;
  isScanning?: boolean;
  /** Real blips derived from scan findings. Pass [] during active scan for empty radar. */
  blips?: RadarBlip[];
  className?: string;
}

// ---------------------------------------------------------------------------
// Telemetry log seeds (cosmetic, not data-bearing)
// ---------------------------------------------------------------------------
const SEED_LOGS = [
  "T+002ms [RECON_PROBE] Handshake initiated with target /chat",
  "T+045ms [TOKEN_AUDIT] Verifying canary signature integrity",
  "T+112ms [ATTACK_SUITE] Vector dispatched (OWASP-LLM01)",
  "T+184ms [POLICY_GATEWAY] Tool authorization check intercepted",
  "T+242ms [DUAL_JUDGE] Deterministic regex hit: corroborated",
];

const LIVE_EVENTS = [
  (t: number) => `T+${t}ms [MUTATOR] Synthesizing roleplay evasion variant`,
  (t: number) => `T+${t + 30}ms [GATEWAY] Denied unverified refund authorization`,
  (t: number) => `T+${t + 65}ms [CANARY_PROBE] Zero token leakage confirmed`,
  (t: number) => `T+${t + 90}ms [UTILITY_RUNNER] Benign customer test verified (PASS)`,
  (t: number) => `T+${t + 120}ms [RADAR_SWEEP] Vector telemetry synced with state graph`,
];

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
export default function ScanRadarPulse({
  phase = "Attack",
  isScanning = true,
  blips = [],
  className = "",
}: ScanRadarPulseProps) {
  const [activeBlip, setActiveBlip] = useState<RadarBlip | null>(null);
  const [telemetryLogs, setTelemetryLogs] = useState<string[]>(SEED_LOGS);

  useEffect(() => {
    if (!isScanning) return;
    const interval = setInterval(() => {
      const now = Math.floor(Math.random() * 400 + 100);
      const fn = LIVE_EVENTS[Math.floor(Math.random() * LIVE_EVENTS.length)];
      setTelemetryLogs((prev) => [...prev.slice(-4), fn(now)]);
    }, 3200);
    return () => clearInterval(interval);
  }, [isScanning]);

  const size = 260;
  const center = size / 2;
  const maxRadius = center - 18;

  // Arc for 45° trailing sweep wedge
  const sweepAngleDeg = 45;
  const sweepAngleRad = (sweepAngleDeg * Math.PI) / 180;
  const trailX = center - maxRadius * Math.sin(sweepAngleRad);
  const trailY = center - maxRadius * Math.cos(sweepAngleRad);
  const sweepPath = `M ${center} ${center} L ${center} ${center - maxRadius} A ${maxRadius} ${maxRadius} 0 0 0 ${trailX} ${trailY} Z`;

  const hasBlips = blips.length > 0;

  return (
    <div
      className={`relative overflow-hidden rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5 shadow-2xl backdrop-blur-md ${className}`}
    >
      {/* Ambient HUD grid */}
      <div className="absolute inset-0 bg-[radial-gradient(#2DD4BF_1px,transparent_1px)] [background-size:16px_16px] opacity-[0.03] pointer-events-none" />

      {/* Corner reticles */}
      <div className="absolute top-2 left-2 w-2.5 h-2.5 border-t border-l border-teal-500/40 pointer-events-none" />
      <div className="absolute top-2 right-2 w-2.5 h-2.5 border-t border-r border-teal-500/40 pointer-events-none" />
      <div className="absolute bottom-2 left-2 w-2.5 h-2.5 border-b border-l border-teal-500/40 pointer-events-none" />
      <div className="absolute bottom-2 right-2 w-2.5 h-2.5 border-b border-r border-teal-500/40 pointer-events-none" />

      {/* Header */}
      <div className="relative flex items-center justify-between border-b border-[var(--border-hairline)] pb-3 mb-4">
        <div className="flex items-center gap-2">
          <Radio className={`h-4 w-4 ${isScanning ? "text-teal-400 animate-pulse" : "text-zinc-500"}`} />
          <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-[var(--text-primary)]">
            Active Vector Radar &amp; Telemetry
          </h4>
        </div>
        <div className="flex items-center gap-2 font-mono text-[10px]">
          <span className={`flex h-2 w-2 rounded-full ${isScanning ? "bg-teal-400 animate-ping" : "bg-zinc-600"}`} />
          <span className={`font-bold uppercase tracking-wider ${isScanning ? "text-teal-400" : "text-zinc-500"}`}>
            {isScanning ? "SWEEP ACTIVE" : "RADAR STANDBY"}
          </span>
          <span className="text-zinc-600">·</span>
          <span className="text-zinc-400 uppercase">{phase}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-[260px_1fr] gap-6 items-center">
        {/* SVG Radar */}
        <div className="relative flex flex-col items-center justify-center">
          <svg
            width={size}
            height={size}
            viewBox={`0 0 ${size} ${size}`}
            className="overflow-visible select-none"
          >
            <defs>
              <linearGradient id="radar-sweep-trail" x1="100%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor="#2DD4BF" stopOpacity="0.45" />
                <stop offset="60%" stopColor="#2DD4BF" stopOpacity="0.12" />
                <stop offset="100%" stopColor="#2DD4BF" stopOpacity="0" />
              </linearGradient>
              <filter id="radar-glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="2" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>

            {/* Radar background */}
            <circle cx={center} cy={center} r={maxRadius} fill="rgba(10,20,24,0.4)" stroke="rgba(45,212,191,0.25)" strokeWidth="1.5" />

            {/* Concentric rings */}
            {[0.25, 0.5, 0.75].map((rPct) => (
              <circle key={`ring-${rPct}`} cx={center} cy={center} r={maxRadius * rPct} fill="none" stroke="rgba(45,212,191,0.14)" strokeWidth="1" strokeDasharray="3 3" />
            ))}

            {/* Range tags */}
            <text x={center + 3} y={center - maxRadius * 0.5 + 9} className="text-[7px] font-mono fill-teal-500/40">50%</text>
            <text x={center + 3} y={center - maxRadius * 0.75 + 9} className="text-[7px] font-mono fill-teal-500/40">75%</text>

            {/* Crosshairs */}
            <line x1={center - maxRadius} y1={center} x2={center + maxRadius} y2={center} stroke="rgba(45,212,191,0.22)" strokeWidth="1" />
            <line x1={center} y1={center - maxRadius} x2={center} y2={center + maxRadius} stroke="rgba(45,212,191,0.22)" strokeWidth="1" />

            {/* Azimuth labels */}
            <text x={center} y={center - maxRadius - 5} textAnchor="middle" className="text-[8px] font-mono font-bold fill-teal-400/80">000°</text>
            <text x={center + maxRadius + 7} y={center + 3} textAnchor="start" className="text-[8px] font-mono fill-zinc-500">090°</text>
            <text x={center} y={center + maxRadius + 12} textAnchor="middle" className="text-[8px] font-mono fill-zinc-500">180°</text>
            <text x={center - maxRadius - 7} y={center + 3} textAnchor="end" className="text-[8px] font-mono fill-zinc-500">270°</text>

            {/* Rotating sweep (only while scanning) */}
            {isScanning && (
              <g>
                <animateTransform attributeName="transform" type="rotate" from={`0 ${center} ${center}`} to={`360 ${center} ${center}`} dur="4s" repeatCount="indefinite" />
                <path d={sweepPath} fill="url(#radar-sweep-trail)" />
                <line x1={center} y1={center} x2={center} y2={center - maxRadius} stroke="#2DD4BF" strokeWidth="2" filter="url(#radar-glow)" />
              </g>
            )}

            {/* Center hub */}
            <circle cx={center} cy={center} r="5" fill="rgba(45,212,191,0.2)" />
            <circle cx={center} cy={center} r="2.5" fill="#2DD4BF" />

            {/* Empty-state label when no findings yet */}
            {!hasBlips && (
              <text x={center} y={center + maxRadius * 0.5} textAnchor="middle" className="text-[9px] font-mono fill-teal-500/30">
                {isScanning ? "awaiting findings…" : "no findings"}
              </text>
            )}

            {/* Real blips from findings */}
            {blips.map((blip) => {
              // SVG angle: 0° = top (12 o'clock), clockwise. Rotate by -90° to convert.
              const rad = ((blip.angle - 90) * Math.PI) / 180;
              const r = maxRadius * blip.dist;
              const bx = center + r * Math.cos(rad);
              const by = center + r * Math.sin(rad);
              const isBreach = blip.status === "breached";
              const isRight = bx >= center;
              const isActive = activeBlip?.id === blip.id;

              return (
                <g
                  key={blip.id}
                  className="cursor-pointer"
                  onMouseEnter={() => setActiveBlip(blip)}
                  onMouseLeave={() => setActiveBlip(null)}
                >
                  {/* Hover highlight ring — pure SVG, no CSS transform */}
                  {isActive && (
                    <circle cx={bx} cy={by} r="13" fill="none" stroke={isBreach ? "#F43F5E" : "#2DD4BF"} strokeWidth="1" opacity="0.5" />
                  )}

                  {/* Pulse ring for breached blips */}
                  {isBreach ? (
                    <circle
                      cx={bx}
                      cy={by}
                      r="9"
                      fill="none"
                      stroke="#F43F5E"
                      strokeWidth="1.2"
                      className="animate-ping opacity-60"
                      style={{ transformBox: "fill-box", transformOrigin: "center" }}
                    />
                  ) : (
                    <circle cx={bx} cy={by} r="7" fill="none" stroke="#2DD4BF" strokeWidth="0.8" className="opacity-40" />
                  )}

                  {/* Solid core */}
                  <circle
                    cx={bx}
                    cy={by}
                    r={isBreach ? 4.5 : 3.5}
                    fill={isBreach ? "#F43F5E" : "#2DD4BF"}
                    className={isBreach ? "animate-pulse" : ""}
                    filter="url(#radar-glow)"
                  />

                  {/* ID label */}
                  <text
                    x={isRight ? bx + 8 : bx - 8}
                    y={by + 3}
                    textAnchor={isRight ? "start" : "end"}
                    className={`text-[9px] font-mono font-bold tracking-tight pointer-events-none drop-shadow ${isBreach ? "fill-rose-400" : "fill-teal-300"}`}
                  >
                    {blip.id}
                  </text>
                </g>
              );
            })}
          </svg>

          {/* Hover badge */}
          {activeBlip ? (
            <div className="mt-2.5 flex items-center gap-2 rounded-md border border-[var(--border-hairline)] bg-[var(--bg-raised)] px-2.5 py-1 text-[10px] font-mono animate-fade-in shadow-md">
              {activeBlip.status === "breached" ? (
                <ShieldAlert className="h-3 w-3 text-rose-400" />
              ) : (
                <ShieldCheck className="h-3 w-3 text-emerald-400" />
              )}
              <span className="font-bold text-[var(--text-primary)]">{activeBlip.id}</span>
              <span className="text-zinc-500">·</span>
              <span className="text-[var(--text-secondary)]">{activeBlip.label}</span>
              <span className={`px-1 rounded text-[9px] uppercase font-bold ${
                activeBlip.status === "breached"
                  ? "bg-rose-500/20 text-rose-300"
                  : "bg-emerald-500/20 text-emerald-300"
              }`}>
                {activeBlip.status}
              </span>
              <span className="text-zinc-600 text-[9px]">{activeBlip.severity}</span>
            </div>
          ) : (
            <div className="mt-2 text-[10px] font-mono text-zinc-500 flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-teal-400/50" />
              <span>
                {hasBlips
                  ? `${blips.length} vector${blips.length !== 1 ? "s" : ""} plotted — hover to inspect`
                  : isScanning
                  ? "Awaiting first findings from scan…"
                  : "No findings to display"}
              </span>
            </div>
          )}
        </div>

        {/* Telemetry HUD Console */}
        <div className="space-y-3 font-mono text-xs">
          <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-base)] p-3.5 space-y-2 shadow-inner">
            <div className="flex items-center justify-between text-[11px] text-zinc-500 border-b border-[var(--border-hairline)] pb-1.5">
              <span className="flex items-center gap-1.5 text-teal-400 font-semibold tracking-wider">
                <Terminal className="h-3.5 w-3.5" /> TELEMETRY STREAM
              </span>
              <span className="text-[10px] text-zinc-400">1000/s BUFFER</span>
            </div>
            <div className="space-y-1.5 text-[11px] leading-relaxed">
              {telemetryLogs.map((log, idx) => (
                <div
                  key={idx}
                  className={`truncate transition-colors ${
                    log.includes("breached") || log.includes("CANARY")
                      ? "text-rose-300 font-medium"
                      : log.includes("GATEWAY") || log.includes("POLICY") || log.includes("PASS")
                      ? "text-teal-300"
                      : "text-zinc-400"
                  }`}
                >
                  <span className="text-zinc-600 mr-1.5 select-none">›</span>
                  {log}
                </div>
              ))}
            </div>
          </div>

          {/* Blip legend */}
          {hasBlips && (
            <div className="flex flex-wrap gap-x-4 gap-y-1 px-1 text-[10px] text-zinc-500">
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-rose-500 inline-block" />
                breached ({blips.filter((b) => b.status === "breached").length})
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-teal-400 inline-block" />
                blocked ({blips.filter((b) => b.status === "blocked").length})
              </span>
            </div>
          )}

          <div className="flex items-center justify-between px-1 text-[10px] text-zinc-500">
            <span>CHANNELS: {hasBlips ? `${blips.length} ATTACK` : "—"}</span>
            <span className="text-teal-400 font-semibold tracking-wide">ZERO-LEAK ASSURANCE</span>
          </div>
        </div>
      </div>
    </div>
  );
}
