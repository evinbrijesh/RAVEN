"use client";

import { useState, useEffect } from "react";
import { Radio, Terminal, ShieldAlert, ShieldCheck } from "lucide-react";

export interface ScanRadarPulseProps {
  phase?: string;
  isScanning?: boolean;
  className?: string;
}

interface Blip {
  id: string;
  angle: number;
  dist: number;
  status: "blocked" | "breached";
  label: string;
  severity: "critical" | "high" | "medium";
}

const RADAR_BLIPS: Blip[] = [
  { id: "A-01", angle: 35, dist: 0.72, status: "blocked", label: "Direct Injection", severity: "high" },
  { id: "A-04", angle: 115, dist: 0.85, status: "breached", label: "Canary Leakage", severity: "critical" },
  { id: "A-07", angle: 195, dist: 0.60, status: "breached", label: "PII Harvest", severity: "critical" },
  { id: "A-10", angle: 265, dist: 0.45, status: "blocked", label: "Tool Escalation", severity: "high" },
  { id: "A-06", angle: 320, dist: 0.78, status: "blocked", label: "Translation Bypass", severity: "medium" },
];

export default function ScanRadarPulse({
  phase = "Attack",
  isScanning = true,
  className = "",
}: ScanRadarPulseProps) {
  const [activeBlip, setActiveBlip] = useState<Blip | null>(null);
  const [telemetryLogs, setTelemetryLogs] = useState<string[]>([
    "T+002ms [RECON_PROBE] Handshake initiated with target /chat",
    "T+045ms [TOKEN_AUDIT] Verifying canary signature integrity",
    "T+112ms [ATTACK_SUITE] Vector A-04 dispatched (OWASP-LLM01)",
    "T+184ms [POLICY_GATEWAY] Tool authorization check: issue_refund intercepted",
    "T+242ms [DUAL_JUDGE] Deterministic regex hit: canary token corroborated",
  ]);

  useEffect(() => {
    if (!isScanning) return;
    const interval = setInterval(() => {
      const now = Math.floor(Math.random() * 400 + 100);
      const events = [
        `T+${now}ms [MUTATOR] Synthesizing roleplay evasion variant`,
        `T+${now + 30}ms [GATEWAY] Denied unverified refund authorization`,
        `T+${now + 65}ms [CANARY_PROBE] Zero token leakage confirmed`,
        `T+${now + 90}ms [UTILITY_RUNNER] Benign customer test verified (PASS)`,
        `T+${now + 120}ms [RADAR_SWEEP] Vector telemetry synced with state graph`,
      ];
      const randomEvent = events[Math.floor(Math.random() * events.length)];
      setTelemetryLogs((prev) => [...prev.slice(-4), randomEvent]);
    }, 3200);

    return () => clearInterval(interval);
  }, [isScanning]);

  const size = 260;
  const center = size / 2;
  const maxRadius = center - 18;

  // Arc calculation for 45-degree trailing sweep sector
  // When leading blade is at 12 o'clock (0, -maxRadius), trailing edge is at -45 deg (-sin(45), -cos(45))
  const sweepAngleDeg = 45;
  const sweepAngleRad = (sweepAngleDeg * Math.PI) / 180;
  const trailX = center - maxRadius * Math.sin(sweepAngleRad);
  const trailY = center - maxRadius * Math.cos(sweepAngleRad);
  const sweepPath = `M ${center} ${center} L ${center} ${center - maxRadius} A ${maxRadius} ${maxRadius} 0 0 0 ${trailX} ${trailY} Z`;

  return (
    <div className={`relative overflow-hidden rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5 shadow-2xl backdrop-blur-md ${className}`}>
      {/* Background ambient HUD grid */}
      <div className="absolute inset-0 bg-[radial-gradient(#2DD4BF_1px,transparent_1px)] [background-size:16px_16px] opacity-[0.03] pointer-events-none" />

      {/* Cyber Reticle Corner Accents */}
      <div className="absolute top-2 left-2 w-2.5 h-2.5 border-t border-l border-teal-500/40 pointer-events-none" />
      <div className="absolute top-2 right-2 w-2.5 h-2.5 border-t border-r border-teal-500/40 pointer-events-none" />
      <div className="absolute bottom-2 left-2 w-2.5 h-2.5 border-b border-l border-teal-500/40 pointer-events-none" />
      <div className="absolute bottom-2 right-2 w-2.5 h-2.5 border-b border-r border-teal-500/40 pointer-events-none" />

      {/* Header */}
      <div className="relative flex items-center justify-between border-b border-[var(--border-hairline)] pb-3 mb-4">
        <div className="flex items-center gap-2">
          <Radio className={`h-4 w-4 ${isScanning ? "text-teal-400 animate-pulse" : "text-zinc-500"}`} />
          <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-[var(--text-primary)]">
            Active Vector Radar & Telemetry
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
        {/* Animated Cyber Radar Display */}
        <div className="relative flex flex-col items-center justify-center">
          <svg
            width={size}
            height={size}
            viewBox={`0 0 ${size} ${size}`}
            className="overflow-visible select-none"
          >
            <defs>
              {/* Radar sweep trailing gradient */}
              <linearGradient id="radar-sweep-trail" x1="100%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor="#2DD4BF" stopOpacity="0.45" />
                <stop offset="60%" stopColor="#2DD4BF" stopOpacity="0.12" />
                <stop offset="100%" stopColor="#2DD4BF" stopOpacity="0" />
              </linearGradient>

              {/* Radial glow filter */}
              <filter id="radar-glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="2" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>

            {/* Radar Circular Background */}
            <circle
              cx={center}
              cy={center}
              r={maxRadius}
              fill="rgba(10, 20, 24, 0.4)"
              stroke="rgba(45, 212, 191, 0.25)"
              strokeWidth="1.5"
            />

            {/* Concentric distance rings */}
            {[0.25, 0.5, 0.75].map((rPct) => (
              <circle
                key={`ring-${rPct}`}
                cx={center}
                cy={center}
                r={maxRadius * rPct}
                fill="none"
                stroke="rgba(45, 212, 191, 0.14)"
                strokeWidth="1"
                strokeDasharray="3 3"
              />
            ))}

            {/* Range distance tags */}
            <text x={center + 3} y={center - maxRadius * 0.5 + 9} className="text-[7px] font-mono fill-teal-500/40">50%</text>
            <text x={center + 3} y={center - maxRadius * 0.75 + 9} className="text-[7px] font-mono fill-teal-500/40">75%</text>

            {/* Crosshair lines */}
            <line
              x1={center - maxRadius}
              y1={center}
              x2={center + maxRadius}
              y2={center}
              stroke="rgba(45, 212, 191, 0.22)"
              strokeWidth="1"
            />
            <line
              x1={center}
              y1={center - maxRadius}
              x2={center}
              y2={center + maxRadius}
              stroke="rgba(45, 212, 191, 0.22)"
              strokeWidth="1"
            />

            {/* Azimuth tick marks */}
            <text x={center} y={center - maxRadius - 5} textAnchor="middle" className="text-[8px] font-mono font-bold fill-teal-400/80">000°</text>
            <text x={center + maxRadius + 7} y={center + 3} textAnchor="start" className="text-[8px] font-mono fill-zinc-500">090°</text>
            <text x={center} y={center + maxRadius + 12} textAnchor="middle" className="text-[8px] font-mono fill-zinc-500">180°</text>
            <text x={center - maxRadius - 7} y={center + 3} textAnchor="end" className="text-[8px] font-mono fill-zinc-500">270°</text>

            {/* 360-Degree Hardware Rotating Sweep (Guaranteed Center Pivot via animateTransform) */}
            {isScanning ? (
              <g>
                <animateTransform
                  attributeName="transform"
                  type="rotate"
                  from={`0 ${center} ${center}`}
                  to={`360 ${center} ${center}`}
                  dur="4s"
                  repeatCount="indefinite"
                />
                {/* Trailing wedge sector */}
                <path d={sweepPath} fill="url(#radar-sweep-trail)" />
                {/* Leading sharp scanning blade */}
                <line
                  x1={center}
                  y1={center}
                  x2={center}
                  y2={center - maxRadius}
                  stroke="#2DD4BF"
                  strokeWidth="2"
                  filter="url(#radar-glow)"
                />
              </g>
            ) : null}

            {/* Center glowing radar hub */}
            <circle cx={center} cy={center} r="5" fill="rgba(45, 212, 191, 0.2)" />
            <circle cx={center} cy={center} r="2.5" fill="#2DD4BF" />

            {/* Target Blips */}
            {RADAR_BLIPS.map((blip) => {
              const rad = (blip.angle * Math.PI) / 180;
              const r = maxRadius * blip.dist;
              const bx = center + r * Math.cos(rad);
              const by = center + r * Math.sin(rad);
              const isBreach = blip.status === "breached";
              const isRight = bx >= center;

              return (
                <g
                  key={blip.id}
                  className="cursor-pointer transition-transform duration-150 hover:scale-125"
                  onMouseEnter={() => setActiveBlip(blip)}
                  onMouseLeave={() => setActiveBlip(null)}
                >
                  {/* Outer pulse echo for breached vectors */}
                  {isBreach ? (
                    <circle
                      cx={bx}
                      cy={by}
                      r="9"
                      fill="none"
                      stroke="#F43F5E"
                      strokeWidth="1.2"
                      className="animate-ping opacity-60"
                    />
                  ) : (
                    <circle
                      cx={bx}
                      cy={by}
                      r="7"
                      fill="none"
                      stroke="#2DD4BF"
                      strokeWidth="0.8"
                      className="opacity-40"
                    />
                  )}

                  {/* Solid blip core */}
                  <circle
                    cx={bx}
                    cy={by}
                    r={isBreach ? 4.5 : 3.5}
                    fill={isBreach ? "#F43F5E" : "#2DD4BF"}
                    className={isBreach ? "animate-pulse" : ""}
                    filter="url(#radar-glow)"
                  />

                  {/* Clean, Non-overlapping text anchor */}
                  <text
                    x={isRight ? bx + 8 : bx - 8}
                    y={by + 3}
                    textAnchor={isRight ? "start" : "end"}
                    className={`text-[9px] font-mono font-bold tracking-tight pointer-events-none drop-shadow ${
                      isBreach ? "fill-rose-400" : "fill-teal-300"
                    }`}
                  >
                    {blip.id}
                  </text>
                </g>
              );
            })}
          </svg>

          {/* Active Blip Mini HUD Badge */}
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
            </div>
          ) : (
            <div className="mt-2 text-[10px] font-mono text-zinc-500 flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-teal-400/50" />
              <span>Hover vector blips to inspect</span>
            </div>
          )}
        </div>

        {/* Real-time Telemetry HUD Console */}
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

          <div className="flex items-center justify-between px-1 text-[10px] text-zinc-500">
            <span>CHANNELS: 12 ATTACK / 10 BENIGN</span>
            <span className="text-teal-400 font-semibold tracking-wide">ZERO-LEAK ASSURANCE</span>
          </div>
        </div>
      </div>
    </div>
  );
}
