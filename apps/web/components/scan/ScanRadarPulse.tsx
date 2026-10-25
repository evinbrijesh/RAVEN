"use client";

import { useState, useEffect } from "react";
import { Activity, Radio, Shield, Terminal, Zap } from "lucide-react";

export interface ScanRadarPulseProps {
  phase?: string;
  isScanning?: boolean;
  className?: string;
}

const RADAR_BLIPS = [
  { id: "A-01", angle: 35, dist: 0.72, status: "blocked", label: "Direct Injection" },
  { id: "A-04", angle: 110, dist: 0.85, status: "breached", label: "Canary Leak" },
  { id: "A-07", angle: 195, dist: 0.60, status: "breached", label: "PII Harvest" },
  { id: "A-10", angle: 260, dist: 0.45, status: "blocked", label: "Tool Escalation" },
  { id: "A-06", angle: 320, dist: 0.78, status: "blocked", label: "Translation Bypass" },
];

export default function ScanRadarPulse({
  phase = "Attack",
  isScanning = true,
  className = "",
}: ScanRadarPulseProps) {
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
      ];
      const randomEvent = events[Math.floor(Math.random() * events.length)];
      setTelemetryLogs((prev) => [...prev.slice(-5), randomEvent]);
    }, 3500);

    return () => clearInterval(interval);
  }, [isScanning]);

  const size = 260;
  const center = size / 2;

  return (
    <div className={`relative overflow-hidden rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5 shadow-2xl backdrop-blur-md ${className}`}>
      {/* Background ambient HUD grid */}
      <div className="absolute inset-0 bg-[radial-gradient(#2DD4BF_1px,transparent_1px)] [background-size:16px_16px] opacity-[0.03] pointer-events-none" />

      {/* Header */}
      <div className="relative flex items-center justify-between border-b border-[var(--border-hairline)] pb-3 mb-4">
        <div className="flex items-center gap-2">
          <Radio className="h-4 w-4 text-teal-400 animate-pulse" />
          <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-[var(--text-primary)]">
            Active Vector Radar & Telemetry
          </h4>
        </div>
        <div className="flex items-center gap-2 font-mono text-[10px]">
          <span className="flex h-2 w-2 rounded-full bg-teal-400 animate-ping" />
          <span className="text-teal-400 font-bold uppercase tracking-wider">
            {isScanning ? "SWEEP ACTIVE" : "IDLE"}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-[260px_1fr] gap-6 items-center">
        {/* Animated Cyber Radar SVG */}
        <div className="relative flex items-center justify-center">
          <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="overflow-visible">
            <defs>
              {/* Radar sweep conic gradient */}
              <linearGradient id="radar-sweep-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#2DD4BF" stopOpacity="0.4" />
                <stop offset="100%" stopColor="#2DD4BF" stopOpacity="0" />
              </linearGradient>
            </defs>

            {/* Concentric radar rings */}
            {[0.25, 0.5, 0.75, 1.0].map((rPct) => (
              <circle
                key={`ring-${rPct}`}
                cx={center}
                cy={center}
                r={(center - 10) * rPct}
                fill="none"
                stroke="rgba(45, 212, 191, 0.15)"
                strokeWidth="1"
                strokeDasharray={rPct === 1.0 ? undefined : "3 3"}
              />
            ))}

            {/* Crosshair lines */}
            <line
              x1={10}
              y1={center}
              x2={size - 10}
              y2={center}
              stroke="rgba(45, 212, 191, 0.2)"
              strokeWidth="1"
            />
            <line
              x1={center}
              y1={10}
              x2={center}
              y2={size - 10}
              stroke="rgba(45, 212, 191, 0.2)"
              strokeWidth="1"
            />

            {/* Rotating Radar Sweep Blade */}
            {isScanning && (
              <g className="origin-center animate-[spin_4s_linear_infinite]">
                <path
                  d={`M ${center} ${center} L ${center} 10 A ${center - 10} ${center - 10} 0 0 1 ${
                    center + (center - 10) * Math.sin(Math.PI / 4)
                  } ${center - (center - 10) * Math.cos(Math.PI / 4)} Z`}
                  fill="url(#radar-sweep-grad)"
                />
                <line
                  x1={center}
                  y1={center}
                  x2={center}
                  y2={10}
                  stroke="#2DD4BF"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                />
              </g>
            )}

            {/* Target Blips */}
            {RADAR_BLIPS.map((blip) => {
              const rad = (blip.angle * Math.PI) / 180;
              const r = (center - 15) * blip.dist;
              const bx = center + r * Math.cos(rad);
              const by = center + r * Math.sin(rad);

              const isBreach = blip.status === "breached";

              return (
                <g key={blip.id} className="cursor-pointer group">
                  <circle
                    cx={bx}
                    cy={by}
                    r={isBreach ? "6" : "4"}
                    fill={isBreach ? "#F43F5E" : "#2DD4BF"}
                    className={isBreach ? "animate-pulse" : ""}
                  />
                  {isBreach && (
                    <circle
                      cx={bx}
                      cy={by}
                      r="10"
                      fill="none"
                      stroke="#F43F5E"
                      strokeWidth="1"
                      className="animate-ping opacity-75"
                    />
                  )}
                  <text
                    x={bx + 8}
                    y={by + 3}
                    className={`text-[9px] font-mono font-bold ${
                      isBreach ? "fill-rose-400" : "fill-teal-300"
                    }`}
                  >
                    {blip.id}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Real-time Telemetry HUD Console */}
        <div className="space-y-3 font-mono text-xs">
          <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-base)] p-3.5 space-y-2">
            <div className="flex items-center justify-between text-[11px] text-zinc-500 border-b border-[var(--border-hairline)] pb-1.5">
              <span className="flex items-center gap-1.5 text-teal-400 font-semibold">
                <Terminal className="h-3.5 w-3.5" /> TELEMETRY STREAM
              </span>
              <span>1000/s BUFFER</span>
            </div>

            <div className="space-y-1.5 text-[11px] leading-relaxed">
              {telemetryLogs.map((log, idx) => (
                <div
                  key={idx}
                  className={`truncate ${
                    log.includes("breached") || log.includes("CANARY")
                      ? "text-rose-300"
                      : log.includes("GATEWAY") || log.includes("POLICY")
                      ? "text-teal-300"
                      : "text-zinc-400"
                  }`}
                >
                  <span className="text-zinc-600 mr-1.5">›</span>
                  {log}
                </div>
              ))}
            </div>
          </div>

          <div className="flex items-center justify-between px-1 text-[10px] text-zinc-500">
            <span>CHANNELS: 12 ATTACK / 10 BENIGN</span>
            <span className="text-teal-400 font-semibold">ZERO-LEAK ASSURANCE</span>
          </div>
        </div>
      </div>
    </div>
  );
}
