"use client";

import { useState } from "react";

export interface FrontierChartProps {
  beforeSecurity?: number; // 0 to 1 (Attack block rate)
  afterSecurity?: number;  // 0 to 1 (Attack block rate)
  beforeUtility?: number;  // 0 to 1 (Benign success rate)
  afterUtility?: number;   // 0 to 1 (Benign success rate)
  overRefusalRate?: number; // 0 to 100
  className?: string;
}

export default function FrontierChart({
  beforeSecurity = 0.20,
  afterSecurity = 0.90,
  beforeUtility = 0.95,
  afterUtility = 0.94,
  overRefusalRate = 0,
  className = "",
}: FrontierChartProps) {
  const [hoveredPoint, setHoveredPoint] = useState<"before" | "after" | null>(null);

  // SVG dimensions
  const width = 560;
  const height = 340;
  const padLeft = 60;
  const padRight = 40;
  const padTop = 30;
  const padBottom = 50;

  const chartW = width - padLeft - padRight;
  const chartH = height - padTop - padBottom;

  // Convert (utility [0,1], security [0,1]) to SVG coords
  const toX = (utility: number) => padLeft + Math.max(0, Math.min(1, utility)) * chartW;
  const toY = (security: number) => padTop + (1 - Math.max(0, Math.min(1, security))) * chartH;

  const beforeX = toX(beforeUtility);
  const beforeY = toY(beforeSecurity);

  const afterX = toX(afterUtility);
  const afterY = toY(afterSecurity);

  // Midpoints for 50% quadrant split
  const midX = padLeft + 0.5 * chartW;
  const midY = padTop + 0.5 * chartH;

  const secDelta = Math.round((afterSecurity - beforeSecurity) * 100);
  const utilDelta = Math.round((afterUtility - beforeUtility) * 100);

  return (
    <div className={`relative rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5 shadow-2xl backdrop-blur-sm ${className}`}>
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border-hairline)] pb-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex h-2.5 w-2.5 items-center justify-center">
              <span className="h-2 w-2 rounded-full bg-teal-400 animate-pulse" />
            </span>
            <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-[var(--text-primary)]">
              Security vs. Utility Frontier (2D Pareto Assurance)
            </h4>
          </div>
          <p className="mt-0.5 text-[11px] text-[var(--text-muted)]">
            Quantifies attack defense gains against legitimate business task preservation
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="rounded border border-teal-500/30 bg-teal-950/40 px-2 py-0.5 text-teal-300 font-semibold">
            Δ Security: {secDelta >= 0 ? `+${secDelta}%` : `${secDelta}%`}
          </span>
          <span className={`rounded border px-2 py-0.5 font-semibold ${
            utilDelta >= 0 ? "border-emerald-500/30 bg-emerald-950/40 text-emerald-300" : "border-zinc-700 bg-zinc-900 text-zinc-300"
          }`}>
            Δ Utility: {utilDelta >= 0 ? `+${utilDelta}%` : `${utilDelta}%`}
          </span>
          {overRefusalRate > 0 && (
            <span className="rounded border border-amber-500/30 bg-amber-950/40 px-2 py-0.5 text-amber-300 font-semibold">
              Paranoia: {overRefusalRate.toFixed(1)}%
            </span>
          )}
        </div>
      </div>

      {/* SVG Canvas */}
      <div className="relative flex justify-center">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="w-full max-w-[620px] select-none overflow-visible"
        >
          <defs>
            {/* Arrowhead marker */}
            <marker
              id="frontier-arrow"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#2DD4BF" />
            </marker>

            {/* Shift vector gradient */}
            <linearGradient id="shift-grad" x1="0%" y1="100%" x2="0%" y2="0%">
              <stop offset="0%" stopColor="#F43F5E" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#2DD4BF" stopOpacity="1" />
            </linearGradient>

            {/* Target Safety Glow Filter */}
            <filter id="teal-glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Quadrant Background Tints */}
          {/* Top-Right: Target Safety Frontier (High Sec, High Util) */}
          <rect
            x={midX}
            y={padTop}
            width={chartW / 2}
            height={chartH / 2}
            fill="rgba(16, 185, 129, 0.05)"
            stroke="rgba(16, 185, 129, 0.15)"
            strokeDasharray="3 3"
          />
          {/* Bottom-Right: Productive but Vulnerable (Low Sec, High Util) */}
          <rect
            x={midX}
            y={midY}
            width={chartW / 2}
            height={chartH / 2}
            fill="rgba(244, 63, 94, 0.03)"
          />
          {/* Top-Left: Brittle Over-Refusal (High Sec, Low Util) */}
          <rect
            x={padLeft}
            y={padTop}
            width={chartW / 2}
            height={chartH / 2}
            fill="rgba(245, 158, 11, 0.03)"
          />
          {/* Bottom-Left: Critical Risk (Low Sec, Low Util) */}
          <rect
            x={padLeft}
            y={midY}
            width={chartW / 2}
            height={chartH / 2}
            fill="rgba(220, 38, 38, 0.05)"
          />

          {/* Quadrant Label Watermarks */}
          <text
            x={midX + chartW / 4}
            y={padTop + 24}
            textAnchor="middle"
            className="text-[10px] font-mono font-bold uppercase tracking-wider fill-emerald-400/40"
          >
            ★ Target Safety Frontier
          </text>
          <text
            x={midX + chartW / 4}
            y={height - padBottom - 14}
            textAnchor="middle"
            className="text-[10px] font-mono font-medium uppercase tracking-wider fill-rose-400/30"
          >
            Vulnerable Productive
          </text>
          <text
            x={padLeft + chartW / 4}
            y={padTop + 24}
            textAnchor="middle"
            className="text-[10px] font-mono font-medium uppercase tracking-wider fill-amber-400/30"
          >
            Brittle Over-Refusal
          </text>
          <text
            x={padLeft + chartW / 4}
            y={height - padBottom - 14}
            textAnchor="middle"
            className="text-[10px] font-mono font-medium uppercase tracking-wider fill-red-500/25"
          >
            Critical Risk Zone
          </text>

          {/* Grid lines */}
          {[0, 0.25, 0.5, 0.75, 1].map((pctVal) => {
            const y = toY(pctVal);
            const x = toX(pctVal);
            return (
              <g key={`grid-${pctVal}`}>
                {/* Horizontal gridline */}
                <line
                  x1={padLeft}
                  y1={y}
                  x2={width - padRight}
                  y2={y}
                  stroke="rgba(255,255,255,0.06)"
                  strokeWidth={pctVal === 0.5 ? 1.5 : 1}
                  strokeDasharray={pctVal === 0.5 ? "4 4" : undefined}
                />
                {/* Y-axis tick label */}
                <text
                  x={padLeft - 8}
                  y={y + 3.5}
                  textAnchor="end"
                  className="text-[10px] font-mono fill-zinc-500"
                >
                  {Math.round(pctVal * 100)}%
                </text>

                {/* Vertical gridline */}
                <line
                  x1={x}
                  y1={padTop}
                  x2={x}
                  y2={height - padBottom}
                  stroke="rgba(255,255,255,0.06)"
                  strokeWidth={pctVal === 0.5 ? 1.5 : 1}
                  strokeDasharray={pctVal === 0.5 ? "4 4" : undefined}
                />
                {/* X-axis tick label */}
                <text
                  x={x}
                  y={height - padBottom + 16}
                  textAnchor="middle"
                  className="text-[10px] font-mono fill-zinc-500"
                >
                  {Math.round(pctVal * 100)}%
                </text>
              </g>
            );
          })}

          {/* Axes Titles */}
          {/* Y Axis Title */}
          <text
            transform={`rotate(-90 ${padLeft - 40} ${padTop + chartH / 2})`}
            x={padLeft - 40}
            y={padTop + chartH / 2}
            textAnchor="middle"
            className="text-[11px] font-mono font-medium tracking-wide fill-zinc-400"
          >
            ← Attack Block Rate (Security %)
          </text>

          {/* X Axis Title */}
          <text
            x={padLeft + chartW / 2}
            y={height - padBottom + 36}
            textAnchor="middle"
            className="text-[11px] font-mono font-medium tracking-wide fill-zinc-400"
          >
            Legitimate Task Completion (Utility %) →
          </text>

          {/* Shift Vector Line (Before -> After) */}
          <line
            x1={beforeX}
            y1={beforeY}
            x2={afterX}
            y2={afterY}
            stroke="url(#shift-grad)"
            strokeWidth="2.5"
            strokeDasharray="4 3"
            markerEnd="url(#frontier-arrow)"
          />

          {/* Vector Shift Label Chip */}
          <g transform={`translate(${(beforeX + afterX) / 2 + 10}, ${(beforeY + afterY) / 2 - 6})`}>
            <rect
              x="-6"
              y="-12"
              width="80"
              height="20"
              rx="4"
              fill="#0A0D12"
              stroke="#2DD4BF"
              strokeWidth="0.8"
            />
            <text
              x="34"
              y="2"
              textAnchor="middle"
              className="text-[9px] font-mono font-bold fill-teal-300"
            >
              +{secDelta}% Defended
            </text>
          </g>

          {/* Point 1: Before Hardening (Red/Rose) */}
          <g
            className="cursor-pointer"
            onMouseEnter={() => setHoveredPoint("before")}
            onMouseLeave={() => setHoveredPoint(null)}
          >
            <circle
              cx={beforeX}
              cy={beforeY}
              r="10"
              fill="rgba(244, 63, 94, 0.2)"
              className="animate-ping"
            />
            <circle
              cx={beforeX}
              cy={beforeY}
              r="6"
              fill="#F43F5E"
              stroke="#FFFFFF"
              strokeWidth="1.5"
            />
            <text
              x={beforeX + 10}
              y={beforeY + 4}
              className="text-[10px] font-mono font-bold fill-rose-300"
            >
              Before ({Math.round(beforeUtility * 100)}%, {Math.round(beforeSecurity * 100)}%)
            </text>
          </g>

          {/* Point 2: After Hardening (Teal/Emerald Star) */}
          <g
            className="cursor-pointer"
            onMouseEnter={() => setHoveredPoint("after")}
            onMouseLeave={() => setHoveredPoint(null)}
            filter="url(#teal-glow)"
          >
            <circle
              cx={afterX}
              cy={afterY}
              r="14"
              fill="rgba(45, 212, 191, 0.25)"
            />
            <circle
              cx={afterX}
              cy={afterY}
              r="7"
              fill="#2DD4BF"
              stroke="#0A0D12"
              strokeWidth="2"
            />
            <text
              x={afterX - 12}
              y={afterY - 12}
              textAnchor="end"
              className="text-[11px] font-mono font-bold fill-teal-300"
            >
              ★ Hardened ({Math.round(afterUtility * 100)}%, {Math.round(afterSecurity * 100)}%)
            </text>
          </g>
        </svg>
      </div>

      {/* Legend & Frontier Interpretation */}
      <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3 border-t border-[var(--border-hairline)] pt-3 text-xs font-mono">
        <div className="flex items-center gap-2">
          <span className="h-3 w-3 rounded-full bg-rose-500 flex-shrink-0" />
          <span className="text-[var(--text-secondary)]">
            <strong className="text-rose-400">Baseline (Pre-Hardening):</strong> Vulnerable to injection and secret leaks.
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="h-3 w-3 rounded-full bg-teal-400 flex-shrink-0" />
          <span className="text-[var(--text-secondary)]">
            <strong className="text-teal-400">Hardened State:</strong> Robust attack defense with zero utility degradation.
          </span>
        </div>
      </div>
    </div>
  );
}
