"use client";

import React from "react";

interface InfoTooltipProps {
  /** Optional header title for the tooltip */
  title?: string;
  /** Primary explanatory content */
  content: React.ReactNode;
  /** Secondary note, displayed with subtle divider */
  footer?: React.ReactNode;
  /** Placement direction */
  placement?: "bottom" | "top" | "left" | "right";
  /** Optional custom width class, defaults to w-72 */
  widthClass?: string;
  /** Optional extra classes for the outer trigger container */
  className?: string;
}

/**
 * Reusable InfoTooltip component with glowing technical dark card
 * Triggered on both hover and keyboard focus for high accessibility.
 */
export default function InfoTooltip({
  title,
  content,
  footer,
  placement = "bottom",
  widthClass = "w-72",
  className = "",
}: InfoTooltipProps) {
  // Placement positioning
  const positionClasses = {
    bottom: "left-1/2 -translate-x-1/2 top-full mt-2",
    top: "left-1/2 -translate-x-1/2 bottom-full mb-2",
    left: "right-full top-1/2 -translate-y-1/2 mr-2",
    right: "left-full top-1/2 -translate-y-1/2 ml-2",
  }[placement];

  return (
    <div className={`group relative inline-flex items-center ml-1.5 align-middle ${className}`}>
      <span
        tabIndex={0}
        role="button"
        aria-label={title ? `Information about ${title}` : "Additional details"}
        className="inline-flex items-center justify-center h-4 w-4 rounded-full border border-teal-500/40 bg-teal-950/60 text-[10px] font-mono font-bold text-teal-300 hover:text-teal-100 hover:border-teal-400 cursor-help transition-all duration-150 select-none focus:outline-none focus:ring-1 focus:ring-teal-400"
      >
        i
      </span>

      <div
        role="tooltip"
        className={`pointer-events-none absolute ${positionClasses} ${widthClass} hidden group-hover:flex group-focus-within:flex flex-col rounded-md border border-teal-500/40 bg-[#090D13] p-3 text-[11px] font-sans font-normal leading-relaxed text-[var(--text-secondary)] shadow-2xl z-50 animate-fade-in`}
      >
        {title && (
          <div className="font-mono text-[10px] uppercase font-semibold text-teal-400 mb-1 flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-teal-400" />
            {title}
          </div>
        )}
        <div className="text-[var(--text-primary)] text-xs font-normal">
          {content}
        </div>
        {footer && (
          <div className="mt-2 text-[10px] text-[var(--text-muted)] border-t border-[var(--border-hairline)] pt-1.5">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}
