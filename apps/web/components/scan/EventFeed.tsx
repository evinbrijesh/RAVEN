"use client";

import { useEffect, useRef, useState } from "react";
import { connectScanEvents, type SseConnectionState } from "@/lib/sse-client";
import type { ScanEvent } from "@/lib/types";

const MAX_EVENTS = 200;

const KIND_ICONS: Record<string, string> = {
  scan_created: "🆕",
  phase_changed: "🔀",
  recon_completed: "🔍",
  attack_started: "⚔️",
  attack_finished: "✅",
  verdict_created: "⚖️",
  hardening_proposed: "🛠️",
  approval_received: "🙋",
  retest_started: "🔁",
  regression_saved: "📉",
  scan_completed: "🏁",
  scan_failed: "💥",
  error: "⚠️",
  stream_end: "🔌",
};

function describeEvent(event: ScanEvent): string {
  const parts: string[] = [];
  if (typeof event.attack_id === "string") parts.push(event.attack_id);
  if (typeof event.category === "string") parts.push(event.category);
  if (typeof event.label === "string") parts.push(event.label);
  if (typeof event.phase === "string") parts.push(`phase=${event.phase}`);
  if (typeof event.status === "string") parts.push(`status=${event.status}`);
  if (typeof event.message === "string") parts.push(event.message);
  if (parts.length === 0) {
    const extra = Object.entries(event)
      .filter(([key]) => key !== "kind")
      .slice(0, 3)
      .map(([key, value]) => `${key}=${String(value)}`);
    parts.push(...extra);
  }
  return parts.join(" · ") || "—";
}

/** Live SSE progress feed for a scan. */
export default function EventFeed({
  scanId,
  onEvent,
  onStateChange,
}: {
  scanId: string;
  /** Optional observer for every event (used by the page to refresh data). */
  onEvent?: (event: ScanEvent) => void;
  /** Optional observer for connection state changes. */
  onStateChange?: (state: SseConnectionState) => void;
}) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [state, setState] = useState<SseConnectionState>("connecting");
  const feedRef = useRef<HTMLDivElement | null>(null);

  // Keep latest callbacks without re-subscribing the stream.
  const onEventRef = useRef(onEvent);
  const onStateChangeRef = useRef(onStateChange);
  useEffect(() => {
    onEventRef.current = onEvent;
    onStateChangeRef.current = onStateChange;
  }, [onEvent, onStateChange]);

  useEffect(() => {
    const client = connectScanEvents(scanId, {
      onEvent: (event) => {
        setEvents((prev) => [...prev.slice(-(MAX_EVENTS - 1)), event]);
        onEventRef.current?.(event);
      },
      onStateChange: (next) => {
        setState(next);
        onStateChangeRef.current?.(next);
      },
      maxReconnectAttempts: 10,
    });
    return () => client.close();
  }, [scanId]);

  // Keep the newest event in view.
  useEffect(() => {
    feedRef.current?.scrollTo({ top: feedRef.current.scrollHeight });
  }, [events.length]);

  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-900/50">
      <header className="flex items-center justify-between border-b border-zinc-800 px-4 py-2.5">
        <h2 className="text-sm font-medium text-zinc-300">Live progress</h2>
        <span className="flex items-center gap-2 text-xs text-zinc-500">
          <span
            aria-hidden
            className={`h-2 w-2 rounded-full ${
              state === "open"
                ? "bg-emerald-400"
                : state === "connecting"
                  ? "animate-pulse bg-amber-400"
                  : state === "error"
                    ? "bg-red-400"
                    : "bg-zinc-600"
            }`}
          />
          {state === "open"
            ? "streaming"
            : state === "connecting"
              ? "connecting…"
              : state === "error"
                ? "reconnecting…"
                : "stream ended"}
        </span>
      </header>
      <div
        ref={feedRef}
        className="max-h-72 space-y-1 overflow-y-auto p-3 font-mono text-xs"
        aria-live="polite"
      >
        {events.length === 0 ? (
          <p className="p-3 text-zinc-500">
            Waiting for scan events… (the worker emits them as the scan runs)
          </p>
        ) : (
          events.map((event, index) => (
            <div
              key={`${index}-${event.kind}`}
              className="flex items-start gap-2 rounded px-2 py-1 hover:bg-zinc-900"
            >
              <span aria-hidden>{KIND_ICONS[event.kind] ?? "•"}</span>
              <span className="shrink-0 text-indigo-300">{event.kind}</span>
              <span className="min-w-0 break-all text-zinc-400">
                {describeEvent(event)}
              </span>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
