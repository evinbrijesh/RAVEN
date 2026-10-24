/**
 * SSE client for GET /api/scans/{id}/events.
 *
 * Wraps EventSource with:
 *  - automatic reconnect with capped backoff (EventSource reconnects natively,
 *    but only while the connection is open; we handle fatal HTTP errors),
 *  - connection-state callbacks (connecting | open | closed | error),
 *  - terminal-event detection (`stream_end` or scan_completed/scan_failed)
 *    so the stream is closed cleanly instead of spinning.
 */
import { API_BASE_URL } from "./api-client";
import type { EventKind, ScanEvent } from "./types";

export type SseConnectionState = "connecting" | "open" | "closed" | "error";

/** Events that mean the scan reached a terminal state; close the stream. */
const TERMINAL_EVENT_KINDS: readonly EventKind[] = [
  "stream_end",
  "scan_completed",
  "scan_failed",
];

export interface SseClientOptions {
  /** Called for every event received on the stream. */
  onEvent: (event: ScanEvent) => void;
  /** Called when the connection state changes. */
  onStateChange?: (state: SseConnectionState) => void;
  /** Max reconnect attempts before giving up (default 10). */
  maxReconnectAttempts?: number;
}

export interface SseClient {
  close(): void;
}

export function connectScanEvents(
  scanId: string,
  options: SseClientOptions,
): SseClient {
  const { onEvent, onStateChange, maxReconnectAttempts = 10 } = options;
  const url = `${API_BASE_URL}/api/scans/${encodeURIComponent(scanId)}/events`;

  let source: EventSource | null = null;
  let closed = false;
  let attempts = 0;
  let backoffMs = 1000;

  function setState(state: SseConnectionState): void {
    if (!closed) options.onStateChange?.(state);
  }

  function open(): void {
    if (closed) return;
    setState("connecting");
    source = new EventSource(url);

    source.onopen = () => {
      attempts = 0;
      backoffMs = 1000;
      setState("open");
    };

    // Named SSE events (event: <kind>); EventSource requires explicit
    // listeners per event name, so register one for every known kind.
    for (const kind of TERMINAL_EVENT_KINDS) {
      source.addEventListener(kind, (ev: MessageEvent<string>) => {
        setState("open");
        dispatch(kind, ev.data);
        // Terminal: the API closes the stream after these; stop listening.
        shutdown();
      });
    }

    // All non-terminal named kinds.
    const nonTerminal: EventKind[] = [
      "scan_created",
      "phase_changed",
      "recon_completed",
      "attack_started",
      "attack_finished",
      "verdict_created",
      "hardening_proposed",
      "approval_received",
      "retest_started",
      "regression_saved",
      "error",
    ];
    for (const kind of nonTerminal) {
      source.addEventListener(kind, (ev: MessageEvent<string>) => {
        setState("open");
        dispatch(kind, ev.data);
      });
    }

    source.onerror = () => {
      if (closed) return;
      // readyState CONNECTING means the browser is retrying on its own.
      if (source?.readyState === EventSource.CONNECTING) {
        setState("error");
        return;
      }
      // CLOSED: give up on the native retry and reconnect manually with
      // backoff so a temporarily-down API does not spin forever.
      source?.close();
      source = null;
      setState("error");
      attempts += 1;
      if (attempts > maxReconnectAttempts) {
        shutdown();
        return;
      }
      setTimeout(open, backoffMs);
      backoffMs = Math.min(backoffMs * 2, 10_000);
    };
  }

  function dispatch(kind: EventKind, data: string | undefined): void {
    let payload: Record<string, unknown> = {};
    if (data) {
      try {
        payload = JSON.parse(data) as Record<string, unknown>;
      } catch {
        // Treat unparseable payloads as untrusted data, not a fatal error.
        payload = { raw: data };
      }
    }
    onEvent({ kind, ...payload });
  }

  function shutdown(): void {
    closed = true;
    source?.close();
    source = null;
    setState("closed");
  }

  open();

  return {
    close: shutdown,
  };
}
