"use client";

import type { TargetProfile } from "@/lib/types";
import { Terminal, Shield, Key, Wrench, FileCode, CheckCircle, AlertCircle } from "lucide-react";

interface ReconProfileCardProps {
  profile?: TargetProfile | null;
  targetId?: string;
}

export default function ReconProfileCard({ profile, targetId }: ReconProfileCardProps) {
  if (!profile) {
    return (
      <div className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-4 text-xs font-mono text-zinc-500">
        <div className="flex items-center gap-2 text-zinc-400">
          <Terminal className="h-4 w-4 text-[var(--accent)]" />
          <span className="font-semibold uppercase tracking-wider">Target Recon Profile</span>
        </div>
        <p className="mt-2 text-zinc-500 italic">Recon probe pending or target profile not yet indexed.</p>
      </div>
    );
  }

  const hasCanary = Boolean(profile.canary_token && profile.canary_token.trim().length > 0);

  return (
    <div className="rounded-[var(--radius-card)] border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-4 text-xs font-sans">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border-hairline)] pb-3">
        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-md border border-teal-500/30 bg-teal-950/40 text-[var(--accent)]">
            <Terminal className="h-3.5 w-3.5" />
          </div>
          <div>
            <h3 className="font-semibold text-[var(--text-primary)] font-mono text-xs uppercase tracking-wider">
              Recon Posture Profile
            </h3>
            <p className="text-[10px] text-[var(--text-muted)] font-mono">
              Target: <span className="text-zinc-300">{profile.target_id || targetId || "unknown"}</span> · Version: {profile.version}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1 rounded bg-teal-950/60 border border-teal-800/40 px-2 py-0.5 text-[10px] font-mono font-medium text-teal-300">
            <Shield className="h-2.5 w-2.5" />
            Passive Recon
          </span>
        </div>
      </div>

      <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
        {/* System Prompt Fingerprint */}
        <div className="rounded border border-[var(--border-hairline)] bg-[var(--bg-base)] p-2.5">
          <div className="flex items-center justify-between text-[10px] text-[var(--text-muted)] uppercase font-mono">
            <span className="flex items-center gap-1">
              <FileCode className="h-3 w-3 text-zinc-400" />
              Prompt SHA-256
            </span>
          </div>
          <p className="mt-1 font-mono text-[11px] text-zinc-300 truncate" title={profile.system_prompt_hash}>
            {profile.system_prompt_hash ? `${profile.system_prompt_hash.slice(0, 16)}…` : "Not hashed"}
          </p>
        </div>

        {/* Canary Token Presence */}
        <div className="rounded border border-[var(--border-hairline)] bg-[var(--bg-base)] p-2.5">
          <div className="flex items-center justify-between text-[10px] text-[var(--text-muted)] uppercase font-mono">
            <span className="flex items-center gap-1">
              <Key className="h-3 w-3 text-amber-400" />
              Canary Detection
            </span>
            {hasCanary ? (
              <span className="text-emerald-400 font-bold flex items-center gap-0.5">
                <CheckCircle className="h-2.5 w-2.5" /> Embedded
              </span>
            ) : (
              <span className="text-zinc-500 flex items-center gap-0.5">
                <AlertCircle className="h-2.5 w-2.5" /> None
              </span>
            )}
          </div>
          <p className="mt-1 font-mono text-[11px] text-zinc-300 truncate">
            {hasCanary ? "RAVEN-CANARY-***" : "No token tracked"}
          </p>
        </div>

        {/* Discovered Tools */}
        <div className="rounded border border-[var(--border-hairline)] bg-[var(--bg-base)] p-2.5 sm:col-span-2 md:col-span-1">
          <div className="flex items-center justify-between text-[10px] text-[var(--text-muted)] uppercase font-mono">
            <span className="flex items-center gap-1">
              <Wrench className="h-3 w-3 text-indigo-400" />
              Tools Exposed
            </span>
            <span className="font-mono text-zinc-400">{profile.tools.length}</span>
          </div>
          <div className="mt-1 flex flex-wrap gap-1">
            {profile.tools.length > 0 ? (
              profile.tools.map((tool) => (
                <span
                  key={tool}
                  className="rounded bg-zinc-800/80 px-1.5 py-0.5 font-mono text-[10px] text-zinc-300 border border-zinc-700/60"
                >
                  {tool}
                </span>
              ))
            ) : (
              <span className="text-[11px] text-zinc-500 font-mono italic">No external tools detected</span>
            )}
          </div>
        </div>
      </div>

      {profile.notes && profile.notes.length > 0 && (
        <div className="mt-2.5 pt-2 border-t border-[var(--border-hairline)]">
          <p className="text-[10px] text-[var(--text-muted)] font-mono uppercase mb-1">Target Surface Notes</p>
          <ul className="space-y-0.5 text-[11px] text-zinc-400 font-mono">
            {profile.notes.map((note, i) => (
              <li key={i} className="flex items-center gap-1.5">
                <span className="text-[var(--accent)]">›</span> {note}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
