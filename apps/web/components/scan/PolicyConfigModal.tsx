"use client";

import { useState } from "react";
import { Check, Copy, Cpu, FileCode, ShieldAlert, X } from "lucide-react";
import type { HardeningProposal, TargetProfile } from "@/lib/types";

interface PolicyConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  scanId: string;
  targetId: string;
  proposal: HardeningProposal | null;
  profile: TargetProfile | null;
}

export default function PolicyConfigModal({
  isOpen,
  onClose,
  scanId,
  targetId,
  proposal,
  profile,
}: PolicyConfigModalProps) {
  const [activeTab, setActiveTab] = useState<"guard" | "yaml" | "manifest">("guard");
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  // Generate dynamic raven.yaml based on target
  const generatedYaml = `# RAVEN Autonomous Security Gate Configuration
version: "1"

target:
  id: "${targetId}"
  adapter: "${targetId.startsWith("http") ? "http" : targetId.startsWith("mcp") ? "mcp" : "local"}"
  url: "${targetId.startsWith("http") ? targetId : "http://localhost:8000/chat"}"
  headers:
    X-Raven-Scan-Consent: "true"
  request_template:
    message: "{prompt}"
  response_json_path: "response"
  timeout_seconds: 15.0

# CI/CD Pull Request Gate Threshold
fail_on: "high"
fail_on_breach: true

# Evaluation Budget Caps
budget:
  max_cases: 12
  max_attempts_per_attack: 2
  per_call_timeout_seconds: 10.0
  scan_timeout_seconds: 120.0

# Active Attack Categories
categories:
  - "direct_injection"
  - "canary_leakage"
  - "tool_misuse"
  - "sensitive_data"

sarif:
  output_file: "raven-report.sarif"

summary:
  output_file: "raven-summary.md"
`;

  // Format policy candidate or fallback
  const policyCandidateJson = proposal?.policy_candidate
    ? JSON.stringify(proposal.policy_candidate, null, 2)
    : proposal?.policy_diff
    ? proposal.policy_diff
    : JSON.stringify(
        {
          tool: "issue_refund",
          conditions: [
            "verified_order_id == true",
            "verified_user == true",
            "amount <= 500.0",
          ],
          high_value_action: "human_approval_required",
          on_violation: "deny_and_log",
        },
        null,
        2,
      );

  const manifestJson = JSON.stringify(
    {
      bundle_version: "1.0",
      scan_id: scanId,
      target_id: targetId,
      artifacts: {
        "report.sarif": "OASIS Standard Static Analysis Results (Level error/warning)",
        "summary.md": "Executive Security Assessment & Attack Success Rate Delta",
        "report.json": "Structured Domain Report Document",
        "findings.json": "Actionable Vulnerability Finding Ledger",
        "transcripts.json": "Redacted Cryptographic Trial Evidence",
        "checksums.sha256": "Cryptographic Manifest Integrity Verification",
      },
    },
    null,
    2,
  );

  const contentToCopy =
    activeTab === "guard"
      ? policyCandidateJson
      : activeTab === "yaml"
      ? generatedYaml
      : manifestJson;

  const handleCopy = () => {
    navigator.clipboard.writeText(contentToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-fade-in"
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
    >
      <div className="flex max-h-[85vh] w-full max-w-3xl flex-col rounded-[var(--radius-card)] border border-[var(--border-subtle)] bg-[var(--bg-surface)] shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[var(--border-hairline)] px-5 py-4 bg-[var(--bg-raised)]">
          <div className="flex items-center gap-2.5">
            <Cpu className="h-5 w-5 text-teal-400" />
            <div>
              <h2 id="modal-title" className="text-sm font-semibold font-mono uppercase tracking-wider text-[var(--text-primary)]">
                Runtime Guard & CI Configuration
              </h2>
              <p className="text-[11px] font-mono text-[var(--text-muted)]">
                Target: {targetId} · Scan: {scanId}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1.5 text-[var(--text-muted)] hover:bg-[var(--bg-base)] hover:text-[var(--text-primary)] transition-colors"
            aria-label="Close modal"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Tab switcher */}
        <div className="flex items-center justify-between border-b border-[var(--border-hairline)] px-5 py-2.5 bg-[var(--bg-base)] font-mono text-xs">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setActiveTab("guard")}
              className={`rounded px-3 py-1 font-medium transition-colors ${
                activeTab === "guard"
                  ? "bg-teal-500/20 text-teal-300 border border-teal-500/40"
                  : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              raven-guard Policy Candidate
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("yaml")}
              className={`rounded px-3 py-1 font-medium transition-colors ${
                activeTab === "yaml"
                  ? "bg-teal-500/20 text-teal-300 border border-teal-500/40"
                  : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              raven.yaml (CI Spec)
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("manifest")}
              className={`rounded px-3 py-1 font-medium transition-colors ${
                activeTab === "manifest"
                  ? "bg-teal-500/20 text-teal-300 border border-teal-500/40"
                  : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              Audit Manifest Spec
            </button>
          </div>

          <button
            type="button"
            onClick={handleCopy}
            className="inline-flex items-center gap-1.5 rounded border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-teal-500/40 transition-colors"
          >
            {copied ? (
              <>
                <Check className="h-3 w-3 text-teal-400" />
                <span className="text-teal-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="h-3 w-3" />
                <span>Copy</span>
              </>
            )}
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-5 font-mono text-xs space-y-4">
          {activeTab === "guard" && (
            <div className="space-y-3">
              <div className="rounded border border-teal-900/50 bg-teal-950/20 p-3 text-[11px] text-teal-300">
                <p className="font-semibold mb-1">Fail-Closed Runtime Enforcement</p>
                <p className="text-teal-300/80">
                  Compiled policy candidate generated by RAVEN Hardening Agent. Drop directly into
                  your application using <code className="text-teal-200">raven_guard.PolicyGateway</code> or LangChain/FastAPI middleware.
                </p>
              </div>
              <pre className="overflow-x-auto rounded border border-[var(--border-hairline)] bg-[var(--bg-base)] p-4 text-zinc-300 text-[11px] leading-relaxed">
                {policyCandidateJson}
              </pre>
            </div>
          )}

          {activeTab === "yaml" && (
            <div className="space-y-3">
              <div className="rounded border border-cyan-900/50 bg-cyan-950/20 p-3 text-[11px] text-cyan-300">
                <p className="font-semibold mb-1">Declarative CI/CD Gate</p>
                <p className="text-cyan-300/80">
                  Commit this file as <code className="text-cyan-200">raven.yaml</code> to run automated PR regression checks in GitHub Actions with zero manual configuration.
                </p>
              </div>
              <pre className="overflow-x-auto rounded border border-[var(--border-hairline)] bg-[var(--bg-base)] p-4 text-zinc-300 text-[11px] leading-relaxed">
                {generatedYaml}
              </pre>
            </div>
          )}

          {activeTab === "manifest" && (
            <div className="space-y-3">
              <div className="rounded border border-indigo-900/50 bg-indigo-950/20 p-3 text-[11px] text-indigo-300">
                <p className="font-semibold mb-1">Compliance Audit Bundle Architecture</p>
                <p className="text-indigo-300/80">
                  Exportable via <code className="text-indigo-200">GET /api/scans/{scanId}/bundle</code>. Contains signed cryptographic evidence with SHA-256 verification manifest.
                </p>
              </div>
              <pre className="overflow-x-auto rounded border border-[var(--border-hairline)] bg-[var(--bg-base)] p-4 text-zinc-300 text-[11px] leading-relaxed">
                {manifestJson}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-[var(--border-hairline)] px-5 py-3 bg-[var(--bg-raised)] font-mono text-xs">
          <span className="text-[11px] text-[var(--text-muted)]">
            RAVEN v1.0 · Autonomous AI Agent Defense
          </span>
          <button
            type="button"
            onClick={onClose}
            className="rounded bg-[var(--bg-base)] border border-[var(--border-subtle)] px-4 py-1.5 font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-teal-500/40 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
