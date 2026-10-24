"use client";

import { useState } from "react";
import type { Report } from "@/lib/types";

const KIND_STYLES: Record<string, string> = {
  run: "bg-sky-950/60 text-sky-300 border-sky-800/40",
  transcript: "bg-violet-950/60 text-violet-300 border-violet-800/40",
  rule_check: "bg-green-950/60 text-green-300 border-green-800/40",
  model_call: "bg-amber-950/60 text-amber-300 border-amber-800/40",
  approval: "bg-zinc-800 text-zinc-300 border-zinc-700",
  test_run: "bg-indigo-950/60 text-indigo-300 border-indigo-800/40",
};

/** Evidence chain table with transcript inspection (report §evidence). */
export default function ReportEvidence({ report }: { report: Report }) {
  const [openRef, setOpenRef] = useState<string | null>(null);

  if (report.evidence.length === 0) {
    return <p className="text-xs text-zinc-500">No evidence entries recorded.</p>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead>
          <tr className="border-b border-zinc-800 text-zinc-500">
            <th className="py-1.5 pr-3 font-medium">Ref</th>
            <th className="py-1.5 pr-3 font-medium">Kind</th>
            <th className="py-1.5 font-medium">Description</th>
          </tr>
        </thead>
        <tbody>
          {report.evidence.map((entry) => (
            <tr key={`${entry.kind}:${entry.ref_id}`} className="border-b border-zinc-800/50 align-top last:border-0">
              <td className="py-1.5 pr-3 font-mono text-zinc-400">{entry.ref_id}</td>
              <td className="py-1.5 pr-3">
                <span
                  className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-medium ${KIND_STYLES[entry.kind] ?? "bg-zinc-800 text-zinc-300 border-zinc-700"}`}
                >
                  {entry.kind}
                </span>
              </td>
              <td className="py-1.5 text-zinc-400">
                {entry.description}
                {entry.transcript && (
                  <>
                    {" "}
                    <button
                      type="button"
                      onClick={() =>
                        setOpenRef(openRef === entry.ref_id ? null : entry.ref_id)
                      }
                      className="text-indigo-400 hover:text-indigo-300"
                    >
                      {openRef === entry.ref_id ? "hide transcript" : "view transcript"}
                    </button>
                    {openRef === entry.ref_id && (
                      <div className="mt-2 max-h-72 overflow-auto rounded-md border border-zinc-800 bg-zinc-950 p-2.5">
                        <p className="mb-1.5 font-mono text-[10px] text-zinc-600">
                          {entry.transcript.transcript_id}
                          {entry.transcript.truncated ? " · truncated" : ""}
                        </p>
                        {entry.transcript.messages.map((message, index) => (
                          <div key={index} className="mb-2 last:mb-0">
                            <p className="font-mono text-[10px] uppercase text-zinc-500">
                              {message.role}
                              {message.tool_name ? ` · ${message.tool_name}` : ""}
                            </p>
                            <p className="whitespace-pre-wrap font-mono text-[11px] text-zinc-300">
                              {message.content}
                            </p>
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
