"use client";

import { useState } from "react";
import Sidebar from "@/components/ui/Sidebar";
import { ProjectProvider } from "@/lib/project-context";

export default function RootShell({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <ProjectProvider>
      <div className="relative flex min-h-dvh">
        {/* Sidebar */}
        <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((v) => !v)} />

        {/* Main content area */}
        <div className="flex min-w-0 flex-1 flex-col">
          {children}

          {/* Footer disclaimer — all result screens */}
          <footer className="mt-auto border-t border-[var(--border-hairline)] px-6 py-3">
            <p className="text-[var(--text-xs)] text-[var(--text-muted)]">
              Results describe only the evaluated cases. Not a proof of security.
            </p>
          </footer>
        </div>
      </div>
    </ProjectProvider>
  );
}
