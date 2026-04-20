"use client";

import { Sidebar } from "./sidebar";

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen overflow-hidden" style={{ background: "var(--bg)" }}>
      <Sidebar />
      <main
        className="flex-1 min-w-0 overflow-y-auto"
        style={{ padding: "var(--space-6)" }}
      >
        {children}
      </main>
    </div>
  );
}
