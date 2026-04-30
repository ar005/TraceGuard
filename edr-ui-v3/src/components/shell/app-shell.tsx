"use client";

import { Sidebar } from "./sidebar";
import { useAuth } from "@/lib/auth";
import { useInactivityTimeout } from "@/hooks/use-inactivity-timeout";
import { LogOut, Clock } from "lucide-react";

/* ── Inactivity warning overlay ───────────────────────────────── */

function InactivityGuard() {
  const { logout } = useAuth();
  const { warningVisible, secondsLeft, dismiss } = useInactivityTimeout(logout);

  if (!warningVisible) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: "oklch(0 0 0 / 0.55)", backdropFilter: "blur(2px)" }}
    >
      <div
        className="flex flex-col gap-4 rounded-xl border shadow-2xl"
        style={{
          background: "var(--surface-0)",
          borderColor: "var(--border)",
          padding: "var(--space-8)",
          width: "min(360px, 90vw)",
        }}
      >
        {/* Icon + heading */}
        <div className="flex items-center gap-3">
          <div
            className="flex items-center justify-center rounded-lg"
            style={{
              width: 40, height: 40,
              background: "oklch(0.55 0.18 25 / 0.15)",
              color: "var(--sev-high)",
              flexShrink: 0,
            }}
          >
            <Clock size={20} />
          </div>
          <div>
            <p
              className="font-display font-bold"
              style={{ fontSize: "var(--text-sm)", color: "var(--fg)", fontFamily: "var(--font-archivo)" }}
            >
              Session Expiring
            </p>
            <p style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)" }}>
              You'll be logged out due to inactivity
            </p>
          </div>
        </div>

        {/* Countdown */}
        <div
          className="flex items-center justify-center rounded-lg"
          style={{
            padding: "var(--space-4)",
            background: "var(--surface-1)",
            border: "1px solid var(--border)",
          }}
        >
          <span
            className="font-display font-black tabular-nums"
            style={{
              fontSize: "var(--text-3xl)",
              color: secondsLeft <= 10 ? "var(--sev-critical)" : "var(--fg)",
              fontFamily: "var(--font-archivo)",
              letterSpacing: "-0.04em",
              lineHeight: 1,
            }}
          >
            {secondsLeft}s
          </span>
        </div>

        {/* Actions */}
        <div className="flex gap-2">
          <button
            onClick={dismiss}
            className="flex-1 rounded-lg border py-2 text-xs font-semibold transition-fast hover:bg-[var(--primary)]/10"
            style={{
              borderColor: "var(--primary)",
              color: "var(--primary)",
              fontFamily: "var(--font-archivo)",
            }}
          >
            Stay Logged In
          </button>
          <button
            onClick={logout}
            className="flex items-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-medium transition-fast hover:bg-[var(--surface-2)]"
            style={{ borderColor: "var(--border)", color: "var(--fg-3)" }}
          >
            <LogOut size={12} />
            Logout
          </button>
        </div>
      </div>
    </div>
  );
}

/* ── Shell ─────────────────────────────────────────────────────── */

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
      <InactivityGuard />
    </div>
  );
}
