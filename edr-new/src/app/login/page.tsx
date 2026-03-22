"use client";

import { FormEvent, useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { AlertTriangle, BookOpen, Loader2 } from "lucide-react";

export default function LoginPage() {
  const { login, token } = useAuth();
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Already logged in — redirect
  useEffect(() => {
    if (token) router.replace("/");
  }, [token, router]);

  if (token) return null;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await login(username, password);
      router.replace("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      className="flex items-center justify-center min-h-screen px-4"
      style={{ background: "var(--bg)" }}
    >
      <div
        className="w-full max-w-sm rounded-lg border p-6"
        style={{
          background: "var(--surface-0)",
          borderColor: "var(--border)",
        }}
      >
        {/* Brand */}
        <div className="flex items-center justify-center gap-2 mb-6">
          <BookOpen size={24} style={{ color: "var(--primary)" }} />
          <span
            className="text-lg font-semibold tracking-wide"
            style={{
              fontFamily: "var(--font-space-grotesk)",
              color: "var(--primary)",
            }}
          >
            TRACEGUARD
          </span>
        </div>

        <h1
          className="text-center text-sm font-medium mb-6"
          style={{ color: "var(--muted)" }}
        >
          Sign in to the command center
        </h1>

        {error && (
          <div
            className="flex items-center gap-2 px-3 py-2 mb-4 rounded text-xs"
            style={{
              background: "oklch(0.55 0.22 25 / 0.1)",
              color: "var(--destructive)",
            }}
          >
            <AlertTriangle size={14} />
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label
              htmlFor="username"
              className="block text-[11px] font-medium uppercase tracking-wider mb-1"
              style={{ color: "var(--muted)" }}
            >
              Username
            </label>
            <input
              id="username"
              type="text"
              required
              autoComplete="username"
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-3 py-2 rounded border text-sm outline-none transition-colors focus-ring"
              style={{
                background: "var(--surface-1)",
                borderColor: "var(--border)",
                color: "var(--fg)",
              }}
            />
          </div>

          <div>
            <label
              htmlFor="password"
              className="block text-[11px] font-medium uppercase tracking-wider mb-1"
              style={{ color: "var(--muted)" }}
            >
              Password
            </label>
            <input
              id="password"
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 rounded border text-sm outline-none transition-colors focus-ring"
              style={{
                background: "var(--surface-1)",
                borderColor: "var(--border)",
                color: "var(--fg)",
              }}
            />
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="flex items-center justify-center gap-2 w-full py-2 rounded text-sm font-semibold transition-colors disabled:opacity-60"
            style={{
              background: "var(--primary)",
              color: "var(--primary-fg)",
            }}
          >
            {submitting && <Loader2 size={14} className="animate-spin" />}
            {submitting ? "Signing in..." : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
