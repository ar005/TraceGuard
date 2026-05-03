"use client";

import { FormEvent, useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { AlertTriangle, BookOpen, Eye, EyeOff, Loader2, ShieldCheck } from "lucide-react";

export default function LoginPage() {
  const { login, verifyTOTP, token } = useAuth();
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  // TOTP state
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaToken, setMfaToken] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const totpRef = useRef<HTMLInputElement>(null);

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
      const res = await login(username, password);
      if (res.mfa_required && res.mfa_token) {
        setMfaRequired(true);
        setMfaToken(res.mfa_token);
        setTotpCode("");
        setTimeout(() => totpRef.current?.focus(), 100);
      } else {
        router.replace("/");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleTOTPSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await verifyTOTP(mfaToken, totpCode);
      router.replace("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid code");
      setTotpCode("");
      totpRef.current?.focus();
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
          {mfaRequired ? "Enter your authentication code" : "Sign in to the command center"}
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

        {/* ── TOTP Step ────────────────────────────────────── */}
        {mfaRequired ? (
          <form onSubmit={handleTOTPSubmit} className="space-y-3">
            <div className="flex items-center justify-center mb-2">
              <ShieldCheck size={40} style={{ color: "var(--primary)", opacity: 0.7 }} />
            </div>
            <p className="text-center text-xs mb-4" style={{ color: "var(--muted)" }}>
              Open your authenticator app and enter the 6-digit code, or use a backup code.
            </p>
            <div>
              <label
                htmlFor="totp-code"
                className="block text-[11px] font-medium uppercase tracking-wider mb-1"
                style={{ color: "var(--muted)" }}
              >
                Verification Code
              </label>
              <input
                ref={totpRef}
                id="totp-code"
                type="text"
                inputMode="numeric"
                pattern="[0-9a-fA-F]*"
                maxLength={8}
                required
                autoComplete="one-time-code"
                autoFocus
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\s/g, ""))}
                className="w-full px-3 py-3 rounded border text-center text-lg font-mono tracking-[0.3em] outline-none transition-colors focus-ring"
                style={{
                  background: "var(--surface-1)",
                  borderColor: "var(--border)",
                  color: "var(--fg)",
                }}
                placeholder="000000"
              />
            </div>

            <button
              type="submit"
              disabled={submitting || totpCode.length < 6}
              className="flex items-center justify-center gap-2 w-full py-2 rounded text-sm font-semibold transition-colors disabled:opacity-60"
              style={{
                background: "var(--primary)",
                color: "var(--primary-fg)",
              }}
            >
              {submitting && <Loader2 size={14} className="animate-spin" />}
              {submitting ? "Verifying..." : "Verify"}
            </button>

            <button
              type="button"
              onClick={() => { setMfaRequired(false); setMfaToken(""); setError(""); setPassword(""); }}
              className="w-full text-center text-xs py-1 transition-colors hover:underline"
              style={{ color: "var(--muted)" }}
            >
              Back to login
            </button>
          </form>
        ) : (
          /* ── Password Step ──────────────────────────────── */
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
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  required
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3 py-2 pr-9 rounded border text-sm outline-none transition-colors focus-ring"
                  style={{
                    background: "var(--surface-1)",
                    borderColor: "var(--border)",
                    color: "var(--fg)",
                  }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 p-0.5 rounded transition-colors hover:bg-[var(--surface-2)]"
                  style={{ color: "var(--muted)" }}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
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
        )}
      </div>
    </div>
  );
}
