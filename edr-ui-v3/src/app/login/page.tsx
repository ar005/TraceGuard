"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { Eye, EyeOff, Loader2 } from "lucide-react";

export default function LoginPage() {
  const { login, verifyTOTP, token } = useAuth();
  const router = useRouter();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // TOTP
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaToken, setMfaToken] = useState("");
  const [totp, setTotp] = useState("");
  const totpRef = useRef<HTMLInputElement>(null);

  useEffect(() => { if (token) router.replace("/"); }, [token, router]);
  if (token) return null;

  async function handleLogin(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      const res = await login(username, password);
      if (res.mfa_required && res.mfa_token) {
        setMfaToken(res.mfa_token);
        setMfaRequired(true);
        setTimeout(() => totpRef.current?.focus(), 50);
      } else {
        router.replace("/dashboard");
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleTotp(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      await verifyTOTP(mfaToken, totp);
      router.replace("/dashboard");
    } catch {
      setError("Invalid code. Try again.");
      setTotp("");
    } finally {
      setSubmitting(false);
    }
  }

  const inputStyle: React.CSSProperties = {
    width: "100%",
    background: "var(--surface-1)",
    border: "1px solid var(--border)",
    borderRadius: "8px",
    padding: "10px 14px",
    fontSize: "var(--text-sm)",
    color: "var(--fg)",
    fontFamily: "var(--font-onest)",
    outline: "none",
    transition: "border-color 0.12s",
  };

  return (
    <div
      className="flex min-h-screen"
      style={{ background: "var(--bg)" }}
    >
      {/* Left decorative panel */}
      <div
        className="hidden lg:flex flex-col justify-between"
        style={{
          width: "420px",
          flexShrink: 0,
          background: "var(--surface-0)",
          borderRight: "1px solid var(--border)",
          padding: "var(--space-12) var(--space-8)",
        }}
      >
        {/* Logo */}
        <div className="flex items-center gap-3">
          <svg width="28" height="28" viewBox="0 0 22 22" fill="none">
            <path
              d="M11 2L3 6v5c0 4.4 3.4 8.5 8 9.5C16.6 19.5 20 15.4 20 11V6L11 2z"
              fill="none"
              stroke="var(--primary)"
              strokeWidth="1.5"
              strokeLinejoin="round"
            />
            <path
              d="M8 11l2 2 4-4"
              stroke="var(--primary)"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <span
            style={{
              fontFamily: "var(--font-archivo)",
              fontWeight: 700,
              fontSize: "var(--text-lg)",
              color: "var(--fg)",
              letterSpacing: "-0.01em",
            }}
          >
            TraceGuard
          </span>
        </div>

        {/* Stats */}
        <div className="flex flex-col gap-8">
          {[
            { num: "24/7", label: "Continuous endpoint monitoring" },
            { num: "ms",   label: "Detection-to-alert latency" },
            { num: "0",    label: "Configuration required to start" },
          ].map(item => (
            <div key={item.label}>
              <div
                style={{
                  fontFamily: "var(--font-archivo)",
                  fontWeight: 900,
                  fontSize: "var(--text-3xl)",
                  color: "var(--primary)",
                  letterSpacing: "-0.03em",
                  lineHeight: 1.1,
                }}
              >
                {item.num}
              </div>
              <div style={{ fontSize: "var(--text-sm)", color: "var(--fg-3)", marginTop: "4px" }}>
                {item.label}
              </div>
            </div>
          ))}
        </div>

        <p style={{ fontSize: "var(--text-xs)", color: "var(--fg-4)" }}>
          Self-hosted · Open source · No telemetry
        </p>
      </div>

      {/* Right — login form */}
      <div className="flex flex-1 items-center justify-center" style={{ padding: "var(--space-8)" }}>
        <div style={{ width: "100%", maxWidth: "360px" }}>

          {/* Mobile logo */}
          <div className="flex items-center gap-2 lg:hidden" style={{ marginBottom: "var(--space-8)" }}>
            <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
              <path d="M11 2L3 6v5c0 4.4 3.4 8.5 8 9.5C16.6 19.5 20 15.4 20 11V6L11 2z" fill="none" stroke="var(--primary)" strokeWidth="1.5" strokeLinejoin="round" />
              <path d="M8 11l2 2 4-4" stroke="var(--primary)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <span style={{ fontFamily: "var(--font-archivo)", fontWeight: 700, fontSize: "var(--text-base)", color: "var(--fg)" }}>TraceGuard</span>
          </div>

          <h1
            style={{
              fontFamily: "var(--font-archivo)",
              fontWeight: 700,
              fontSize: "var(--text-xl)",
              color: "var(--fg)",
              letterSpacing: "-0.01em",
              marginBottom: "var(--space-1)",
            }}
          >
            {mfaRequired ? "Two-factor auth" : "Sign in"}
          </h1>
          <p style={{ fontSize: "var(--text-sm)", color: "var(--fg-3)", marginBottom: "var(--space-6)" }}>
            {mfaRequired ? "Enter the 6-digit code from your authenticator app." : "Access your SOC dashboard."}
          </p>

          {error && (
            <div
              style={{
                background: "var(--sev-critical-bg)",
                border: "1px solid var(--sev-critical)",
                borderRadius: "8px",
                padding: "var(--space-3) var(--space-4)",
                fontSize: "var(--text-sm)",
                color: "var(--sev-critical)",
                marginBottom: "var(--space-4)",
              }}
            >
              {error}
            </div>
          )}

          {!mfaRequired ? (
            <form onSubmit={handleLogin} className="flex flex-col gap-3">
              <div>
                <label className="section-label" style={{ display: "block", marginBottom: "var(--space-1)" }}>
                  Username or email
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  autoFocus
                  autoComplete="username"
                  required
                  style={inputStyle}
                  placeholder="admin"
                />
              </div>

              <div>
                <label className="section-label" style={{ display: "block", marginBottom: "var(--space-1)" }}>
                  Password
                </label>
                <div style={{ position: "relative" }}>
                  <input
                    type={showPw ? "text" : "password"}
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    autoComplete="current-password"
                    required
                    style={{ ...inputStyle, paddingRight: "40px" }}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPw(v => !v)}
                    style={{
                      position: "absolute",
                      right: "12px",
                      top: "50%",
                      transform: "translateY(-50%)",
                      background: "none",
                      border: "none",
                      cursor: "pointer",
                      color: "var(--fg-3)",
                      padding: 0,
                      display: "flex",
                    }}
                  >
                    {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={submitting}
                style={{
                  marginTop: "var(--space-2)",
                  padding: "10px 0",
                  borderRadius: "8px",
                  border: "none",
                  background: "var(--primary)",
                  color: "var(--primary-fg)",
                  fontFamily: "var(--font-archivo)",
                  fontWeight: 700,
                  fontSize: "var(--text-sm)",
                  cursor: submitting ? "default" : "pointer",
                  opacity: submitting ? 0.7 : 1,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "6px",
                  transition: "opacity 0.12s",
                }}
              >
                {submitting && <Loader2 size={14} className="animate-spin" />}
                {submitting ? "Signing in…" : "Sign in"}
              </button>
            </form>
          ) : (
            <form onSubmit={handleTotp} className="flex flex-col gap-3">
              <div>
                <label className="section-label" style={{ display: "block", marginBottom: "var(--space-1)" }}>
                  Authenticator code
                </label>
                <input
                  ref={totpRef}
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  value={totp}
                  onChange={e => setTotp(e.target.value.replace(/\D/g, ""))}
                  required
                  style={{ ...inputStyle, letterSpacing: "0.3em", textAlign: "center", fontSize: "var(--text-lg)" }}
                  placeholder="000000"
                />
              </div>
              <button
                type="submit"
                disabled={submitting || totp.length < 6}
                style={{
                  padding: "10px 0",
                  borderRadius: "8px",
                  border: "none",
                  background: "var(--primary)",
                  color: "var(--primary-fg)",
                  fontFamily: "var(--font-archivo)",
                  fontWeight: 700,
                  fontSize: "var(--text-sm)",
                  cursor: submitting || totp.length < 6 ? "default" : "pointer",
                  opacity: submitting || totp.length < 6 ? 0.6 : 1,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "6px",
                  transition: "opacity 0.12s",
                }}
              >
                {submitting && <Loader2 size={14} className="animate-spin" />}
                Verify
              </button>
              <button
                type="button"
                onClick={() => { setMfaRequired(false); setMfaToken(""); setError(""); }}
                style={{ background: "none", border: "none", cursor: "pointer", fontSize: "var(--text-xs)", color: "var(--fg-3)", fontFamily: "var(--font-onest)" }}
              >
                ← Back to login
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
