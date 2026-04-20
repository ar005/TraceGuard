"use client";

import { useCallback, useEffect, useState } from "react";
import { useTheme } from "next-themes";
import {
  Palette,
  Database,
  Brain,
  Check,
  Loader2,
  FlaskConical,
} from "lucide-react";
import { api } from "@/lib/api-client";
import { useApi } from "@/hooks/use-api";
import type { LLMSettings, RetentionSettings } from "@/types";

/* ----------------------------------------------------------------
   Theme definitions
   ---------------------------------------------------------------- */
interface ThemeDef {
  id: string;
  label: string;
  swatches: [string, string, string, string];
  base: "light" | "dark";
  dataTheme?: string;
}

const THEMES: ThemeDef[] = [
  { id: "light", label: "Light", swatches: ["#f1f3f5", "#ffffff", "#e8a83e", "#e9ecef"], base: "light" },
  { id: "dark", label: "Dark", swatches: ["#131929", "#1a2236", "#e8a83e", "#232d42"], base: "dark" },
  { id: "midnight", label: "Midnight", swatches: ["#0d1117", "#141b24", "#4d8fef", "#1c2635"], base: "dark", dataTheme: "midnight" },
  { id: "ember", label: "Ember", swatches: ["#161110", "#1c1613", "#f37216", "#231c17"], base: "dark", dataTheme: "ember" },
  { id: "arctic", label: "Arctic", swatches: ["#ebeff5", "#f7f9fc", "#2e8bc0", "#dce3ed"], base: "light", dataTheme: "arctic" },
  { id: "verdant", label: "Verdant", swatches: ["#0d1510", "#121e16", "#2dbd6e", "#1a2b20"], base: "dark", dataTheme: "verdant" },
  { id: "rose", label: "Rose", swatches: ["#151013", "#1c1419", "#e3499a", "#261c22"], base: "dark", dataTheme: "rose" },
];

const LLM_PROVIDERS = [
  { value: "ollama", label: "Ollama" },
  { value: "openai", label: "OpenAI" },
  { value: "anthropic", label: "Anthropic" },
  { value: "gemini", label: "Gemini" },
];

/* ----------------------------------------------------------------
   Component
   ---------------------------------------------------------------- */
export default function SettingsPage() {
  const { setTheme } = useTheme();
  const [activeThemeId, setActiveThemeId] = useState<string>("dark");

  // Retention state
  const [eventsDays, setEventsDays] = useState(90);
  const [alertsDays, setAlertsDays] = useState(365);
  const [retentionSaving, setRetentionSaving] = useState(false);
  const [retentionMsg, setRetentionMsg] = useState<string | null>(null);

  // LLM state
  const [llm, setLlm] = useState<LLMSettings>({
    provider: "ollama",
    model: "",
    base_url: "",
    api_key: "",
    enabled: false,
  });
  const [llmSaving, setLlmSaving] = useState(false);
  const [llmMsg, setLlmMsg] = useState<string | null>(null);
  const [llmTesting, setLlmTesting] = useState(false);
  const [llmTestMsg, setLlmTestMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // Load saved theme from localStorage
  useEffect(() => {
    const saved = localStorage.getItem("edr-theme-id");
    if (saved) {
      setActiveThemeId(saved);
    }
  }, []);

  // Load retention settings
  const fetchRetention = useCallback(
    () => api.get<RetentionSettings>("/api/v1/settings/retention"),
    []
  );
  const { data: retentionData } = useApi(fetchRetention);

  useEffect(() => {
    if (retentionData) {
      setEventsDays(retentionData.events_days ?? 90);
      setAlertsDays(retentionData.alerts_days ?? 365);
    }
  }, [retentionData]);

  // Load LLM settings
  const fetchLlm = useCallback(
    () => api.get<LLMSettings>("/api/v1/settings/llm"),
    []
  );
  const { data: llmData } = useApi(fetchLlm);

  useEffect(() => {
    if (llmData) {
      setLlm(llmData);
    }
  }, [llmData]);

  /* ---- Theme actions ---- */
  function applyTheme(t: ThemeDef) {
    setActiveThemeId(t.id);
    localStorage.setItem("edr-theme-id", t.id);
    setTheme(t.base);
    if (t.dataTheme) {
      document.documentElement.setAttribute("data-theme", t.dataTheme);
    } else {
      document.documentElement.removeAttribute("data-theme");
    }
  }

  /* ---- Retention actions ---- */
  async function saveRetention() {
    setRetentionSaving(true);
    setRetentionMsg(null);
    try {
      await api.post("/api/v1/settings/retention", {
        events_days: eventsDays,
        alerts_days: alertsDays,
      });
      setRetentionMsg("Retention settings saved");
    } catch (err) {
      setRetentionMsg(err instanceof Error ? err.message : "Failed to save");
    } finally {
      setRetentionSaving(false);
    }
  }

  /* ---- LLM actions ---- */
  async function saveLlm() {
    setLlmSaving(true);
    setLlmMsg(null);
    try {
      await api.post("/api/v1/settings/llm", llm);
      setLlmMsg("LLM settings saved");
    } catch (err) {
      setLlmMsg(err instanceof Error ? err.message : "Failed to save");
    } finally {
      setLlmSaving(false);
    }
  }

  async function testLlm() {
    setLlmTesting(true);
    setLlmTestMsg(null);
    try {
      await api.post("/api/v1/settings/llm/test", llm);
      setLlmTestMsg({ ok: true, text: "Connection successful" });
    } catch (err) {
      setLlmTestMsg({ ok: false, text: err instanceof Error ? err.message : "Connection failed" });
    } finally {
      setLlmTesting(false);
    }
  }

  /* ---- Shared styles ---- */
  const cardClass = "rounded border p-5";
  const cardStyle = { background: "var(--surface-0)", borderColor: "var(--border)" };
  const inputClass = "w-full rounded border px-3 py-2 text-sm font-mono focus-ring";
  const inputStyle = { background: "var(--surface-1)", borderColor: "var(--border)", color: "var(--fg)" };
  const labelClass = "block text-xs font-medium mb-1.5";
  const labelStyle = { color: "var(--muted)" };
  const btnPrimaryClass =
    "inline-flex items-center gap-2 rounded px-4 py-2 text-sm font-medium transition-colors";
  const btnPrimaryStyle = { background: "var(--primary)", color: "var(--primary-fg)" };

  return (
    <div className="space-y-6 max-w-3xl">
      {/* Header */}
      <div>
        <h1 className="font-heading text-xl font-bold">Settings</h1>
        <p className="text-sm" style={{ color: "var(--muted)" }}>
          System configuration and preferences
        </p>
      </div>

      {/* ============================================================
          Section 1: Theme / Appearance
          ============================================================ */}
      <section className={cardClass} style={cardStyle}>
        <h2 className="font-heading text-sm font-semibold flex items-center gap-2 mb-4">
          <Palette size={16} style={{ color: "var(--primary)" }} />
          Theme / Appearance
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
          {THEMES.map((t) => {
            const isActive = activeThemeId === t.id;
            return (
              <button
                key={t.id}
                onClick={() => applyTheme(t)}
                className="relative rounded border p-3 text-left transition-all"
                style={{
                  borderColor: isActive ? "var(--primary)" : "var(--border)",
                  background: "var(--surface-1)",
                  boxShadow: isActive ? "0 0 0 2px var(--ring)" : "none",
                }}
              >
                {/* Color swatches */}
                <div className="flex gap-1 mb-2">
                  {t.swatches.map((color, i) => (
                    <div
                      key={i}
                      className="h-5 flex-1 rounded-sm"
                      style={{ background: color }}
                    />
                  ))}
                </div>
                <span className="text-xs font-medium" style={{ color: "var(--fg)" }}>
                  {t.label}
                </span>
                {isActive && (
                  <div
                    className="absolute top-1.5 right-1.5 h-4 w-4 rounded-full flex items-center justify-center"
                    style={{ background: "var(--primary)", color: "var(--primary-fg)" }}
                  >
                    <Check size={10} />
                  </div>
                )}
              </button>
            );
          })}
        </div>
      </section>

      {/* ============================================================
          Section 2: Data Retention
          ============================================================ */}
      <section className={cardClass} style={cardStyle}>
        <h2 className="font-heading text-sm font-semibold flex items-center gap-2 mb-4">
          <Database size={16} style={{ color: "var(--primary)" }} />
          Data Retention
        </h2>
        <div className="grid sm:grid-cols-2 gap-4 mb-4">
          <div>
            <label className={labelClass} style={labelStyle}>
              Events retention (days)
            </label>
            <input
              type="number"
              min={1}
              value={eventsDays}
              onChange={(e) => setEventsDays(Number(e.target.value))}
              className={inputClass}
              style={inputStyle}
            />
          </div>
          <div>
            <label className={labelClass} style={labelStyle}>
              Alerts retention (days)
            </label>
            <input
              type="number"
              min={1}
              value={alertsDays}
              onChange={(e) => setAlertsDays(Number(e.target.value))}
              className={inputClass}
              style={inputStyle}
            />
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={saveRetention} disabled={retentionSaving} className={btnPrimaryClass} style={btnPrimaryStyle}>
            {retentionSaving && <Loader2 size={14} className="animate-spin" />}
            Save Retention
          </button>
          {retentionMsg && (
            <span className="text-xs" style={{ color: "var(--success)" }}>
              {retentionMsg}
            </span>
          )}
        </div>
      </section>

      {/* ============================================================
          Section 3: AI / LLM Provider
          ============================================================ */}
      <section className={cardClass} style={cardStyle}>
        <h2 className="font-heading text-sm font-semibold flex items-center gap-2 mb-4">
          <Brain size={16} style={{ color: "var(--primary)" }} />
          AI / LLM Provider
        </h2>

        <div className="space-y-4">
          {/* Provider */}
          <div>
            <label className={labelClass} style={labelStyle}>
              Provider
            </label>
            <select
              value={llm.provider}
              onChange={(e) => setLlm((s) => ({ ...s, provider: e.target.value }))}
              className={inputClass}
              style={inputStyle}
            >
              {LLM_PROVIDERS.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </select>
          </div>

          <div className="grid sm:grid-cols-2 gap-4">
            {/* Model */}
            <div>
              <label className={labelClass} style={labelStyle}>
                Model
              </label>
              <input
                type="text"
                value={llm.model}
                onChange={(e) => setLlm((s) => ({ ...s, model: e.target.value }))}
                placeholder="e.g. llama3, gpt-4o, claude-sonnet"
                className={inputClass}
                style={inputStyle}
              />
            </div>
            {/* Base URL */}
            <div>
              <label className={labelClass} style={labelStyle}>
                Base URL
              </label>
              <input
                type="text"
                value={llm.base_url}
                onChange={(e) => setLlm((s) => ({ ...s, base_url: e.target.value }))}
                placeholder="e.g. http://localhost:11434"
                className={inputClass}
                style={inputStyle}
              />
            </div>
          </div>

          {/* API Key */}
          <div>
            <label className={labelClass} style={labelStyle}>
              API Key
            </label>
            <input
              type="password"
              value={llm.api_key}
              onChange={(e) => setLlm((s) => ({ ...s, api_key: e.target.value }))}
              placeholder="sk-..."
              className={inputClass}
              style={inputStyle}
            />
          </div>

          {/* Enabled toggle */}
          <div className="flex items-center gap-3">
            <label className="relative inline-flex cursor-pointer items-center">
              <input
                type="checkbox"
                checked={llm.enabled}
                onChange={(e) => setLlm((s) => ({ ...s, enabled: e.target.checked }))}
                className="peer sr-only"
              />
              <div
                className="h-5 w-9 rounded-full transition-colors after:absolute after:left-[2px] after:top-[2px] after:h-4 after:w-4 after:rounded-full after:transition-all after:content-[''] peer-checked:after:translate-x-full"
                style={{
                  background: llm.enabled ? "var(--primary)" : "var(--surface-2)",
                }}
              >
                <div
                  className="absolute top-[2px] left-[2px] h-4 w-4 rounded-full transition-transform"
                  style={{
                    background: "var(--fg)",
                    transform: llm.enabled ? "translateX(16px)" : "translateX(0)",
                  }}
                />
              </div>
            </label>
            <span className="text-sm" style={{ color: "var(--fg)" }}>
              {llm.enabled ? "Enabled" : "Disabled"}
            </span>
          </div>

          {/* Actions */}
          <div className="flex items-center gap-3 flex-wrap">
            <button onClick={saveLlm} disabled={llmSaving} className={btnPrimaryClass} style={btnPrimaryStyle}>
              {llmSaving && <Loader2 size={14} className="animate-spin" />}
              Save LLM Settings
            </button>
            <button
              onClick={testLlm}
              disabled={llmTesting}
              className="inline-flex items-center gap-2 rounded border px-4 py-2 text-sm font-medium transition-colors"
              style={{
                borderColor: "var(--border)",
                color: "var(--fg)",
                background: "var(--surface-1)",
              }}
            >
              {llmTesting ? <Loader2 size={14} className="animate-spin" /> : <FlaskConical size={14} />}
              Test Connection
            </button>
            {llmMsg && (
              <span className="text-xs" style={{ color: "var(--success)" }}>
                {llmMsg}
              </span>
            )}
            {llmTestMsg && (
              <span
                className="text-xs"
                style={{ color: llmTestMsg.ok ? "var(--success)" : "var(--destructive)" }}
              >
                {llmTestMsg.text}
              </span>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
