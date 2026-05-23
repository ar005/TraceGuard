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
  ScanSearch,
  ChevronRight,
} from "lucide-react";
import { api } from "@/lib/api-client";
import { useApi } from "@/hooks/use-api";
import type { LLMSettings, RetentionSettings } from "@/types";
import { cn } from "@/lib/utils";

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
  { id: "light",    label: "Light",    swatches: ["#f1f3f5","#ffffff","#e8a83e","#e9ecef"],   base: "light" },
  { id: "dark",     label: "Dark",     swatches: ["#131929","#1a2236","#e8a83e","#232d42"],   base: "dark" },
  { id: "midnight", label: "Midnight", swatches: ["#0d1117","#141b24","#4d8fef","#1c2635"],   base: "dark", dataTheme: "midnight" },
  { id: "ember",    label: "Ember",    swatches: ["#161110","#1c1613","#f37216","#231c17"],    base: "dark", dataTheme: "ember" },
  { id: "arctic",   label: "Arctic",   swatches: ["#ebeff5","#f7f9fc","#2e8bc0","#dce3ed"],   base: "light", dataTheme: "arctic" },
  { id: "verdant",  label: "Verdant",  swatches: ["#0d1510","#121e16","#2dbd6e","#1a2b20"],   base: "dark", dataTheme: "verdant" },
  { id: "rose",     label: "Rose",     swatches: ["#151013","#1c1419","#e3499a","#261c22"],    base: "dark", dataTheme: "rose" },
];

const LLM_PROVIDERS = [
  { value: "ollama",    label: "Ollama" },
  { value: "openai",   label: "OpenAI" },
  { value: "anthropic",label: "Anthropic" },
  { value: "gemini",   label: "Gemini" },
];

type Section = "appearance" | "retention" | "llm" | "enrichment";

const NAV: { id: Section; label: string; icon: React.ElementType; desc: string }[] = [
  { id: "appearance", label: "Appearance",     icon: Palette,     desc: "Theme & display preferences" },
  { id: "retention",  label: "Data Retention", icon: Database,    desc: "Event & alert storage windows" },
  { id: "llm",        label: "AI / LLM",       icon: Brain,       desc: "Language model provider" },
  { id: "enrichment", label: "Enrichment",     icon: ScanSearch,  desc: "VirusTotal & AbuseIPDB keys" },
];

/* ----------------------------------------------------------------
   Shared field components
   ---------------------------------------------------------------- */
function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <label className="block text-xs font-medium text-white/40 uppercase tracking-wider">{label}</label>
      {children}
    </div>
  );
}

const inputCls =
  "w-full rounded-lg border border-white/10 bg-white/[0.04] px-3 py-2 text-sm text-white font-mono placeholder:text-white/20 focus:outline-none focus:border-white/25 transition-colors";

function SaveRow({
  onSave,
  saving,
  msg,
  disabled,
  extra,
}: {
  onSave: () => void;
  saving: boolean;
  msg: string | null;
  disabled?: boolean;
  extra?: React.ReactNode;
}) {
  return (
    <div className="flex items-center gap-3 flex-wrap pt-2">
      <button
        onClick={onSave}
        disabled={saving || disabled}
        className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 px-4 py-2 text-sm font-medium text-white transition-colors"
      >
        {saving ? <Loader2 size={14} className="animate-spin" /> : <Check size={14} />}
        Save
      </button>
      {extra}
      {msg && (
        <span className={cn("text-xs", msg.toLowerCase().startsWith("fail") || msg.toLowerCase().startsWith("error") ? "text-red-400" : "text-emerald-400")}>
          {msg}
        </span>
      )}
    </div>
  );
}

/* ----------------------------------------------------------------
   Page
   ---------------------------------------------------------------- */
export default function SettingsPage() {
  const { setTheme } = useTheme();
  const [active, setActive] = useState<Section>("appearance");
  const [activeThemeId, setActiveThemeId] = useState<string>("dark");

  // Retention
  const [eventsDays, setEventsDays] = useState(90);
  const [alertsDays, setAlertsDays] = useState(365);
  const [retentionSaving, setRetentionSaving] = useState(false);
  const [retentionMsg, setRetentionMsg] = useState<string | null>(null);

  // LLM
  const [llm, setLlm] = useState<LLMSettings>({ provider: "ollama", model: "", base_url: "", api_key: "", enabled: false });
  const [llmSaving, setLlmSaving] = useState(false);
  const [llmMsg, setLlmMsg] = useState<string | null>(null);
  const [llmTesting, setLlmTesting] = useState(false);
  const [llmTestMsg, setLlmTestMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // Enrichment
  const [vtKey, setVtKey] = useState("");
  const [abuseKey, setAbuseKey] = useState("");
  const [enrichSaving, setEnrichSaving] = useState(false);
  const [enrichMsg, setEnrichMsg] = useState<string | null>(null);
  const [enrichStatus, setEnrichStatus] = useState<{ vt_key_set: boolean; abuse_key_set: boolean } | null>(null);

  useEffect(() => {
    const saved = localStorage.getItem("edr-theme-id");
    if (saved) setActiveThemeId(saved);
  }, []);

  const fetchRetention = useCallback(
    (s: AbortSignal) => api.get<RetentionSettings>("/api/v1/settings/retention", undefined, s), []
  );
  const { data: retentionData } = useApi(fetchRetention);
  useEffect(() => {
    if (retentionData) {
      setEventsDays(retentionData.events_days ?? 90);
      setAlertsDays(retentionData.alerts_days ?? 365);
    }
  }, [retentionData]);

  const fetchLlm = useCallback(
    (s: AbortSignal) => api.get<LLMSettings>("/api/v1/settings/llm", undefined, s), []
  );
  const { data: llmData } = useApi(fetchLlm);
  useEffect(() => { if (llmData) setLlm(llmData); }, [llmData]);

  const fetchEnrichStatus = useCallback(
    (s: AbortSignal) => api.get<{ vt_key_set: boolean; abuse_key_set: boolean }>("/api/v1/settings/enrichment", undefined, s), []
  );
  const { data: enrichStatusData } = useApi(fetchEnrichStatus);
  useEffect(() => { if (enrichStatusData) setEnrichStatus(enrichStatusData); }, [enrichStatusData]);

  function applyTheme(t: ThemeDef) {
    setActiveThemeId(t.id);
    localStorage.setItem("edr-theme-id", t.id);
    setTheme(t.base);
    if (t.dataTheme) document.documentElement.setAttribute("data-theme", t.dataTheme);
    else document.documentElement.removeAttribute("data-theme");
  }

  async function saveRetention() {
    setRetentionSaving(true); setRetentionMsg(null);
    try {
      await api.post("/api/v1/settings/retention", { events_days: eventsDays, alerts_days: alertsDays });
      setRetentionMsg("Saved");
    } catch (err) { setRetentionMsg(err instanceof Error ? err.message : "Failed to save"); }
    finally { setRetentionSaving(false); }
  }

  async function saveLlm() {
    setLlmSaving(true); setLlmMsg(null);
    try {
      await api.post("/api/v1/settings/llm", llm);
      setLlmMsg("Saved");
    } catch (err) { setLlmMsg(err instanceof Error ? err.message : "Failed to save"); }
    finally { setLlmSaving(false); }
  }

  async function testLlm() {
    setLlmTesting(true); setLlmTestMsg(null);
    try {
      await api.post("/api/v1/settings/llm/test", llm);
      setLlmTestMsg({ ok: true, text: "Connection successful" });
    } catch (err) { setLlmTestMsg({ ok: false, text: err instanceof Error ? err.message : "Connection failed" }); }
    finally { setLlmTesting(false); }
  }

  async function saveEnrichment() {
    setEnrichSaving(true); setEnrichMsg(null);
    try {
      await api.post("/api/v1/settings/enrichment", {
        virustotal_api_key: vtKey || undefined,
        abuseipdb_api_key:  abuseKey || undefined,
      });
      setEnrichMsg("Saved");
      setVtKey(""); setAbuseKey("");
      const status = await api.get<{ vt_key_set: boolean; abuse_key_set: boolean }>("/api/v1/settings/enrichment");
      setEnrichStatus(status);
    } catch { setEnrichMsg("Failed to save keys"); }
    finally { setEnrichSaving(false); }
  }

  const activeNav = NAV.find((n) => n.id === active)!;

  return (
    <div className="animate-fade-in flex gap-0 min-h-[calc(100vh-8rem)]">
      {/* ── Left sidebar nav ── */}
      <aside className="w-56 shrink-0 border-r border-white/[0.06] pr-4 space-y-1">
        <p className="text-[10px] font-semibold text-white/30 uppercase tracking-widest px-3 py-2">Settings</p>
        {NAV.map(({ id, label, icon: Icon, desc }) => {
          const isActive = active === id;
          return (
            <button
              key={id}
              onClick={() => setActive(id)}
              className={cn(
                "w-full flex items-center gap-3 rounded-lg px-3 py-2.5 text-left transition-colors group",
                isActive
                  ? "bg-white/[0.06] text-white"
                  : "text-white/50 hover:text-white hover:bg-white/[0.03]"
              )}
            >
              <Icon size={15} className={isActive ? "text-indigo-400" : "text-white/30 group-hover:text-white/60"} />
              <span className="flex-1 text-sm font-medium">{label}</span>
              {isActive && <ChevronRight size={12} className="text-white/30" />}
            </button>
          );
        })}
      </aside>

      {/* ── Right content ── */}
      <main className="flex-1 pl-8 min-w-0">
        {/* Section header */}
        <div className="mb-6">
          <div className="flex items-center gap-2.5">
            <activeNav.icon size={18} className="text-indigo-400" />
            <h1 className="text-lg font-semibold text-white">{activeNav.label}</h1>
          </div>
          <p className="text-sm text-white/40 mt-0.5 ml-[26px]">{activeNav.desc}</p>
        </div>

        {/* ── APPEARANCE ── */}
        {active === "appearance" && (
          <div className="space-y-6">
            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-6">
              <p className="text-xs font-semibold text-white/40 uppercase tracking-wider mb-4">Color Theme</p>
              <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-4 gap-3">
                {THEMES.map((t) => {
                  const isActive = activeThemeId === t.id;
                  return (
                    <button
                      key={t.id}
                      onClick={() => applyTheme(t)}
                      className={cn(
                        "relative rounded-lg border p-3 text-left transition-all",
                        isActive
                          ? "border-indigo-500 ring-1 ring-indigo-500/40 bg-white/[0.04]"
                          : "border-white/10 hover:border-white/20 bg-white/[0.02] hover:bg-white/[0.04]"
                      )}
                    >
                      <div className="flex gap-1 mb-2.5">
                        {t.swatches.map((color, i) => (
                          <div key={i} className="h-5 flex-1 rounded-sm" style={{ background: color }} />
                        ))}
                      </div>
                      <span className="text-xs font-medium text-white/70">{t.label}</span>
                      {isActive && (
                        <div className="absolute top-2 right-2 h-4 w-4 rounded-full bg-indigo-500 flex items-center justify-center">
                          <Check size={9} className="text-white" />
                        </div>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* ── RETENTION ── */}
        {active === "retention" && (
          <div className="rounded-xl border border-white/10 bg-white/[0.02] p-6 space-y-6 max-w-2xl">
            <p className="text-xs text-white/40">
              Events and alerts older than the configured window are purged from the database during nightly maintenance.
              Longer windows increase storage requirements.
            </p>
            <div className="grid sm:grid-cols-2 gap-5">
              <Field label="Events retention (days)">
                <input
                  type="number" min={1}
                  value={eventsDays}
                  onChange={(e) => setEventsDays(Number(e.target.value))}
                  className={inputCls}
                />
              </Field>
              <Field label="Alerts retention (days)">
                <input
                  type="number" min={1}
                  value={alertsDays}
                  onChange={(e) => setAlertsDays(Number(e.target.value))}
                  className={inputCls}
                />
              </Field>
            </div>
            <SaveRow onSave={saveRetention} saving={retentionSaving} msg={retentionMsg} />
          </div>
        )}

        {/* ── LLM ── */}
        {active === "llm" && (
          <div className="rounded-xl border border-white/10 bg-white/[0.02] p-6 space-y-5 max-w-2xl">
            <p className="text-xs text-white/40">
              Configure the AI provider used for alert summaries, incident triage suggestions, and threat hunt assistance.
            </p>

            <Field label="Provider">
              <select
                value={llm.provider}
                onChange={(e) => setLlm((s) => ({ ...s, provider: e.target.value }))}
                className={inputCls}
              >
                {LLM_PROVIDERS.map((p) => (
                  <option key={p.value} value={p.value}>{p.label}</option>
                ))}
              </select>
            </Field>

            <div className="grid sm:grid-cols-2 gap-5">
              <Field label="Model">
                <input
                  type="text"
                  value={llm.model}
                  onChange={(e) => setLlm((s) => ({ ...s, model: e.target.value }))}
                  placeholder="llama3, gpt-4o, claude-sonnet…"
                  className={inputCls}
                />
              </Field>
              <Field label="Base URL">
                <input
                  type="text"
                  value={llm.base_url}
                  onChange={(e) => setLlm((s) => ({ ...s, base_url: e.target.value }))}
                  placeholder="http://localhost:11434"
                  className={inputCls}
                />
              </Field>
            </div>

            <Field label="API Key">
              <input
                type="password"
                value={llm.api_key}
                onChange={(e) => setLlm((s) => ({ ...s, api_key: e.target.value }))}
                placeholder="sk-…"
                className={inputCls}
              />
            </Field>

            {/* Toggle */}
            <div className="flex items-center gap-3">
              <button
                onClick={() => setLlm((s) => ({ ...s, enabled: !s.enabled }))}
                className={cn(
                  "relative w-10 h-5.5 rounded-full transition-colors",
                  llm.enabled ? "bg-indigo-600" : "bg-white/10"
                )}
                style={{ height: "22px" }}
              >
                <span
                  className={cn(
                    "absolute top-0.5 h-4 w-4 rounded-full bg-white transition-transform shadow",
                    llm.enabled ? "translate-x-5" : "translate-x-0.5"
                  )}
                />
              </button>
              <span className="text-sm text-white/60">
                {llm.enabled ? "AI features enabled" : "AI features disabled"}
              </span>
            </div>

            <SaveRow
              onSave={saveLlm}
              saving={llmSaving}
              msg={llmMsg}
              extra={
                <button
                  onClick={testLlm}
                  disabled={llmTesting}
                  className="inline-flex items-center gap-2 rounded-lg border border-white/10 hover:bg-white/[0.04] px-4 py-2 text-sm text-white/60 hover:text-white transition-colors disabled:opacity-50"
                >
                  {llmTesting ? <Loader2 size={14} className="animate-spin" /> : <FlaskConical size={14} />}
                  Test Connection
                </button>
              }
            />
            {llmTestMsg && (
              <p className={cn("text-xs", llmTestMsg.ok ? "text-emerald-400" : "text-red-400")}>
                {llmTestMsg.text}
              </p>
            )}
          </div>
        )}

        {/* ── ENRICHMENT ── */}
        {active === "enrichment" && (
          <div className="rounded-xl border border-white/10 bg-white/[0.02] p-6 space-y-5 max-w-2xl">
            <p className="text-xs text-white/40">
              API keys for automatic enrichment of alerts with VirusTotal (IPs, hashes, domains) and AbuseIPDB (IPs).
              Keys are stored encrypted. Leave a field blank to keep the existing key.
            </p>

            {/* Status badges */}
            {enrichStatus && (
              <div className="flex gap-2 flex-wrap">
                {[
                  { label: "VirusTotal",  set: enrichStatus.vt_key_set },
                  { label: "AbuseIPDB",   set: enrichStatus.abuse_key_set },
                ].map(({ label, set }) => (
                  <span
                    key={label}
                    className={cn(
                      "inline-flex items-center gap-1.5 text-[11px] font-semibold px-2.5 py-1 rounded-full border",
                      set
                        ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                        : "bg-white/5 border-white/10 text-white/30"
                    )}
                  >
                    {set && <Check size={10} />}
                    {label} — {set ? "configured" : "not set"}
                  </span>
                ))}
              </div>
            )}

            <div className="grid sm:grid-cols-2 gap-5">
              <Field label="VirusTotal API Key">
                <input
                  type="password"
                  className={inputCls}
                  placeholder={enrichStatus?.vt_key_set ? "••••••••  (already set)" : "Enter VT API key"}
                  value={vtKey}
                  onChange={(e) => setVtKey(e.target.value)}
                  autoComplete="new-password"
                />
              </Field>
              <Field label="AbuseIPDB API Key">
                <input
                  type="password"
                  className={inputCls}
                  placeholder={enrichStatus?.abuse_key_set ? "••••••••  (already set)" : "Enter AbuseIPDB key"}
                  value={abuseKey}
                  onChange={(e) => setAbuseKey(e.target.value)}
                  autoComplete="new-password"
                />
              </Field>
            </div>

            <SaveRow
              onSave={saveEnrichment}
              saving={enrichSaving}
              msg={enrichMsg}
              disabled={!vtKey && !abuseKey}
            />
          </div>
        )}
      </main>
    </div>
  );
}
