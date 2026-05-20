"use client";

import { useState, useCallback } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn } from "@/lib/utils";
import {
  Link2, CheckCircle2, AlertCircle, RefreshCw,
  Clock, ArrowDown, ArrowUp, Loader2, Shield, Settings2,
} from "lucide-react";

interface TIPSettings {
  id: string;
  tenant_id: string;
  misp_url: string;
  misp_api_key: string;
  auto_pull: boolean;
  pull_interval_hours: number;
  auto_push_matches: boolean;
  enabled: boolean;
  last_pull_at: string | null;
  last_push_at: string | null;
  updated_at: string;
}

interface SyncLogEntry {
  id: string;
  direction: string;
  status: string;
  ioc_count: number;
  error_msg: string;
  synced_at: string;
}

interface TIPStatus {
  enabled: boolean;
  last_pull_at: string | null;
  last_push_at: string | null;
  sync_log: SyncLogEntry[];
}

function reltime(ts: string | null): string {
  if (!ts) return "never";
  const diff = Date.now() - new Date(ts).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function TIPPage() {
  const [activeTab, setActiveTab] = useState<"settings" | "status">("settings");
  const [saving, setSaving] = useState(false);
  const [pulling, setPulling] = useState(false);
  const [pushing, setPushing] = useState(false);
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);

  const { data: settings, refetch: refetchSettings } =
    useApi<TIPSettings>(useCallback((s: AbortSignal) => api.get<TIPSettings>("/api/v1/tip/settings", undefined, s), []));
  const { data: status, loading: loadingStatus, refetch: refetchStatus } =
    useApi<TIPStatus>(useCallback((s: AbortSignal) => api.get<TIPStatus>("/api/v1/tip/status", undefined, s), []));

  const [form, setForm] = useState<Partial<TIPSettings>>({});
  const merged = { ...settings, ...form } as TIPSettings;

  const showToast = (msg: string, ok: boolean) => {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 3500);
  };

  const handleSave = useCallback(async () => {
    setSaving(true);
    try {
      await api.put("/api/v1/tip/settings", merged);
      setForm({});
      refetchSettings();
      showToast("Settings saved", true);
    } catch (e: unknown) {
      showToast(e instanceof Error ? e.message : "Save failed", false);
    } finally {
      setSaving(false);
    }
  }, [merged, refetchSettings]);

  const handlePull = async () => {
    setPulling(true);
    try {
      const r = await api.post<{ imported: number }>("/api/v1/tip/pull", {});
      showToast(`Pulled ${r.imported} IOCs from MISP`, true);
      refetchStatus();
    } catch (e: unknown) {
      showToast(e instanceof Error ? e.message : "Pull failed", false);
    } finally {
      setPulling(false);
    }
  };

  const handlePush = async () => {
    setPushing(true);
    try {
      const r = await api.post<{ pushed: number }>("/api/v1/tip/push", {});
      showToast(`Pushed ${r.pushed} IOCs to MISP`, true);
      refetchStatus();
    } catch (e: unknown) {
      showToast(e instanceof Error ? e.message : "Push failed", false);
    } finally {
      setPushing(false);
    }
  };

  const field = (k: keyof TIPSettings, v: unknown) =>
    setForm(f => ({ ...f, [k]: v }));

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-500/15 flex items-center justify-center">
            <Link2 size={20} className="text-blue-400" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-[var(--color-text-primary)]">TIP Integration</h1>
            <p className="text-sm text-[var(--color-text-muted)]">Bi-directional MISP sync for threat indicators</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handlePull}
            disabled={pulling || !merged.enabled}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors",
              "bg-[var(--color-bg-secondary)] border border-[var(--color-border)] text-[var(--color-text-secondary)]",
              "hover:bg-[var(--color-bg-tertiary)] disabled:opacity-40"
            )}
          >
            {pulling ? <Loader2 size={14} className="animate-spin" /> : <ArrowDown size={14} />}
            Pull from MISP
          </button>
          <button
            onClick={handlePush}
            disabled={pushing || !merged.enabled}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors",
              "bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-40"
            )}
          >
            {pushing ? <Loader2 size={14} className="animate-spin" /> : <ArrowUp size={14} />}
            Push to MISP
          </button>
        </div>
      </div>

      {/* Status strip */}
      {status && (
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: "Status", value: status.enabled ? "Connected" : "Disabled", icon: Shield, ok: status.enabled },
            { label: "Last Pull", value: reltime(status.last_pull_at), icon: ArrowDown, ok: !!status.last_pull_at },
            { label: "Last Push", value: reltime(status.last_push_at), icon: ArrowUp, ok: !!status.last_push_at },
          ].map(({ label, value, icon: Icon, ok }) => (
            <div key={label} className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl p-4 flex items-center gap-3">
              <div className={cn("w-9 h-9 rounded-lg flex items-center justify-center", ok ? "bg-green-500/10" : "bg-[var(--color-bg-tertiary)]")}>
                <Icon size={18} className={ok ? "text-green-400" : "text-[var(--color-text-muted)]"} />
              </div>
              <div>
                <p className="text-xs text-[var(--color-text-muted)]">{label}</p>
                <p className="text-sm font-medium text-[var(--color-text-primary)]">{value}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[var(--color-border)]">
        {(["settings", "status"] as const).map(t => (
          <button
            key={t}
            onClick={() => setActiveTab(t)}
            className={cn(
              "px-4 py-2 text-sm font-medium capitalize transition-colors border-b-2 -mb-px",
              activeTab === t
                ? "border-blue-500 text-blue-400"
                : "border-transparent text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]"
            )}
          >
            {t === "settings" ? "Configuration" : "Sync History"}
          </button>
        ))}
      </div>

      {/* Settings Tab */}
      {activeTab === "settings" && (
        <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl p-6 space-y-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-[var(--color-text-primary)]">Enable TIP Integration</p>
              <p className="text-xs text-[var(--color-text-muted)]">Activate MISP sync for this tenant</p>
            </div>
            <button
              onClick={() => field("enabled", !merged.enabled)}
              className={cn(
                "relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none",
                merged.enabled ? "bg-blue-600" : "bg-[var(--color-bg-tertiary)] border border-[var(--color-border)]"
              )}
            >
              <span className={cn("inline-block h-4 w-4 transform rounded-full bg-white transition-transform", merged.enabled ? "translate-x-6" : "translate-x-1")} />
            </button>
          </div>

          <div className="grid grid-cols-1 gap-4">
            <div>
              <label className="block text-xs font-medium text-[var(--color-text-secondary)] mb-1">MISP URL</label>
              <input
                value={merged.misp_url ?? ""}
                onChange={e => field("misp_url", e.target.value)}
                placeholder="https://misp.example.com"
                className="w-full px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--color-text-secondary)] mb-1">API Key</label>
              <input
                type="password"
                value={merged.misp_api_key ?? ""}
                onChange={e => field("misp_api_key", e.target.value)}
                placeholder="Enter new key to update"
                className="w-full px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 pt-2 border-t border-[var(--color-border)]">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--color-text-primary)]">Auto Pull</p>
                <p className="text-xs text-[var(--color-text-muted)]">Scheduled indicator import</p>
              </div>
              <button
                onClick={() => field("auto_pull", !merged.auto_pull)}
                className={cn("relative inline-flex h-5 w-9 items-center rounded-full transition-colors",
                  merged.auto_pull ? "bg-blue-600" : "bg-[var(--color-bg-tertiary)] border border-[var(--color-border)]")}
              >
                <span className={cn("inline-block h-3 w-3 transform rounded-full bg-white transition-transform", merged.auto_pull ? "translate-x-5" : "translate-x-1")} />
              </button>
            </div>
            {merged.auto_pull && (
              <div>
                <label className="block text-xs font-medium text-[var(--color-text-secondary)] mb-1">Pull Interval (hours)</label>
                <input
                  type="number"
                  min={1}
                  max={168}
                  value={merged.pull_interval_hours ?? 24}
                  onChange={e => field("pull_interval_hours", parseInt(e.target.value) || 24)}
                  className="w-full px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-blue-500"
                />
              </div>
            )}
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--color-text-primary)]">Auto-promote IOC matches</p>
                <p className="text-xs text-[var(--color-text-muted)]">Push matched IOCs back to MISP</p>
              </div>
              <button
                onClick={() => field("auto_push_matches", !merged.auto_push_matches)}
                className={cn("relative inline-flex h-5 w-9 items-center rounded-full transition-colors",
                  merged.auto_push_matches ? "bg-blue-600" : "bg-[var(--color-bg-tertiary)] border border-[var(--color-border)]")}
              >
                <span className={cn("inline-block h-3 w-3 transform rounded-full bg-white transition-transform", merged.auto_push_matches ? "translate-x-5" : "translate-x-1")} />
              </button>
            </div>
          </div>

          <div className="flex justify-end pt-2">
            <button
              onClick={handleSave}
              disabled={saving}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
            >
              {saving ? <Loader2 size={14} className="animate-spin" /> : <Settings2 size={14} />}
              Save Settings
            </button>
          </div>
        </div>
      )}

      {/* Sync History Tab */}
      {activeTab === "status" && (
        <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--color-border)]">
            <p className="text-sm font-medium text-[var(--color-text-primary)]">Sync History</p>
            <button onClick={refetchStatus} className="text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)] transition-colors">
              <RefreshCw size={14} />
            </button>
          </div>
          {loadingStatus ? (
            <div className="flex justify-center py-10"><Loader2 size={20} className="animate-spin text-[var(--color-text-muted)]" /></div>
          ) : !status?.sync_log?.length ? (
            <div className="text-center py-10 text-sm text-[var(--color-text-muted)]">No sync events yet</div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--color-border)] text-[var(--color-text-muted)] text-xs">
                  <th className="text-left px-4 py-2">Direction</th>
                  <th className="text-left px-4 py-2">Status</th>
                  <th className="text-right px-4 py-2">IOCs</th>
                  <th className="text-left px-4 py-2">Note</th>
                  <th className="text-right px-4 py-2">Time</th>
                </tr>
              </thead>
              <tbody>
                {status.sync_log.map(row => (
                  <tr key={row.id} className="border-b border-[var(--color-border)] last:border-0 hover:bg-[var(--color-bg-tertiary)]">
                    <td className="px-4 py-2.5">
                      <span className={cn("flex items-center gap-1.5 w-fit px-2 py-0.5 rounded-full text-xs font-medium",
                        row.direction === "pull" ? "bg-blue-500/10 text-blue-400" : "bg-purple-500/10 text-purple-400")}>
                        {row.direction === "pull" ? <ArrowDown size={10} /> : <ArrowUp size={10} />}
                        {row.direction}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={cn("flex items-center gap-1 text-xs",
                        row.status === "ok" ? "text-green-400" : "text-red-400")}>
                        {row.status === "ok" ? <CheckCircle2 size={12} /> : <AlertCircle size={12} />}
                        {row.status}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono">{row.ioc_count.toLocaleString()}</td>
                    <td className="px-4 py-2.5 text-[var(--color-text-muted)] max-w-xs truncate">{row.error_msg || "—"}</td>
                    <td className="px-4 py-2.5 text-right text-[var(--color-text-muted)]">
                      <span className="flex items-center justify-end gap-1"><Clock size={11} />{reltime(row.synced_at)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Toast */}
      {toast && (
        <div className={cn(
          "fixed bottom-5 right-5 flex items-center gap-2 px-4 py-2.5 rounded-lg shadow-lg text-sm font-medium text-white z-50 transition-all",
          toast.ok ? "bg-green-600" : "bg-red-600"
        )}>
          {toast.ok ? <CheckCircle2 size={15} /> : <AlertCircle size={15} />}
          {toast.msg}
        </div>
      )}
    </div>
  );
}
