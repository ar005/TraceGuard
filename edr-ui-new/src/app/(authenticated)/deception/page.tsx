"use client";

import { useState, useCallback } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn } from "@/lib/utils";
import {
  Crosshair, Plus, Trash2, Download, RefreshCw, Loader2,
  Server, FileCode2, CheckCircle2, AlertCircle, Wifi, Globe,
  Lock, Zap, Clock,
} from "lucide-react";

interface Agent {
  id: string;
  hostname: string;
  os: string;
  is_online: boolean;
}

interface HoneypotDeployment {
  id: string;
  agent_id: string;
  name: string;
  htype: string;
  port: number;
  status: string;
  canary_id: string;
  triggered: number;
  last_trigger: string | null;
  created_at: string;
}

interface LureFile {
  id: string;
  agent_id: string;
  name: string;
  deploy_path: string;
  lure_type: string;
  canary_id: string;
  status: string;
  triggered: number;
  last_trigger: string | null;
  created_at: string;
}

const HTYPE_META: Record<string, { label: string; icon: typeof Wifi; color: string; defaultPort: number }> = {
  http: { label: "HTTP Server", icon: Globe, color: "text-blue-400 bg-blue-500/10", defaultPort: 8888 },
  ssh:  { label: "SSH Service", icon: Lock,  color: "text-green-400 bg-green-500/10", defaultPort: 2222 },
  smb:  { label: "SMB Share",   icon: Server, color: "text-orange-400 bg-orange-500/10", defaultPort: 4445 },
};

const LURE_TYPES = ["script", "batch", "powershell", "python"];

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

export default function DeceptionPage() {
  const [tab, setTab] = useState<"honeypots" | "lures">("honeypots");
  const [showHPForm, setShowHPForm] = useState(false);
  const [showLureForm, setShowLureForm] = useState(false);
  const [creating, setCreating] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);

  const { data: hpData, loading: hpLoading, refetch: refetchHP } =
    useApi<{ honeypots: HoneypotDeployment[] }>(useCallback((s: AbortSignal) => api.get("/api/v1/deception/honeypots", undefined, s), []));
  const { data: lureData, loading: lureLoading, refetch: refetchLures } =
    useApi<{ lures: LureFile[] }>(useCallback((s: AbortSignal) => api.get("/api/v1/deception/lures", undefined, s), []));
  const { data: agentData } =
    useApi<{ agents: Agent[] }>(useCallback((s: AbortSignal) => api.get("/api/v1/agents", { limit: 200 }, s), []));

  const honeypots = hpData?.honeypots ?? [];
  const lures = lureData?.lures ?? [];
  const agents = agentData?.agents ?? [];

  // Honeypot form state
  const [hpForm, setHPForm] = useState({ agent_id: "", name: "", htype: "http", port: 8888 });
  // Lure form state
  const [lureForm, setLureForm] = useState({ agent_id: "", name: "", deploy_path: "", lure_type: "script" });

  const showToast = (msg: string, ok: boolean) => {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 3500);
  };

  const createHoneypot = useCallback(async () => {
    if (!hpForm.agent_id || !hpForm.name) return;
    setCreating(true);
    try {
      await api.post("/api/v1/deception/honeypots", hpForm);
      setShowHPForm(false);
      setHPForm({ agent_id: "", name: "", htype: "http", port: 8888 });
      refetchHP();
      showToast("Honeypot created", true);
    } catch (e: unknown) {
      showToast(e instanceof Error ? e.message : "Create failed", false);
    } finally {
      setCreating(false);
    }
  }, [hpForm, refetchHP]);

  const deleteHoneypot = async (id: string) => {
    setDeletingId(id);
    try {
      await api.delete(`/api/v1/deception/honeypots/${id}`);
      refetchHP();
      showToast("Honeypot removed", true);
    } catch {
      showToast("Delete failed", false);
    } finally {
      setDeletingId(null);
    }
  };

  const createLure = useCallback(async () => {
    if (!lureForm.agent_id || !lureForm.name || !lureForm.deploy_path) return;
    setCreating(true);
    try {
      await api.post("/api/v1/deception/lures", lureForm);
      setShowLureForm(false);
      setLureForm({ agent_id: "", name: "", deploy_path: "", lure_type: "script" });
      refetchLures();
      showToast("Lure file created", true);
    } catch (e: unknown) {
      showToast(e instanceof Error ? e.message : "Create failed", false);
    } finally {
      setCreating(false);
    }
  }, [lureForm, refetchLures]);

  const deleteLure = async (id: string) => {
    setDeletingId(id);
    try {
      await api.delete(`/api/v1/deception/lures/${id}`);
      refetchLures();
      showToast("Lure removed", true);
    } catch {
      showToast("Delete failed", false);
    } finally {
      setDeletingId(null);
    }
  };

  const downloadLure = (id: string) => {
    window.open(`/api/v1/deception/lures/${id}/download`, "_blank");
  };

  const agentLabel = (id: string) => {
    const a = agents.find(ag => ag.id === id);
    return a ? a.hostname : id.slice(0, 8);
  };

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-orange-500/15 flex items-center justify-center">
            <Crosshair size={20} className="text-orange-400" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-[var(--color-text-primary)]">Deception Network</h1>
            <p className="text-sm text-[var(--color-text-muted)]">Honeypots and lure files that alert on intruder access</p>
          </div>
        </div>
        <button
          onClick={() => tab === "honeypots" ? setShowHPForm(true) : setShowLureForm(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-orange-600 hover:bg-orange-700 text-white text-sm font-medium rounded-lg transition-colors"
        >
          <Plus size={14} />
          {tab === "honeypots" ? "Deploy Honeypot" : "Create Lure"}
        </button>
      </div>

      {/* Stats strip */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: "Honeypots",   value: honeypots.length,                                  icon: Server,   color: "text-blue-400 bg-blue-500/10" },
          { label: "Lure Files",  value: lures.length,                                       icon: FileCode2, color: "text-purple-400 bg-purple-500/10" },
          { label: "HP Triggers", value: honeypots.reduce((s, h) => s + h.triggered, 0),    icon: Zap,      color: "text-orange-400 bg-orange-500/10" },
          { label: "Lure Hits",   value: lures.reduce((s, l) => s + l.triggered, 0),        icon: AlertCircle, color: "text-red-400 bg-red-500/10" },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl p-4 flex items-center gap-3">
            <div className={cn("w-9 h-9 rounded-lg flex items-center justify-center", color.split(" ")[1])}>
              <Icon size={18} className={color.split(" ")[0]} />
            </div>
            <div>
              <p className="text-xs text-[var(--color-text-muted)]">{label}</p>
              <p className="text-xl font-semibold text-[var(--color-text-primary)]">{value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[var(--color-border)]">
        {(["honeypots", "lures"] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={cn(
              "px-4 py-2 text-sm font-medium capitalize transition-colors border-b-2 -mb-px",
              tab === t
                ? "border-orange-500 text-orange-400"
                : "border-transparent text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]"
            )}
          >
            {t === "honeypots" ? "Honeypots" : "Lure Files"}
          </button>
        ))}
      </div>

      {/* Honeypots Tab */}
      {tab === "honeypots" && (
        <>
          {/* Create form */}
          {showHPForm && (
            <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl p-5 space-y-4">
              <p className="text-sm font-medium text-[var(--color-text-primary)]">Deploy New Honeypot</p>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-[var(--color-text-muted)] mb-1">Agent</label>
                  <select
                    value={hpForm.agent_id}
                    onChange={e => setHPForm(f => ({ ...f, agent_id: e.target.value }))}
                    className="w-full px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-orange-500"
                  >
                    <option value="">Select agent…</option>
                    {agents.map(a => (
                      <option key={a.id} value={a.id}>{a.hostname} ({a.os})</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-[var(--color-text-muted)] mb-1">Display Name</label>
                  <input
                    value={hpForm.name}
                    onChange={e => setHPForm(f => ({ ...f, name: e.target.value }))}
                    placeholder="e.g. Finance SMB Decoy"
                    className="w-full px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:border-orange-500"
                  />
                </div>
                <div>
                  <label className="block text-xs text-[var(--color-text-muted)] mb-1">Type</label>
                  <select
                    value={hpForm.htype}
                    onChange={e => {
                      const meta = HTYPE_META[e.target.value];
                      setHPForm(f => ({ ...f, htype: e.target.value, port: meta?.defaultPort ?? f.port }));
                    }}
                    className="w-full px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-orange-500"
                  >
                    {Object.entries(HTYPE_META).map(([k, v]) => (
                      <option key={k} value={k}>{v.label}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-[var(--color-text-muted)] mb-1">Port</label>
                  <input
                    type="number"
                    value={hpForm.port}
                    onChange={e => setHPForm(f => ({ ...f, port: parseInt(e.target.value) || 0 }))}
                    className="w-full px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-orange-500"
                  />
                </div>
              </div>
              <div className="flex gap-2 justify-end">
                <button onClick={() => setShowHPForm(false)} className="px-3 py-1.5 text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)] transition-colors">Cancel</button>
                <button
                  onClick={createHoneypot}
                  disabled={creating || !hpForm.agent_id || !hpForm.name}
                  className="flex items-center gap-1.5 px-4 py-1.5 bg-orange-600 hover:bg-orange-700 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
                >
                  {creating ? <Loader2 size={13} className="animate-spin" /> : <Plus size={13} />}
                  Deploy
                </button>
              </div>
            </div>
          )}

          {/* Honeypot list */}
          <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--color-border)]">
              <p className="text-sm font-medium text-[var(--color-text-primary)]">Deployed Honeypots</p>
              <button onClick={refetchHP} className="text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]"><RefreshCw size={13} /></button>
            </div>
            {hpLoading ? (
              <div className="flex justify-center py-10"><Loader2 size={20} className="animate-spin text-[var(--color-text-muted)]" /></div>
            ) : honeypots.length === 0 ? (
              <div className="text-center py-12 text-sm text-[var(--color-text-muted)]">
                <Crosshair size={28} className="mx-auto mb-2 opacity-30" />
                No honeypots deployed yet
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--color-border)] text-[var(--color-text-muted)] text-xs">
                    <th className="text-left px-4 py-2">Name</th>
                    <th className="text-left px-4 py-2">Type</th>
                    <th className="text-left px-4 py-2">Agent</th>
                    <th className="text-right px-4 py-2">Port</th>
                    <th className="text-center px-4 py-2">Triggers</th>
                    <th className="text-right px-4 py-2">Last Hit</th>
                    <th className="w-10 px-4 py-2" />
                  </tr>
                </thead>
                <tbody>
                  {honeypots.map(hp => {
                    const meta = HTYPE_META[hp.htype];
                    const Icon = meta?.icon ?? Server;
                    return (
                      <tr key={hp.id} className="border-b border-[var(--color-border)] last:border-0 hover:bg-[var(--color-bg-tertiary)]">
                        <td className="px-4 py-3 font-medium text-[var(--color-text-primary)]">{hp.name}</td>
                        <td className="px-4 py-3">
                          <span className={cn("flex items-center gap-1.5 w-fit px-2 py-0.5 rounded-full text-xs font-medium", meta?.color ?? "text-[var(--color-text-muted)] bg-[var(--color-bg-tertiary)]")}>
                            <Icon size={10} />
                            {meta?.label ?? hp.htype}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-[var(--color-text-secondary)]">{agentLabel(hp.agent_id)}</td>
                        <td className="px-4 py-3 text-right font-mono text-[var(--color-text-secondary)]">{hp.port}</td>
                        <td className="px-4 py-3 text-center">
                          {hp.triggered > 0
                            ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-red-500/15 text-red-400 text-xs font-semibold"><Zap size={10} />{hp.triggered}</span>
                            : <span className="text-[var(--color-text-muted)]">—</span>}
                        </td>
                        <td className="px-4 py-3 text-right text-[var(--color-text-muted)] text-xs">
                          {hp.last_trigger ? <span className="flex items-center justify-end gap-1"><Clock size={10} />{reltime(hp.last_trigger)}</span> : "—"}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <button
                            onClick={() => deleteHoneypot(hp.id)}
                            disabled={deletingId === hp.id}
                            className="p-1 rounded text-[var(--color-text-muted)] hover:text-red-400 hover:bg-red-500/10 transition-colors"
                          >
                            {deletingId === hp.id ? <Loader2 size={13} className="animate-spin" /> : <Trash2 size={13} />}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}

      {/* Lure Files Tab */}
      {tab === "lures" && (
        <>
          {showLureForm && (
            <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl p-5 space-y-4">
              <p className="text-sm font-medium text-[var(--color-text-primary)]">Create Lure File</p>
              <p className="text-xs text-[var(--color-text-muted)]">A lure is a decoy script that calls back to TraceGuard when executed — place it somewhere an attacker might explore.</p>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-[var(--color-text-muted)] mb-1">Agent</label>
                  <select
                    value={lureForm.agent_id}
                    onChange={e => setLureForm(f => ({ ...f, agent_id: e.target.value }))}
                    className="w-full px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-orange-500"
                  >
                    <option value="">Select agent…</option>
                    {agents.map(a => <option key={a.id} value={a.id}>{a.hostname} ({a.os})</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-[var(--color-text-muted)] mb-1">File Name (without extension)</label>
                  <input
                    value={lureForm.name}
                    onChange={e => setLureForm(f => ({ ...f, name: e.target.value }))}
                    placeholder="passwords_backup"
                    className="w-full px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:border-orange-500"
                  />
                </div>
                <div>
                  <label className="block text-xs text-[var(--color-text-muted)] mb-1">Deploy Path</label>
                  <input
                    value={lureForm.deploy_path}
                    onChange={e => setLureForm(f => ({ ...f, deploy_path: e.target.value }))}
                    placeholder="/home/admin/documents/"
                    className="w-full px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:border-orange-500"
                  />
                </div>
                <div>
                  <label className="block text-xs text-[var(--color-text-muted)] mb-1">Script Type</label>
                  <select
                    value={lureForm.lure_type}
                    onChange={e => setLureForm(f => ({ ...f, lure_type: e.target.value }))}
                    className="w-full px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-orange-500"
                  >
                    {LURE_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                  </select>
                </div>
              </div>
              <div className="flex gap-2 justify-end">
                <button onClick={() => setShowLureForm(false)} className="px-3 py-1.5 text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)] transition-colors">Cancel</button>
                <button
                  onClick={createLure}
                  disabled={creating || !lureForm.agent_id || !lureForm.name || !lureForm.deploy_path}
                  className="flex items-center gap-1.5 px-4 py-1.5 bg-orange-600 hover:bg-orange-700 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
                >
                  {creating ? <Loader2 size={13} className="animate-spin" /> : <Plus size={13} />}
                  Create
                </button>
              </div>
            </div>
          )}

          <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--color-border)]">
              <p className="text-sm font-medium text-[var(--color-text-primary)]">Lure Files</p>
              <button onClick={refetchLures} className="text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]"><RefreshCw size={13} /></button>
            </div>
            {lureLoading ? (
              <div className="flex justify-center py-10"><Loader2 size={20} className="animate-spin text-[var(--color-text-muted)]" /></div>
            ) : lures.length === 0 ? (
              <div className="text-center py-12 text-sm text-[var(--color-text-muted)]">
                <FileCode2 size={28} className="mx-auto mb-2 opacity-30" />
                No lure files created yet
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--color-border)] text-[var(--color-text-muted)] text-xs">
                    <th className="text-left px-4 py-2">Name</th>
                    <th className="text-left px-4 py-2">Agent</th>
                    <th className="text-left px-4 py-2">Path</th>
                    <th className="text-left px-4 py-2">Type</th>
                    <th className="text-center px-4 py-2">Triggers</th>
                    <th className="text-right px-4 py-2">Last Hit</th>
                    <th className="w-20 px-4 py-2" />
                  </tr>
                </thead>
                <tbody>
                  {lures.map(lf => (
                    <tr key={lf.id} className="border-b border-[var(--color-border)] last:border-0 hover:bg-[var(--color-bg-tertiary)]">
                      <td className="px-4 py-3 font-medium text-[var(--color-text-primary)]">{lf.name}</td>
                      <td className="px-4 py-3 text-[var(--color-text-secondary)]">{agentLabel(lf.agent_id)}</td>
                      <td className="px-4 py-3 font-mono text-xs text-[var(--color-text-muted)] max-w-[180px] truncate">{lf.deploy_path}</td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded-full bg-[var(--color-bg-tertiary)] text-xs text-[var(--color-text-secondary)] border border-[var(--color-border)]">{lf.lure_type}</span>
                      </td>
                      <td className="px-4 py-3 text-center">
                        {lf.triggered > 0
                          ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-red-500/15 text-red-400 text-xs font-semibold"><Zap size={10} />{lf.triggered}</span>
                          : <span className="text-[var(--color-text-muted)]">—</span>}
                      </td>
                      <td className="px-4 py-3 text-right text-[var(--color-text-muted)] text-xs">
                        {lf.last_trigger ? <span className="flex items-center justify-end gap-1"><Clock size={10} />{reltime(lf.last_trigger)}</span> : "—"}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => downloadLure(lf.id)}
                            title="Download lure script"
                            className="p-1 rounded text-[var(--color-text-muted)] hover:text-blue-400 hover:bg-blue-500/10 transition-colors"
                          >
                            <Download size={13} />
                          </button>
                          <button
                            onClick={() => deleteLure(lf.id)}
                            disabled={deletingId === lf.id}
                            className="p-1 rounded text-[var(--color-text-muted)] hover:text-red-400 hover:bg-red-500/10 transition-colors"
                          >
                            {deletingId === lf.id ? <Loader2 size={13} className="animate-spin" /> : <Trash2 size={13} />}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}

      {/* Toast */}
      {toast && (
        <div className={cn(
          "fixed bottom-5 right-5 flex items-center gap-2 px-4 py-2.5 rounded-lg shadow-lg text-sm font-medium text-white z-50",
          toast.ok ? "bg-green-600" : "bg-red-600"
        )}>
          {toast.ok ? <CheckCircle2 size={15} /> : <AlertCircle size={15} />}
          {toast.msg}
        </div>
      )}
    </div>
  );
}
