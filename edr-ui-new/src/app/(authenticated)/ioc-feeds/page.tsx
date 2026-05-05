"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import {
  RefreshCw, Plus, ChevronDown, ChevronUp, CheckCircle2,
  AlertTriangle, Clock, Wifi, WifiOff, Activity,
} from "lucide-react";

interface IOCFeed {
  id: string;
  name: string;
  url: string;
  format: string;
  feed_type: string;
  enabled: boolean;
  last_synced_at: string | null;
  entry_count: number;
  created_at: string;
  protocol: string;
  taxii_url: string;
  taxii_username: string;
  misp_url: string;
  hit_count: number;
  false_pos_count: number;
  quality_score: number;
}

interface SyncLogEntry {
  id: string;
  started_at: string;
  finished_at: string | null;
  added: number;
  updated: number;
  error: string;
}

const FORMAT_LABELS: Record<string, string> = { txt: "Plain text", csv: "CSV", stix: "STIX 2.x" };
const TYPE_LABELS: Record<string, string> = { ip: "IP Addresses", domain: "Domains", hash: "File Hashes", url: "URLs" };
const PROTOCOL_LABELS: Record<string, string> = { http: "HTTP", taxii: "TAXII 2.1", misp: "MISP" };

const TYPE_COLORS: Record<string, string> = {
  ip:     "text-red-400 bg-red-500/10 border-red-500/20",
  domain: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  hash:   "text-violet-400 bg-violet-500/10 border-violet-500/20",
  url:    "text-blue-400 bg-blue-500/10 border-blue-500/20",
};

function genID() { return "feed-" + Math.random().toString(36).slice(2, 10); }

function QualityBadge({ score }: { score: number }) {
  const color = score >= 60 ? "text-emerald-400 border-emerald-500/30 bg-emerald-500/10"
    : score >= 25 ? "text-amber-400 border-amber-500/30 bg-amber-500/10"
    : "text-white/30 border-white/10 bg-white/5";
  const label = score >= 60 ? "Good" : score >= 25 ? "Fair" : "Low";
  return (
    <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${color}`}>
      {label} {score}%
    </span>
  );
}

function SyncLogDrawer({ feedId }: { feedId: string }) {
  const { data, loading } = useApi<{ logs: SyncLogEntry[] }>(
    (signal) => api.get(`/ioc-feeds/${feedId}/log`, {}, signal),
  );
  const logs = data?.logs ?? [];

  if (loading) return <p className="text-white/30 text-xs py-2">Loading history…</p>;
  if (logs.length === 0) return <p className="text-white/20 text-xs py-2">No sync history yet.</p>;

  return (
    <div className="space-y-1">
      {logs.map((l) => (
        <div key={l.id} className="flex items-center gap-3 text-xs">
          {l.error ? (
            <AlertTriangle size={11} className="text-red-400 shrink-0" />
          ) : (
            <CheckCircle2 size={11} className="text-emerald-400 shrink-0" />
          )}
          <span className="text-white/30 font-mono w-32 shrink-0">
            {new Date(l.started_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
          </span>
          {l.error ? (
            <span className="text-red-400 truncate">{l.error}</span>
          ) : (
            <span className="text-white/50">+{l.added} added</span>
          )}
          {l.finished_at && (
            <span className="text-white/20 ml-auto shrink-0">
              {Math.round((new Date(l.finished_at).getTime() - new Date(l.started_at).getTime()) / 1000)}s
            </span>
          )}
        </div>
      ))}
    </div>
  );
}

const EMPTY_FEED = (): Partial<IOCFeed> => ({
  id: genID(), name: "", url: "", format: "txt", feed_type: "ip",
  enabled: true, protocol: "http", taxii_url: "", taxii_username: "", misp_url: "",
});

function FeedForm({
  initial, onSave, onCancel,
}: {
  initial: Partial<IOCFeed>;
  onSave: (data: Partial<IOCFeed>) => Promise<void>;
  onCancel: () => void;
}) {
  const [form, setForm] = useState<Partial<IOCFeed>>(initial);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ reachable: boolean; detail: string } | null>(null);
  const [error, setError] = useState("");

  const set = (patch: Partial<IOCFeed>) => setForm((f) => ({ ...f, ...patch }));
  const field = "rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-sm text-white placeholder-white/20 focus:outline-none focus:border-white/20 w-full";

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError("");
    try { await onSave(form); }
    catch (err: unknown) { setError(err instanceof Error ? err.message : "Save failed"); }
    finally { setSaving(false); }
  }

  async function handleTest() {
    if (!form.id) return;
    setTesting(true);
    setTestResult(null);
    try {
      const r = await api.post(`/ioc-feeds/${form.id}/test`, {}) as { reachable: boolean; detail: string };
      setTestResult(r);
    } catch { setTestResult({ reachable: false, detail: "Request failed" }); }
    finally { setTesting(false); }
  }

  return (
    <form onSubmit={handleSave} className="space-y-3">
      <input className={field} placeholder="Feed name *" value={form.name ?? ""} onChange={(e) => set({ name: e.target.value })} required />

      {/* Protocol selector */}
      <div>
        <label className="text-[10px] text-white/30 uppercase tracking-wider block mb-1">Protocol</label>
        <div className="flex gap-2">
          {(["http", "taxii", "misp"] as const).map((p) => (
            <button key={p} type="button"
              onClick={() => set({ protocol: p })}
              className={`flex-1 rounded-lg border py-1.5 text-xs transition-colors ${form.protocol === p ? "border-white/20 bg-white/[0.06] text-white" : "border-white/8 text-white/40 hover:text-white/70"}`}
            >
              {PROTOCOL_LABELS[p]}
            </button>
          ))}
        </div>
      </div>

      {/* HTTP fields */}
      {form.protocol === "http" && (
        <>
          <input className={`${field} font-mono`} type="url" placeholder="https://example.com/feed.txt" value={form.url ?? ""} onChange={(e) => set({ url: e.target.value })} />
          <div className="grid grid-cols-2 gap-3">
            <select className={field} value={form.feed_type ?? "ip"} onChange={(e) => set({ feed_type: e.target.value })}>
              {Object.entries(TYPE_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
            <select className={field} value={form.format ?? "txt"} onChange={(e) => set({ format: e.target.value })}>
              {Object.entries(FORMAT_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </div>
        </>
      )}

      {/* TAXII fields */}
      {form.protocol === "taxii" && (
        <>
          <input className={`${field} font-mono`} placeholder="TAXII base URL (e.g. https://tip.example.com/taxii2/)" value={form.taxii_url ?? ""} onChange={(e) => set({ taxii_url: e.target.value })} />
          <div className="grid grid-cols-2 gap-3">
            <input className={field} placeholder="Username (optional)" value={form.taxii_username ?? ""} onChange={(e) => set({ taxii_username: e.target.value })} />
            <input className={field} type="password" placeholder="Password (optional)" onChange={(e) => set({ taxii_password: e.target.value } as Partial<IOCFeed>)} />
          </div>
        </>
      )}

      {/* MISP fields */}
      {form.protocol === "misp" && (
        <>
          <input className={`${field} font-mono`} placeholder="MISP URL (e.g. https://misp.example.com)" value={form.misp_url ?? ""} onChange={(e) => set({ misp_url: e.target.value })} />
          <input className={field} type="password" placeholder="MISP API key" onChange={(e) => set({ misp_key: e.target.value } as Partial<IOCFeed>)} />
        </>
      )}

      <label className="flex items-center gap-2 cursor-pointer">
        <input type="checkbox" checked={form.enabled ?? true} onChange={(e) => set({ enabled: e.target.checked })} />
        <span className="text-sm text-white/60">Sync automatically</span>
      </label>

      {error && <p className="text-red-400 text-xs">{error}</p>}
      {testResult && (
        <div className={`flex items-center gap-2 rounded-lg border p-2 text-xs ${testResult.reachable ? "border-emerald-500/30 bg-emerald-500/5 text-emerald-300" : "border-red-500/30 bg-red-500/5 text-red-300"}`}>
          {testResult.reachable ? <CheckCircle2 size={12} /> : <AlertTriangle size={12} />}
          {testResult.detail}
        </div>
      )}

      <div className="flex gap-2 justify-end">
        <button type="button" onClick={onCancel} className="rounded-lg border border-white/10 px-3 py-1.5 text-xs text-white/50 hover:text-white transition-colors">Cancel</button>
        <button type="button" onClick={handleTest} disabled={testing}
          className="rounded-lg border border-white/10 px-3 py-1.5 text-xs text-white/50 hover:text-white transition-colors disabled:opacity-50">
          {testing ? "Testing…" : "Test"}
        </button>
        <button type="submit" disabled={saving || !form.name?.trim()}
          className="rounded-lg bg-white/10 border border-white/20 px-3 py-1.5 text-xs text-white hover:bg-white/15 transition-colors disabled:opacity-50">
          {saving ? "Saving…" : "Save"}
        </button>
      </div>
    </form>
  );
}

function FeedRow({ feed, onRefresh }: { feed: IOCFeed; onRefresh: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const [editing, setEditing] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<{ added: number } | null>(null);

  async function sync() {
    setSyncing(true);
    setSyncResult(null);
    try {
      const r = await api.post(`/ioc-feeds/${feed.id}/sync`, {}) as { added: number };
      setSyncResult(r);
      onRefresh();
    } finally { setSyncing(false); }
  }

  async function del() {
    if (!confirm(`Delete feed "${feed.name}"?`)) return;
    await api.del(`/ioc-feeds/${feed.id}`);
    onRefresh();
  }

  async function save(data: Partial<IOCFeed>) {
    await api.put(`/ioc-feeds/${feed.id}`, { ...feed, ...data });
    setEditing(false);
    onRefresh();
  }

  return (
    <div className={`rounded-xl border bg-white/[0.02] transition-colors ${editing ? "border-white/20" : "border-white/8"}`}>
      <div className="flex items-center gap-3 px-4 py-3">
        {/* Status dot */}
        <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${feed.enabled ? "bg-emerald-500" : "bg-white/20"}`} />

        {/* Name + meta */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-sm font-medium text-white/90">{feed.name}</p>
            <span className="rounded border border-white/10 bg-white/5 px-1.5 py-0.5 text-[10px] text-white/40">
              {PROTOCOL_LABELS[feed.protocol] ?? "HTTP"}
            </span>
            {feed.feed_type && (
              <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${TYPE_COLORS[feed.feed_type] ?? "text-white/40 border-white/10 bg-white/5"}`}>
                {TYPE_LABELS[feed.feed_type] ?? feed.feed_type}
              </span>
            )}
            {feed.entry_count > 0 && <QualityBadge score={feed.quality_score} />}
          </div>
          <div className="flex items-center gap-3 mt-0.5 text-[11px] text-white/30">
            <span className="font-mono truncate max-w-[220px]">{feed.taxii_url || feed.misp_url || feed.url || "—"}</span>
            {feed.entry_count > 0 && <span>{feed.entry_count.toLocaleString()} IOCs</span>}
            {feed.hit_count > 0 && <span className="text-amber-400/60">{feed.hit_count} hits</span>}
            {feed.last_synced_at && (
              <span className="flex items-center gap-1">
                <Clock size={9} />
                {new Date(feed.last_synced_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
              </span>
            )}
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-1 shrink-0">
          {syncResult && <span className="text-[10px] text-emerald-400">+{syncResult.added}</span>}
          <button onClick={sync} disabled={syncing} title="Sync now"
            className="rounded p-1.5 text-white/30 hover:text-white hover:bg-white/5 transition-colors disabled:opacity-40">
            <RefreshCw size={13} className={syncing ? "animate-spin" : ""} />
          </button>
          <button onClick={() => { setEditing(!editing); setExpanded(false); }} title="Edit"
            className="rounded p-1.5 text-white/30 hover:text-white hover:bg-white/5 transition-colors text-xs px-2">
            Edit
          </button>
          <button onClick={del} title="Delete"
            className="rounded p-1.5 text-red-400/40 hover:text-red-400 hover:bg-red-500/5 transition-colors text-xs px-2">
            Delete
          </button>
          <button onClick={() => { setExpanded(!expanded); setEditing(false); }}
            className="rounded p-1.5 text-white/20 hover:text-white/60 transition-colors">
            {expanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
          </button>
        </div>
      </div>

      {editing && (
        <div className="border-t border-white/8 px-4 py-4">
          <FeedForm initial={feed} onSave={save} onCancel={() => setEditing(false)} />
        </div>
      )}

      {expanded && !editing && (
        <div className="border-t border-white/8 px-4 py-3">
          <p className="text-[10px] font-medium text-white/30 uppercase tracking-wider mb-2">Sync History</p>
          <SyncLogDrawer feedId={feed.id} />
        </div>
      )}
    </div>
  );
}

export default function IOCFeedsPage() {
  const { data, loading, refetch } = useApi<IOCFeed[]>(
    (signal) => api.get("/ioc-feeds", {}, signal),
  );
  const [creating, setCreating] = useState(false);

  const feeds = data ?? [];

  async function create(form: Partial<IOCFeed>) {
    if (!form.id) return;
    await api.put(`/ioc-feeds/${form.id}`, form);
    setCreating(false);
    refetch();
  }

  const totalIOCs = feeds.reduce((s, f) => s + f.entry_count, 0);
  const totalHits = feeds.reduce((s, f) => s + f.hit_count, 0);
  const active = feeds.filter((f) => f.enabled).length;

  return (
    <div className="space-y-5 max-w-4xl">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Custom IOC Feeds</h1>
          <p className="text-sm text-white/50 mt-0.5">HTTP, TAXII 2.1, and MISP threat intelligence feeds</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="flex items-center gap-1.5 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-white/60 hover:text-white transition-colors">
            <RefreshCw size={13} />
          </button>
          <button onClick={() => setCreating(true)}
            className="flex items-center gap-1.5 rounded-lg border border-white/20 bg-white/[0.06] px-3 py-1.5 text-xs text-white hover:bg-white/10 transition-colors">
            <Plus size={13} /> Add Feed
          </button>
        </div>
      </div>

      {/* Stats */}
      {feeds.length > 0 && (
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: "Feeds", value: feeds.length, sub: `${active} active` },
            { label: "Total IOCs", value: totalIOCs.toLocaleString(), sub: "across all feeds" },
            { label: "Match hits", value: totalHits, sub: "IOCs that fired" },
            { label: "Avg quality", value: feeds.length ? Math.round(feeds.reduce((s, f) => s + f.quality_score, 0) / feeds.length) + "%" : "—", sub: "hit rate - staleness" },
          ].map(({ label, value, sub }) => (
            <div key={label} className="rounded-xl border border-white/8 bg-white/[0.02] p-3 text-center">
              <p className="text-xl font-bold text-white tabular-nums">{value}</p>
              <p className="text-[10px] text-white/40 mt-0.5">{label}</p>
              <p className="text-[10px] text-white/20">{sub}</p>
            </div>
          ))}
        </div>
      )}

      {/* Create form */}
      {creating && (
        <div className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
          <p className="text-sm font-semibold text-white mb-4">New Feed</p>
          <FeedForm initial={EMPTY_FEED()} onSave={create} onCancel={() => setCreating(false)} />
        </div>
      )}

      {loading && <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center text-white/30 text-sm">Loading…</div>}

      {!loading && feeds.length === 0 && !creating && (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center space-y-2">
          <Activity size={28} className="mx-auto text-white/20" />
          <p className="text-white/30 text-sm">No custom feeds yet.</p>
          <p className="text-white/20 text-xs">Add HTTP, TAXII 2.1, or MISP feeds to extend coverage beyond built-in sources.</p>
        </div>
      )}

      <div className="space-y-2">
        {feeds.map((f) => <FeedRow key={f.id} feed={f} onRefresh={refetch} />)}
      </div>

      {/* Built-in feeds reference */}
      <div className="rounded-xl border border-white/8 bg-white/[0.02] p-4 space-y-2">
        <p className="text-xs font-medium text-white/40 uppercase tracking-wider">Built-in feeds (read-only)</p>
        <div className="grid grid-cols-2 gap-2 text-xs">
          {[
            { name: "Feodo Tracker", type: "C2 IPs", ok: true },
            { name: "Emerging Threats", type: "Compromised IPs", ok: true },
            { name: "URLhaus", type: "Malicious URLs/Domains", ok: true },
            { name: "MalwareBazaar", type: "SHA256 Hashes", ok: true },
          ].map((f) => (
            <div key={f.name} className="flex items-center gap-2 text-white/40">
              {f.ok ? <Wifi size={11} className="text-emerald-500 shrink-0" /> : <WifiOff size={11} className="text-white/20 shrink-0" />}
              <span>{f.name}</span>
              <span className="text-white/20">— {f.type}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
