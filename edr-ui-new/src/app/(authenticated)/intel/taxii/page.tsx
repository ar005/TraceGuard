"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { Rss, RefreshCw, Trash2, Plus, CheckCircle, XCircle, Clock, ChevronDown, ChevronRight, AlertCircle } from "lucide-react";
import { cn, timeAgo } from "@/lib/utils";

interface TAXIIFeed {
  id: string;
  name: string;
  discovery_url: string;
  api_root: string;
  collection_id: string;
  username: string;
  poll_interval: number;
  last_polled_at?: string;
  next_poll_at?: string;
  enabled: boolean;
  ioc_count: number;
  last_error: string;
  created_at: string;
  hit_count?: number;
  last_hit_at?: string;
  quality_score?: number;
}

interface PollRun {
  id: string;
  feed_id: string;
  started_at: string;
  finished_at?: string;
  objects_fetched: number;
  iocs_imported: number;
  status: "running" | "ok" | "error";
  error: string;
}

interface TAXIICollection {
  id: string;
  title: string;
  description: string;
  can_read: boolean;
}

function StatusBadge({ feed }: { feed: TAXIIFeed }) {
  if (!feed.enabled)
    return <span className="text-xs px-2 py-0.5 rounded-full border border-[hsl(var(--border))] text-[hsl(var(--muted-foreground))]">disabled</span>;
  if (feed.last_error)
    return (
      <span className="flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border border-red-500/40 bg-red-500/10 text-red-400">
        <AlertCircle size={11} /> error
      </span>
    );
  if (feed.last_polled_at)
    return (
      <span className="flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border border-green-500/40 bg-green-500/10 text-green-400">
        <CheckCircle size={11} /> active
      </span>
    );
  return (
    <span className="flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border border-yellow-500/40 bg-yellow-500/10 text-yellow-400">
      <Clock size={11} /> pending
    </span>
  );
}

function QualityBadge({ score }: { score: number }) {
  const cls =
    score >= 60 ? "border-green-500/40 bg-green-500/10 text-green-400" :
    score >= 30 ? "border-yellow-500/40 bg-yellow-500/10 text-yellow-400" :
                  "border-red-500/40 bg-red-500/10 text-red-400";
  return (
    <span className={cn("text-xs px-2 py-0.5 rounded-full border font-medium", cls)}>
      Q{score}
    </span>
  );
}

function PollRunRow({ run }: { run: PollRun }) {
  const icon =
    run.status === "ok"    ? <CheckCircle size={13} className="text-green-400" /> :
    run.status === "error" ? <XCircle size={13} className="text-red-400" /> :
                             <Clock size={13} className="text-yellow-400 animate-spin" />;
  return (
    <div className="flex items-center gap-3 text-xs px-3 py-1.5 rounded bg-[hsl(var(--muted)/.3)]">
      {icon}
      <span className="text-[hsl(var(--muted-foreground))]">{new Date(run.started_at).toLocaleString()}</span>
      <span className="ml-auto font-mono">
        {run.iocs_imported > 0
          ? <span className="text-green-400 font-semibold">+{run.iocs_imported} IOCs</span>
          : <span className="text-[hsl(var(--muted-foreground))]">0 new</span>}
        {" / "}{run.objects_fetched} objects
      </span>
      {run.error && <span className="text-red-400 truncate max-w-[180px]" title={run.error}>{run.error}</span>}
    </div>
  );
}

function FeedRunHistory({ feedId }: { feedId: string }) {
  const { data: runs } = useApi<PollRun[]>(
    (sig) => api.get<PollRun[]>(`/intel/taxii-feeds/${feedId}/runs`, {}, sig)
  );
  if (!runs || runs.length === 0) {
    return <p className="text-xs text-[hsl(var(--muted-foreground))] italic">No polls yet.</p>;
  }
  return (
    <div className="space-y-1.5">
      {runs.slice(0, 10).map((r) => <PollRunRow key={r.id} run={r} />)}
    </div>
  );
}

function FeedCard({
  feed,
  onPoll,
  onToggle,
  onDelete,
}: {
  feed: TAXIIFeed;
  onPoll: (id: string) => Promise<void>;
  onToggle: (id: string, enabled: boolean) => void;
  onDelete: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [polling, setPolling] = useState(false);

  const handlePoll = async () => {
    setPolling(true);
    try { await onPoll(feed.id); } finally { setTimeout(() => setPolling(false), 1500); }
  };

  return (
    <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-3">
        <button onClick={() => setOpen((v) => !v)} className="text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors">
          {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </button>
        <Rss size={15} className={feed.enabled ? "text-[hsl(var(--primary))]" : "text-[hsl(var(--muted-foreground))]"} />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium truncate">{feed.name}</p>
          <p className="text-xs text-[hsl(var(--muted-foreground))] truncate">{feed.discovery_url}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <StatusBadge feed={feed} />
          {feed.quality_score != null && feed.ioc_count > 0 && (
            <QualityBadge score={feed.quality_score} />
          )}
          <span className="text-xs font-mono text-[hsl(var(--muted-foreground))] hidden sm:block">
            {feed.ioc_count.toLocaleString()} IOCs
          </span>
          {(feed.hit_count ?? 0) > 0 && (
            <span className="text-xs font-mono text-orange-400 hidden sm:block">
              {feed.hit_count} hits
            </span>
          )}
          {feed.last_polled_at && (
            <span className="text-xs text-[hsl(var(--muted-foreground))] hidden md:block">
              {new Date(feed.last_polled_at).toLocaleString()}
            </span>
          )}
          <button onClick={handlePoll} disabled={polling} title="Poll now"
            className="p-1.5 rounded hover:bg-[hsl(var(--accent))] transition-colors disabled:opacity-50">
            <RefreshCw size={14} className={cn("text-[hsl(var(--primary))]", polling && "animate-spin")} />
          </button>
          <button onClick={() => onToggle(feed.id, !feed.enabled)}
            className="p-1.5 rounded hover:bg-[hsl(var(--accent))] transition-colors text-xs font-medium text-[hsl(var(--muted-foreground))]">
            {feed.enabled ? "Disable" : "Enable"}
          </button>
          <button onClick={() => onDelete(feed.id)} title="Delete"
            className="p-1.5 rounded hover:bg-red-500/10 text-[hsl(var(--muted-foreground))] hover:text-red-400 transition-colors">
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      {feed.last_error && (
        <div className="border-t border-red-500/20 bg-red-500/5 px-4 py-2">
          <p className="text-xs text-red-400">{feed.last_error}</p>
        </div>
      )}

      {open && (
        <div className="border-t border-[hsl(var(--border))] px-4 py-3 space-y-3">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div>
              <p className="text-[hsl(var(--muted-foreground))] uppercase tracking-wider mb-0.5">API Root</p>
              <p className="font-mono truncate">{feed.api_root || "—"}</p>
            </div>
            <div>
              <p className="text-[hsl(var(--muted-foreground))] uppercase tracking-wider mb-0.5">Collection</p>
              <p className="font-mono truncate">{feed.collection_id || "auto-discover"}</p>
            </div>
            <div>
              <p className="text-[hsl(var(--muted-foreground))] uppercase tracking-wider mb-0.5">Poll Interval</p>
              <p>{Math.round(feed.poll_interval / 60)} min</p>
            </div>
            <div>
              <p className="text-[hsl(var(--muted-foreground))] uppercase tracking-wider mb-0.5">Next Poll</p>
              <p>{feed.next_poll_at ? new Date(feed.next_poll_at).toLocaleString() : "—"}</p>
            </div>
          </div>

          {/* Feed quality panel */}
          {feed.ioc_count > 0 && (
            <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--muted)/.15)] px-4 py-3 space-y-2">
              <p className="text-xs font-medium text-[hsl(var(--muted-foreground))] uppercase tracking-wider">Feed Quality</p>
              <div className="flex items-center gap-3">
                <div className="flex-1 h-2 rounded-full bg-[hsl(var(--muted)/.3)] overflow-hidden">
                  <div
                    className={cn("h-full rounded-full transition-all",
                      (feed.quality_score ?? 0) >= 60 ? "bg-green-500" :
                      (feed.quality_score ?? 0) >= 30 ? "bg-yellow-500" : "bg-red-500"
                    )}
                    style={{ width: `${feed.quality_score ?? 0}%` }}
                  />
                </div>
                <span className="text-sm font-semibold font-mono w-8 shrink-0 text-right">
                  {feed.quality_score ?? 0}
                </span>
              </div>
              <div className="grid grid-cols-3 gap-3 text-xs">
                <div>
                  <p className="text-[hsl(var(--muted-foreground))] uppercase tracking-wider mb-0.5">Alert Hits</p>
                  <p className="font-semibold font-mono">{(feed.hit_count ?? 0).toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-[hsl(var(--muted-foreground))] uppercase tracking-wider mb-0.5">Hit Rate</p>
                  <p className="font-semibold font-mono">
                    {feed.ioc_count > 0
                      ? `${Math.round(((feed.hit_count ?? 0) / feed.ioc_count) * 100)}%`
                      : "—"}
                  </p>
                </div>
                <div>
                  <p className="text-[hsl(var(--muted-foreground))] uppercase tracking-wider mb-0.5">Last Hit</p>
                  <p className="font-semibold">{feed.last_hit_at ? timeAgo(feed.last_hit_at) : "never"}</p>
                </div>
              </div>
              {feed.enabled && (feed.hit_count ?? 0) === 0 && feed.last_polled_at && (() => {
                const daysSinceFirstPoll = (Date.now() - new Date(feed.last_polled_at).getTime()) / 86_400_000;
                if (daysSinceFirstPoll > 30) {
                  return (
                    <p className="text-xs text-amber-400">
                      ⚠ No hits in {Math.round(daysSinceFirstPoll)} days — feed may be auto-disabled after 60 days.
                    </p>
                  );
                }
                return null;
              })()}
            </div>
          )}
          <div>
            <p className="text-xs font-medium text-[hsl(var(--muted-foreground))] uppercase tracking-wider mb-2">Recent polls</p>
            <FeedRunHistory feedId={feed.id} />
          </div>
        </div>
      )}
    </div>
  );
}

function CreateModal({ onClose, onCreate }: { onClose: () => void; onCreate: () => void }) {
  const [form, setForm] = useState({
    name: "",
    discovery_url: "",
    api_root: "",
    collection_id: "",
    username: "",
    password: "",
    poll_interval: 3600,
    enabled: true,
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [discovering, setDiscovering] = useState(false);
  const [collections, setCollections] = useState<TAXIICollection[] | null>(null);

  const submit = async () => {
    if (!form.name.trim() || !form.discovery_url.trim()) {
      setError("Name and discovery URL are required.");
      return;
    }
    setSaving(true);
    try {
      await api.post("/intel/taxii-feeds", form);
      onCreate();
      onClose();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to create feed");
    } finally {
      setSaving(false);
    }
  };

  const discoverCollections = async () => {
    if (!form.discovery_url) return;
    setDiscovering(true);
    setCollections(null);
    try {
      const tmpFeed = await api.post<TAXIIFeed>("/intel/taxii-feeds", {
        ...form,
        name: form.name || "__discover_tmp__",
        enabled: false,
      });
      const cols = await api.get<TAXIICollection[]>(`/intel/taxii-feeds/${tmpFeed.id}/collections`);
      await api.del(`/intel/taxii-feeds/${tmpFeed.id}`);
      setCollections(cols);
    } catch {
      setError("Could not reach TAXII server. Check URL and credentials.");
    } finally {
      setDiscovering(false);
    }
  };

  const INTERVAL_PRESETS = [
    { label: "15 min",  value: 900 },
    { label: "1 hour",  value: 3600 },
    { label: "6 hours", value: 21600 },
    { label: "Daily",   value: 86400 },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="w-full max-w-lg rounded-xl border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-6 shadow-xl space-y-4 max-h-[90vh] overflow-y-auto">
        <h2 className="text-base font-semibold">Add TAXII 2.1 Feed</h2>
        <div className="space-y-3">
          <div>
            <label className="text-xs font-medium text-[hsl(var(--muted-foreground))] uppercase tracking-wider">Name</label>
            <input className="mt-1 w-full rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[hsl(var(--primary))]"
              placeholder="CISA Known Exploited Vulnerabilities" value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
          </div>
          <div>
            <label className="text-xs font-medium text-[hsl(var(--muted-foreground))] uppercase tracking-wider">Discovery URL</label>
            <div className="mt-1 flex gap-2">
              <input className="flex-1 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[hsl(var(--primary))]"
                placeholder="https://otx.alienvault.com/taxii/root" value={form.discovery_url}
                onChange={(e) => setForm((f) => ({ ...f, discovery_url: e.target.value }))} />
              <button onClick={discoverCollections} disabled={discovering || !form.discovery_url}
                className="px-3 py-2 text-xs rounded-md border border-[hsl(var(--border))] hover:bg-[hsl(var(--accent))] transition-colors disabled:opacity-50 whitespace-nowrap">
                {discovering ? "Discovering…" : "Discover"}
              </button>
            </div>
          </div>
          {collections && collections.length > 0 && (
            <div>
              <label className="text-xs font-medium text-[hsl(var(--muted-foreground))] uppercase tracking-wider">Collection</label>
              <select className="mt-1 w-full rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[hsl(var(--primary))]"
                value={form.collection_id} onChange={(e) => setForm((f) => ({ ...f, collection_id: e.target.value }))}>
                <option value="">Auto-select first readable</option>
                {collections.filter((c) => c.can_read).map((c) => (
                  <option key={c.id} value={c.id}>{c.title || c.id}</option>
                ))}
              </select>
            </div>
          )}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-[hsl(var(--muted-foreground))] uppercase tracking-wider">Username</label>
              <input className="mt-1 w-full rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[hsl(var(--primary))]"
                placeholder="optional" value={form.username} onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))} />
            </div>
            <div>
              <label className="text-xs font-medium text-[hsl(var(--muted-foreground))] uppercase tracking-wider">Password / API Key</label>
              <input type="password" className="mt-1 w-full rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[hsl(var(--primary))]"
                placeholder="optional" value={form.password} onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))} />
            </div>
          </div>
          <div>
            <label className="text-xs font-medium text-[hsl(var(--muted-foreground))] uppercase tracking-wider">Poll Interval</label>
            <div className="mt-1 flex gap-2">
              {INTERVAL_PRESETS.map((p) => (
                <button key={p.value} onClick={() => setForm((f) => ({ ...f, poll_interval: p.value }))}
                  className={cn("flex-1 text-xs py-1.5 rounded-md border transition-colors",
                    form.poll_interval === p.value
                      ? "border-[hsl(var(--primary))] bg-[hsl(var(--primary)/.1)] text-[hsl(var(--primary))]"
                      : "border-[hsl(var(--border))] text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]")}>
                  {p.label}
                </button>
              ))}
            </div>
          </div>
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input type="checkbox" checked={form.enabled}
              onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))} className="rounded" />
            Enable immediately (poll on next tick)
          </label>
        </div>
        {error && <p className="text-xs text-red-400">{error}</p>}
        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose}
            className="px-4 py-2 text-sm rounded-lg border border-[hsl(var(--border))] hover:bg-[hsl(var(--accent))] transition-colors">
            Cancel
          </button>
          <button onClick={submit} disabled={saving}
            className="px-4 py-2 text-sm rounded-lg bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity disabled:opacity-50">
            {saving ? "Adding…" : "Add Feed"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function TAXIIFeedsPage() {
  const [tick, setTick] = useState(0);
  const refresh = () => setTick((k) => k + 1);

  const { data: feeds, loading } = useApi<TAXIIFeed[]>(
    // eslint-disable-next-line react-hooks/exhaustive-deps
    (sig) => api.get<TAXIIFeed[]>("/intel/taxii-feeds", { _t: tick }, sig)
  );

  const [showCreate, setShowCreate] = useState(false);

  const handlePoll = async (id: string) => {
    await api.post(`/intel/taxii-feeds/${id}/poll`, {});
    setTimeout(refresh, 2000);
  };

  const handleToggle = async (id: string, enabled: boolean) => {
    await api.put(`/intel/taxii-feeds/${id}`, { enabled });
    refresh();
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this TAXII feed?")) return;
    await api.del(`/intel/taxii-feeds/${id}`);
    refresh();
  };

  const totalIOCs   = feeds?.reduce((sum, f) => sum + f.ioc_count, 0) ?? 0;
  const totalHits   = feeds?.reduce((sum, f) => sum + (f.hit_count ?? 0), 0) ?? 0;
  const activeCount = feeds?.filter((f) => f.enabled).length ?? 0;
  const errorCount  = feeds?.filter((f) => f.last_error).length ?? 0;
  const avgQuality  = feeds && feeds.length > 0
    ? Math.round(feeds.reduce((sum, f) => sum + (f.quality_score ?? 0), 0) / feeds.length)
    : 0;

  return (
    <div className="p-6 space-y-6 max-w-4xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">TAXII 2.1 Feeds</h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">
            Pull STIX 2.1 indicators from external threat intel servers automatically.
          </p>
        </div>
        <button onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] text-sm font-medium hover:opacity-90 transition-opacity">
          <Plus size={15} /> Add Feed
        </button>
      </div>

      <div className="grid grid-cols-6 gap-4">
        {[
          { label: "Total Feeds",   value: feeds?.length ?? 0,        danger: false, warn: false },
          { label: "Active",        value: activeCount,                danger: false, warn: false },
          { label: "IOCs Imported", value: totalIOCs.toLocaleString(), danger: false, warn: false },
          { label: "Alert Hits",    value: totalHits.toLocaleString(), danger: false, warn: false },
          { label: "Avg Quality",   value: avgQuality,                 danger: false, warn: avgQuality < 30 && (feeds?.length ?? 0) > 0 },
          { label: "Errors",        value: errorCount,                 danger: errorCount > 0, warn: false },
        ].map((s) => (
          <div key={s.label} className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-4 py-3">
            <p className="text-xs text-[hsl(var(--muted-foreground))] uppercase tracking-wider">{s.label}</p>
            <p className={cn("text-2xl font-semibold mt-1",
              s.danger && "text-red-400",
              s.warn && "text-amber-400"
            )}>{s.value}</p>
          </div>
        ))}
      </div>

      {loading ? (
        <div className="space-y-3">
          {[1, 2, 3].map((i) => <div key={i} className="h-16 rounded-lg bg-[hsl(var(--muted)/.3)] animate-pulse" />)}
        </div>
      ) : !feeds || feeds.length === 0 ? (
        <div className="rounded-lg border border-dashed border-[hsl(var(--border))] p-10 text-center">
          <Rss size={32} className="mx-auto mb-3 text-[hsl(var(--muted-foreground))]" />
          <p className="text-sm text-[hsl(var(--muted-foreground))]">
            No TAXII feeds configured. Add a feed to start pulling indicators automatically.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {feeds.map((f) => (
            <FeedCard key={f.id} feed={f} onPoll={handlePoll} onToggle={handleToggle} onDelete={handleDelete} />
          ))}
        </div>
      )}

      {showCreate && <CreateModal onClose={() => setShowCreate(false)} onCreate={refresh} />}
    </div>
  );
}
