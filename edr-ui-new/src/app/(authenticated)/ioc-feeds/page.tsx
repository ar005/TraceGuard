"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";

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
}

const FORMAT_LABELS: Record<string, string> = { txt: "Plain text", csv: "CSV", stix: "STIX 2.x" };
const TYPE_LABELS: Record<string, string> = { ip: "IP Addresses", domain: "Domains", hash: "File Hashes" };
const TYPE_COLORS: Record<string, string> = {
  ip: "text-red-400 bg-red-500/10 border-red-500/20",
  domain: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  hash: "text-purple-400 bg-purple-500/10 border-purple-500/20",
};

function genID() {
  return "feed-" + Math.random().toString(36).slice(2, 10);
}

const EMPTY = (): Partial<IOCFeed> => ({
  id: genID(),
  name: "",
  url: "",
  format: "txt",
  feed_type: "ip",
  enabled: true,
});

export default function IOCFeedsPage() {
  const { data: feeds, loading, refetch } = useApi<IOCFeed[]>(
    () => api.get("/ioc-feeds"),
  );

  const [editing, setEditing] = useState<Partial<IOCFeed> | null>(null);
  const [saving, setSaving] = useState(false);
  const [syncing, setSyncing] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  const rows = feeds ?? [];

  async function save() {
    if (!editing) return;
    setSaving(true);
    try {
      await api.put(`/ioc-feeds/${editing.id}`, editing);
      setEditing(null);
      refetch();
    } finally {
      setSaving(false);
    }
  }

  async function syncFeed(id: string) {
    setSyncing(id);
    try {
      await api.post(`/ioc-feeds/${id}/sync`, {});
      refetch();
    } finally {
      setSyncing(null);
    }
  }

  async function del(id: string) {
    setDeleting(id);
    try {
      await api.del(`/ioc-feeds/${id}`);
      refetch();
    } finally {
      setDeleting(null);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Custom IOC Feeds</h1>
          <p className="text-sm text-white/50 mt-0.5">
            Add custom threat intelligence feeds beyond the built-in sources
          </p>
        </div>
        <button
          onClick={() => setEditing(EMPTY())}
          className="px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors"
        >
          + Add Feed
        </button>
      </div>

      {/* Modal */}
      {editing && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="w-full max-w-lg bg-[#0f1117] border border-white/10 rounded-2xl p-6 space-y-4 shadow-2xl">
            <p className="text-base font-semibold text-white">
              {rows.find((f) => f.id === editing.id) ? "Edit Feed" : "Add Custom Feed"}
            </p>

            <label className="block space-y-1">
              <span className="text-xs text-white/50">Feed name</span>
              <input
                className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50"
                value={editing.name ?? ""}
                onChange={(e) => setEditing((f) => ({ ...f, name: e.target.value }))}
                placeholder="My TI Feed"
              />
            </label>

            <label className="block space-y-1">
              <span className="text-xs text-white/50">Feed URL</span>
              <input
                type="url"
                className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50 font-mono"
                value={editing.url ?? ""}
                onChange={(e) => setEditing((f) => ({ ...f, url: e.target.value }))}
                placeholder="https://example.com/ioc-list.txt"
              />
            </label>

            <div className="grid grid-cols-2 gap-3">
              <label className="block space-y-1">
                <span className="text-xs text-white/50">IOC type</span>
                <select
                  className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50"
                  value={editing.feed_type ?? "ip"}
                  onChange={(e) => setEditing((f) => ({ ...f, feed_type: e.target.value }))}
                >
                  {Object.entries(TYPE_LABELS).map(([v, l]) => (
                    <option key={v} value={v}>{l}</option>
                  ))}
                </select>
              </label>

              <label className="block space-y-1">
                <span className="text-xs text-white/50">Format</span>
                <select
                  className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50"
                  value={editing.format ?? "txt"}
                  onChange={(e) => setEditing((f) => ({ ...f, format: e.target.value }))}
                >
                  {Object.entries(FORMAT_LABELS).map(([v, l]) => (
                    <option key={v} value={v}>{l}</option>
                  ))}
                </select>
              </label>
            </div>

            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={editing.enabled ?? true}
                onChange={(e) => setEditing((f) => ({ ...f, enabled: e.target.checked }))}
              />
              <span className="text-sm text-white/70">Enabled (sync automatically)</span>
            </label>

            <div className="flex gap-2 pt-2">
              <button
                onClick={save}
                disabled={saving || !editing.name?.trim() || !editing.url?.trim()}
                className="flex-1 py-2 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white transition-colors"
              >
                {saving ? "Saving…" : "Save"}
              </button>
              <button
                onClick={() => setEditing(null)}
                className="flex-1 py-2 text-sm font-medium rounded-lg border border-white/10 text-white/60 hover:text-white transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Feeds table */}
      <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/10">
              {["Name", "Type", "Format", "Entries", "Last Sync", "Status", ""].map((h) => (
                <th key={h} className="text-left px-4 py-3 text-xs font-medium text-white/40 uppercase tracking-wider">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {loading && (
              <tr><td colSpan={7} className="px-4 py-10 text-center text-white/30 text-sm">Loading…</td></tr>
            )}
            {!loading && rows.length === 0 && (
              <tr><td colSpan={7} className="px-4 py-10 text-center text-white/30 text-sm">
                No custom feeds yet. Add one to extend threat intelligence coverage.
              </td></tr>
            )}
            {rows.map((f) => (
              <tr key={f.id} className="hover:bg-white/[0.02] transition-colors">
                <td className="px-4 py-3">
                  <div>
                    <p className="text-white font-medium">{f.name}</p>
                    <p className="text-white/30 text-xs font-mono truncate max-w-xs">{f.url}</p>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${TYPE_COLORS[f.feed_type] ?? "text-white/50 bg-white/5 border-white/10"}`}>
                    {TYPE_LABELS[f.feed_type] ?? f.feed_type}
                  </span>
                </td>
                <td className="px-4 py-3 text-white/50 text-xs">{FORMAT_LABELS[f.format] ?? f.format}</td>
                <td className="px-4 py-3 text-white/60 font-mono text-xs">
                  {f.entry_count > 0 ? f.entry_count.toLocaleString() : "—"}
                </td>
                <td className="px-4 py-3 text-white/30 text-xs font-mono">
                  {f.last_synced_at ? new Date(f.last_synced_at).toLocaleString() : "Never"}
                </td>
                <td className="px-4 py-3">
                  <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${f.enabled ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" : "text-white/30 bg-white/5 border-white/10"}`}>
                    {f.enabled ? "Active" : "Disabled"}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center justify-end gap-2">
                    <button
                      onClick={() => syncFeed(f.id)}
                      disabled={syncing === f.id}
                      className="text-xs text-blue-400/70 hover:text-blue-400 transition-colors px-2 py-1"
                    >
                      {syncing === f.id ? "Syncing…" : "Sync"}
                    </button>
                    <button
                      onClick={() => setEditing({ ...f })}
                      className="text-xs text-white/40 hover:text-white transition-colors px-2 py-1"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => del(f.id)}
                      disabled={deleting === f.id}
                      className="text-xs text-red-400/60 hover:text-red-400 transition-colors px-2 py-1"
                    >
                      {deleting === f.id ? "…" : "Delete"}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4 space-y-2">
        <p className="text-xs font-medium text-white/60 uppercase tracking-wider">Built-in feeds (read-only)</p>
        <div className="grid grid-cols-2 gap-2 text-xs text-white/40">
          {["Feodo Tracker (IPs)", "Emerging Threats (IPs)", "URLhaus (URLs/Domains)", "Abuse.ch (Hashes)"].map((f) => (
            <div key={f} className="flex items-center gap-2">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              {f}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
