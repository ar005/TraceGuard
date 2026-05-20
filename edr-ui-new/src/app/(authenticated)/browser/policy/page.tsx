"use client";

import { useCallback, useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn } from "@/lib/utils";
import {
  ShieldCheck, ShieldOff, Plus, Trash2, RefreshCw, Loader2,
  CheckCircle2, AlertCircle, Globe, Info,
} from "lucide-react";

interface BrowserPolicyEntry {
  id: string;
  tenant_id: string;
  domain: string;
  entry_type: "allow" | "block";
  description: string;
  created_by: string;
  created_at: string;
}

export default function BrowserPolicyPage() {
  const [newDomain, setNewDomain] = useState("");
  const [newType, setNewType] = useState<"allow" | "block">("block");
  const [newDesc, setNewDesc] = useState("");
  const [saving, setSaving] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);

  const { data, loading, refetch } = useApi<{ entries: BrowserPolicyEntry[] }>(
    useCallback((s: AbortSignal) => api.get("/api/v1/browser/policy", undefined, s), [])
  );

  const entries = data?.entries ?? [];
  const allowed = entries.filter(e => e.entry_type === "allow");
  const blocked = entries.filter(e => e.entry_type === "block");

  const showToast = (msg: string, ok: boolean) => {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 3000);
  };

  const handleAdd = async () => {
    const domain = newDomain.trim().toLowerCase();
    if (!domain) return;
    setSaving(true);
    try {
      await api.post("/api/v1/browser/policy", {
        domain,
        entry_type: newType,
        description: newDesc,
      });
      setNewDomain("");
      setNewDesc("");
      refetch();
      showToast(`${newType === "allow" ? "Allowlisted" : "Blocklisted"}: ${domain}`, true);
    } catch (e: unknown) {
      showToast(e instanceof Error ? e.message : "Failed to add entry", false);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: string) => {
    setDeletingId(id);
    try {
      await api.delete(`/api/v1/browser/policy/${id}`);
      refetch();
      showToast("Entry removed", true);
    } catch {
      showToast("Delete failed", false);
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-indigo-500/15 flex items-center justify-center">
            <Globe size={20} className="text-indigo-400" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-[var(--color-text-primary)]">Browser Domain Policy</h1>
            <p className="text-sm text-[var(--color-text-muted)]">Allowlist trusted domains to suppress events · Blocklist domains to escalate alerts</p>
          </div>
        </div>
        <button onClick={refetch} className="text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)] transition-colors">
          <RefreshCw size={15} />
        </button>
      </div>

      {/* How it works banner */}
      <div className="flex gap-3 p-4 rounded-xl bg-[var(--color-bg-secondary)] border border-[var(--color-border)] text-sm text-[var(--color-text-secondary)]">
        <Info size={16} className="shrink-0 mt-0.5 text-indigo-400" />
        <p>
          <span className="font-medium text-green-400">Allowlisted</span> domains are silently suppressed at the agent — events are not forwarded to the backend (reduces noise from internal tools, CDNs, etc.).{" "}
          <span className="font-medium text-red-400">Blocklisted</span> domains are forwarded with HIGH severity and tagged <code className="text-xs bg-[var(--color-bg-tertiary)] px-1 rounded">policy-blocked</code>.
          Wildcards are supported: <code className="text-xs bg-[var(--color-bg-tertiary)] px-1 rounded">*.example.com</code>
        </p>
      </div>

      {/* Add entry form */}
      <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl p-5 space-y-3">
        <p className="text-sm font-medium text-[var(--color-text-primary)]">Add Domain</p>
        <div className="flex gap-2">
          <div className="flex rounded-lg overflow-hidden border border-[var(--color-border)] shrink-0">
            {(["block", "allow"] as const).map(t => (
              <button
                key={t}
                onClick={() => setNewType(t)}
                className={cn(
                  "px-3 py-2 text-xs font-medium flex items-center gap-1.5 transition-colors",
                  newType === t
                    ? t === "block"
                      ? "bg-red-500/20 text-red-400"
                      : "bg-green-500/20 text-green-400"
                    : "bg-[var(--color-bg-tertiary)] text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]"
                )}
              >
                {t === "block" ? <ShieldOff size={12} /> : <ShieldCheck size={12} />}
                {t === "block" ? "Block" : "Allow"}
              </button>
            ))}
          </div>
          <input
            value={newDomain}
            onChange={e => setNewDomain(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleAdd()}
            placeholder="example.com or *.example.com"
            className="flex-1 px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:border-indigo-500"
          />
          <input
            value={newDesc}
            onChange={e => setNewDesc(e.target.value)}
            placeholder="Note (optional)"
            className="w-48 px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:border-indigo-500"
          />
          <button
            onClick={handleAdd}
            disabled={saving || !newDomain.trim()}
            className="flex items-center gap-1.5 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
          >
            {saving ? <Loader2 size={13} className="animate-spin" /> : <Plus size={13} />}
            Add
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex justify-center py-10"><Loader2 size={20} className="animate-spin text-[var(--color-text-muted)]" /></div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* Blocklist */}
          <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-[var(--color-border)] bg-red-500/5">
              <ShieldOff size={14} className="text-red-400" />
              <p className="text-sm font-medium text-red-400">Blocklist</p>
              <span className="ml-auto text-xs text-[var(--color-text-muted)] bg-[var(--color-bg-tertiary)] px-2 py-0.5 rounded-full">{blocked.length}</span>
            </div>
            {blocked.length === 0 ? (
              <p className="text-center py-8 text-sm text-[var(--color-text-muted)]">No blocked domains</p>
            ) : (
              <ul className="divide-y divide-[var(--color-border)]">
                {blocked.map(e => (
                  <li key={e.id} className="flex items-center gap-2 px-4 py-2.5 hover:bg-[var(--color-bg-tertiary)] group">
                    <code className="flex-1 text-sm text-red-300 font-mono truncate">{e.domain}</code>
                    {e.description && (
                      <span className="text-xs text-[var(--color-text-muted)] truncate max-w-[100px]">{e.description}</span>
                    )}
                    <button
                      onClick={() => handleDelete(e.id)}
                      disabled={deletingId === e.id}
                      className="opacity-0 group-hover:opacity-100 p-1 rounded text-[var(--color-text-muted)] hover:text-red-400 hover:bg-red-500/10 transition-all"
                    >
                      {deletingId === e.id ? <Loader2 size={12} className="animate-spin" /> : <Trash2 size={12} />}
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* Allowlist */}
          <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-[var(--color-border)] bg-green-500/5">
              <ShieldCheck size={14} className="text-green-400" />
              <p className="text-sm font-medium text-green-400">Allowlist</p>
              <span className="ml-auto text-xs text-[var(--color-text-muted)] bg-[var(--color-bg-tertiary)] px-2 py-0.5 rounded-full">{allowed.length}</span>
            </div>
            {allowed.length === 0 ? (
              <p className="text-center py-8 text-sm text-[var(--color-text-muted)]">No allowed domains</p>
            ) : (
              <ul className="divide-y divide-[var(--color-border)]">
                {allowed.map(e => (
                  <li key={e.id} className="flex items-center gap-2 px-4 py-2.5 hover:bg-[var(--color-bg-tertiary)] group">
                    <code className="flex-1 text-sm text-green-300 font-mono truncate">{e.domain}</code>
                    {e.description && (
                      <span className="text-xs text-[var(--color-text-muted)] truncate max-w-[100px]">{e.description}</span>
                    )}
                    <button
                      onClick={() => handleDelete(e.id)}
                      disabled={deletingId === e.id}
                      className="opacity-0 group-hover:opacity-100 p-1 rounded text-[var(--color-text-muted)] hover:text-red-400 hover:bg-red-500/10 transition-all"
                    >
                      {deletingId === e.id ? <Loader2 size={12} className="animate-spin" /> : <Trash2 size={12} />}
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
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
