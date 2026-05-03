"use client";

import { useCallback, useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn, timeAgo } from "@/lib/utils";

/* ---------- Types ---------- */
interface CanaryToken {
  id: string;
  name: string;
  type: "credential" | "file" | "url" | "dns";
  token: string;
  deployed_to: string;
  description: string;
  created_at: string;
  triggered_at: string | null;
  trigger_count: number;
}

/* ---------- Helpers ---------- */
function typeBadgeClass(type: CanaryToken["type"]): string {
  switch (type) {
    case "credential": return "bg-violet-500/10 text-violet-400 border-violet-500/20";
    case "file":       return "bg-blue-500/10 text-blue-400 border-blue-500/20";
    case "url":        return "bg-amber-500/10 text-amber-400 border-amber-500/20";
    case "dns":        return "bg-cyan-500/10 text-cyan-400 border-cyan-500/20";
  }
}

function statusDotClass(token: CanaryToken): string {
  if (!token.triggered_at) return "bg-emerald-500";
  const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const triggeredMs = new Date(token.triggered_at).getTime();
  if (triggeredMs >= sevenDaysAgo) return "bg-red-500 animate-pulse";
  return "bg-amber-500";
}

const TYPE_OPTIONS: { value: CanaryToken["type"]; label: string }[] = [
  { value: "credential", label: "Credential" },
  { value: "file",       label: "File" },
  { value: "url",        label: "URL" },
  { value: "dns",        label: "DNS" },
];

const TYPE_INSTRUCTIONS: Record<CanaryToken["type"], string> = {
  credential: "Embed in a fake password manager entry or Active Directory account. Any login attempt fires an alert.",
  file:       "Embed a tracking URL in a document. The URL pings a callback when the file is opened.",
  url:        "Deploy as a hidden 1×1 img src on an internal page. Any render triggers the token.",
  dns:        "Configure as a hostname. Any DNS lookup (e.g. resolving an internal config value) fires the token.",
};

/* ---------- New Token Modal ---------- */
interface NewTokenModalProps {
  onClose: () => void;
  onCreated: (token: CanaryToken) => void;
}

function NewTokenModal({ onClose, onCreated }: NewTokenModalProps) {
  const [name, setName] = useState("");
  const [type, setType] = useState<CanaryToken["type"]>("credential");
  const [deployedTo, setDeployedTo] = useState("");
  const [description, setDescription] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) { setError("Name is required"); return; }
    setSubmitting(true);
    setError(null);
    try {
      const res = await api.post<{ token: CanaryToken }>("/api/v1/canary/tokens", {
        name: name.trim(),
        type,
        deployed_to: deployedTo.trim(),
        description: description.trim(),
      });
      onCreated(res.token);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create token");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="relative rounded-xl border border-white/10 bg-[hsl(220_20%_8%)] w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-white/10">
          <h2 className="text-sm font-semibold text-white">New Canary Token</h2>
          <button onClick={onClose} className="text-white/40 hover:text-white/70 transition-colors text-sm">✕</button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          {error && (
            <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-3 text-xs text-red-400">{error}</div>
          )}

          <div className="space-y-1">
            <label className="text-xs text-white/50">Name <span className="text-red-400">*</span></label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. AWS Admin Credentials"
              className="w-full rounded-lg border border-white/10 bg-white/[0.04] px-3 py-2 text-xs text-white placeholder:text-white/25 outline-none focus:border-white/20"
            />
          </div>

          <div className="space-y-1">
            <label className="text-xs text-white/50">Type</label>
            <select
              value={type}
              onChange={(e) => setType(e.target.value as CanaryToken["type"])}
              className="w-full rounded-lg border border-white/10 bg-white/[0.04] px-3 py-2 text-xs text-white outline-none focus:border-white/20"
            >
              {TYPE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>

          <div className="space-y-1">
            <label className="text-xs text-white/50">Deployed To</label>
            <input
              type="text"
              value={deployedTo}
              onChange={(e) => setDeployedTo(e.target.value)}
              placeholder="e.g. Active Directory, /etc/passwd, S3 bucket"
              className="w-full rounded-lg border border-white/10 bg-white/[0.04] px-3 py-2 text-xs text-white placeholder:text-white/25 outline-none focus:border-white/20"
            />
          </div>

          <div className="space-y-1">
            <label className="text-xs text-white/50">Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
              placeholder="Optional notes about this canary…"
              className="w-full rounded-lg border border-white/10 bg-white/[0.04] px-3 py-2 text-xs text-white placeholder:text-white/25 outline-none focus:border-white/20 resize-none"
            />
          </div>

          {/* Usage instructions */}
          <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-white/30 mb-1">How to use: {type}</p>
            <p className="text-xs text-white/50">{TYPE_INSTRUCTIONS[type]}</p>
          </div>

          <div className="flex items-center justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 text-xs rounded-lg border border-white/10 hover:bg-white/5 text-white/60 hover:text-white transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-4 py-1.5 text-xs rounded-lg bg-[hsl(var(--primary)/.9)] hover:bg-[hsl(var(--primary))] text-white transition-colors disabled:opacity-50"
            >
              {submitting ? "Creating…" : "Create Token"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ---------- Canary Page ---------- */
export default function CanaryPage() {
  const [showModal, setShowModal] = useState(false);
  const [newTokenSecret, setNewTokenSecret] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const { data, loading, error, refetch } = useApi(
    useCallback((signal: AbortSignal) =>
      api.get<{ tokens: CanaryToken[] }>("/api/v1/canary/tokens", undefined, signal),
      []
    )
  );

  const tokens = data?.tokens ?? [];
  const triggered = tokens.filter((t) => t.trigger_count > 0);
  const neverTriggered = tokens.filter((t) => t.trigger_count === 0);

  function handleCreated(token: CanaryToken) {
    setShowModal(false);
    setNewTokenSecret(token.token);
    refetch();
  }

  async function handleDelete(id: string) {
    if (!confirm("Delete this canary token? This cannot be undone.")) return;
    setDeletingId(id);
    try {
      await api.del(`/api/v1/canary/tokens/${id}`);
      refetch();
    } catch {
      // silently handle
    } finally {
      setDeletingId(null);
    }
  }

  async function handleCopy(tokenValue: string, id: string) {
    try {
      await navigator.clipboard.writeText(tokenValue);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 1500);
    } catch {
      // silently handle
    }
  }

  return (
    <div className="animate-fade-in space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Canary Tokens</h1>
          <p className="text-sm text-white/50 mt-0.5">High-fidelity deception assets — any trigger indicates compromise</p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="px-4 py-1.5 text-xs rounded-lg bg-[hsl(var(--primary)/.9)] hover:bg-[hsl(var(--primary))] text-white transition-colors"
        >
          New Token
        </button>
      </div>

      {/* Triggered warning banner */}
      {triggered.length > 0 && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 px-4 py-3 flex items-center gap-3">
          <span className="text-amber-400 text-sm">⚠</span>
          <p className="text-sm text-amber-300">
            <span className="font-semibold">{triggered.length}</span> canary token{triggered.length !== 1 ? "s" : ""} have been triggered — check Alerts for details.
          </p>
        </div>
      )}

      {/* New token secret banner */}
      {newTokenSecret && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 px-4 py-3">
          <div className="flex items-start justify-between gap-3">
            <div className="flex-1 min-w-0">
              <p className="text-xs font-semibold text-amber-300 mb-1">Copy this token now — it won&apos;t be shown again</p>
              <code className="text-xs font-mono text-amber-200 break-all">{newTokenSecret}</code>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={() => { navigator.clipboard.writeText(newTokenSecret); }}
                className="px-3 py-1.5 text-xs rounded-lg border border-amber-500/30 text-amber-300 hover:bg-amber-500/10 transition-colors"
              >
                Copy
              </button>
              <button
                onClick={() => setNewTokenSecret(null)}
                className="text-white/30 hover:text-white/60 transition-colors text-sm"
              >
                ✕
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <p className="text-xs text-white/40 uppercase tracking-wider mb-1">Active Tokens</p>
          {loading ? (
            <div className="h-7 w-10 rounded animate-pulse bg-white/5" />
          ) : (
            <p className="text-2xl font-semibold text-white">{tokens.length}</p>
          )}
        </div>
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <p className="text-xs text-white/40 uppercase tracking-wider mb-1">Triggered</p>
          {loading ? (
            <div className="h-7 w-10 rounded animate-pulse bg-white/5" />
          ) : (
            <p className={cn("text-2xl font-semibold", triggered.length > 0 ? "text-red-400" : "text-white")}>
              {triggered.length}
            </p>
          )}
        </div>
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <p className="text-xs text-white/40 uppercase tracking-wider mb-1">Never Triggered</p>
          {loading ? (
            <div className="h-7 w-10 rounded animate-pulse bg-white/5" />
          ) : (
            <p className="text-2xl font-semibold text-emerald-400">{neverTriggered.length}</p>
          )}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">{error}</div>
      )}

      {/* Tokens table */}
      {loading && tokens.length === 0 ? (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center text-white/30 text-sm">
          Loading…
        </div>
      ) : (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-white/[0.06]">
                <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left w-6"></th>
                <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Name</th>
                <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Type</th>
                <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Deployed To</th>
                <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Token</th>
                <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Triggers</th>
                <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Last Triggered</th>
                <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left w-8"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {tokens.map((token) => (
                <tr key={token.id} className="hover:bg-white/[0.03] transition-colors">
                  {/* Status dot */}
                  <td className="px-4 py-3">
                    <span className={cn("h-2 w-2 rounded-full inline-block", statusDotClass(token))} />
                  </td>

                  {/* Name + description */}
                  <td className="px-4 py-3">
                    <p className="font-medium text-white">{token.name}</p>
                    {token.description && (
                      <p className="text-[10px] text-white/35 mt-0.5 truncate max-w-[180px]">{token.description}</p>
                    )}
                  </td>

                  {/* Type badge */}
                  <td className="px-4 py-3">
                    <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase border", typeBadgeClass(token.type))}>
                      {token.type}
                    </span>
                  </td>

                  {/* Deployed To */}
                  <td className="px-4 py-3 text-white/60 truncate max-w-[140px]">{token.deployed_to || "—"}</td>

                  {/* Token */}
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      <code className="font-mono text-[10px] text-white/50">
                        {token.token.slice(0, 8)}…
                      </code>
                      <button
                        onClick={() => handleCopy(token.token, token.id)}
                        title="Copy full token"
                        className={cn(
                          "px-1.5 py-0.5 rounded text-[10px] border transition-colors",
                          copiedId === token.id
                            ? "border-emerald-500/30 text-emerald-400 bg-emerald-500/5"
                            : "border-white/10 text-white/30 hover:text-white/60 hover:bg-white/5"
                        )}
                      >
                        {copiedId === token.id ? "Copied" : "Copy"}
                      </button>
                    </div>
                  </td>

                  {/* Trigger count */}
                  <td className="px-4 py-3">
                    {token.trigger_count > 0 ? (
                      <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold bg-red-500/15 text-red-400 border border-red-500/20">
                        {token.trigger_count}
                      </span>
                    ) : (
                      <span className="text-white/25">0</span>
                    )}
                  </td>

                  {/* Last triggered */}
                  <td className="px-4 py-3 text-white/40 font-mono">
                    {token.triggered_at ? timeAgo(token.triggered_at) : "Never"}
                  </td>

                  {/* Delete */}
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleDelete(token.id)}
                      disabled={deletingId === token.id}
                      title="Delete token"
                      className="text-white/20 hover:text-red-400 transition-colors disabled:opacity-40 text-sm"
                    >
                      {deletingId === token.id ? "…" : "✕"}
                    </button>
                  </td>
                </tr>
              ))}
              {tokens.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center text-white/30">No canary tokens yet — create one to get started</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* New token modal */}
      {showModal && (
        <NewTokenModal onClose={() => setShowModal(false)} onCreated={handleCreated} />
      )}
    </div>
  );
}
