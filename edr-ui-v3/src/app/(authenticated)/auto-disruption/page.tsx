"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { ShieldOff, Plus, Pencil, Trash2, Unlock, Zap } from "lucide-react";

interface DisruptionPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  min_severity: number;
  rule_ids: string[];
  host_groups: string[];
  action: string;
  auto_release_hours: number;
  created_at: string;
}

interface ActiveContainment {
  id: string;
  policy_name: string;
  alert_id: string;
  agent_id: string;
  hostname: string;
  action: string;
  status: string;
  contained_at: string;
  release_at: string | null;
  released_at: string | null;
  released_by: string;
  release_note: string;
}

const SEVERITY_LABELS: Record<number, { label: string; cls: string }> = {
  1: { label: "Low",      cls: "bg-blue-500/20 text-blue-300" },
  2: { label: "Medium",   cls: "bg-amber-500/20 text-amber-300" },
  3: { label: "High",     cls: "bg-orange-500/20 text-orange-300" },
  4: { label: "Critical", cls: "bg-red-500/20 text-red-300" },
};

function timeRemaining(releaseAt: string | null): string {
  if (!releaseAt) return "manual only";
  const ms = new Date(releaseAt).getTime() - Date.now();
  if (ms <= 0) return "releasing…";
  const h = Math.floor(ms / 3600000);
  const m = Math.floor((ms % 3600000) / 60000);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

function PolicyModal({
  initial,
  onSave,
  onClose,
}: {
  initial?: Partial<DisruptionPolicy>;
  onSave: (d: Partial<DisruptionPolicy>) => Promise<void>;
  onClose: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [minSeverity, setMinSeverity] = useState(initial?.min_severity ?? 4);
  const [ruleIds, setRuleIds] = useState((initial?.rule_ids ?? []).join(", "));
  const [autoReleaseHours, setAutoReleaseHours] = useState(initial?.auto_release_hours ?? 4);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function handleSave() {
    if (!name.trim()) { setError("Name is required"); return; }
    setSaving(true); setError("");
    try {
      await onSave({
        name: name.trim(),
        description,
        enabled,
        min_severity: minSeverity,
        rule_ids: ruleIds.split(",").map(s => s.trim()).filter(Boolean),
        host_groups: [],
        action: "isolate",
        auto_release_hours: autoReleaseHours,
      });
      onClose();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-neutral-900 border border-neutral-700 rounded-xl w-full max-w-lg">
        <div className="flex items-center justify-between px-5 py-4 border-b border-neutral-800">
          <h2 className="font-semibold text-sm">{initial?.id ? "Edit Policy" : "New Disruption Policy"}</h2>
          <button onClick={onClose} className="text-neutral-400 hover:text-white text-lg leading-none">&times;</button>
        </div>
        <div className="p-5 space-y-4">
          {error && <p className="text-xs text-red-400 bg-red-500/10 px-3 py-2 rounded">{error}</p>}

          <div>
            <label className="text-xs text-neutral-400 mb-1 block">Name *</label>
            <input value={name} onChange={e => setName(e.target.value)}
              placeholder="e.g. Isolate on Critical"
              className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm" />
          </div>

          <div>
            <label className="text-xs text-neutral-400 mb-1 block">Description</label>
            <input value={description} onChange={e => setDescription(e.target.value)}
              placeholder="Optional description"
              className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm" />
          </div>

          <div className="flex items-center gap-3">
            <label className="text-xs text-neutral-400">Enabled</label>
            <button type="button" onClick={() => setEnabled(!enabled)}
              className={`relative w-9 h-5 rounded-full transition-colors ${enabled ? "bg-cyan-600" : "bg-neutral-700"}`}>
              <span className={`absolute top-0.5 w-4 h-4 bg-white rounded-full transition-transform ${enabled ? "translate-x-4" : "translate-x-0.5"}`} />
            </button>
          </div>

          <div>
            <label className="text-xs text-neutral-400 mb-1 block">Minimum Severity</label>
            <select value={minSeverity} onChange={e => setMinSeverity(Number(e.target.value))}
              className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm">
              <option value={1}>Low (1+)</option>
              <option value={2}>Medium (2+)</option>
              <option value={3}>High (3+)</option>
              <option value={4}>Critical only (4)</option>
            </select>
          </div>

          <div>
            <label className="text-xs text-neutral-400 mb-1 block">Rule IDs (comma-separated, empty = any rule)</label>
            <input value={ruleIds} onChange={e => setRuleIds(e.target.value)}
              placeholder="e.g. rule-abc123, rule-def456  (leave blank for all rules)"
              className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm" />
          </div>

          <div>
            <label className="text-xs text-neutral-400 mb-1 block">Auto-release after (hours, 0 = manual only)</label>
            <input type="number" min={0} max={168} value={autoReleaseHours}
              onChange={e => setAutoReleaseHours(Number(e.target.value))}
              className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm" />
            <p className="text-xs text-neutral-600 mt-1">Host will be automatically released after this many hours. Set 0 to require manual release.</p>
          </div>
        </div>
        <div className="flex justify-end gap-2 px-5 py-3 border-t border-neutral-800">
          <button onClick={onClose} className="px-3 py-1.5 text-sm rounded border border-neutral-700 hover:bg-neutral-800">Cancel</button>
          <button onClick={handleSave} disabled={saving}
            className="px-4 py-1.5 text-sm rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 font-medium">
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function AutoDisruptionPage() {
  const { data: policiesData, loading: pLoading, error: pError, refetch: refetchPolicies } =
    useApi<{ policies: DisruptionPolicy[] }>(() => api.get<{ policies: DisruptionPolicy[] }>("/api/v1/disruption/policies"));

  const { data: containmentsData, loading: cLoading, refetch: refetchContainments } =
    useApi<{ containments: ActiveContainment[] }>(() => api.get<{ containments: ActiveContainment[] }>("/api/v1/disruption/containments"));

  const policies = policiesData?.policies ?? [];
  const containments = containmentsData?.containments ?? [];
  const active = containments.filter(c => c.status === "active");
  const history = containments.filter(c => c.status !== "active");

  const [modal, setModal] = useState<{ open: boolean; policy?: DisruptionPolicy }>({ open: false });
  const [releasing, setReleasing] = useState<string | null>(null);

  async function handleCreate(d: Partial<DisruptionPolicy>) {
    await api.post("/api/v1/disruption/policies", d);
    refetchPolicies();
  }

  async function handleUpdate(id: string, d: Partial<DisruptionPolicy>) {
    await api.put(`/api/v1/disruption/policies/${id}`, d);
    refetchPolicies();
  }

  async function handleDelete(id: string, name: string) {
    if (!confirm(`Delete policy "${name}"?`)) return;
    await api.del(`/api/v1/disruption/policies/${id}`);
    refetchPolicies();
  }

  async function handleRelease(id: string) {
    if (!confirm("Release this containment? The host will be reconnected to the network.")) return;
    setReleasing(id);
    try {
      await api.post(`/api/v1/disruption/containments/${id}/release`, {});
      refetchContainments();
    } finally {
      setReleasing(null);
    }
  }

  return (
    <div className="p-6 space-y-8 max-w-5xl">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-lg font-semibold flex items-center gap-2">
            <Zap size={18} /> Autonomous Attack Disruption
          </h1>
          <p className="text-xs text-neutral-400 mt-0.5">
            Automatically isolate hosts when alerts match configured conditions. Containments auto-release after the configured window.
          </p>
        </div>
        <button onClick={() => setModal({ open: true })}
          className="flex items-center gap-2 px-3 py-1.5 text-sm rounded bg-cyan-600 hover:bg-cyan-500 font-medium">
          <Plus size={14} /> New Policy
        </button>
      </div>

      {/* Active containments */}
      <section className="space-y-3">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-semibold">Active Containments</h2>
          {cLoading && <span className="text-xs text-neutral-500">Loading…</span>}
          {active.length > 0 && (
            <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-red-500/20 text-red-400">{active.length}</span>
          )}
        </div>

        {!cLoading && active.length === 0 && (
          <div className="text-center py-8 rounded-xl border border-dashed border-neutral-800 text-neutral-600 text-sm">
            No active containments — all hosts are connected normally.
          </div>
        )}

        {active.length > 0 && (
          <div className="rounded-xl border border-neutral-800 divide-y divide-neutral-800 overflow-hidden">
            {active.map(c => (
              <div key={c.id} className="flex items-center gap-4 px-4 py-3 bg-red-500/5">
                <ShieldOff size={15} className="text-red-400 shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium">{c.hostname}</div>
                  <div className="text-xs text-neutral-400">
                    policy: {c.policy_name} · alert: <span className="font-mono">{c.alert_id.slice(0, 12)}…</span>
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <div className="text-xs text-neutral-300">{timeRemaining(c.release_at)} remaining</div>
                  <div className="text-[10px] text-neutral-500">
                    contained {new Date(c.contained_at).toLocaleString()}
                  </div>
                </div>
                <button
                  onClick={() => handleRelease(c.id)}
                  disabled={releasing === c.id}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded border border-neutral-700 hover:bg-neutral-800 disabled:opacity-50 shrink-0"
                >
                  <Unlock size={12} />
                  {releasing === c.id ? "Releasing…" : "Release"}
                </button>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Policies */}
      <section className="space-y-3">
        <h2 className="text-sm font-semibold">Disruption Policies</h2>
        {pLoading && <p className="text-sm text-neutral-400">Loading…</p>}
        {pError && <p className="text-sm text-red-400">{pError}</p>}

        {!pLoading && policies.length === 0 && (
          <div className="text-center py-10 rounded-xl border border-dashed border-neutral-800 text-neutral-600 text-sm">
            <Zap size={28} className="mx-auto mb-2 opacity-30" />
            <p>No disruption policies configured.</p>
            <p className="text-xs mt-1 text-neutral-700">Create a policy to automatically isolate hosts when high-severity alerts fire.</p>
            <button onClick={() => setModal({ open: true })}
              className="mt-3 text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 mx-auto">
              <Plus size={11} /> Create first policy
            </button>
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {policies.map(p => {
            const sev = SEVERITY_LABELS[p.min_severity] ?? SEVERITY_LABELS[4];
            return (
              <div key={p.id} className={`bg-neutral-900 border rounded-xl p-4 space-y-2 ${p.enabled ? "border-neutral-800" : "border-neutral-800 opacity-60"}`}>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-sm truncate">{p.name}</span>
                      {!p.enabled && <span className="text-[10px] px-1.5 py-0.5 rounded bg-neutral-800 text-neutral-500">disabled</span>}
                    </div>
                    {p.description && <p className="text-xs text-neutral-400 mt-0.5 truncate">{p.description}</p>}
                  </div>
                  <div className="flex gap-1 shrink-0">
                    <button onClick={() => setModal({ open: true, policy: p })}
                      className="p-1.5 rounded hover:bg-neutral-800 text-neutral-400 hover:text-white">
                      <Pencil size={12} />
                    </button>
                    <button onClick={() => handleDelete(p.id, p.name)}
                      className="p-1.5 rounded hover:bg-neutral-800 text-neutral-400 hover:text-red-400">
                      <Trash2 size={12} />
                    </button>
                  </div>
                </div>

                <div className="flex flex-wrap gap-1.5 text-xs">
                  <span className={`px-2 py-0.5 rounded-full font-medium ${sev.cls}`}>
                    {sev.label}+
                  </span>
                  <span className="px-2 py-0.5 rounded-full bg-neutral-800 text-neutral-300">
                    action: {p.action}
                  </span>
                  <span className="px-2 py-0.5 rounded-full bg-neutral-800 text-neutral-300">
                    {p.auto_release_hours > 0 ? `auto-release ${p.auto_release_hours}h` : "manual release"}
                  </span>
                </div>

                {p.rule_ids.length > 0 && (
                  <div className="flex items-center gap-1.5 flex-wrap text-xs">
                    <span className="text-neutral-500 shrink-0">rules:</span>
                    {p.rule_ids.slice(0, 3).map(r => (
                      <span key={r} className="font-mono px-1.5 py-0.5 rounded bg-neutral-800 text-neutral-300 truncate max-w-[100px]">{r}</span>
                    ))}
                    {p.rule_ids.length > 3 && <span className="text-neutral-600">+{p.rule_ids.length - 3}</span>}
                  </div>
                )}
                {p.rule_ids.length === 0 && (
                  <p className="text-[10px] text-neutral-600 italic">applies to all rules</p>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* Recent history */}
      {history.length > 0 && (
        <section className="space-y-3">
          <h2 className="text-sm font-semibold text-neutral-400">Containment History</h2>
          <div className="rounded-xl border border-neutral-800 divide-y divide-neutral-800 overflow-hidden">
            {history.slice(0, 20).map(c => (
              <div key={c.id} className="flex items-center gap-4 px-4 py-2.5 text-sm">
                <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                  c.status === "released" ? "bg-emerald-500/15 text-emerald-400" : "bg-red-500/15 text-red-400"
                }`}>{c.status}</span>
                <span className="font-medium">{c.hostname}</span>
                <span className="text-xs text-neutral-500 ml-auto">{c.policy_name}</span>
                <span className="text-xs text-neutral-600">
                  {c.released_at ? new Date(c.released_at).toLocaleString() : "—"}
                  {c.released_by && c.released_by !== "system" && ` by ${c.released_by}`}
                </span>
              </div>
            ))}
          </div>
        </section>
      )}

      {modal.open && (
        <PolicyModal
          initial={modal.policy}
          onSave={modal.policy ? d => handleUpdate(modal.policy!.id, d) : handleCreate}
          onClose={() => setModal({ open: false })}
        />
      )}
    </div>
  );
}
