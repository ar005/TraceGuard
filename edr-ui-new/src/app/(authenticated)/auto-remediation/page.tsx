"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";

interface RemediationRule {
  id: string;
  name: string;
  trigger_type: string;
  trigger_value: string;
  action: string;
  playbook_id: string;
  min_severity: number;
  enabled: boolean;
  created_at: string;
}

const TRIGGER_TYPES = ["rule_id", "mitre_id", "severity"] as const;
const ACTIONS = ["isolate_host", "kill_process", "block_user", "run_playbook"] as const;
const ACTION_LABELS: Record<string, string> = {
  isolate_host: "Isolate Host",
  kill_process: "Kill Process",
  block_user: "Block User",
  run_playbook: "Run Playbook",
};
const TRIGGER_LABELS: Record<string, string> = {
  rule_id: "Rule ID",
  mitre_id: "MITRE Technique",
  severity: "Min Severity (any)",
};

const ACTION_COLORS: Record<string, string> = {
  isolate_host: "text-red-400 bg-red-500/10 border-red-500/20",
  kill_process: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  block_user: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  run_playbook: "text-blue-400 bg-blue-500/10 border-blue-500/20",
};

function genID() {
  return "rule-" + Math.random().toString(36).slice(2, 10);
}

const EMPTY_RULE = (): Partial<RemediationRule> => ({
  id: genID(),
  name: "",
  trigger_type: "rule_id",
  trigger_value: "",
  action: "isolate_host",
  playbook_id: "",
  min_severity: 4,
  enabled: true,
});

export default function AutoRemediationPage() {
  const { data: rules, loading, refetch } = useApi<RemediationRule[]>(
    () => api.get("/remediation/rules"),
  );

  const [editing, setEditing] = useState<Partial<RemediationRule> | null>(null);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);

  const rows = rules ?? [];

  async function save() {
    if (!editing) return;
    setSaving(true);
    try {
      await api.put(`/remediation/rules/${editing.id}`, editing);
      setEditing(null);
      refetch();
    } finally {
      setSaving(false);
    }
  }

  async function del(id: string) {
    setDeleting(id);
    try {
      await api.del(`/remediation/rules/${id}`);
      refetch();
    } finally {
      setDeleting(null);
    }
  }

  async function toggle(rule: RemediationRule) {
    await api.put(`/remediation/rules/${rule.id}`, { ...rule, enabled: !rule.enabled });
    refetch();
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Auto-Remediation</h1>
          <p className="text-sm text-white/50 mt-0.5">
            Automatically trigger actions when alerts match conditions
          </p>
        </div>
        <button
          onClick={() => setEditing(EMPTY_RULE())}
          className="px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors"
        >
          + New Rule
        </button>
      </div>

      {/* Rule editor modal */}
      {editing && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="w-full max-w-lg bg-[#0f1117] border border-white/10 rounded-2xl p-6 space-y-4 shadow-2xl">
            <p className="text-base font-semibold text-white">
              {rules?.find((r) => r.id === editing.id) ? "Edit Rule" : "New Rule"}
            </p>

            <label className="block space-y-1">
              <span className="text-xs text-white/50">Rule name</span>
              <input
                className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50"
                value={editing.name ?? ""}
                onChange={(e) => setEditing((r) => ({ ...r, name: e.target.value }))}
                placeholder="Ransomware → Isolate"
              />
            </label>

            <div className="grid grid-cols-2 gap-3">
              <label className="block space-y-1">
                <span className="text-xs text-white/50">Trigger type</span>
                <select
                  className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50"
                  value={editing.trigger_type ?? "rule_id"}
                  onChange={(e) => setEditing((r) => ({ ...r, trigger_type: e.target.value }))}
                >
                  {TRIGGER_TYPES.map((t) => (
                    <option key={t} value={t}>{TRIGGER_LABELS[t]}</option>
                  ))}
                </select>
              </label>

              <label className="block space-y-1">
                <span className="text-xs text-white/50">
                  {editing.trigger_type === "severity" ? "Min severity (1-5)" : "Trigger value"}
                </span>
                <input
                  className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50"
                  value={editing.trigger_value ?? ""}
                  onChange={(e) => setEditing((r) => ({ ...r, trigger_value: e.target.value }))}
                  placeholder={editing.trigger_type === "rule_id" ? "rule-ransomware" : editing.trigger_type === "mitre_id" ? "T1486" : "4"}
                />
              </label>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <label className="block space-y-1">
                <span className="text-xs text-white/50">Action</span>
                <select
                  className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50"
                  value={editing.action ?? "isolate_host"}
                  onChange={(e) => setEditing((r) => ({ ...r, action: e.target.value }))}
                >
                  {ACTIONS.map((a) => (
                    <option key={a} value={a}>{ACTION_LABELS[a]}</option>
                  ))}
                </select>
              </label>

              <label className="block space-y-1">
                <span className="text-xs text-white/50">Min severity</span>
                <select
                  className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50"
                  value={editing.min_severity ?? 4}
                  onChange={(e) => setEditing((r) => ({ ...r, min_severity: Number(e.target.value) }))}
                >
                  {[1, 2, 3, 4, 5].map((n) => (
                    <option key={n} value={n}>≥ {n}</option>
                  ))}
                </select>
              </label>
            </div>

            {editing.action === "run_playbook" && (
              <label className="block space-y-1">
                <span className="text-xs text-white/50">Playbook ID</span>
                <input
                  className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50"
                  value={editing.playbook_id ?? ""}
                  onChange={(e) => setEditing((r) => ({ ...r, playbook_id: e.target.value }))}
                  placeholder="playbook-abc123"
                />
              </label>
            )}

            <div className="flex items-center gap-2 pt-1">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={editing.enabled ?? true}
                  onChange={(e) => setEditing((r) => ({ ...r, enabled: e.target.checked }))}
                  className="rounded"
                />
                <span className="text-sm text-white/70">Enabled</span>
              </label>
            </div>

            <div className="flex gap-2 pt-2">
              <button
                onClick={save}
                disabled={saving || !editing.name?.trim()}
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

      {/* Rules table */}
      <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/10">
              {["Name", "Trigger", "Action", "Min Sev", "Status", ""].map((h) => (
                <th key={h} className="text-left px-4 py-3 text-xs font-medium text-white/40 uppercase tracking-wider">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {loading && (
              <tr><td colSpan={6} className="px-4 py-10 text-center text-white/30 text-sm">Loading…</td></tr>
            )}
            {!loading && rows.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-10 text-center text-white/30 text-sm">
                No rules yet — create one to automatically respond to threats.
              </td></tr>
            )}
            {rows.map((r) => (
              <tr key={r.id} className="hover:bg-white/[0.02] transition-colors">
                <td className="px-4 py-3 text-white font-medium">{r.name}</td>
                <td className="px-4 py-3">
                  <span className="text-xs text-white/50">{TRIGGER_LABELS[r.trigger_type]}: </span>
                  <span className="text-xs font-mono text-white/70">{r.trigger_value || "—"}</span>
                </td>
                <td className="px-4 py-3">
                  <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${ACTION_COLORS[r.action] ?? "text-white/50 bg-white/5 border-white/10"}`}>
                    {ACTION_LABELS[r.action] ?? r.action}
                  </span>
                </td>
                <td className="px-4 py-3 text-white/50 text-xs">≥ {r.min_severity}</td>
                <td className="px-4 py-3">
                  <button onClick={() => toggle(r)} className="flex items-center gap-1.5">
                    <div className={`w-8 h-4 rounded-full transition-colors ${r.enabled ? "bg-blue-600" : "bg-white/10"} relative`}>
                      <div className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${r.enabled ? "left-4" : "left-0.5"}`} />
                    </div>
                    <span className={`text-xs ${r.enabled ? "text-blue-400" : "text-white/30"}`}>
                      {r.enabled ? "On" : "Off"}
                    </span>
                  </button>
                </td>
                <td className="px-4 py-3 text-right">
                  <div className="flex items-center justify-end gap-2">
                    <button
                      onClick={() => setEditing({ ...r })}
                      className="text-xs text-white/40 hover:text-white transition-colors px-2 py-1"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => del(r.id)}
                      disabled={deleting === r.id}
                      className="text-xs text-red-400/60 hover:text-red-400 transition-colors px-2 py-1"
                    >
                      {deleting === r.id ? "…" : "Delete"}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Info box */}
      <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-4 text-sm text-blue-300/70">
        <strong className="text-blue-300">How it works:</strong> when an alert matches a rule (by rule ID, MITRE technique, or minimum severity), the configured action fires automatically within seconds of alert creation. Use <em>Run Playbook</em> to chain complex multi-step responses.
      </div>
    </div>
  );
}
