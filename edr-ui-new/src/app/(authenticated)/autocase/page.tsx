"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";

interface AutoCasePolicy {
  id: string;
  tenant_id: string;
  name: string;
  min_severity: number;
  rule_ids: string[];
  mitre_ids: string[];
  enabled: boolean;
  created_at: string;
}

function genID() {
  return "policy-" + Math.random().toString(36).slice(2, 10);
}

const EMPTY_POLICY = (): Partial<AutoCasePolicy> & {
  _rule_ids_str: string;
  _mitre_ids_str: string;
} => ({
  id: genID(),
  name: "",
  min_severity: 3,
  rule_ids: [],
  mitre_ids: [],
  enabled: true,
  _rule_ids_str: "",
  _mitre_ids_str: "",
});

type EditingPolicy = Partial<AutoCasePolicy> & {
  _rule_ids_str: string;
  _mitre_ids_str: string;
};

function toEditingPolicy(p: AutoCasePolicy): EditingPolicy {
  return {
    ...p,
    _rule_ids_str: (p.rule_ids ?? []).join(", "),
    _mitre_ids_str: (p.mitre_ids ?? []).join(", "),
  };
}

function splitIds(str: string): string[] {
  return str
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export default function AutoCasePoliciesPage() {
  const { data: policies, loading, refetch } = useApi<AutoCasePolicy[]>(
    () => api.get("/autocase/policies"),
  );

  const [editing, setEditing] = useState<EditingPolicy | null>(null);
  const [saving, setSaving] = useState(false);

  const rows = policies ?? [];

  async function save() {
    if (!editing) return;
    setSaving(true);
    try {
      const payload: Partial<AutoCasePolicy> = {
        ...editing,
        rule_ids: splitIds(editing._rule_ids_str),
        mitre_ids: splitIds(editing._mitre_ids_str),
      };
      // Remove our local helper keys
      delete (payload as Record<string, unknown>)._rule_ids_str;
      delete (payload as Record<string, unknown>)._mitre_ids_str;
      await api.put(`/autocase/policies/${editing.id}`, payload);
      setEditing(null);
      refetch();
    } finally {
      setSaving(false);
    }
  }

  async function toggle(policy: AutoCasePolicy) {
    await api.put(`/autocase/policies/${policy.id}`, {
      ...policy,
      enabled: !policy.enabled,
    });
    refetch();
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Auto-Case Policies</h1>
          <p className="text-sm text-white/50 mt-0.5">
            Automatically open investigation cases when alerts match conditions
          </p>
        </div>
        <button
          onClick={() => setEditing(EMPTY_POLICY())}
          className="px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors"
        >
          + New Policy
        </button>
      </div>

      {/* Policy editor modal */}
      {editing && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="w-full max-w-lg bg-[#0f1117] border border-white/10 rounded-2xl p-6 space-y-4 shadow-2xl">
            <p className="text-base font-semibold text-white">
              {rows.find((p) => p.id === editing.id) ? "Edit Policy" : "New Policy"}
            </p>

            <label className="block space-y-1">
              <span className="text-xs text-white/50">Policy name</span>
              <input
                className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50"
                value={editing.name ?? ""}
                onChange={(e) => setEditing((p) => ({ ...p!, name: e.target.value }))}
                placeholder="High-severity ransomware cases"
              />
            </label>

            <label className="block space-y-1">
              <span className="text-xs text-white/50">Min severity (1 = Info, 5 = Critical)</span>
              <select
                className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50"
                value={editing.min_severity ?? 3}
                onChange={(e) =>
                  setEditing((p) => ({ ...p!, min_severity: Number(e.target.value) }))
                }
              >
                {[1, 2, 3, 4, 5].map((n) => (
                  <option key={n} value={n}>
                    ≥ {n} — {["Info", "Low", "Medium", "High", "Critical"][n - 1]}
                  </option>
                ))}
              </select>
            </label>

            <label className="block space-y-1">
              <span className="text-xs text-white/50">
                Rule IDs{" "}
                <span className="text-white/30">(comma-separated, leave blank for any)</span>
              </span>
              <input
                className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-blue-500/50"
                value={editing._rule_ids_str}
                onChange={(e) =>
                  setEditing((p) => ({ ...p!, _rule_ids_str: e.target.value }))
                }
                placeholder="rule-ransomware, rule-lateral-movement"
              />
            </label>

            <label className="block space-y-1">
              <span className="text-xs text-white/50">
                MITRE Technique IDs{" "}
                <span className="text-white/30">(comma-separated, leave blank for any)</span>
              </span>
              <input
                className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-blue-500/50"
                value={editing._mitre_ids_str}
                onChange={(e) =>
                  setEditing((p) => ({ ...p!, _mitre_ids_str: e.target.value }))
                }
                placeholder="T1486, T1055, T1059"
              />
            </label>

            <div className="flex items-center gap-2 pt-1">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={editing.enabled ?? true}
                  onChange={(e) => setEditing((p) => ({ ...p!, enabled: e.target.checked }))}
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

      {/* Policies table */}
      <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/10">
              {["Name", "Min Severity", "Rule IDs", "MITRE IDs", "Status", ""].map((h) => (
                <th
                  key={h}
                  className="text-left px-4 py-3 text-xs font-medium text-white/40 uppercase tracking-wider"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {loading && (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center text-white/30 text-sm">
                  Loading…
                </td>
              </tr>
            )}
            {!loading && rows.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center text-white/30 text-sm">
                  No policies yet — create one to auto-open cases when alerts match.
                </td>
              </tr>
            )}
            {rows.map((p) => (
              <tr key={p.id} className="hover:bg-white/[0.02] transition-colors">
                <td className="px-4 py-3 text-white font-medium">{p.name}</td>
                <td className="px-4 py-3">
                  <span className="text-xs text-white/50">
                    ≥ {p.min_severity} —{" "}
                    {["Info", "Low", "Medium", "High", "Critical"][p.min_severity - 1]}
                  </span>
                </td>
                <td className="px-4 py-3">
                  {p.rule_ids && p.rule_ids.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {p.rule_ids.slice(0, 3).map((id) => (
                        <span
                          key={id}
                          className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/5 text-white/50"
                        >
                          {id}
                        </span>
                      ))}
                      {p.rule_ids.length > 3 && (
                        <span className="text-[10px] text-white/30">
                          +{p.rule_ids.length - 3} more
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className="text-xs text-white/20">any</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  {p.mitre_ids && p.mitre_ids.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {p.mitre_ids.slice(0, 3).map((id) => (
                        <span
                          key={id}
                          className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400"
                        >
                          {id}
                        </span>
                      ))}
                      {p.mitre_ids.length > 3 && (
                        <span className="text-[10px] text-white/30">
                          +{p.mitre_ids.length - 3} more
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className="text-xs text-white/20">any</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <button onClick={() => toggle(p)} className="flex items-center gap-1.5">
                    <div
                      className={`w-8 h-4 rounded-full transition-colors ${
                        p.enabled ? "bg-blue-600" : "bg-white/10"
                      } relative`}
                    >
                      <div
                        className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${
                          p.enabled ? "left-4" : "left-0.5"
                        }`}
                      />
                    </div>
                    <span className={`text-xs ${p.enabled ? "text-blue-400" : "text-white/30"}`}>
                      {p.enabled ? "On" : "Off"}
                    </span>
                  </button>
                </td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={() => setEditing(toEditingPolicy(p))}
                    className="text-xs text-white/40 hover:text-white transition-colors px-2 py-1"
                  >
                    Edit
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Info box */}
      <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-4 text-sm text-blue-300/70">
        <strong className="text-blue-300">How it works:</strong> when an alert matches a policy
        (by rule ID, MITRE technique, or minimum severity), a new investigation case is
        automatically created and linked to the alert within seconds. Cases group related alerts
        so analysts can work them as a single incident.
      </div>
    </div>
  );
}
