"use client";

import { useState, useCallback } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { timeAgo } from "@/lib/utils";
import { ShieldCheck, RefreshCw, CheckCircle2, XCircle, Clock, Loader2 } from "lucide-react";

interface ResponseAction {
  id: string;
  action_type: string;
  target_type: string;
  target_id: string;
  status: string;
  triggered_by: string;
  playbook_run_id: string;
  params: Record<string, unknown>;
  result: Record<string, unknown>;
  created_at: string;
  reversed_at?: string;
  reversed_by: string;
  notes: string;
}

const STATUS_ICON: Record<string, React.ReactNode> = {
  success:  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />,
  failed:   <XCircle      className="w-3.5 h-3.5 text-red-400" />,
  pending:  <Clock        className="w-3.5 h-3.5 text-amber-400" />,
  running:  <Loader2      className="w-3.5 h-3.5 text-blue-400 animate-spin" />,
};

const STATUS_STYLE: Record<string, string> = {
  success: "bg-emerald-500/15 text-emerald-400",
  failed:  "bg-red-500/15 text-red-400",
  pending: "bg-amber-500/15 text-amber-400",
  running: "bg-blue-500/15 text-blue-400",
};

const ACTION_TYPE_STYLE: Record<string, string> = {
  isolate_host:     "bg-red-500/10 text-red-300",
  block_ip:         "bg-orange-500/10 text-orange-300",
  disable_identity: "bg-purple-500/10 text-purple-300",
  enrich:           "bg-blue-500/10 text-blue-300",
  ticket:           "bg-cyan-500/10 text-cyan-300",
  slack:            "bg-green-500/10 text-green-300",
  pagerduty:        "bg-violet-500/10 text-violet-300",
  email:            "bg-sky-500/10 text-sky-300",
  webhook:          "bg-neutral-500/10 text-neutral-300",
  update_alert:     "bg-neutral-500/10 text-neutral-300",
  run_hunt:         "bg-indigo-500/10 text-indigo-300",
};

const LIMIT_OPTIONS = [50, 100, 200, 500];

export default function ResponseActionsPage() {
  const [limit, setLimit] = useState(200);

  const fetchActions = useCallback(
    () => api.get<{ actions: ResponseAction[] }>(`/api/v1/response/actions?limit=${limit}`),
    [limit],
  );
  const { data, loading, error, refetch } = useApi(fetchActions);

  const actions = data?.actions ?? [];

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
          <h1 className="text-lg font-semibold text-neutral-100">Response Actions</h1>
          <span className="text-xs text-neutral-500 ml-1">SOAR audit trail</span>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={limit}
            onChange={e => setLimit(Number(e.target.value))}
            className="text-xs bg-neutral-800 border border-neutral-700 rounded px-2 py-1 text-neutral-300"
          >
            {LIMIT_OPTIONS.map(n => (
              <option key={n} value={n}>Last {n}</option>
            ))}
          </select>
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1 text-xs text-neutral-400 hover:text-neutral-200 border border-neutral-700 rounded px-2 py-1 transition-colors"
          >
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
        </div>
      </div>

      {/* Summary chips */}
      {actions.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {["success", "failed", "pending", "running"].map(s => {
            const count = actions.filter(a => a.status === s).length;
            if (count === 0) return null;
            return (
              <span
                key={s}
                className={`flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${STATUS_STYLE[s] ?? ""}`}
              >
                {STATUS_ICON[s]}
                {count} {s}
              </span>
            );
          })}
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded p-3">
          {error}
        </div>
      )}

      {/* Table */}
      <div className="overflow-x-auto rounded border border-neutral-800">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-neutral-800 bg-neutral-900/60 text-neutral-400">
              <th className="text-left px-3 py-2 font-medium">Time</th>
              <th className="text-left px-3 py-2 font-medium">Action</th>
              <th className="text-left px-3 py-2 font-medium">Target</th>
              <th className="text-left px-3 py-2 font-medium">Status</th>
              <th className="text-left px-3 py-2 font-medium">Triggered By</th>
              <th className="text-left px-3 py-2 font-medium">Playbook Run</th>
              <th className="text-left px-3 py-2 font-medium">Notes / Result</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={7} className="text-center py-10 text-neutral-500">
                  <Loader2 className="w-5 h-5 animate-spin inline-block" />
                </td>
              </tr>
            )}
            {!loading && actions.length === 0 && (
              <tr>
                <td colSpan={7} className="text-center py-10 text-neutral-500">
                  No response actions recorded yet.
                </td>
              </tr>
            )}
            {actions.map(a => (
              <tr
                key={a.id}
                className="border-b border-neutral-800/60 hover:bg-neutral-800/30 transition-colors"
              >
                <td className="px-3 py-2 text-neutral-400 whitespace-nowrap">
                  {timeAgo(a.created_at)}
                </td>
                <td className="px-3 py-2">
                  <span
                    className={`inline-block px-2 py-0.5 rounded font-medium ${
                      ACTION_TYPE_STYLE[a.action_type] ?? "bg-neutral-700/50 text-neutral-300"
                    }`}
                  >
                    {a.action_type}
                  </span>
                </td>
                <td className="px-3 py-2 text-neutral-300">
                  <span className="text-neutral-500">{a.target_type}/</span>
                  <span className="font-mono">{a.target_id || "—"}</span>
                </td>
                <td className="px-3 py-2">
                  <span
                    className={`flex items-center gap-1 w-fit px-2 py-0.5 rounded ${
                      STATUS_STYLE[a.status] ?? "text-neutral-400"
                    }`}
                  >
                    {STATUS_ICON[a.status] ?? null}
                    {a.status}
                  </span>
                </td>
                <td className="px-3 py-2 text-neutral-400 font-mono text-[11px]">
                  {a.triggered_by || "system"}
                </td>
                <td className="px-3 py-2 text-neutral-500 font-mono text-[11px]">
                  {a.playbook_run_id ? a.playbook_run_id.slice(0, 8) + "…" : "—"}
                </td>
                <td className="px-3 py-2 text-neutral-400 max-w-xs truncate">
                  {a.reversed_at ? (
                    <span className="text-amber-400 mr-2">
                      reversed {timeAgo(a.reversed_at)}
                    </span>
                  ) : null}
                  {a.notes ||
                    (Object.keys(a.result ?? {}).length > 0
                      ? JSON.stringify(a.result).slice(0, 80)
                      : "—")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
