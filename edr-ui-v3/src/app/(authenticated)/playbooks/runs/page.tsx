"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { timeAgo } from "@/lib/utils";
import { ChevronDown, ChevronRight, CheckCircle2, XCircle, Clock } from "lucide-react";
import Link from "next/link";

interface ActionResult {
  type: string;
  status: "success" | "failed" | "skipped";
  detail?: string;
  at: string;
}

interface PlaybookRun {
  id: string;
  playbook_id: string;
  playbook_name: string;
  trigger_type: string;
  trigger_id: string;
  status: "running" | "success" | "failed";
  error_msg?: string;
  actions_log: ActionResult[];
  triggered_by: string;
  started_at: string;
  finished_at?: string;
}

function RunStatusBadge({ status }: { status: PlaybookRun["status"] }) {
  if (status === "success")
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-emerald-500/15 text-emerald-400">
        <CheckCircle2 size={10} /> Success
      </span>
    );
  if (status === "failed")
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-red-500/15 text-red-400">
        <XCircle size={10} /> Failed
      </span>
    );
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-blue-500/15 text-blue-400">
      <Clock size={10} /> Running
    </span>
  );
}

function ActionDot({ status }: { status: ActionResult["status"] }) {
  if (status === "success") return <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" />;
  if (status === "failed") return <span className="w-2 h-2 rounded-full bg-red-500 shrink-0" />;
  return <span className="w-2 h-2 rounded-full bg-neutral-600 shrink-0" />;
}

function RunRow({ run }: { run: PlaybookRun }) {
  const [open, setOpen] = useState(false);
  const actions: ActionResult[] = Array.isArray(run.actions_log) ? run.actions_log : [];

  return (
    <div className="bg-neutral-900 border border-neutral-800 rounded-xl overflow-hidden">
      <div
        className="flex items-center gap-3 px-4 py-3 cursor-pointer select-none hover:bg-neutral-800/40"
        onClick={() => setOpen((o) => !o)}
      >
        <span className="text-neutral-500">{open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</span>
        <RunStatusBadge status={run.status} />
        <span className="font-medium text-sm flex-1 truncate">{run.playbook_name}</span>
        <div className="flex items-center gap-3 text-xs text-neutral-500 shrink-0">
          <span className="font-mono px-1.5 py-0.5 rounded bg-neutral-800">{run.trigger_type}</span>
          <span>{actions.length} action{actions.length !== 1 ? "s" : ""}</span>
          <span>{timeAgo(run.started_at)}</span>
        </div>
      </div>
      {open && (
        <div className="border-t border-neutral-800 px-4 py-3 space-y-2 bg-neutral-950/40">
          <div className="grid grid-cols-2 gap-4 text-xs text-neutral-400 mb-3">
            <div><span className="text-neutral-600">Trigger ID: </span>{run.trigger_id}</div>
            <div><span className="text-neutral-600">Run ID: </span><span className="font-mono">{run.id}</span></div>
            <div><span className="text-neutral-600">Triggered by: </span>{run.triggered_by}</div>
            {run.finished_at && <div><span className="text-neutral-600">Finished: </span>{timeAgo(run.finished_at)}</div>}
          </div>
          {run.error_msg && (
            <div className="text-xs text-red-400 bg-red-500/10 px-3 py-2 rounded">{run.error_msg}</div>
          )}
          {actions.length > 0 ? (
            <div className="space-y-1">
              {actions.map((a, i) => (
                <div key={i} className="flex items-start gap-2 text-xs">
                  <ActionDot status={a.status} />
                  <span className="font-mono text-neutral-300 w-28 shrink-0">{a.type}</span>
                  <span className={
                    a.status === "failed" ? "text-red-400" :
                    a.status === "skipped" ? "text-neutral-500" : "text-emerald-400"
                  }>
                    {a.status}
                  </span>
                  {a.detail && <span className="text-neutral-500 truncate ml-2">{a.detail}</span>}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-neutral-600">No action log available.</p>
          )}
        </div>
      )}
    </div>
  );
}

export default function PlaybookRunsPage() {
  const [limit] = useState(100);
  const { data, loading, error } = useApi<{ runs: PlaybookRun[] }>(
    () => api.get<{ runs: PlaybookRun[] }>(`/api/v1/playbooks/runs?limit=${limit}`)
  );
  const runs = data?.runs ?? [];

  const successCount = runs.filter((r) => r.status === "success").length;
  const failedCount = runs.filter((r) => r.status === "failed").length;

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Playbook Run History</h1>
          <p className="text-xs text-neutral-400 mt-0.5">Last {limit} execution records across all playbooks</p>
        </div>
        <Link href="/playbooks"
          className="px-3 py-1.5 text-sm rounded border border-neutral-700 hover:bg-neutral-800">
          ← Playbooks
        </Link>
      </div>

      {!loading && runs.length > 0 && (
        <div className="flex gap-4 text-sm">
          <span className="text-emerald-400">{successCount} succeeded</span>
          <span className="text-neutral-500">·</span>
          <span className="text-red-400">{failedCount} failed</span>
          <span className="text-neutral-500">·</span>
          <span className="text-neutral-400">{runs.length} total</span>
        </div>
      )}

      {loading && <p className="text-sm text-neutral-400">Loading…</p>}
      {error && <p className="text-sm text-red-400">{error}</p>}

      {!loading && runs.length === 0 && (
        <div className="text-center py-16 text-neutral-500 text-sm">
          No playbook runs yet. Runs are created when a playbook fires.
        </div>
      )}

      <div className="space-y-2">
        {runs.map((run) => (
          <RunRow key={run.id} run={run} />
        ))}
      </div>
    </div>
  );
}
