"use client";

import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { timeAgo } from "@/lib/utils";
import { useState } from "react";
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
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/15 text-emerald-400">
        <CheckCircle2 size={10} /> Success
      </span>
    );
  if (status === "failed")
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-red-500/15 text-red-400">
        <XCircle size={10} /> Failed
      </span>
    );
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-blue-500/15 text-blue-400">
      <Clock size={10} /> Running
    </span>
  );
}

function ActionDot({ status }: { status: ActionResult["status"] }) {
  if (status === "success") return <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0 mt-0.5" />;
  if (status === "failed")  return <span className="w-2 h-2 rounded-full bg-red-500 shrink-0 mt-0.5" />;
  return <span className="w-2 h-2 rounded-full bg-white/20 shrink-0 mt-0.5" />;
}

function RunRow({ run }: { run: PlaybookRun }) {
  const [open, setOpen] = useState(false);
  const actions: ActionResult[] = Array.isArray(run.actions_log) ? run.actions_log : [];

  return (
    <div className="rounded-xl border border-white/10 overflow-hidden">
      <div
        className="flex items-center gap-3 px-4 py-3 cursor-pointer select-none hover:bg-white/[0.03] transition-colors"
        onClick={() => setOpen((o) => !o)}
      >
        <span className="text-white/30 shrink-0">
          {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </span>
        <RunStatusBadge status={run.status} />
        <span className="font-medium text-sm text-white flex-1 truncate">{run.playbook_name}</span>
        <div className="flex items-center gap-3 text-xs text-white/40 shrink-0">
          <span className="font-mono px-1.5 py-0.5 rounded bg-white/5 border border-white/10">{run.trigger_type}</span>
          <span>{actions.length} action{actions.length !== 1 ? "s" : ""}</span>
          <span>{timeAgo(run.started_at)}</span>
        </div>
      </div>

      {open && (
        <div className="border-t border-white/10 px-4 py-4 space-y-3 bg-black/20">
          <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-xs text-white/40">
            <div><span className="text-white/20">Trigger ID: </span>{run.trigger_id || "—"}</div>
            <div><span className="text-white/20">Run ID: </span><span className="font-mono">{run.id}</span></div>
            <div><span className="text-white/20">Triggered by: </span>{run.triggered_by || "system"}</div>
            {run.finished_at && (
              <div><span className="text-white/20">Finished: </span>{timeAgo(run.finished_at)}</div>
            )}
          </div>

          {run.error_msg && (
            <div className="text-xs text-red-400 bg-red-500/10 px-3 py-2 rounded-lg border border-red-500/20">
              {run.error_msg}
            </div>
          )}

          {actions.length > 0 ? (
            <div className="space-y-1.5 pt-1">
              {actions.map((a, i) => (
                <div key={i} className="flex items-start gap-2 text-xs">
                  <ActionDot status={a.status} />
                  <span className="font-mono text-white/60 w-32 shrink-0">{a.type}</span>
                  <span className={
                    a.status === "failed"  ? "text-red-400" :
                    a.status === "skipped" ? "text-white/30" :
                    "text-emerald-400"
                  }>
                    {a.status}
                  </span>
                  {a.detail && <span className="text-white/30 truncate ml-2">{a.detail}</span>}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-white/25">No action log available.</p>
          )}
        </div>
      )}
    </div>
  );
}

export default function PlaybookRunsPage() {
  const { data, loading, error } = useApi<{ runs: PlaybookRun[] }>(
    (signal) => api.get<{ runs: PlaybookRun[] }>("/api/v1/playbooks/runs", { limit: 100 }, signal)
  );
  const runs = data?.runs ?? [];

  const successCount = runs.filter((r) => r.status === "success").length;
  const failedCount  = runs.filter((r) => r.status === "failed").length;

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-semibold text-white">Playbook Run History</h1>
          <p className="text-sm text-white/50 mt-0.5">Last 100 execution records across all playbooks</p>
        </div>
        <Link
          href="/playbooks"
          className="px-3 py-1.5 text-sm rounded-lg border border-white/10 hover:bg-white/5 text-white/50 hover:text-white transition-colors"
        >
          ← Playbooks
        </Link>
      </div>

      {!loading && runs.length > 0 && (
        <div className="flex items-center gap-3 text-sm">
          <span className="text-emerald-400">{successCount} succeeded</span>
          <span className="text-white/20">·</span>
          <span className="text-red-400">{failedCount} failed</span>
          <span className="text-white/20">·</span>
          <span className="text-white/40">{runs.length} total</span>
        </div>
      )}

      {loading && (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center text-white/30 text-sm">
          Loading…
        </div>
      )}
      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">{error}</div>
      )}

      {!loading && runs.length === 0 && (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] py-16 text-center text-white/30 text-sm">
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
