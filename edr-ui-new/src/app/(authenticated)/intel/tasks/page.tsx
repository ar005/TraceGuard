"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { timeAgo } from "@/lib/utils";
import {
  Zap, Search, Shield, RefreshCw, CheckCircle2, XCircle, Clock,
  ExternalLink, ChevronDown, ChevronRight,
} from "lucide-react";

interface IntelTask {
  id: string;
  name: string;
  task_type: string;   // hunt | yara_rule | detection_rule
  source_type: string; // actor | campaign | ioc | manual
  source_id: string;
  artifact_id: string;
  status: string;      // pending | done | failed
  created_at: string;
  created_by: string;
}

interface SavedHunt {
  id: string;
  name: string;
  query: string;
  source_id: string;
  created_at: string;
}

const TASK_TYPE_META: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
  hunt:            { label: "Hunt",       icon: <Search size={11} />,  color: "text-blue-400 bg-blue-500/10 border-blue-500/20" },
  yara_rule:       { label: "YARA Rule",  icon: <Shield size={11} />,  color: "text-purple-400 bg-purple-500/10 border-purple-500/20" },
  detection_rule:  { label: "Rule",       icon: <Zap size={11} />,     color: "text-amber-400 bg-amber-500/10 border-amber-500/20" },
};

const STATUS_META: Record<string, { icon: React.ReactNode; color: string }> = {
  pending: { icon: <Clock size={11} />,        color: "text-white/40" },
  done:    { icon: <CheckCircle2 size={11} />, color: "text-emerald-400" },
  failed:  { icon: <XCircle size={11} />,      color: "text-red-400" },
};

function artifactLink(task: IntelTask): string | null {
  if (!task.artifact_id) return null;
  switch (task.task_type) {
    case "yara_rule": return `/yara?id=${task.artifact_id}`;
    case "hunt":      return `/hunt?saved=${task.artifact_id}`;
    default: return null;
  }
}

function TaskRow({ task }: { task: IntelTask }) {
  const typeMeta = TASK_TYPE_META[task.task_type] ?? { label: task.task_type, icon: <Zap size={11} />, color: "text-white/40 bg-white/5 border-white/10" };
  const statusMeta = STATUS_META[task.status] ?? STATUS_META.pending;
  const link = artifactLink(task);

  return (
    <tr className="border-b border-white/5 hover:bg-white/[0.02] text-xs">
      <td className="px-4 py-3">
        <span className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] font-medium ${typeMeta.color}`}>
          {typeMeta.icon} {typeMeta.label}
        </span>
      </td>
      <td className="px-4 py-3 text-white/80 max-w-xs">
        <div className="truncate">{task.name}</div>
      </td>
      <td className="px-4 py-3">
        <span className="text-[10px] rounded px-1.5 py-0.5 bg-white/5 text-white/40 uppercase">{task.source_type}</span>
      </td>
      <td className="px-4 py-3">
        <span className={`flex items-center gap-1 ${statusMeta.color}`}>
          {statusMeta.icon} {task.status}
        </span>
      </td>
      <td className="px-4 py-3 text-white/30">{task.created_by}</td>
      <td className="px-4 py-3 text-white/30">{timeAgo(task.created_at)}</td>
      <td className="px-4 py-3">
        {link && task.status === "done" && (
          <a href={link} className="flex items-center gap-1 text-blue-400 hover:text-blue-300 transition-colors text-[10px]">
            View <ExternalLink size={10} />
          </a>
        )}
      </td>
    </tr>
  );
}

function HuntRow({ hunt, onDelete }: { hunt: SavedHunt; onDelete: () => void }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border-b border-white/5 last:border-0">
      <div
        className="flex items-center gap-3 px-4 py-3 hover:bg-white/[0.02] cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <span className="text-white/30">{expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}</span>
        <div className="flex-1 min-w-0">
          <p className="text-xs text-white/80 truncate">{hunt.name}</p>
          <p className="text-[10px] text-white/30 mt-0.5">{timeAgo(hunt.created_at)}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <a
            href={`/hunt?query=${encodeURIComponent(hunt.query)}`}
            onClick={(e) => e.stopPropagation()}
            className="flex items-center gap-1 text-blue-400/70 hover:text-blue-400 text-[10px] transition-colors"
          >
            Run <ExternalLink size={10} />
          </a>
          <button
            onClick={(e) => { e.stopPropagation(); if (confirm("Delete this saved hunt?")) onDelete(); }}
            className="text-red-400/40 hover:text-red-400 transition-colors text-[10px]"
          >
            Delete
          </button>
        </div>
      </div>
      {expanded && (
        <div className="px-4 pb-3">
          <pre className="rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2 text-[10px] text-white/60 font-mono whitespace-pre-wrap break-all">
            {hunt.query}
          </pre>
        </div>
      )}
    </div>
  );
}

export default function IntelTasksPage() {
  const [tab, setTab] = useState<"tasks" | "hunts">("tasks");

  const { data: tasksData, loading: tLoading, refetch: refetchTasks } = useApi<{ tasks: IntelTask[] }>(
    (signal) => api.get("/intel/tasks", { limit: "100" }, signal),
  );

  const { data: huntsData, loading: hLoading, refetch: refetchHunts } = useApi<{ hunts: SavedHunt[] }>(
    (signal) => api.get("/intel/saved-hunts", {}, signal),
  );

  const tasks = tasksData?.tasks ?? [];
  const hunts = huntsData?.hunts ?? [];

  const done   = tasks.filter((t) => t.status === "done").length;
  const failed = tasks.filter((t) => t.status === "failed").length;
  const pending = tasks.filter((t) => t.status === "pending").length;

  async function deleteHunt(id: string) {
    await api.del(`/intel/saved-hunts/${id}`);
    refetchHunts();
  }

  return (
    <div className="space-y-5 max-w-5xl">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Intel Tasking</h1>
          <p className="text-sm text-white/50 mt-0.5">
            Auto-generated artifacts from threat intel — YARA rules and hunt queries.
          </p>
        </div>
        <button
          onClick={() => { refetchTasks(); refetchHunts(); }}
          className="flex items-center gap-1.5 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-white/60 hover:text-white transition-colors"
        >
          <RefreshCw size={13} />
        </button>
      </div>

      {/* Stats */}
      {tasks.length > 0 && (
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: "Total Tasks",    value: tasks.length },
            { label: "Completed",      value: done,    highlight: done > 0 },
            { label: "Failed",         value: failed,  warn: failed > 0 },
            { label: "Saved Hunts",    value: hunts.length },
          ].map(({ label, value, highlight, warn }) => (
            <div key={label} className="rounded-xl border border-white/8 bg-white/[0.02] p-4 text-center">
              <p className={`text-2xl font-bold tabular-nums ${warn ? "text-red-400" : highlight ? "text-emerald-400" : "text-white"}`}>{value}</p>
              <p className="text-xs text-white/40 mt-0.5">{label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Pending banner */}
      {pending > 0 && (
        <div className="flex items-center gap-2 rounded-lg border border-blue-500/20 bg-blue-500/5 px-3 py-2 text-xs text-blue-300/80">
          <Clock size={12} className="shrink-0" />
          {pending} task{pending !== 1 ? "s" : ""} pending — artifacts generated asynchronously after IOC enrichment completes.
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-white/8">
        {(["tasks", "hunts"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-xs font-medium transition-colors border-b-2 -mb-px ${tab === t ? "border-white/60 text-white" : "border-transparent text-white/30 hover:text-white/60"}`}
          >
            {t === "tasks" ? `Tasks (${tasks.length})` : `Saved Hunts (${hunts.length})`}
          </button>
        ))}
      </div>

      {/* Tasks table */}
      {tab === "tasks" && (
        <>
          {tLoading && <div className="rounded-xl border border-white/10 bg-white/[0.02] p-10 text-center text-white/30 text-sm">Loading…</div>}
          {!tLoading && tasks.length === 0 && (
            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center space-y-2">
              <Zap size={28} className="mx-auto text-white/20" />
              <p className="text-white/30 text-sm">No tasks generated yet.</p>
              <p className="text-white/20 text-xs">Tasks are auto-created when hash IOCs with VT detections are added, or when threat actors with linked IOCs are created.</p>
            </div>
          )}
          {tasks.length > 0 && (
            <div className="rounded-xl border border-white/10 overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-white/5 text-white/30">
                    {["Type", "Name", "Source", "Status", "By", "Created", ""].map((h) => (
                      <th key={h} className="px-4 py-2.5 text-left text-[10px] font-normal uppercase tracking-wider">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {tasks.map((t) => <TaskRow key={t.id} task={t} />)}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {/* Saved hunts */}
      {tab === "hunts" && (
        <>
          {hLoading && <div className="rounded-xl border border-white/10 bg-white/[0.02] p-10 text-center text-white/30 text-sm">Loading…</div>}
          {!hLoading && hunts.length === 0 && (
            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center space-y-2">
              <Search size={28} className="mx-auto text-white/20" />
              <p className="text-white/30 text-sm">No saved hunts yet.</p>
              <p className="text-white/20 text-xs">Hunts are auto-generated when a threat actor with linked IOCs is created.</p>
            </div>
          )}
          {hunts.length > 0 && (
            <div className="rounded-xl border border-white/10 overflow-hidden">
              {hunts.map((h) => <HuntRow key={h.id} hunt={h} onDelete={() => deleteHunt(h.id)} />)}
            </div>
          )}
        </>
      )}
    </div>
  );
}
