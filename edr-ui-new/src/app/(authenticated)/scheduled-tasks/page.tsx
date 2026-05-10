"use client";

import { useState } from "react";
import Link from "next/link";
import {
  CalendarClock,
  CheckCircle2,
  PauseCircle,
  Clock,
  X,
  Loader2,
  RefreshCw,
  ChevronRight,
  History,
  Play,
} from "lucide-react";
import { api } from "@/lib/api-client";
import { useApi } from "@/hooks/use-api";
import { cn, timeAgo } from "@/lib/utils";

interface AgentTask {
  id: string;
  agent_id: string;
  name: string;
  type: string;
  schedule: string;
  status: string;
  last_run_at: string | null;
  next_run_at: string | null;
  created_at: string;
  created_by: string;
}

interface TaskEvent {
  id: string;
  task_id: string;
  agent_id: string;
  task_name: string;
  task_type: string;
  action: string;
  actor: string;
  detail: Record<string, unknown>;
  occurred_at: string;
}

const STATUS_ICON: Record<string, React.ReactNode> = {
  active:    <CheckCircle2 size={13} className="text-emerald-400" />,
  paused:    <PauseCircle  size={13} className="text-yellow-400" />,
  completed: <CheckCircle2 size={13} className="text-sky-400" />,
  deleted:   <X            size={13} className="text-red-400" />,
};

const ACTION_STYLE: Record<string, string> = {
  created:  "bg-emerald-500/10 text-emerald-400",
  deleted:  "bg-red-500/10 text-red-400",
  paused:   "bg-yellow-500/10 text-yellow-400",
  resumed:  "bg-sky-500/10 text-sky-400",
  updated:  "bg-violet-500/10 text-violet-400",
  executed: "bg-blue-500/10 text-blue-400",
};

const STATUS_COUNTS = (tasks: AgentTask[]) => ({
  active:    tasks.filter((t) => t.status === "active").length,
  paused:    tasks.filter((t) => t.status === "paused").length,
  completed: tasks.filter((t) => t.status === "completed").length,
});

export default function ScheduledTasksPage() {
  const [view, setView] = useState<"tasks" | "history">("tasks");
  const [statusFilter, setStatusFilter] = useState("all");
  const [search, setSearch] = useState("");

  const {
    data: tasksData,
    loading: tasksLoading,
    refetch: refreshTasks,
  } = useApi<{ tasks: AgentTask[]; total: number }>(
    (signal) => api.get("/api/v1/tasks", {}, signal)
  );

  const {
    data: historyData,
    loading: historyLoading,
  } = useApi<{ events: TaskEvent[]; total: number }>(
    (signal) => api.get("/api/v1/tasks/history", { limit: 100 }, signal)
  );

  const tasks = tasksData?.tasks ?? [];
  const events = historyData?.events ?? [];
  const counts = STATUS_COUNTS(tasks);

  async function handleRun(agentId: string, taskId: string) {
    await api.post(`/api/v1/agents/${agentId}/tasks/${taskId}/run`, {});
    refreshTasks();
  }

  const filteredTasks = tasks.filter((t) => {
    if (statusFilter !== "all" && t.status !== statusFilter) return false;
    if (search && !t.name.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <CalendarClock size={22} className="text-[hsl(var(--primary))]" />
          <div>
            <h1 className="text-xl font-bold tracking-tight">Scheduled Tasks</h1>
            <p className="text-xs mt-0.5" style={{ color: "var(--muted)" }}>
              All tasks scheduled across your endpoints
            </p>
          </div>
        </div>
        <button
          onClick={refreshTasks}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border hover:bg-[hsl(var(--accent))] transition-colors"
          style={{ borderColor: "var(--border)" }}
        >
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      {/* Stat chips */}
      <div className="grid grid-cols-3 gap-3">
        {(["active", "paused", "completed"] as const).map((s) => (
          <button
            key={s}
            onClick={() => setStatusFilter(statusFilter === s ? "all" : s)}
            className={cn(
              "rounded-xl border p-4 text-left transition-colors",
              statusFilter === s
                ? "border-[hsl(var(--primary)/.5)] bg-[hsl(var(--primary)/.08)]"
                : "hover:bg-[hsl(var(--accent)/.5)]"
            )}
            style={{ borderColor: statusFilter === s ? undefined : "var(--border)" }}
          >
            <div className="flex items-center gap-2 mb-1">
              {STATUS_ICON[s]}
              <span className="text-xs font-medium capitalize" style={{ color: "var(--muted)" }}>{s}</span>
            </div>
            <p className="text-2xl font-bold">{counts[s]}</p>
          </button>
        ))}
      </div>

      {/* View toggle */}
      <div className="flex items-center gap-2">
        <div className="flex gap-1 text-xs">
          {(["tasks", "history"] as const).map((v) => (
            <button
              key={v}
              onClick={() => setView(v)}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-colors capitalize",
                view === v
                  ? "bg-[hsl(var(--primary)/.15)] text-[hsl(var(--primary))]"
                  : "text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--accent))]"
              )}
            >
              {v === "history" ? <History size={13} /> : <CalendarClock size={13} />}
              {v === "tasks" ? `All Tasks (${tasks.length})` : "Audit History"}
            </button>
          ))}
        </div>

        {view === "tasks" && (
          <input
            className="ml-auto px-3 py-1.5 rounded-lg border text-xs bg-transparent w-56"
            style={{ borderColor: "var(--border)" }}
            placeholder="Search tasks…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        )}
      </div>

      {/* Tasks table */}
      {view === "tasks" && (
        <div className="rounded-xl border overflow-hidden" style={{ borderColor: "var(--border)" }}>
          {tasksLoading ? (
            <div className="py-16 flex justify-center">
              <Loader2 size={24} className="animate-spin opacity-40" />
            </div>
          ) : filteredTasks.length === 0 ? (
            <div className="py-16 text-center text-xs" style={{ color: "var(--muted)" }}>
              {tasks.length === 0 ? "No scheduled tasks yet" : "No tasks match your filter"}
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr
                  className="border-b text-xs font-medium uppercase tracking-wide"
                  style={{ borderColor: "var(--border)", color: "var(--muted)" }}
                >
                  <th className="px-4 py-3 text-left">Name</th>
                  <th className="px-4 py-3 text-left">Type</th>
                  <th className="px-4 py-3 text-left">Schedule</th>
                  <th className="px-4 py-3 text-left">Status</th>
                  <th className="px-4 py-3 text-left">Agent</th>
                  <th className="px-4 py-3 text-left">Last Run</th>
                  <th className="px-4 py-3 text-left">Next Run</th>
                  <th className="px-4 py-3 text-left">Created By</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody>
                {filteredTasks.map((t) => (
                  <tr
                    key={t.id}
                    className="border-b last:border-0 hover:bg-[hsl(var(--accent)/.4)] transition-colors"
                    style={{ borderColor: "var(--border)" }}
                  >
                    <td className="px-4 py-3 font-medium">{t.name}</td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded-full text-xs bg-[hsl(var(--primary)/.1)] text-[hsl(var(--primary))]">
                        {t.type}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs" style={{ color: "var(--muted)" }}>
                      {t.schedule || "—"}
                    </td>
                    <td className="px-4 py-3">
                      <span className="flex items-center gap-1.5">
                        {STATUS_ICON[t.status] ?? <Clock size={13} />}
                        <span className="text-xs capitalize">{t.status}</span>
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <Link
                        href={`/agents/${t.agent_id}?tab=tasks`}
                        className="text-xs text-[hsl(var(--primary))] hover:underline font-mono"
                      >
                        {t.agent_id.slice(0, 8)}…
                      </Link>
                    </td>
                    <td className="px-4 py-3 text-xs" style={{ color: "var(--muted)" }}>
                      {t.last_run_at ? timeAgo(t.last_run_at) : "Never"}
                    </td>
                    <td className="px-4 py-3 text-xs" style={{ color: "var(--muted)" }}>
                      {t.next_run_at ? timeAgo(t.next_run_at) : "—"}
                    </td>
                    <td className="px-4 py-3 text-xs" style={{ color: "var(--muted)" }}>
                      {t.created_by}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => handleRun(t.agent_id, t.id)}
                          title="Run now"
                          className="p-1 rounded hover:bg-emerald-500/10 text-emerald-400 transition-colors"
                        >
                          <Play size={14} />
                        </button>
                        <Link
                          href={`/agents/${t.agent_id}?tab=tasks`}
                          className="p-1 rounded hover:bg-[hsl(var(--accent))] transition-colors inline-flex"
                          title="View on agent"
                        >
                          <ChevronRight size={14} style={{ color: "var(--muted)" }} />
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* History table */}
      {view === "history" && (
        <div className="rounded-xl border overflow-hidden" style={{ borderColor: "var(--border)" }}>
          {historyLoading ? (
            <div className="py-16 flex justify-center">
              <Loader2 size={24} className="animate-spin opacity-40" />
            </div>
          ) : events.length === 0 ? (
            <div className="py-16 text-center text-xs" style={{ color: "var(--muted)" }}>
              No task history yet
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr
                  className="border-b text-xs font-medium uppercase tracking-wide"
                  style={{ borderColor: "var(--border)", color: "var(--muted)" }}
                >
                  <th className="px-4 py-3 text-left">Time</th>
                  <th className="px-4 py-3 text-left">Task</th>
                  <th className="px-4 py-3 text-left">Type</th>
                  <th className="px-4 py-3 text-left">Action</th>
                  <th className="px-4 py-3 text-left">Agent</th>
                  <th className="px-4 py-3 text-left">Actor</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr
                    key={e.id}
                    className="border-b last:border-0 hover:bg-[hsl(var(--accent)/.4)] transition-colors"
                    style={{ borderColor: "var(--border)" }}
                  >
                    <td className="px-4 py-3 text-xs" style={{ color: "var(--muted)" }}>
                      {timeAgo(e.occurred_at)}
                    </td>
                    <td className="px-4 py-3 font-medium">{e.task_name}</td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded-full text-xs bg-[hsl(var(--primary)/.1)] text-[hsl(var(--primary))]">
                        {e.task_type}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={cn(
                          "px-2 py-0.5 rounded-full text-xs font-medium",
                          ACTION_STYLE[e.action] ?? "bg-zinc-500/10 text-zinc-400"
                        )}
                      >
                        {e.action}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <Link
                        href={`/agents/${e.agent_id}?tab=tasks`}
                        className="text-xs text-[hsl(var(--primary))] hover:underline font-mono"
                      >
                        {e.agent_id.slice(0, 8)}…
                      </Link>
                    </td>
                    <td className="px-4 py-3 text-xs" style={{ color: "var(--muted)" }}>
                      {e.actor}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
