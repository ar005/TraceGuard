"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { CalendarClock, Play, Pause, Trash2, Plus, Clock, CheckCircle, XCircle, ChevronDown, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

interface HuntSchedule {
  id: string;
  saved_hunt_id: string;
  name: string;
  cron_expr: string;
  enabled: boolean;
  alert_on_hit: boolean;
  last_run_at?: string;
  next_run_at?: string;
  created_at: string;
}

interface ScheduleRun {
  id: string;
  schedule_id: string;
  started_at: string;
  finished_at?: string;
  row_count: number;
  hit_count: number;
  status: "running" | "ok" | "error";
  error: string;
}

interface SavedHunt {
  id: string;
  name: string;
  query: string;
}

const CRON_PRESETS = [
  { label: "Every 15 min",  value: "*/15 * * * *" },
  { label: "Every 30 min",  value: "*/30 * * * *" },
  { label: "Every hour",    value: "0 */1 * * *" },
  { label: "Every 6 hours", value: "0 */6 * * *" },
  { label: "Daily at 00:00", value: "0 0 * * *" },
  { label: "Daily at 08:00", value: "0 8 * * *" },
];

function RunHistoryRow({ run }: { run: ScheduleRun }) {
  const statusIcon =
    run.status === "ok"    ? <CheckCircle size={13} className="text-green-400" /> :
    run.status === "error" ? <XCircle size={13} className="text-red-400" /> :
                             <Clock size={13} className="text-yellow-400 animate-spin" />;
  return (
    <div className="flex items-center gap-3 text-xs px-3 py-1.5 rounded bg-[hsl(var(--muted)/.3)]">
      {statusIcon}
      <span className="text-[hsl(var(--muted-foreground))]">
        {new Date(run.started_at).toLocaleString()}
      </span>
      <span className="ml-auto font-mono">
        {run.hit_count > 0
          ? <span className="text-orange-400 font-semibold">{run.hit_count} hits</span>
          : <span className="text-[hsl(var(--muted-foreground))]">0 hits</span>}
        {" / "}{run.row_count} rows
      </span>
      {run.error && (
        <span className="text-red-400 truncate max-w-[180px]" title={run.error}>{run.error}</span>
      )}
    </div>
  );
}

function ScheduleRunHistory({ scheduleId }: { scheduleId: string }) {
  const { data: runs } = useApi<ScheduleRun[]>(
    (sig) => api.get<ScheduleRun[]>(`/intel/hunt-schedules/${scheduleId}/runs`, {}, sig)
  );
  if (!runs || runs.length === 0) {
    return <p className="text-xs text-[hsl(var(--muted-foreground))] italic">No runs yet.</p>;
  }
  return (
    <div className="space-y-1.5">
      {runs.slice(0, 10).map((r) => <RunHistoryRow key={r.id} run={r} />)}
    </div>
  );
}

function ScheduleCard({
  schedule,
  onToggle,
  onDelete,
}: {
  schedule: HuntSchedule;
  onToggle: (id: string, enabled: boolean) => void;
  onDelete: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);

  return (
    <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-3">
        <button
          onClick={() => setOpen((v) => !v)}
          className="text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors"
        >
          {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </button>

        <CalendarClock size={15} className={schedule.enabled ? "text-[hsl(var(--primary))]" : "text-[hsl(var(--muted-foreground))]"} />

        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium truncate">{schedule.name}</p>
          <p className="text-xs text-[hsl(var(--muted-foreground))] font-mono">{schedule.cron_expr}</p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {schedule.next_run_at && (
            <span className="text-xs text-[hsl(var(--muted-foreground))] hidden sm:block">
              Next: {new Date(schedule.next_run_at).toLocaleString()}
            </span>
          )}
          <span className={cn(
            "text-xs px-2 py-0.5 rounded-full border font-medium",
            schedule.alert_on_hit
              ? "border-orange-500/40 bg-orange-500/10 text-orange-400"
              : "border-[hsl(var(--border))] text-[hsl(var(--muted-foreground))]"
          )}>
            {schedule.alert_on_hit ? "alert on hit" : "no alert"}
          </span>
          <button
            onClick={() => onToggle(schedule.id, !schedule.enabled)}
            title={schedule.enabled ? "Disable" : "Enable"}
            className="p-1.5 rounded hover:bg-[hsl(var(--accent))] transition-colors"
          >
            {schedule.enabled
              ? <Pause size={14} className="text-[hsl(var(--primary))]" />
              : <Play size={14} className="text-[hsl(var(--muted-foreground))]" />}
          </button>
          <button
            onClick={() => onDelete(schedule.id)}
            title="Delete"
            className="p-1.5 rounded hover:bg-red-500/10 text-[hsl(var(--muted-foreground))] hover:text-red-400 transition-colors"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      {open && (
        <div className="border-t border-[hsl(var(--border))] px-4 py-3 space-y-2">
          <p className="text-xs font-medium text-[hsl(var(--muted-foreground))] uppercase tracking-wider mb-2">
            Recent runs
          </p>
          <ScheduleRunHistory scheduleId={schedule.id} />
        </div>
      )}
    </div>
  );
}

function CreateModal({
  hunts,
  onClose,
  onCreate,
}: {
  hunts: SavedHunt[];
  onClose: () => void;
  onCreate: () => void;
}) {
  const [form, setForm] = useState({
    saved_hunt_id: hunts[0]?.id ?? "",
    name: "",
    cron_expr: "*/30 * * * *",
    alert_on_hit: true,
    enabled: true,
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const submit = async () => {
    if (!form.name.trim() || !form.saved_hunt_id) {
      setError("Name and hunt are required.");
      return;
    }
    setSaving(true);
    try {
      await api.post("/intel/hunt-schedules", form);
      onCreate();
      onClose();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to create schedule");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="w-full max-w-md rounded-xl border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-6 shadow-xl space-y-4">
        <h2 className="text-base font-semibold">New Hunt Schedule</h2>
        <div className="space-y-3">
          <div>
            <label className="text-xs font-medium text-[hsl(var(--muted-foreground))] uppercase tracking-wider">Name</label>
            <input
              className="mt-1 w-full rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[hsl(var(--primary))]"
              placeholder="Hourly lateral movement check"
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            />
          </div>
          <div>
            <label className="text-xs font-medium text-[hsl(var(--muted-foreground))] uppercase tracking-wider">Saved Hunt</label>
            <select
              className="mt-1 w-full rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[hsl(var(--primary))]"
              value={form.saved_hunt_id}
              onChange={(e) => setForm((f) => ({ ...f, saved_hunt_id: e.target.value }))}
            >
              {hunts.map((h) => (
                <option key={h.id} value={h.id}>{h.name}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs font-medium text-[hsl(var(--muted-foreground))] uppercase tracking-wider">Schedule</label>
            <div className="mt-1 flex gap-2 flex-wrap">
              {CRON_PRESETS.map((p) => (
                <button
                  key={p.value}
                  onClick={() => setForm((f) => ({ ...f, cron_expr: p.value }))}
                  className={cn(
                    "text-xs px-2.5 py-1 rounded-md border transition-colors",
                    form.cron_expr === p.value
                      ? "border-[hsl(var(--primary))] bg-[hsl(var(--primary)/.1)] text-[hsl(var(--primary))]"
                      : "border-[hsl(var(--border))] text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]"
                  )}
                >
                  {p.label}
                </button>
              ))}
            </div>
            <input
              className="mt-2 w-full rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-[hsl(var(--primary))]"
              placeholder="*/30 * * * *"
              value={form.cron_expr}
              onChange={(e) => setForm((f) => ({ ...f, cron_expr: e.target.value }))}
            />
          </div>
          <div className="flex gap-4">
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={form.alert_on_hit}
                onChange={(e) => setForm((f) => ({ ...f, alert_on_hit: e.target.checked }))} className="rounded" />
              Alert on hit
            </label>
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={form.enabled}
                onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))} className="rounded" />
              Enabled immediately
            </label>
          </div>
        </div>
        {error && <p className="text-xs text-red-400">{error}</p>}
        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose}
            className="px-4 py-2 text-sm rounded-lg border border-[hsl(var(--border))] hover:bg-[hsl(var(--accent))] transition-colors">
            Cancel
          </button>
          <button onClick={submit} disabled={saving}
            className="px-4 py-2 text-sm rounded-lg bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity disabled:opacity-50">
            {saving ? "Creating…" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function HuntSchedulesPage() {
  const [tick, setTick] = useState(0);
  const refresh = () => setTick((k) => k + 1);

  const { data: schedules, loading } = useApi<HuntSchedule[]>(
    // eslint-disable-next-line react-hooks/exhaustive-deps
    (sig) => api.get<HuntSchedule[]>("/intel/hunt-schedules", { _t: tick }, sig)
  );
  const { data: hunts } = useApi<SavedHunt[]>(
    (sig) => api.get<SavedHunt[]>("/intel/saved-hunts", {}, sig)
  );

  const [showCreate, setShowCreate] = useState(false);

  const handleToggle = async (id: string, enabled: boolean) => {
    await api.put(`/intel/hunt-schedules/${id}`, { enabled });
    refresh();
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this schedule?")) return;
    await api.del(`/intel/hunt-schedules/${id}`);
    refresh();
  };

  const enabledCount = schedules?.filter((s) => s.enabled).length ?? 0;

  return (
    <div className="p-6 space-y-6 max-w-4xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Hunt Schedules</h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">
            Auto-run saved hunts on a cron schedule and alert on hits.
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] text-sm font-medium hover:opacity-90 transition-opacity"
        >
          <Plus size={15} /> New Schedule
        </button>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {[
          { label: "Total Schedules", value: schedules?.length ?? 0 },
          { label: "Active",          value: enabledCount },
          { label: "Saved Hunts",     value: hunts?.length ?? 0 },
        ].map((s) => (
          <div key={s.label} className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-4 py-3">
            <p className="text-xs text-[hsl(var(--muted-foreground))] uppercase tracking-wider">{s.label}</p>
            <p className="text-2xl font-semibold mt-1">{s.value}</p>
          </div>
        ))}
      </div>

      {hunts && hunts.length === 0 && (
        <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-4 py-3 text-sm text-yellow-300">
          No saved hunts found. Create a saved hunt from the Tasking page first.
        </div>
      )}

      {loading ? (
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-16 rounded-lg bg-[hsl(var(--muted)/.3)] animate-pulse" />
          ))}
        </div>
      ) : !schedules || schedules.length === 0 ? (
        <div className="rounded-lg border border-dashed border-[hsl(var(--border))] p-10 text-center">
          <CalendarClock size={32} className="mx-auto mb-3 text-[hsl(var(--muted-foreground))]" />
          <p className="text-sm text-[hsl(var(--muted-foreground))]">No schedules yet. Create one to automate your hunts.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {schedules.map((hs) => (
            <ScheduleCard key={hs.id} schedule={hs} onToggle={handleToggle} onDelete={handleDelete} />
          ))}
        </div>
      )}

      {showCreate && hunts && (
        <CreateModal hunts={hunts} onClose={() => setShowCreate(false)} onCreate={refresh} />
      )}
    </div>
  );
}
