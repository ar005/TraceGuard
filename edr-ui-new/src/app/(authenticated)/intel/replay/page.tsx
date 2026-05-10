"use client";

import { useState, useEffect, useRef } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import {
  RefreshCw, Play, CheckCircle2, AlertTriangle,
  Clock, Loader2, Database, ShieldAlert,
} from "lucide-react";

interface ReplayJob {
  id: string;
  triggered_by: string;
  ioc_ids: string[];
  lookback_days: number;
  status: "queued" | "running" | "done" | "failed";
  matched_count: number;
  scanned_count: number;
  created_at: string;
  finished_at?: string;
}

interface JobsResponse {
  jobs: ReplayJob[];
  total: number;
}

const STATUS_STYLES: Record<string, string> = {
  queued:  "text-white/40 border-white/10 bg-white/5",
  running: "text-blue-400 border-blue-500/30 bg-blue-500/10",
  done:    "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
  failed:  "text-red-400 border-red-500/30 bg-red-500/10",
};

const STATUS_ICONS: Record<string, React.ReactNode> = {
  queued:  <Clock size={11} />,
  running: <Loader2 size={11} className="animate-spin" />,
  done:    <CheckCircle2 size={11} />,
  failed:  <AlertTriangle size={11} />,
};

function elapsed(start: string, end?: string) {
  const ms = new Date(end ?? Date.now()).getTime() - new Date(start).getTime();
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

function timeAgo(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function ProgressBar({ job }: { job: ReplayJob }) {
  // Estimate progress as days scanned / lookback_days
  // scanned_count is rough (hours * 100), lookback_days * 24 * 100
  const total = job.lookback_days * 24 * 100;
  const pct = total > 0 ? Math.min((job.scanned_count / total) * 100, 99) : 0;
  const displayPct = job.status === "done" ? 100 : Math.round(pct);

  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-white/5">
        <div
          className={`h-full rounded-full transition-all duration-1000 ${job.status === "done" ? "bg-emerald-500" : job.status === "failed" ? "bg-red-500" : "bg-blue-500"}`}
          style={{ width: `${displayPct}%` }}
        />
      </div>
      <span className="text-[10px] text-white/30 w-8 text-right tabular-nums">{displayPct}%</span>
    </div>
  );
}

function LiveJobRow({ jobId, tenantId }: { jobId: string; tenantId: string }) {
  const [job, setJob] = useState<ReplayJob | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const _ = tenantId;

  useEffect(() => {
    const poll = async () => {
      try {
        const data = await api.get(`/intel/replay/${jobId}`) as ReplayJob;
        setJob(data);
        if (data.status === "done" || data.status === "failed") {
          if (intervalRef.current) clearInterval(intervalRef.current);
        }
      } catch { /* ignore */ }
    };
    poll();
    intervalRef.current = setInterval(poll, 3000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [jobId]);

  if (!job) return null;

  return <JobRow job={job} />;
}

function JobRow({ job }: { job: ReplayJob }) {
  const isActive = job.status === "queued" || job.status === "running";

  return (
    <tr className="border-b border-white/5 hover:bg-white/[0.02]">
      <td className="px-4 py-3">
        <span className={`flex items-center gap-1.5 rounded border px-2 py-0.5 text-[10px] font-medium w-fit ${STATUS_STYLES[job.status]}`}>
          {STATUS_ICONS[job.status]}
          {job.status}
        </span>
      </td>
      <td className="px-4 py-3">
        {job.ioc_ids?.length > 0 ? (
          <span className="text-xs text-white/60">
            {job.ioc_ids.length} IOC{job.ioc_ids.length !== 1 ? "s" : ""}
          </span>
        ) : (
          <span className="text-xs text-white/30">All IOCs</span>
        )}
      </td>
      <td className="px-4 py-3 text-xs text-white/50">{job.lookback_days}d lookback</td>
      <td className="px-4 py-3 w-44">
        {isActive ? (
          <ProgressBar job={job} />
        ) : (
          <div className="flex items-center gap-3 text-xs">
            {job.matched_count > 0 ? (
              <span className="flex items-center gap-1 text-amber-400">
                <ShieldAlert size={11} /> {job.matched_count} match{job.matched_count !== 1 ? "es" : ""}
              </span>
            ) : (
              <span className="text-white/25">No matches</span>
            )}
          </div>
        )}
      </td>
      <td className="px-4 py-3 text-xs text-white/30">{job.triggered_by}</td>
      <td className="px-4 py-3 text-xs text-white/30">
        <div>{timeAgo(job.created_at)}</div>
        {(job.status === "done" || job.status === "failed") && job.finished_at && (
          <div className="text-white/20">in {elapsed(job.created_at, job.finished_at)}</div>
        )}
        {isActive && (
          <div className="text-blue-400/60">running {elapsed(job.created_at)}</div>
        )}
      </td>
    </tr>
  );
}

export default function ReplayPage() {
  const [lookback, setLookback] = useState(30);
  const [launching, setLaunching] = useState(false);
  const [launchedId, setLaunchedId] = useState<string | null>(null);

  const { data, loading, error, refetch } = useApi<JobsResponse>(
    (signal) => api.get("/intel/replay?limit=50", {}, signal),
  );

  const jobs = data?.jobs ?? [];
  const running = jobs.filter((j) => j.status === "running" || j.status === "queued");
  const done = jobs.filter((j) => j.status === "done" || j.status === "failed");

  async function launch() {
    setLaunching(true);
    try {
      const job = await api.post("/intel/replay", { lookback_days: lookback }) as ReplayJob;
      setLaunchedId(job.id);
      refetch();
    } finally {
      setLaunching(false);
    }
  }

  const totalMatches = jobs.filter((j) => j.status === "done").reduce((s, j) => s + j.matched_count, 0);

  return (
    <div className="space-y-5 max-w-5xl">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Intel Replay</h1>
          <p className="text-sm text-white/50 mt-0.5">
            Retroactive IOC scan — find historical matches for newly added indicators
          </p>
        </div>
        <button onClick={() => refetch()} className="flex items-center gap-1.5 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-white/60 hover:text-white transition-colors">
          <RefreshCw size={13} />
        </button>
      </div>

      {/* Launch panel */}
      <div className="rounded-xl border border-white/10 bg-white/[0.02] p-5 space-y-4">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-sm font-semibold text-white">Run Retroactive Scan</p>
            <p className="text-xs text-white/40 mt-0.5">
              Scans all enabled IOCs against historical events. New IOCs are replayed automatically on import.
            </p>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <div className="flex items-center gap-2">
              <span className="text-xs text-white/40">Lookback</span>
              {[7, 14, 30, 60].map((d) => (
                <button key={d}
                  onClick={() => setLookback(d)}
                  className={`rounded-lg border px-2.5 py-1 text-xs transition-colors ${lookback === d ? "border-white/20 bg-white/[0.06] text-white" : "border-white/8 text-white/40 hover:text-white/70"}`}
                >
                  {d}d
                </button>
              ))}
            </div>
            <button
              onClick={launch}
              disabled={launching || running.length > 0}
              className="flex items-center gap-1.5 rounded-lg border border-white/20 bg-white/[0.06] px-4 py-1.5 text-xs text-white hover:bg-white/10 transition-colors disabled:opacity-40"
            >
              {launching ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />}
              {launching ? "Launching…" : "Run now"}
            </button>
          </div>
        </div>

        {running.length > 0 && (
          <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-xs text-blue-300/80 flex items-center gap-2">
            <Loader2 size={12} className="animate-spin shrink-0" />
            {running.length} job{running.length !== 1 ? "s" : ""} running — new scan queued automatically on IOC import
          </div>
        )}
      </div>

      {/* Stats */}
      {jobs.length > 0 && (
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: "Total jobs run", value: jobs.length },
            { label: "Historical matches", value: totalMatches, highlight: totalMatches > 0 },
            { label: "Active jobs", value: running.length },
          ].map(({ label, value, highlight }) => (
            <div key={label} className="rounded-xl border border-white/8 bg-white/[0.02] p-4 text-center">
              <p className={`text-2xl font-bold tabular-nums ${highlight ? "text-amber-400" : "text-white"}`}>{value}</p>
              <p className="text-xs text-white/40 mt-0.5">{label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Running jobs (live-updating rows) */}
      {running.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-white/30 uppercase tracking-wider">Active</p>
          <div className="rounded-xl border border-white/10 overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-white/5 text-white/30">
                  {["Status", "Scope", "Window", "Progress", "By", "Started"].map((h) => (
                    <th key={h} className="px-4 py-2.5 text-left font-normal">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {running.map((j) => (
                  <LiveJobRow key={j.id} jobId={j.id} tenantId={j.id} />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Completed jobs */}
      {loading && <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center text-white/30 text-sm">Loading…</div>}
      {error && <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">{error}</div>}

      {!loading && jobs.length === 0 && (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center space-y-2">
          <Database size={28} className="mx-auto text-white/20" />
          <p className="text-white/30 text-sm">No replay jobs yet.</p>
          <p className="text-white/20 text-xs">Jobs are auto-enqueued when IOCs are imported, or run manually above.</p>
        </div>
      )}

      {done.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-white/30 uppercase tracking-wider">History</p>
          <div className="rounded-xl border border-white/10 overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-white/5 text-white/30">
                  {["Status", "Scope", "Window", "Result", "By", "Completed"].map((h) => (
                    <th key={h} className="px-4 py-2.5 text-left font-normal">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {done.map((j) => <JobRow key={j.id} job={j} />)}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Info box — link to alerts */}
      {totalMatches > 0 && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-xs text-amber-300/80">
          <ShieldAlert size={12} className="mt-0.5 shrink-0 text-amber-500" />
          {totalMatches} historical match alert{totalMatches !== 1 ? "s" : ""} created — check the{" "}
          <a href="/alerts" className="underline underline-offset-2 hover:text-amber-200">Alerts</a> page filtered to source = intel_replay.
        </div>
      )}

      {launchedId && (
        <p className="text-xs text-emerald-400">Job {launchedId} queued — scanner picks it up within 10 seconds.</p>
      )}
    </div>
  );
}
