"use client";

import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { timeAgo } from "@/lib/utils";
import {
  RefreshCw, CheckCircle2, XCircle, Clock, Loader2,
  AlertTriangle, ShieldAlert, Database, Zap, Search,
  Share2, RotateCcw, Users, Flag, TrendingUp,
} from "lucide-react";

/* ── Types ─────────────────────────────────────────────────────────────────── */
interface DashStats {
  total_iocs: number;
  enabled_iocs: number;
  enriched_iocs: number;
  total_hits: number;
  actor_count: number;
  campaign_count: number;
  replay_total: number;
  replay_matches: number;
  task_total: number;
  task_done: number;
  task_failed: number;
  sharing_groups: number;
}

interface ReplayJob {
  id: string;
  status: string;
  matched_count: number;
  scanned_count: number;
  lookback_days: number;
  created_at: string;
  finished_at?: string;
}

interface IntelTask {
  id: string;
  name: string;
  task_type: string;
  status: string;
  created_at: string;
}

interface Feed {
  id: string;
  name: string;
  url: string;
  protocol?: string;
  enabled: boolean;
  last_sync_at?: string;
  ioc_count: number;
  hit_count: number;
  quality_score?: number;
}

interface SharingGroup {
  id: string;
  name: string;
  tlp_floor: string;
  updated_at: string;
}

interface DashboardData {
  stats: DashStats;
  recent_replay: ReplayJob[];
  recent_tasks: IntelTask[];
  feeds: Feed[];
  sharing_groups: SharingGroup[];
}

/* ── Helpers ────────────────────────────────────────────────────────────────── */
const REPLAY_STATUS_STYLE: Record<string, string> = {
  queued:  "text-white/40",
  running: "text-blue-400",
  done:    "text-emerald-400",
  failed:  "text-red-400",
};

const REPLAY_STATUS_ICON: Record<string, React.ReactNode> = {
  queued:  <Clock size={10} />,
  running: <Loader2 size={10} className="animate-spin" />,
  done:    <CheckCircle2 size={10} />,
  failed:  <XCircle size={10} />,
};

const TASK_TYPE_COLOR: Record<string, string> = {
  hunt:           "text-blue-400 bg-blue-500/10",
  yara_rule:      "text-purple-400 bg-purple-500/10",
  detection_rule: "text-amber-400 bg-amber-500/10",
};

const TLP_STYLE: Record<string, string> = {
  WHITE: "border-white/20 text-white/60",
  GREEN: "border-emerald-500/30 text-emerald-400",
  AMBER: "border-amber-500/30 text-amber-400",
  RED:   "border-red-500/30 text-red-400",
};

function qualityColor(score: number) {
  if (score >= 70) return "text-emerald-400";
  if (score >= 40) return "text-amber-400";
  return "text-red-400";
}

function qualityBarColor(score: number) {
  if (score >= 70) return "bg-emerald-500";
  if (score >= 40) return "bg-amber-500";
  return "bg-red-500";
}

/* ── Sub-components ─────────────────────────────────────────────────────────── */
function StatCard({
  label, value, sub, icon, accent,
}: {
  label: string;
  value: number | string;
  sub?: string;
  icon: React.ReactNode;
  accent?: string;
}) {
  return (
    <div className="rounded-xl border border-white/8 bg-white/[0.02] p-4 flex items-start gap-3">
      <div className="mt-0.5 shrink-0 text-white/20">{icon}</div>
      <div className="min-w-0">
        <p className={`text-2xl font-bold tabular-nums leading-none ${accent ?? "text-white"}`}>
          {typeof value === "number" ? value.toLocaleString() : value}
        </p>
        <p className="text-xs text-white/40 mt-1">{label}</p>
        {sub && <p className="text-[10px] text-white/25 mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

function SectionHeader({ title, href }: { title: string; href?: string }) {
  return (
    <div className="flex items-center justify-between mb-3">
      <p className="text-xs font-semibold text-white/50 uppercase tracking-wider">{title}</p>
      {href && (
        <a href={href} className="text-[10px] text-white/30 hover:text-white/60 transition-colors">
          View all →
        </a>
      )}
    </div>
  );
}

function EnrichmentGauge({ total, enriched }: { total: number; enriched: number }) {
  const pct = total > 0 ? Math.round((enriched / total) * 100) : 0;
  const color = pct >= 80 ? "bg-emerald-500" : pct >= 50 ? "bg-amber-500" : "bg-red-500";
  const textColor = pct >= 80 ? "text-emerald-400" : pct >= 50 ? "text-amber-400" : "text-red-400";
  return (
    <div className="rounded-xl border border-white/8 bg-white/[0.02] p-4 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs text-white/50 uppercase tracking-wider font-semibold">Enrichment Coverage</p>
        <span className={`text-2xl font-bold tabular-nums ${textColor}`}>{pct}%</span>
      </div>
      <div className="h-2 rounded-full bg-white/5">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <div className="flex justify-between text-[10px] text-white/30">
        <span>{enriched.toLocaleString()} enriched</span>
        <span>{(total - enriched).toLocaleString()} pending</span>
      </div>
    </div>
  );
}

function FeedHealthTable({ feeds }: { feeds: Feed[] }) {
  if (feeds.length === 0) {
    return <p className="text-xs text-white/25 py-4 text-center">No custom feeds configured.</p>;
  }
  return (
    <div className="rounded-xl border border-white/8 overflow-hidden">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-white/5 text-white/25">
            {["Feed", "Protocol", "IOCs", "Hits", "Quality", "Last Sync"].map((h) => (
              <th key={h} className="px-3 py-2 text-left font-normal text-[10px] uppercase tracking-wider">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {feeds.map((f) => {
            const score = f.quality_score ?? 0;
            return (
              <tr key={f.id} className="border-b border-white/5 last:border-0 hover:bg-white/[0.02]">
                <td className="px-3 py-2.5">
                  <div className="flex items-center gap-2">
                    <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${f.enabled ? "bg-emerald-400" : "bg-white/20"}`} />
                    <span className="text-white/70 truncate max-w-[140px]">{f.name}</span>
                  </div>
                </td>
                <td className="px-3 py-2.5">
                  <span className="rounded px-1.5 py-0.5 text-[10px] bg-white/5 text-white/40 uppercase">
                    {f.protocol || "http"}
                  </span>
                </td>
                <td className="px-3 py-2.5 tabular-nums text-white/60">{f.ioc_count.toLocaleString()}</td>
                <td className="px-3 py-2.5 tabular-nums text-white/60">{f.hit_count}</td>
                <td className="px-3 py-2.5">
                  <div className="flex items-center gap-2">
                    <div className="w-16 h-1.5 rounded-full bg-white/5">
                      <div
                        className={`h-full rounded-full ${qualityBarColor(score)}`}
                        style={{ width: `${score}%` }}
                      />
                    </div>
                    <span className={`tabular-nums text-[10px] ${qualityColor(score)}`}>{score}</span>
                  </div>
                </td>
                <td className="px-3 py-2.5 text-white/30">
                  {f.last_sync_at ? timeAgo(f.last_sync_at) : <span className="text-white/15">never</span>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function ReplayList({ jobs }: { jobs: ReplayJob[] }) {
  if (jobs.length === 0) {
    return <p className="text-xs text-white/25 py-4 text-center">No replay jobs yet.</p>;
  }
  return (
    <div className="rounded-xl border border-white/8 overflow-hidden">
      {jobs.map((j, i) => (
        <div key={j.id} className={`flex items-center gap-3 px-3 py-2.5 text-xs ${i < jobs.length - 1 ? "border-b border-white/5" : ""}`}>
          <span className={`flex items-center gap-1 shrink-0 ${REPLAY_STATUS_STYLE[j.status] ?? "text-white/30"}`}>
            {REPLAY_STATUS_ICON[j.status]}
            <span className="capitalize">{j.status}</span>
          </span>
          <span className="text-white/30 shrink-0">{j.lookback_days}d lookback</span>
          <span className="flex-1" />
          {j.matched_count > 0 && (
            <span className="flex items-center gap-1 text-amber-400">
              <AlertTriangle size={10} /> {j.matched_count} match{j.matched_count !== 1 ? "es" : ""}
            </span>
          )}
          <span className="text-white/25">{timeAgo(j.created_at)}</span>
        </div>
      ))}
    </div>
  );
}

function TaskList({ tasks }: { tasks: IntelTask[] }) {
  if (tasks.length === 0) {
    return <p className="text-xs text-white/25 py-4 text-center">No tasks generated yet.</p>;
  }
  return (
    <div className="rounded-xl border border-white/8 overflow-hidden">
      {tasks.map((t, i) => (
        <div key={t.id} className={`flex items-center gap-2.5 px-3 py-2.5 text-xs ${i < tasks.length - 1 ? "border-b border-white/5" : ""}`}>
          <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium shrink-0 ${TASK_TYPE_COLOR[t.task_type] ?? "text-white/40 bg-white/5"}`}>
            {t.task_type === "yara_rule" ? "YARA" : t.task_type === "hunt" ? "Hunt" : "Rule"}
          </span>
          <span className="text-white/60 truncate flex-1 min-w-0">{t.name}</span>
          <span className={`shrink-0 flex items-center gap-1 ${t.status === "done" ? "text-emerald-400" : t.status === "failed" ? "text-red-400" : "text-white/30"}`}>
            {t.status === "done" ? <CheckCircle2 size={10} /> : t.status === "failed" ? <XCircle size={10} /> : <Clock size={10} />}
          </span>
          <span className="text-white/25 shrink-0">{timeAgo(t.created_at)}</span>
        </div>
      ))}
    </div>
  );
}

function SharingList({ groups }: { groups: SharingGroup[] }) {
  if (groups.length === 0) {
    return <p className="text-xs text-white/25 py-4 text-center">No sharing groups configured.</p>;
  }
  return (
    <div className="space-y-2">
      {groups.map((g) => (
        <div key={g.id} className="flex items-center gap-3 rounded-lg border border-white/8 px-3 py-2.5">
          <div className="flex-1 min-w-0">
            <p className="text-xs text-white/70 truncate">{g.name}</p>
            <p className="text-[10px] text-white/25 mt-0.5">Updated {timeAgo(g.updated_at)}</p>
          </div>
          <span className={`rounded border px-1.5 py-0.5 text-[10px] font-bold tracking-wider ${TLP_STYLE[g.tlp_floor] ?? TLP_STYLE.AMBER}`}>
            TLP:{g.tlp_floor}
          </span>
        </div>
      ))}
    </div>
  );
}

/* ── Page ────────────────────────────────────────────────────────────────────── */
export default function IntelDashboardPage() {
  const { data, loading, error, refetch } = useApi<DashboardData>(
    (signal) => api.get("/intel/dashboard", {}, signal),
  );

  const s = data?.stats;

  return (
    <div className="space-y-6 max-w-6xl">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Intel Pipeline</h1>
          <p className="text-sm text-white/50 mt-0.5">
            Health overview across all intel pipeline stages.
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-1.5 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-white/60 hover:text-white transition-colors"
        >
          <RefreshCw size={13} />
        </button>
      </div>

      {loading && (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-16 text-center text-white/30 text-sm">
          Loading…
        </div>
      )}
      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">{error}</div>
      )}

      {s && (
        <>
          {/* Top stats grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <StatCard label="Total IOCs" value={s.total_iocs}
              sub={`${s.enabled_iocs.toLocaleString()} enabled`}
              icon={<Database size={18} />} />
            <StatCard label="Total Hits" value={s.total_hits}
              icon={<ShieldAlert size={18} />}
              accent={s.total_hits > 0 ? "text-amber-400" : "text-white"} />
            <StatCard label="Actors / Campaigns" value={`${s.actor_count} / ${s.campaign_count}`}
              icon={<Users size={18} />} />
            <StatCard label="Replay Matches" value={s.replay_matches}
              sub={`${s.replay_total} jobs run`}
              icon={<RotateCcw size={18} />}
              accent={s.replay_matches > 0 ? "text-amber-400" : "text-white"} />
          </div>

          {/* Second row: enrichment + tasks + sharing */}
          <div className="grid grid-cols-3 gap-3">
            <EnrichmentGauge total={s.total_iocs} enriched={s.enriched_iocs} />
            <StatCard label="Tasks Generated"
              value={s.task_done}
              sub={`${s.task_failed > 0 ? s.task_failed + " failed · " : ""}${s.task_total} total`}
              icon={<Zap size={18} />}
              accent={s.task_done > 0 ? "text-emerald-400" : "text-white"} />
            <StatCard label="Sharing Groups"
              value={s.sharing_groups}
              icon={<Share2 size={18} />} />
          </div>

          {/* Feed health + Replay */}
          <div className="grid grid-cols-[1fr_320px] gap-5">
            <div>
              <SectionHeader title="Feed Health" href="/ioc-feeds" />
              <FeedHealthTable feeds={data?.feeds ?? []} />
            </div>
            <div>
              <SectionHeader title="Recent Replay Jobs" href="/intel/replay" />
              <ReplayList jobs={data?.recent_replay ?? []} />
            </div>
          </div>

          {/* Tasks + Sharing */}
          <div className="grid grid-cols-[1fr_300px] gap-5">
            <div>
              <SectionHeader title="Recent Tasks" href="/intel/tasks" />
              <TaskList tasks={data?.recent_tasks ?? []} />
            </div>
            <div>
              <SectionHeader title="Sharing Groups" href="/intel/sharing" />
              <SharingList groups={data?.sharing_groups ?? []} />
            </div>
          </div>

          {/* Quick nav links */}
          <div className="grid grid-cols-5 gap-2">
            {[
              { label: "Actors",    href: "/intel/actors",    icon: <Users size={14} /> },
              { label: "Campaigns", href: "/intel/campaigns", icon: <Flag size={14} /> },
              { label: "Replay",    href: "/intel/replay",    icon: <RotateCcw size={14} /> },
              { label: "Sharing",   href: "/intel/sharing",   icon: <Share2 size={14} /> },
              { label: "Tasking",   href: "/intel/tasks",     icon: <Zap size={14} /> },
            ].map((item) => (
              <a
                key={item.href}
                href={item.href}
                className="flex items-center justify-center gap-2 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2.5 text-xs text-white/40 hover:text-white/70 hover:bg-white/[0.04] transition-colors"
              >
                {item.icon}
                {item.label}
              </a>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
