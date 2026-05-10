"use client";

import { useState } from "react";
import Link from "next/link";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { TrendingUp, TrendingDown, Minus, RefreshCw } from "lucide-react";

interface TrendPoint {
  date: string;
  score: number;
  agents: number;
  users: number;
}

interface AgentRisk {
  id: string;
  hostname: string;
  ip: string;
  risk_score: number;
  risk_factors: string[] | null;
}

interface UserRisk {
  canonical_uid: string;
  display_name: string;
  risk_score: number;
  risk_factors: string[] | null;
  is_privileged: boolean;
}

interface OrgThreatScore {
  org_score: number;
  score_delta_24h: number;
  trend: TrendPoint[];
  top_agents: AgentRisk[];
  top_users: UserRisk[];
  factor_breakdown: Record<string, number>;
}

const DAYS_OPTIONS = [7, 14, 30] as const;

function scoreColor(score: number) {
  if (score >= 70) return "text-red-400";
  if (score >= 31) return "text-amber-400";
  return "text-emerald-400";
}

function scoreBg(score: number) {
  if (score >= 70) return "bg-red-500/10 border-red-500/20";
  if (score >= 31) return "bg-amber-500/10 border-amber-500/20";
  return "bg-emerald-500/10 border-emerald-500/20";
}

function scoreLabel(score: number) {
  if (score >= 70) return "Critical";
  if (score >= 50) return "High";
  if (score >= 31) return "Medium";
  if (score > 0) return "Low";
  return "Healthy";
}

// Simple SVG line chart
function TrendChart({ points, days }: { points: TrendPoint[]; days: number }) {
  const W = 600;
  const H = 120;
  const PAD = { t: 10, r: 20, b: 30, l: 36 };
  const iW = W - PAD.l - PAD.r;
  const iH = H - PAD.t - PAD.b;

  if (points.length < 2) {
    return (
      <div className="h-[120px] flex items-center justify-center text-white/20 text-xs">
        Not enough history yet — data accumulates hourly.
      </div>
    );
  }

  const maxScore = Math.max(...points.map((p) => Math.max(p.agents, p.users, p.score)), 10);
  const xScale = (i: number) => PAD.l + (i / (points.length - 1)) * iW;
  const yScale = (v: number) => PAD.t + iH - (v / maxScore) * iH;

  const pathD = (getter: (p: TrendPoint) => number) =>
    points
      .map((p, i) => `${i === 0 ? "M" : "L"}${xScale(i).toFixed(1)},${yScale(getter(p)).toFixed(1)}`)
      .join(" ");

  const yTicks = [0, Math.round(maxScore / 2), maxScore];

  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} className="block overflow-visible">
      {/* Y-axis ticks */}
      {yTicks.map((v) => (
        <g key={v}>
          <line x1={PAD.l} y1={yScale(v)} x2={W - PAD.r} y2={yScale(v)} stroke="#ffffff08" />
          <text x={PAD.l - 6} y={yScale(v) + 4} textAnchor="end" fontSize={9} fill="#ffffff30">{v}</text>
        </g>
      ))}

      {/* X-axis labels — show first, mid, last */}
      {[0, Math.floor((points.length - 1) / 2), points.length - 1].map((i) => (
        <text key={i} x={xScale(i)} y={H - 4} textAnchor="middle" fontSize={9} fill="#ffffff30">
          {points[i]?.date?.slice(5)}
        </text>
      ))}

      {/* Agent line */}
      <path d={pathD((p) => p.agents)} fill="none" stroke="#f59e0b" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
      {/* User line */}
      <path d={pathD((p) => p.users)} fill="none" stroke="#a78bfa" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" strokeDasharray="4 2" />
      {/* Org score line */}
      <path d={pathD((p) => p.score)} fill="none" stroke="#ffffff" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// Horizontal bar for factor breakdown
function FactorBar({ label, count, max }: { label: string; count: number; max: number }) {
  const pct = max > 0 ? (count / max) * 100 : 0;
  return (
    <div className="flex items-center gap-3">
      <span className="w-28 text-xs text-white/50 shrink-0 capitalize">{label.replace("_", " ")}</span>
      <div className="flex-1 h-1.5 rounded-full bg-white/8 overflow-hidden">
        <div className="h-full rounded-full bg-amber-500/70" style={{ width: `${pct}%` }} />
      </div>
      <span className="w-6 text-right text-xs text-white/40">{count}</span>
    </div>
  );
}

// Sparkline for entity rows
function Sparkline({ entityId, entityType }: { entityId: string; entityType: string }) {
  const { data } = useApi<{ history: TrendPoint[] }>(
    (signal) => api.get(`/xdr/threat-score/history?entity_id=${entityId}&entity_type=${entityType}&days=7`, {}, signal),
  );
  const pts = data?.history ?? [];
  if (pts.length < 2) return <span className="text-white/20 text-xs">—</span>;

  const W = 60;
  const H = 20;
  const max = Math.max(...pts.map((p) => p.score), 1);
  const xS = (i: number) => (i / (pts.length - 1)) * W;
  const yS = (v: number) => H - (v / max) * H;
  const d = pts.map((p, i) => `${i === 0 ? "M" : "L"}${xS(i).toFixed(1)},${yS(p.score).toFixed(1)}`).join(" ");
  const last = pts[pts.length - 1].score;

  return (
    <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`}>
      <path d={d} fill="none" stroke={last >= 70 ? "#ef4444" : last >= 31 ? "#f59e0b" : "#22c55e"} strokeWidth={1.5} strokeLinecap="round" />
    </svg>
  );
}

export default function ThreatScorePage() {
  const [days, setDays] = useState(30);

  const { data, loading, error, refetch } = useApi<OrgThreatScore>(
    (signal) => api.get(`/xdr/threat-score?days=${days}`, {}, signal),
  );

  const delta = data?.score_delta_24h ?? 0;
  const factorEntries = Object.entries(data?.factor_breakdown ?? {}).sort((a, b) => b[1] - a[1]);
  const maxFactor = factorEntries[0]?.[1] ?? 1;

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Threat Score Dashboard</h1>
          <p className="text-sm text-white/50 mt-0.5">
            Org-wide security posture — risk trends for hosts and users
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 rounded-lg border border-white/10 bg-white/[0.03] p-1">
            {DAYS_OPTIONS.map((d) => (
              <button
                key={d}
                onClick={() => setDays(d)}
                className={`rounded-md px-3 py-1 text-xs transition-colors ${
                  days === d ? "bg-white/15 text-white" : "text-white/40 hover:text-white/70"
                }`}
              >
                {d}d
              </button>
            ))}
          </div>
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-white/60 hover:text-white hover:border-white/20 transition-colors"
          >
            <RefreshCw size={13} />
            Refresh
          </button>
        </div>
      </div>

      {loading && (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center text-white/30 text-sm">
          Loading…
        </div>
      )}
      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">{error}</div>
      )}

      {!loading && data && (
        <>
          {/* Org score + delta */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className={`col-span-1 rounded-xl border p-6 flex flex-col items-center justify-center gap-2 ${scoreBg(data.org_score)}`}>
              <p className="text-xs font-medium text-white/40 uppercase tracking-wider">Org Score</p>
              <p className={`text-6xl font-bold tabular-nums ${scoreColor(data.org_score)}`}>
                {data.org_score}
              </p>
              <p className={`text-sm font-medium ${scoreColor(data.org_score)}`}>
                {scoreLabel(data.org_score)}
              </p>
              <div className="flex items-center gap-1 mt-1">
                {delta > 0 ? (
                  <TrendingUp size={14} className="text-red-400" />
                ) : delta < 0 ? (
                  <TrendingDown size={14} className="text-emerald-400" />
                ) : (
                  <Minus size={14} className="text-white/30" />
                )}
                <span className={`text-xs ${delta > 0 ? "text-red-400" : delta < 0 ? "text-emerald-400" : "text-white/30"}`}>
                  {delta > 0 ? "+" : ""}{delta} vs 24 h ago
                </span>
              </div>
            </div>

            {/* Factor breakdown */}
            <div className="col-span-2 rounded-xl border border-white/10 bg-white/[0.02] p-5 space-y-3">
              <p className="text-xs font-medium text-white/40 uppercase tracking-wider">Risk Drivers</p>
              {factorEntries.length === 0 ? (
                <p className="text-white/20 text-sm">No risk factors recorded yet.</p>
              ) : (
                <div className="space-y-2.5">
                  {factorEntries.slice(0, 8).map(([label, count]) => (
                    <FactorBar key={label} label={label} count={count} max={maxFactor} />
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Trend chart */}
          <div className="rounded-xl border border-white/10 bg-white/[0.02] p-5 space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-xs font-medium text-white/40 uppercase tracking-wider">Score Trend — {days} days</p>
              <div className="flex items-center gap-4 text-xs">
                <span className="flex items-center gap-1.5 text-white/50">
                  <span className="w-4 h-0.5 bg-white inline-block rounded" /> Org
                </span>
                <span className="flex items-center gap-1.5 text-white/50">
                  <span className="w-4 h-0.5 bg-amber-500 inline-block rounded" /> Hosts
                </span>
                <span className="flex items-center gap-1.5 text-white/50">
                  <span className="w-4 h-0.5 bg-violet-400 inline-block rounded" style={{ borderTop: "2px dashed" }} /> Users
                </span>
              </div>
            </div>
            <TrendChart points={data.trend} days={days} />
          </div>

          {/* Top agents + users tables */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Top Risk Agents */}
            <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
              <div className="px-4 py-3 border-b border-white/8">
                <p className="text-xs font-medium text-white/40 uppercase tracking-wider">Top Risk Agents</p>
              </div>
              {data.top_agents.length === 0 ? (
                <p className="p-4 text-sm text-white/20">No agents with elevated risk.</p>
              ) : (
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-white/5 text-white/30">
                      <th className="px-4 py-2 text-left font-normal">Host</th>
                      <th className="px-4 py-2 text-right font-normal">Score</th>
                      <th className="px-4 py-2 text-right font-normal">7-day</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.top_agents.map((a) => (
                      <tr key={a.id} className="border-b border-white/5 hover:bg-white/[0.02]">
                        <td className="px-4 py-2">
                          <Link href={`/agents/${a.id}`} className="text-white/70 hover:text-white transition-colors">
                            {a.hostname}
                          </Link>
                          <div className="text-white/30 font-mono">{a.ip}</div>
                        </td>
                        <td className="px-4 py-2 text-right">
                          <span className={`font-semibold ${scoreColor(a.risk_score)}`}>{a.risk_score}</span>
                        </td>
                        <td className="px-4 py-2 text-right">
                          <div className="flex justify-end">
                            <Sparkline entityId={a.id} entityType="agent" />
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            {/* Top Risk Users */}
            <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
              <div className="px-4 py-3 border-b border-white/8">
                <p className="text-xs font-medium text-white/40 uppercase tracking-wider">Top Risk Users</p>
              </div>
              {data.top_users.length === 0 ? (
                <p className="p-4 text-sm text-white/20">No users with elevated risk.</p>
              ) : (
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-white/5 text-white/30">
                      <th className="px-4 py-2 text-left font-normal">User</th>
                      <th className="px-4 py-2 text-right font-normal">Score</th>
                      <th className="px-4 py-2 text-right font-normal">7-day</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.top_users.map((u) => (
                      <tr key={u.canonical_uid} className="border-b border-white/5 hover:bg-white/[0.02]">
                        <td className="px-4 py-2">
                          <div className="flex items-center gap-1.5">
                            <span className="text-white/70">
                              {u.display_name || u.canonical_uid}
                            </span>
                            {u.is_privileged && (
                              <span className="rounded border border-amber-500/30 text-amber-400 text-[9px] px-1">PRIV</span>
                            )}
                          </div>
                          <div className="text-white/30 font-mono text-[10px]">{u.canonical_uid}</div>
                        </td>
                        <td className="px-4 py-2 text-right">
                          <span className={`font-semibold ${scoreColor(u.risk_score)}`}>{u.risk_score}</span>
                        </td>
                        <td className="px-4 py-2 text-right">
                          <div className="flex justify-end">
                            <Sparkline entityId={u.canonical_uid} entityType="user" />
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
