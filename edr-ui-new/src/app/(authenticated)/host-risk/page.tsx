"use client";

import { useState, useEffect } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";

interface Agent {
  id: string;
  hostname: string;
  os: string;
  tenant_id: string;
  risk_score: number;
  risk_factors: string[] | null;
  risk_updated_at: string | null;
  last_seen: string | null;
  status: string;
}

function RiskBar({ score }: { score: number }) {
  const pct = Math.min(100, Math.max(0, score));
  const color =
    pct >= 75
      ? "bg-red-500"
      : pct >= 50
        ? "bg-orange-500"
        : pct >= 25
          ? "bg-yellow-500"
          : "bg-emerald-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-white/10">
        <div
          className={`h-full rounded-full ${color} transition-all`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span
        className={`text-xs font-mono font-semibold w-8 text-right ${
          pct >= 75
            ? "text-red-400"
            : pct >= 50
              ? "text-orange-400"
              : pct >= 25
                ? "text-yellow-400"
                : "text-emerald-400"
        }`}
      >
        {score}
      </span>
    </div>
  );
}

function RiskLabel({ score }: { score: number }) {
  if (score >= 75)
    return (
      <span className="text-xs font-semibold text-red-400 bg-red-500/10 px-2 py-0.5 rounded-full border border-red-500/20">
        CRITICAL
      </span>
    );
  if (score >= 50)
    return (
      <span className="text-xs font-semibold text-orange-400 bg-orange-500/10 px-2 py-0.5 rounded-full border border-orange-500/20">
        HIGH
      </span>
    );
  if (score >= 25)
    return (
      <span className="text-xs font-semibold text-yellow-400 bg-yellow-500/10 px-2 py-0.5 rounded-full border border-yellow-500/20">
        MEDIUM
      </span>
    );
  return (
    <span className="text-xs font-semibold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full border border-emerald-500/20">
      LOW
    </span>
  );
}

export default function HostRiskPage() {
  const [limit, setLimit] = useState(20);

  const { data: agents, loading, refetch } = useApi<Agent[]>(
    () => api.get(`/agents/top-risk?limit=${limit}`),
  );

  useEffect(() => {
    refetch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [limit]);

  const rows = agents ?? [];

  const critCount = rows.filter((a) => a.risk_score >= 75).length;
  const highCount = rows.filter(
    (a) => a.risk_score >= 50 && a.risk_score < 75,
  ).length;
  const medCount = rows.filter(
    (a) => a.risk_score >= 25 && a.risk_score < 50,
  ).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Host Risk Score</h1>
          <p className="text-sm text-white/50 mt-0.5">
            Behavioural risk scoring for endpoints — updated on each detection
            event
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-white/50">Show top</label>
          {[10, 20, 50].map((n) => (
            <button
              key={n}
              onClick={() => setLimit(n)}
              className={`text-xs px-3 py-1.5 rounded-md border transition-colors ${
                limit === n
                  ? "border-blue-500 bg-blue-500/10 text-blue-400"
                  : "border-white/10 text-white/50 hover:text-white hover:border-white/20"
              }`}
            >
              {n}
            </button>
          ))}
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-4">
        {[
          {
            label: "Critical (≥75)",
            count: critCount,
            color: "text-red-400",
            bg: "bg-red-500/10 border-red-500/20",
          },
          {
            label: "High (50–74)",
            count: highCount,
            color: "text-orange-400",
            bg: "bg-orange-500/10 border-orange-500/20",
          },
          {
            label: "Medium (25–49)",
            count: medCount,
            color: "text-yellow-400",
            bg: "bg-yellow-500/10 border-yellow-500/20",
          },
        ].map((s) => (
          <div
            key={s.label}
            className={`rounded-xl border p-4 ${s.bg} flex flex-col gap-1`}
          >
            <p className="text-xs text-white/50">{s.label}</p>
            <p className={`text-3xl font-bold ${s.color}`}>{s.count}</p>
          </div>
        ))}
      </div>

      {/* Table */}
      <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/10">
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40 uppercase tracking-wider">
                Rank
              </th>
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40 uppercase tracking-wider">
                Hostname
              </th>
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40 uppercase tracking-wider">
                OS
              </th>
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40 uppercase tracking-wider w-48">
                Risk Score
              </th>
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40 uppercase tracking-wider">
                Level
              </th>
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40 uppercase tracking-wider">
                Risk Factors
              </th>
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40 uppercase tracking-wider">
                Updated
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {loading && (
              <tr>
                <td colSpan={7} className="px-4 py-10 text-center text-white/30 text-sm">
                  Loading…
                </td>
              </tr>
            )}
            {!loading && rows.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-10 text-center text-white/30 text-sm">
                  No risk data yet — risk scores are updated as the behavioral
                  engine processes events.
                </td>
              </tr>
            )}
            {rows.map((agent, i) => (
              <tr key={agent.id} className="hover:bg-white/[0.02] transition-colors">
                <td className="px-4 py-3 text-white/30 font-mono text-xs">
                  #{i + 1}
                </td>
                <td className="px-4 py-3">
                  <a
                    href={`/agents/${agent.id}`}
                    className="text-white font-medium hover:text-blue-400 transition-colors"
                  >
                    {agent.hostname}
                  </a>
                </td>
                <td className="px-4 py-3 text-white/50 text-xs">{agent.os}</td>
                <td className="px-4 py-3 w-48">
                  <RiskBar score={agent.risk_score} />
                </td>
                <td className="px-4 py-3">
                  <RiskLabel score={agent.risk_score} />
                </td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {(agent.risk_factors ?? []).map((f) => (
                      <span
                        key={f}
                        className="text-xs bg-white/5 border border-white/10 text-white/60 px-2 py-0.5 rounded-full"
                      >
                        {f}
                      </span>
                    ))}
                    {(!agent.risk_factors || agent.risk_factors.length === 0) && (
                      <span className="text-white/20 text-xs">—</span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3 text-white/30 text-xs font-mono">
                  {agent.risk_updated_at
                    ? new Date(agent.risk_updated_at).toLocaleString()
                    : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
