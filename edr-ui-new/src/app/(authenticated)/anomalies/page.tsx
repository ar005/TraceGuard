"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import {
  RefreshCw,
  Activity,
  TrendingUp,
  Server,
  User,
  Filter,
  AlertTriangle,
  CheckCircle2,
} from "lucide-react";

interface AnomalyScore {
  id: string;
  tenant_id: string;
  entity_type: string;
  entity_id: string;
  entity_label: string;
  metric: string;
  z_score: number;
  observed_value: number;
  expected_value: number;
  std_dev: number;
  is_active: boolean;
  detected_at: string;
  resolved_at?: string;
}

interface AnomaliesResponse {
  anomalies: AnomalyScore[];
  total: number;
}

const METRIC_LABELS: Record<string, string> = {
  process_rate: "Process Rate",
  net_bytes_out: "Net Bytes Out",
  distinct_users: "Distinct Users",
  login_count: "Login Count",
  auth_failures: "Auth Failures",
  distinct_hosts: "Distinct Hosts",
};

const METRIC_UNITS: Record<string, string> = {
  process_rate: "proc/5m",
  net_bytes_out: "bytes/5m",
  distinct_users: "users",
  login_count: "logins/5m",
  auth_failures: "failures/5m",
  distinct_hosts: "hosts",
};

function zScoreColor(z: number) {
  const abs = Math.abs(z);
  if (abs >= 6) return "text-red-400 border-red-500/30 bg-red-500/10";
  if (abs >= 4) return "text-orange-400 border-orange-500/30 bg-orange-500/10";
  return "text-amber-400 border-amber-500/30 bg-amber-500/10";
}

function zScoreBar(z: number) {
  const abs = Math.min(Math.abs(z), 10);
  const pct = (abs / 10) * 100;
  const color = abs >= 6 ? "bg-red-500" : abs >= 4 ? "bg-orange-500" : "bg-amber-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-white/5">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="tabular-nums text-xs text-white/60 w-10 text-right">
        {z > 0 ? "+" : ""}{z.toFixed(1)}σ
      </span>
    </div>
  );
}

function fmtVal(metric: string, v: number) {
  if (metric === "net_bytes_out") {
    if (v >= 1_048_576) return (v / 1_048_576).toFixed(1) + " MB";
    if (v >= 1024) return (v / 1024).toFixed(1) + " KB";
    return v.toFixed(0) + " B";
  }
  return v.toFixed(1);
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

export default function AnomaliesPage() {
  const [activeOnly, setActiveOnly] = useState(true);
  const [entityFilter, setEntityFilter] = useState<"all" | "agent" | "user">("all");

  const { data, loading, error, refetch } = useApi<AnomaliesResponse>(
    (signal) => api.get(`/xdr/anomalies?active_only=${activeOnly}&limit=100`, {}, signal),
  );

  const anomalies = (data?.anomalies ?? []).filter(
    (a) => entityFilter === "all" || a.entity_type === entityFilter,
  );

  const activeCount = data?.anomalies?.filter((a) => a.is_active).length ?? 0;
  const agentCount = data?.anomalies?.filter((a) => a.entity_type === "agent").length ?? 0;
  const userCount = data?.anomalies?.filter((a) => a.entity_type === "user").length ?? 0;

  return (
    <div className="space-y-5 max-w-5xl">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Behavioral Anomalies</h1>
          <p className="text-sm text-white/50 mt-0.5">
            EWMA baselines — deviations beyond 3σ from normal behavior
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveOnly(!activeOnly)}
            className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs transition-colors ${
              activeOnly
                ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
                : "border-white/10 text-white/50 hover:text-white"
            }`}
          >
            <Filter size={12} />
            Active only
          </button>
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-white/60 hover:text-white hover:border-white/20 transition-colors"
          >
            <RefreshCw size={13} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "Active anomalies", value: activeCount, icon: AlertTriangle, color: "text-amber-400" },
          { label: "Host anomalies", value: agentCount, icon: Server, color: "text-blue-400" },
          { label: "User anomalies", value: userCount, icon: User, color: "text-violet-400" },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-xl border border-white/10 bg-white/[0.02] p-4 text-center">
            <div className="flex items-center justify-center gap-2">
              <Icon size={14} className={color} />
              <p className={`text-2xl font-bold tabular-nums ${color}`}>{value}</p>
            </div>
            <p className="text-xs text-white/40 mt-0.5">{label}</p>
          </div>
        ))}
      </div>

      {/* Entity type filter */}
      <div className="flex items-center gap-2">
        {(["all", "agent", "user"] as const).map((f) => (
          <button
            key={f}
            onClick={() => setEntityFilter(f)}
            className={`rounded-lg border px-3 py-1 text-xs transition-colors capitalize ${
              entityFilter === f
                ? "border-white/20 bg-white/[0.06] text-white"
                : "border-white/8 text-white/40 hover:text-white/70"
            }`}
          >
            {f === "all" ? "All entities" : f === "agent" ? "Hosts" : "Users"}
          </button>
        ))}
        <span className="text-xs text-white/30 ml-auto">{anomalies.length} result{anomalies.length !== 1 ? "s" : ""}</span>
      </div>

      {loading && (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center text-white/30 text-sm">
          Loading…
        </div>
      )}
      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">{error}</div>
      )}

      {!loading && !error && anomalies.length === 0 && (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center space-y-2">
          <CheckCircle2 size={28} className="mx-auto text-emerald-500/40" />
          <p className="text-white/30 text-sm">No anomalies detected.</p>
          <p className="text-white/20 text-xs">
            Baselines warm up after 10+ samples per metric — check back after a few minutes.
          </p>
        </div>
      )}

      {anomalies.length > 0 && (
        <div className="rounded-xl border border-white/10 overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-white/5 text-white/30">
                <th className="px-4 py-2.5 text-left font-normal">Entity</th>
                <th className="px-4 py-2.5 text-left font-normal">Metric</th>
                <th className="px-4 py-2.5 text-left font-normal w-40">Deviation</th>
                <th className="px-4 py-2.5 text-left font-normal">Observed</th>
                <th className="px-4 py-2.5 text-left font-normal">Status</th>
                <th className="px-4 py-2.5 text-left font-normal">Detected</th>
              </tr>
            </thead>
            <tbody>
              {anomalies.map((a) => (
                <tr key={a.id} className="border-b border-white/5 hover:bg-white/[0.02]">
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      {a.entity_type === "agent" ? (
                        <Server size={12} className="text-blue-400 shrink-0" />
                      ) : (
                        <User size={12} className="text-violet-400 shrink-0" />
                      )}
                      <div>
                        <p className="text-white/80 font-medium truncate max-w-[140px]">
                          {a.entity_label || a.entity_id}
                        </p>
                        <p className="text-white/30 font-mono text-[10px] truncate max-w-[140px]">
                          {a.entity_id}
                        </p>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-1.5">
                      <Activity size={11} className="text-white/30 shrink-0" />
                      <span className="text-white/60">{METRIC_LABELS[a.metric] ?? a.metric}</span>
                    </div>
                    <p className="text-white/25 text-[10px] mt-0.5">{METRIC_UNITS[a.metric]}</p>
                  </td>
                  <td className="px-4 py-2.5 w-40">
                    {zScoreBar(a.z_score)}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium tabular-nums ${zScoreColor(a.z_score)}`}>
                      {fmtVal(a.metric, a.observed_value)}
                    </span>
                    {a.expected_value > 0 && (
                      <p className="text-white/25 text-[10px] mt-0.5">
                        expected ~{fmtVal(a.metric, a.expected_value)}
                      </p>
                    )}
                  </td>
                  <td className="px-4 py-2.5">
                    {a.is_active ? (
                      <span className="flex items-center gap-1 text-amber-400">
                        <TrendingUp size={10} /> Active
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-white/25">
                        <CheckCircle2 size={10} /> Resolved
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-white/40">{timeAgo(a.detected_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
