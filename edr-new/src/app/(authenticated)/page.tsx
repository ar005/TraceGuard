"use client";

import { useCallback, useState } from "react";
import Link from "next/link";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn, timeAgo, severityLabel, severityBgClass } from "@/lib/utils";
import type { DashboardData, Agent } from "@/types";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

const TIME_RANGES = ["1h", "6h", "24h", "7d"] as const;
type TimeRange = (typeof TIME_RANGES)[number];

const SEVERITY_COLORS: Record<string, string> = {
  INFO: "#3b82f6",
  LOW: "#22c55e",
  MEDIUM: "#eab308",
  HIGH: "#f97316",
  CRITICAL: "#ef4444",
};

const SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

/* ---------- Skeleton helpers ---------- */
function SkeletonBox({ className }: { className?: string }) {
  return <div className={cn("animate-shimmer rounded", className)} />;
}

function StatCardSkeleton() {
  return (
    <div
      className="rounded-lg border-l-2 p-4"
      style={{
        background: "var(--surface-0)",
        borderColor: "var(--border)",
        borderRightColor: "var(--border)",
        borderTopColor: "var(--border)",
        borderBottomColor: "var(--border)",
        borderRightWidth: 1,
        borderTopWidth: 1,
        borderBottomWidth: 1,
      }}
    >
      <SkeletonBox className="h-8 w-20 mb-2" />
      <SkeletonBox className="h-4 w-24" />
    </div>
  );
}

/* ---------- Stat Card ---------- */
function StatCard({
  value,
  label,
  borderColor,
}: {
  value: number;
  label: string;
  borderColor: string;
}) {
  return (
    <div
      className="rounded-lg border p-4"
      style={{
        background: "var(--surface-0)",
        borderColor: "var(--border)",
        borderLeftWidth: 2,
        borderLeftColor: borderColor,
      }}
    >
      <div className="font-mono text-2xl font-bold" style={{ color: "var(--fg)" }}>
        {value.toLocaleString()}
      </div>
      <div className="text-xs mt-1" style={{ color: "var(--muted)" }}>
        {label}
      </div>
    </div>
  );
}

/* ---------- Dashboard Page ---------- */
export default function DashboardPage() {
  const [range, setRange] = useState<TimeRange>("24h");

  const fetchDashboard = useCallback(
    () => api.get<DashboardData>("/api/v1/dashboard", { range }),
    [range]
  );
  const fetchAgents = useCallback(
    () =>
      api
        .get<{ agents?: Agent[] } | Agent[]>("/api/v1/agents")
        .then((r) => (Array.isArray(r) ? r : r.agents ?? [])),
    []
  );

  const { data: dash, loading: dashLoading, error: dashError } = useApi(fetchDashboard);
  const { data: agents, loading: agentsLoading } = useApi(fetchAgents);

  const onlineAgents = (agents ?? []).filter((a) => a.is_online);

  /* Build chart data from by_severity */
  const chartData = SEVERITY_ORDER.map((sev) => ({
    name: sev,
    count: dash?.alert_stats?.by_severity?.[sev] ?? 0,
    fill: SEVERITY_COLORS[sev] ?? "#6b7280",
  }));

  if (dashError) {
    return (
      <div className="animate-fade-in p-6">
        <h1
          className="text-lg font-semibold mb-4"
          style={{ fontFamily: "var(--font-space-grotesk)" }}
        >
          Dashboard
        </h1>
        <div
          className="rounded-lg border p-6 text-center"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
        >
          <p className="text-sm text-red-400 mb-2">Failed to load dashboard data</p>
          <p className="text-xs" style={{ color: "var(--muted)" }}>
            {dashError}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="animate-fade-in space-y-5">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <h1
          className="text-lg font-semibold"
          style={{ fontFamily: "var(--font-space-grotesk)" }}
        >
          Dashboard
        </h1>

        {/* Time range selector */}
        <div
          className="flex rounded-md overflow-hidden border text-xs"
          style={{ borderColor: "var(--border)" }}
        >
          {TIME_RANGES.map((r) => (
            <button
              key={r}
              onClick={() => setRange(r)}
              className={cn(
                "px-3 py-1.5 font-medium transition-colors uppercase",
                r === range
                  ? "text-[var(--primary-fg)]"
                  : "hover:bg-[var(--surface-2)]"
              )}
              style={{
                background: r === range ? "var(--primary)" : "var(--surface-0)",
                color: r === range ? "var(--primary-fg)" : "var(--muted)",
              }}
            >
              {r}
            </button>
          ))}
        </div>
      </div>

      {/* Stat cards */}
      {dashLoading ? (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <StatCardSkeleton key={i} />
          ))}
        </div>
      ) : dash ? (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <StatCard value={dash.events_24h} label="Total Events" borderColor="#3b82f6" />
          <StatCard
            value={dash.alert_stats?.open ?? 0}
            label="Open Alerts"
            borderColor="#ef4444"
          />
          <StatCard value={dash.agents_online} label="Online Agents" borderColor="#22c55e" />
          <StatCard
            value={dash.alert_stats?.total ?? 0}
            label="Active Rules"
            borderColor="#a855f7"
          />
        </div>
      ) : null}

      {/* Middle row: chart + recent alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Alerts by severity chart */}
        <div
          className="rounded-lg border p-4"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
        >
          <h2
            className="text-sm font-semibold mb-3"
            style={{ fontFamily: "var(--font-space-grotesk)" }}
          >
            Alerts by Severity
          </h2>
          {dashLoading ? (
            <SkeletonBox className="h-48 w-full" />
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={chartData} layout="vertical" margin={{ left: 8, right: 16 }}>
                <XAxis type="number" hide />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={70}
                  tick={{ fill: "var(--muted)", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    background: "var(--surface-1)",
                    border: "1px solid var(--border)",
                    borderRadius: 6,
                    fontSize: 12,
                    color: "var(--fg)",
                  }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={18}>
                  {chartData.map((entry) => (
                    <Cell key={entry.name} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Recent alerts */}
        <div
          className="rounded-lg border p-4"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
        >
          <h2
            className="text-sm font-semibold mb-3"
            style={{ fontFamily: "var(--font-space-grotesk)" }}
          >
            Recent Alerts
          </h2>
          {dashLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <SkeletonBox key={i} className="h-8 w-full" />
              ))}
            </div>
          ) : (
            <div className="space-y-1">
              {(dash?.recent_alerts ?? []).slice(0, 5).map((alert) => (
                <Link
                  key={alert.id}
                  href="/alerts"
                  className="flex items-center gap-3 rounded px-2 py-1.5 text-xs transition-colors hover:bg-[var(--surface-2)]"
                >
                  <span
                    className={cn(
                      "inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                      severityBgClass(alert.severity)
                    )}
                  >
                    {severityLabel(alert.severity)}
                  </span>
                  <span className="flex-1 truncate" style={{ color: "var(--fg)" }}>
                    {alert.title}
                  </span>
                  <span className="shrink-0" style={{ color: "var(--muted)" }}>
                    {alert.hostname}
                  </span>
                  <span className="shrink-0 font-mono" style={{ color: "var(--muted-fg)" }}>
                    {timeAgo(alert.last_seen || alert.first_seen)}
                  </span>
                </Link>
              ))}
              {(dash?.recent_alerts ?? []).length === 0 && (
                <p className="text-xs py-4 text-center" style={{ color: "var(--muted)" }}>
                  No recent alerts
                </p>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Online agents */}
      <div
        className="rounded-lg border p-4"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
      >
        <h2
          className="text-sm font-semibold mb-3"
          style={{ fontFamily: "var(--font-space-grotesk)" }}
        >
          Online Agents
        </h2>
        {agentsLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 3 }).map((_, i) => (
              <SkeletonBox key={i} className="h-7 w-full" />
            ))}
          </div>
        ) : onlineAgents.length === 0 ? (
          <p className="text-xs py-4 text-center" style={{ color: "var(--muted)" }}>
            No agents online
          </p>
        ) : (
          <div className="space-y-1">
            {onlineAgents.map((agent) => (
              <div
                key={agent.id}
                className="flex items-center gap-3 rounded px-2 py-1.5 text-xs"
              >
                <span className="relative flex h-2 w-2 shrink-0">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
                </span>
                <span className="font-medium" style={{ color: "var(--fg)" }}>
                  {agent.hostname}
                </span>
                <span className="font-mono" style={{ color: "var(--muted)" }}>
                  {agent.ip}
                </span>
                <span className="ml-auto font-mono" style={{ color: "var(--muted-fg)" }}>
                  {timeAgo(agent.last_seen)}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
