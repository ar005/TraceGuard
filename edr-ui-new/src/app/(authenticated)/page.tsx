"use client";

import { useCallback, useMemo, useState } from "react";
import Link from "next/link";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn, timeAgo, severityLabel, severityBgClass, eventTypeColor } from "@/lib/utils";
import type { DashboardData, Agent, Event } from "@/types";
import {
  AreaChart,
  Area,
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

const MONITOR_TYPES = [
  { key: "PROCESS", label: "Process", color: "#22c55e", prefixes: ["PROCESS_"] },
  { key: "NET", label: "Network", color: "#8b5cf6", prefixes: ["NET_CONNECT", "NET_ACCEPT", "NET_CLOSE"] },
  { key: "FILE", label: "File", color: "#3b82f6", prefixes: ["FILE_"] },
  { key: "DNS", label: "DNS", color: "#6366f1", prefixes: ["NET_DNS", "DNS_"] },
  { key: "BROWSER", label: "Browser", color: "#ec4899", prefixes: ["BROWSER_"] },
  { key: "KERNEL", label: "Kernel", color: "#ef4444", prefixes: ["KMOD_"] },
  { key: "USB", label: "USB", color: "#f97316", prefixes: ["USB_"] },
  { key: "MEMORY", label: "Memory", color: "#dc2626", prefixes: ["MEMORY_"] },
  { key: "CRON", label: "Cron", color: "#eab308", prefixes: ["CRON_"] },
  { key: "PIPE", label: "Pipe", color: "#06b6d4", prefixes: ["PIPE_"] },
  { key: "SHARE", label: "Share", color: "#14b8a6", prefixes: ["SHARE_"] },
  { key: "TLS_SNI", label: "TLS SNI", color: "#6366f1", prefixes: ["TLS_SNI"] },
  { key: "AUTH", label: "Auth", color: "#f59e0b", prefixes: ["LOGIN_", "SUDO_"] },
  { key: "CMD", label: "Commands", color: "#10b981", prefixes: ["CMD_"] },
];

const EVENT_TYPE_COLORS: Record<string, string> = {
  PROCESS_EXEC: "#22c55e",
  PROCESS_EXIT: "#16a34a",
  FILE_OPEN: "#3b82f6",
  FILE_CREATE: "#60a5fa",
  FILE_DELETE: "#2563eb",
  FILE_RENAME: "#1d4ed8",
  NET_CONNECT: "#8b5cf6",
  NET_ACCEPT: "#7c3aed",
  DNS_QUERY: "#6366f1",
  BROWSER_REQUEST: "#ec4899",
  KERNEL_MODULE_LOAD: "#ef4444",
  KERNEL_MODULE_UNLOAD: "#dc2626",
  USB_CONNECT: "#f97316",
  USB_DISCONNECT: "#ea580c",
  MEMORY_INJECT: "#dc2626",
  CRON_MODIFY: "#eab308",
  PIPE_CREATE: "#06b6d4",
  NET_TLS_SNI: "#6366f1",
  SHARE_MOUNT: "#14b8a6",
  SHARE_UNMOUNT: "#0d9488",
  USER_LOGIN: "#f59e0b",
  USER_LOGOUT: "#d97706",
  FIM_VIOLATION: "#f43f5e",
};

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
  subValue,
  subLabel,
}: {
  value: number | string;
  label: string;
  borderColor: string;
  subValue?: string;
  subLabel?: string;
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
        {typeof value === "number" ? value.toLocaleString() : value}
      </div>
      <div className="text-xs mt-1" style={{ color: "var(--muted)" }}>
        {label}
      </div>
      {subValue && (
        <div className="text-[10px] font-mono mt-1" style={{ color: "var(--muted-fg)" }}>
          {subValue} {subLabel}
        </div>
      )}
    </div>
  );
}

/* ---------- Mini Stat Card ---------- */
function MiniStatCard({
  value,
  label,
  color,
}: {
  value: string | number;
  label: string;
  color: string;
}) {
  return (
    <div
      className="rounded border px-3 py-2 text-center"
      style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
    >
      <div className="font-mono text-sm font-bold" style={{ color }}>
        {value}
      </div>
      <div className="text-[10px] mt-0.5" style={{ color: "var(--muted)" }}>
        {label}
      </div>
    </div>
  );
}

/* ---------- Section Panel ---------- */
function Panel({
  title,
  children,
  className,
  action,
}: {
  title: string;
  children: React.ReactNode;
  className?: string;
  action?: React.ReactNode;
}) {
  return (
    <div
      className={cn("rounded-lg border p-4", className)}
      style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
    >
      <div className="flex items-center justify-between mb-3">
        <h2
          className="text-sm font-semibold"
          style={{ fontFamily: "var(--font-space-grotesk)" }}
        >
          {title}
        </h2>
        {action}
      </div>
      {children}
    </div>
  );
}

/* ---------- Custom Tooltip ---------- */
function ChartTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ value: number; name: string }>;
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div
      className="rounded-md px-3 py-2 text-xs shadow-lg"
      style={{
        background: "var(--surface-1)",
        border: "1px solid var(--border)",
        color: "var(--fg)",
      }}
    >
      <div className="font-mono mb-1" style={{ color: "var(--muted)" }}>
        {label}
      </div>
      {payload.map((p, i) => (
        <div key={i} className="font-semibold">
          {p.value.toLocaleString()} {p.name}
        </div>
      ))}
    </div>
  );
}

/* ---------- Build timeline from events ---------- */
function buildTimeline(
  events: Event[],
  range: TimeRange
): Array<{ time: string; count: number }> {
  if (!events.length) return [];

  const rangeMs: Record<TimeRange, number> = {
    "1h": 60 * 60 * 1000,
    "6h": 6 * 60 * 60 * 1000,
    "24h": 24 * 60 * 60 * 1000,
    "7d": 7 * 24 * 60 * 60 * 1000,
  };

  const bucketMs: Record<TimeRange, number> = {
    "1h": 5 * 60 * 1000,       // 5 min buckets
    "6h": 30 * 60 * 1000,      // 30 min buckets
    "24h": 60 * 60 * 1000,     // 1 hour buckets
    "7d": 6 * 60 * 60 * 1000,  // 6 hour buckets
  };

  const now = Date.now();
  const start = now - rangeMs[range];
  const bucket = bucketMs[range];
  const bucketCount = Math.ceil(rangeMs[range] / bucket);

  const counts = new Array(bucketCount).fill(0);

  for (const ev of events) {
    const t = new Date(ev.timestamp).getTime();
    if (t < start || t > now) continue;
    const idx = Math.min(Math.floor((t - start) / bucket), bucketCount - 1);
    counts[idx]++;
  }

  const fmt = range === "7d"
    ? (d: Date) => d.toLocaleDateString("en-US", { month: "short", day: "numeric" })
    : (d: Date) => d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: false });

  return counts.map((count, i) => ({
    time: fmt(new Date(start + i * bucket)),
    count,
  }));
}

/* ---------- Build event type distribution ---------- */
function buildEventTypeDist(events: Event[]): Array<{ type: string; count: number; fill: string }> {
  const map: Record<string, number> = {};
  for (const ev of events) {
    const t = ev.event_type || "UNKNOWN";
    map[t] = (map[t] || 0) + 1;
  }
  return Object.entries(map)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([type, count]) => ({
      type,
      count,
      fill: EVENT_TYPE_COLORS[type] || "#6b7280",
    }));
}

/* ---------- Build top alerting agents ---------- */
function buildTopAlertingAgents(
  alerts: Array<{ hostname: string; severity: number }>
): Array<{ hostname: string; count: number; maxSeverity: number }> {
  const map: Record<string, { count: number; maxSev: number }> = {};
  for (const a of alerts) {
    const h = a.hostname || "unknown";
    if (!map[h]) map[h] = { count: 0, maxSev: 0 };
    map[h].count++;
    map[h].maxSev = Math.max(map[h].maxSev, a.severity);
  }
  return Object.entries(map)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 5)
    .map(([hostname, { count, maxSev }]) => ({
      hostname,
      count,
      maxSeverity: maxSev,
    }));
}

/* ---------- Detect active monitor types ---------- */
function detectActiveMonitors(events: Event[]): Set<string> {
  const active = new Set<string>();
  const oneHourAgo = Date.now() - 60 * 60 * 1000;
  for (const ev of events) {
    if (new Date(ev.timestamp).getTime() > oneHourAgo) {
      const t = (ev.event_type || "").toUpperCase();
      for (const m of MONITOR_TYPES) {
        if (m.prefixes.some((p) => t.startsWith(p))) {
          active.add(m.key);
          break;
        }
      }
    }
  }
  return active;
}

/* ---------- Event summary helper ---------- */
function eventSummary(ev: Event): string {
  const p = ev.payload || {};
  const type = (ev.event_type || "").toUpperCase();

  if (type.startsWith("PROCESS")) {
    const comm = (p.comm as string) || (p.filename as string) || "";
    const pid = p.pid ? `PID ${p.pid}` : "";
    return [comm, pid].filter(Boolean).join(" ") || type;
  }
  if (type.startsWith("NET") || type === "DNS_QUERY") {
    const dst = (p.dest_ip as string) || (p.domain as string) || (p.query as string) || "";
    const port = p.dest_port ? `:${p.dest_port}` : "";
    return `${dst}${port}` || type;
  }
  if (type.startsWith("FILE")) {
    return (p.path as string) || (p.filename as string) || type;
  }
  return (p.comm as string) || (p.path as string) || (p.summary as string) || type;
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
  const fetchRecentEvents = useCallback(
    () =>
      api
        .get<{ events?: Event[] } | Event[]>("/api/v1/events", { limit: 500 })
        .then((r) => (Array.isArray(r) ? r : r.events ?? [])),
    []
  );

  const { data: dash, loading: dashLoading, error: dashError } = useApi(fetchDashboard);
  const { data: agents, loading: agentsLoading } = useApi(fetchAgents);
  const { data: recentEvents, loading: eventsLoading } = useApi(fetchRecentEvents);

  const allAgents = agents ?? [];
  const onlineAgents = allAgents.filter((a) => a.is_online);
  const events = recentEvents ?? [];

  /* Derived data */
  const chartData = SEVERITY_ORDER.map((sev) => ({
    name: sev,
    count: dash?.alert_stats?.by_severity?.[sev] ?? 0,
    fill: SEVERITY_COLORS[sev] ?? "#6b7280",
  }));

  const timelineData = useMemo(() => buildTimeline(events, range), [events, range]);
  const eventTypeDist = useMemo(() => buildEventTypeDist(events), [events]);
  const topAlertingAgents = useMemo(
    () => buildTopAlertingAgents(dash?.recent_alerts ?? []),
    [dash?.recent_alerts]
  );
  const activeMonitors = useMemo(() => detectActiveMonitors(events), [events]);

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
    <div className="animate-fade-in space-y-4">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div>
          <h1
            className="text-lg font-semibold"
            style={{ fontFamily: "var(--font-space-grotesk)" }}
          >
            Command Center
          </h1>
          <p className="text-xs mt-0.5" style={{ color: "var(--muted)" }}>
            Real-time endpoint security overview
          </p>
        </div>

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

      {/* Stat cards row */}
      {dashLoading ? (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <StatCardSkeleton key={i} />
          ))}
        </div>
      ) : dash ? (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <StatCard
            value={dash.events_24h}
            label="Total Events"
            borderColor="#3b82f6"
          />
          <StatCard
            value={dash.alert_stats?.open ?? 0}
            label="Open Alerts"
            borderColor="#ef4444"
            subValue={`${dash.alert_stats?.investigating ?? 0}`}
            subLabel="investigating"
          />
          <StatCard
            value={onlineAgents.length}
            label="Online Agents"
            borderColor="#22c55e"
            subValue={`${allAgents.length}`}
            subLabel="total"
          />
          <StatCard
            value={dash.alert_stats?.total ?? 0}
            label="Total Alerts"
            borderColor="#a855f7"
          />
          <StatCard
            value={dash.alert_stats?.by_severity?.["CRITICAL"] ?? 0}
            label="Critical"
            borderColor="#ef4444"
          />
          <StatCard
            value={dash.alert_stats?.by_severity?.["HIGH"] ?? 0}
            label="High Severity"
            borderColor="#f97316"
          />
        </div>
      ) : null}

      {/* Events timeline — full width */}
      <Panel title="Events Timeline">
        {eventsLoading ? (
          <SkeletonBox className="h-40 w-full" />
        ) : timelineData.length > 0 ? (
          <ResponsiveContainer width="100%" height={160}>
            <AreaChart data={timelineData} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
              <defs>
                <linearGradient id="eventsFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="var(--primary)" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <XAxis
                dataKey="time"
                tick={{ fill: "var(--muted)", fontSize: 10 }}
                axisLine={false}
                tickLine={false}
                interval="preserveStartEnd"
              />
              <YAxis
                tick={{ fill: "var(--muted)", fontSize: 10 }}
                axisLine={false}
                tickLine={false}
                width={36}
              />
              <Tooltip content={<ChartTooltip />} />
              <Area
                type="monotone"
                dataKey="count"
                name="events"
                stroke="var(--primary)"
                strokeWidth={1.5}
                fill="url(#eventsFill)"
              />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <p className="text-xs py-8 text-center" style={{ color: "var(--muted)" }}>
            No event data for the selected range
          </p>
        )}
      </Panel>

      {/* Middle row: severity chart + event type distribution + top alerting agents */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Alerts by severity chart */}
        <Panel title="Alerts by Severity">
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
                <Tooltip content={<ChartTooltip />} />
                <Bar dataKey="count" name="alerts" radius={[0, 4, 4, 0]} barSize={18}>
                  {chartData.map((entry) => (
                    <Cell key={entry.name} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </Panel>

        {/* Event Type Distribution */}
        <Panel title="Event Type Distribution">
          {eventsLoading ? (
            <SkeletonBox className="h-48 w-full" />
          ) : eventTypeDist.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart
                data={eventTypeDist}
                layout="vertical"
                margin={{ left: 4, right: 16 }}
              >
                <XAxis type="number" hide />
                <YAxis
                  type="category"
                  dataKey="type"
                  width={100}
                  tick={{ fill: "var(--muted)", fontSize: 10, fontFamily: "var(--font-jetbrains-mono)" }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip content={<ChartTooltip />} />
                <Bar dataKey="count" name="events" radius={[0, 4, 4, 0]} barSize={14}>
                  {eventTypeDist.map((entry) => (
                    <Cell key={entry.type} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-xs py-8 text-center" style={{ color: "var(--muted)" }}>
              No events in range
            </p>
          )}
        </Panel>

        {/* Top Alerting Agents */}
        <Panel title="Top Alerting Agents">
          {dashLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 4 }).map((_, i) => (
                <SkeletonBox key={i} className="h-7 w-full" />
              ))}
            </div>
          ) : topAlertingAgents.length > 0 ? (
            <div className="space-y-1.5">
              {topAlertingAgents.map((agent) => {
                const maxCount = topAlertingAgents[0]?.count || 1;
                const pct = (agent.count / maxCount) * 100;
                return (
                  <div key={agent.hostname}>
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className="font-medium truncate" style={{ color: "var(--fg)" }}>
                        {agent.hostname}
                      </span>
                      <div className="flex items-center gap-2">
                        <span
                          className={cn(
                            "inline-flex items-center rounded px-1 py-0.5 text-[9px] font-semibold uppercase",
                            severityBgClass(agent.maxSeverity)
                          )}
                        >
                          {severityLabel(agent.maxSeverity)}
                        </span>
                        <span className="font-mono" style={{ color: "var(--muted)" }}>
                          {agent.count}
                        </span>
                      </div>
                    </div>
                    <div
                      className="h-1.5 rounded-full overflow-hidden"
                      style={{ background: "var(--surface-2)" }}
                    >
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{
                          width: `${pct}%`,
                          background: agent.maxSeverity >= 3 ? "#ef4444" : "var(--primary)",
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <p className="text-xs py-8 text-center" style={{ color: "var(--muted)" }}>
              No alerting agents
            </p>
          )}
        </Panel>
      </div>

      {/* Active Monitors + System Health row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Active Monitor Status */}
        <Panel title="Active Monitors">
          {eventsLoading ? (
            <SkeletonBox className="h-24 w-full" />
          ) : (
            <div className="grid grid-cols-4 sm:grid-cols-7 gap-2">
              {MONITOR_TYPES.map((m) => {
                const isActive = activeMonitors.has(m.key);
                return (
                  <div
                    key={m.key}
                    className="flex flex-col items-center gap-1 rounded px-1.5 py-2"
                    style={{
                      background: isActive ? "var(--surface-1)" : "transparent",
                    }}
                  >
                    <span
                      className="inline-flex h-2.5 w-2.5 rounded-full"
                      style={{
                        background: isActive ? m.color : "var(--surface-2)",
                        boxShadow: isActive ? `0 0 6px ${m.color}50` : "none",
                      }}
                    />
                    <span
                      className="text-[9px] font-medium text-center leading-tight"
                      style={{ color: isActive ? "var(--fg)" : "var(--muted-fg)" }}
                    >
                      {m.label}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>

        {/* System Health */}
        <Panel title="System Health">
          {dashLoading || agentsLoading ? (
            <SkeletonBox className="h-24 w-full" />
          ) : (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <MiniStatCard
                value={`${onlineAgents.length}/${allAgents.length}`}
                label="Agents Online"
                color="#22c55e"
              />
              <MiniStatCard
                value={dash?.alert_stats?.open ?? 0}
                label="Open Alerts"
                color={
                  (dash?.alert_stats?.open ?? 0) > 0 ? "#ef4444" : "#22c55e"
                }
              />
              <MiniStatCard
                value={events.length > 0 ? "Active" : "Idle"}
                label="Event Ingest"
                color={events.length > 0 ? "#22c55e" : "#6b7280"}
              />
              <MiniStatCard
                value={activeMonitors.size}
                label="Active Probes"
                color="var(--primary)"
              />
            </div>
          )}
        </Panel>
      </div>

      {/* Bottom row: Recent Alerts + Recent Events */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recent alerts */}
        <Panel
          title="Recent Alerts"
          action={
            <Link
              href="/alerts"
              className="text-[10px] font-medium transition-colors hover:underline"
              style={{ color: "var(--primary)" }}
            >
              View all
            </Link>
          }
        >
          {dashLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <SkeletonBox key={i} className="h-8 w-full" />
              ))}
            </div>
          ) : (
            <div className="space-y-0.5">
              {(dash?.recent_alerts ?? []).slice(0, 8).map((alert) => (
                <Link
                  key={alert.id}
                  href="/alerts"
                  className="flex items-center gap-2 rounded px-2 py-1.5 text-xs transition-colors hover:bg-[var(--surface-2)]"
                >
                  <span
                    className={cn(
                      "inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase shrink-0",
                      severityBgClass(alert.severity)
                    )}
                  >
                    {severityLabel(alert.severity)}
                  </span>
                  <span className="flex-1 truncate" style={{ color: "var(--fg)" }}>
                    {alert.title}
                  </span>
                  <span className="shrink-0 text-[10px]" style={{ color: "var(--muted)" }}>
                    {alert.hostname}
                  </span>
                  <span className="shrink-0 font-mono text-[10px]" style={{ color: "var(--muted-fg)" }}>
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
        </Panel>

        {/* Recent Events */}
        <Panel
          title="Latest Events"
          action={
            <Link
              href="/events"
              className="text-[10px] font-medium transition-colors hover:underline"
              style={{ color: "var(--primary)" }}
            >
              View all
            </Link>
          }
        >
          {eventsLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <SkeletonBox key={i} className="h-8 w-full" />
              ))}
            </div>
          ) : events.length > 0 ? (
            <div className="space-y-0.5">
              {events.slice(0, 10).map((ev) => (
                <Link
                  key={ev.id}
                  href="/events"
                  className="flex items-center gap-2 rounded px-2 py-1.5 text-xs transition-colors hover:bg-[var(--surface-2)]"
                >
                  <span
                    className={cn(
                      "inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase shrink-0",
                      eventTypeColor(ev.event_type)
                    )}
                    style={{ background: "var(--surface-2)" }}
                  >
                    {(ev.event_type || "").replace(/_/g, " ")}
                  </span>
                  <span
                    className="flex-1 truncate font-mono text-[11px]"
                    style={{ color: "var(--fg)" }}
                  >
                    {eventSummary(ev)}
                  </span>
                  <span className="shrink-0 text-[10px]" style={{ color: "var(--muted)" }}>
                    {ev.hostname}
                  </span>
                  <span className="shrink-0 font-mono text-[10px]" style={{ color: "var(--muted-fg)" }}>
                    {timeAgo(ev.timestamp)}
                  </span>
                </Link>
              ))}
            </div>
          ) : (
            <p className="text-xs py-4 text-center" style={{ color: "var(--muted)" }}>
              No recent events
            </p>
          )}
        </Panel>
      </div>

      {/* Online agents */}
      <Panel
        title="Online Agents"
        action={
          <Link
            href="/agents"
            className="text-[10px] font-medium transition-colors hover:underline"
            style={{ color: "var(--primary)" }}
          >
            View all
          </Link>
        }
      >
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
          <div className="grid grid-cols-1 md:grid-cols-2 gap-x-4">
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
                <span className="font-mono text-[10px]" style={{ color: "var(--muted)" }}>
                  {agent.ip}
                </span>
                <span className="font-mono text-[10px]" style={{ color: "var(--muted-fg)" }}>
                  {agent.os} {agent.agent_ver ? `v${agent.agent_ver}` : ""}
                </span>
                <span className="ml-auto font-mono text-[10px]" style={{ color: "var(--muted-fg)" }}>
                  {timeAgo(agent.last_seen)}
                </span>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
