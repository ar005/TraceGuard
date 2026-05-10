"use client";

import React, { useCallback, useEffect, useRef, useState, useMemo } from "react";
import Link from "next/link";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { timeAgo, formatDate } from "@/lib/utils";
import type { Alert, Event } from "@/types";
import {
  ShieldAlert, MonitorCheck, Activity, TrendingUp,
  ExternalLink, Circle, Network, Users, Server, UserCheck,
} from "lucide-react";

// ── Types ────────────────────────────────────────────────────────────────────

interface TimelinePoint {
  hour: string;
  count: number;
}

interface RiskyUser {
  canonical_uid: string;
  display_name: string;
  risk_score: number;
  is_privileged: boolean;
}

interface XdrSummary {
  sources_total: number;
  sources_online: number;
  top_risky_users: RiskyUser[];
  total_assets: number;
  covered_assets: number;
}

interface DashboardStats {
  total_agents?: number;
  online_agents?: number;
  open_alerts?: number;
  critical_alerts?: number;
  events_today?: number;
  recent_alerts?: Alert[];
  timeline?: TimelinePoint[];
  xdr?: XdrSummary;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function sevLabel(n: number) {
  return ["INFO", "LOW", "MED", "HIGH", "CRIT"][n] ?? "?";
}

function sevClass(n: number): string {
  return (["sev-text-info", "sev-text-low", "sev-text-medium", "sev-text-high", "sev-text-critical"] as const)[n] ?? "sev-text-info";
}

function sevRowClass(n: number): string {
  return (["sev-row-info", "sev-row-low", "sev-row-medium", "sev-row-high", "sev-row-critical"] as const)[n] ?? "";
}

function eventTypeColor(t: string): string {
  const map: Record<string, string> = {
    PROCESS_EXEC: "oklch(0.62 0.14 240)",
    CMD_EXEC:     "oklch(0.62 0.14 295)",
    NET_CONNECT:  "oklch(0.62 0.12 195)",
    FILE_WRITE:   "oklch(0.68 0.15 68)",
    FILE_CREATE:  "oklch(0.65 0.13 80)",
    FILE_DELETE:  "oklch(0.55 0.20 22)",
    BROWSER_REQUEST: "oklch(0.62 0.16 330)",
    NET_DNS:      "oklch(0.58 0.12 185)",
  };
  return map[t?.toUpperCase()] ?? "var(--fg-3)";
}

// ── Subcomponents ─────────────────────────────────────────────────────────────

function StatBar({ stats, loading }: { stats: DashboardStats | null; loading: boolean }) {
  const items = [
    {
      value: stats?.open_alerts ?? 0,
      label: "Open Alerts",
      icon: ShieldAlert,
      urgent: (stats?.open_alerts ?? 0) > 0,
      href: "/alerts",
    },
    {
      value: stats?.critical_alerts ?? 0,
      label: "Critical",
      icon: ShieldAlert,
      urgent: (stats?.critical_alerts ?? 0) > 0,
      href: "/alerts?severity=4",
      large: true,
    },
    {
      value: stats?.online_agents ?? 0,
      label: `of ${stats?.total_agents ?? "—"} Agents Online`,
      icon: MonitorCheck,
      urgent: false,
      href: "/agents",
    },
    {
      value: stats?.events_today ?? 0,
      label: "Events Today",
      icon: Activity,
      urgent: false,
      href: "/events",
    },
  ];

  return (
    <div
      className="flex items-stretch gap-0"
      style={{
        background: "var(--surface-0)",
        border: "1px solid var(--border)",
        borderRadius: "10px",
        overflow: "hidden",
        marginBottom: "var(--space-6)",
      }}
    >
      {items.map((item, i) => (
        <Link
          key={item.label}
          href={item.href}
          className="flex-1 flex flex-col justify-between transition-fast hover:bg-[var(--surface-1)]"
          style={{
            padding: "var(--space-4) var(--space-6)",
            borderRight: i < items.length - 1 ? "1px solid var(--border)" : "none",
            minWidth: 0,
            textDecoration: "none",
          }}
        >
          {loading ? (
            <>
              <div className="animate-shimmer h-7 w-16 mb-2" />
              <div className="animate-shimmer h-3 w-20" />
            </>
          ) : (
            <>
              <span
                className="font-display block"
                style={{
                  fontWeight: 900,
                  fontSize: item.large ? "var(--text-3xl)" : "var(--text-2xl)",
                  lineHeight: 1.1,
                  letterSpacing: "-0.03em",
                  color: item.urgent ? "var(--sev-critical)" : "var(--fg)",
                  fontFamily: "var(--font-archivo)",
                }}
              >
                {item.value.toLocaleString()}
              </span>
              <span style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)", marginTop: "var(--space-1)", display: "block" }}>
                {item.label}
              </span>
            </>
          )}
        </Link>
      ))}
    </div>
  );
}

function AlertRow({ alert }: { alert: Alert }) {
  const sev = alert.severity ?? 0;
  return (
    <Link
      href={`/alerts`}
      className={`flex items-center gap-3 transition-fast ${sevRowClass(sev)}`}
      style={{
        padding: "7px var(--space-4)",
        borderRadius: "6px",
        textDecoration: "none",
        display: "flex",
      }}
    >
      <span
        className="status-dot shrink-0"
        style={{ background: `var(--sev-${["info","low","medium","high","critical"][sev] ?? "info"})` }}
      />
      <span
        className={`font-display shrink-0 ${sevClass(sev)}`}
        style={{ fontWeight: 700, fontSize: "var(--text-xs)", width: "34px", fontFamily: "var(--font-archivo)" }}
      >
        {sevLabel(sev)}
      </span>
      <span style={{ fontSize: "var(--text-sm)", color: "var(--fg)", flex: 1, minWidth: 0 }} className="truncate">
        {alert.rule_name ?? alert.title ?? "Alert"}
      </span>
      <span style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)", flexShrink: 0, whiteSpace: "nowrap" }}>
        {timeAgo(alert.first_seen)}
      </span>
    </Link>
  );
}

function SkeletonAlertRow() {
  return (
    <div className="flex items-center gap-3 px-4 py-2">
      <div className="animate-shimmer w-2 h-2 rounded-full" />
      <div className="animate-shimmer h-3 w-8 rounded" />
      <div className="animate-shimmer h-3 flex-1 rounded" />
      <div className="animate-shimmer h-3 w-12 rounded" />
    </div>
  );
}

const EventStreamItem = React.memo(function EventStreamItem({ event }: { event: Event }) {
  const color = eventTypeColor(event.event_type ?? "");
  const type = (event.event_type ?? "EVENT").replace(/_/g, " ");
  return (
    <div
      className="flex items-start gap-2 transition-fast"
      style={{ padding: "5px var(--space-3)", borderRadius: "4px" }}
    >
      <span
        className="shrink-0 mt-0.5"
        style={{
          width: "6px",
          height: "6px",
          borderRadius: "50%",
          background: color,
          display: "inline-block",
          marginTop: "5px",
        }}
      />
      <div className="min-w-0 flex-1">
        <span
          style={{
            fontSize: "var(--text-xs)",
            fontWeight: 600,
            color,
            fontFamily: "var(--font-archivo)",
            letterSpacing: "0.04em",
            display: "block",
            lineHeight: 1.3,
          }}
        >
          {type}
        </span>
        <span
          style={{
            fontSize: "var(--text-xs)",
            color: "var(--fg-3)",
            display: "block",
            lineHeight: 1.3,
          }}
          className="truncate"
        >
          {event.hostname ?? "unknown"} · {timeAgo(event.timestamp)}
        </span>
      </div>
    </div>
  );
});

// ── Event Timeline Chart ─────────────────────────────────────────────────────

function TimelineChart({ points }: { points: TimelinePoint[] }) {
  const max = Math.max(...points.map((p) => p.count), 1);

  if (points.length === 0) {
    return (
      <div className="flex items-center justify-center" style={{ height: "80px" }}>
        <p style={{ fontSize: "var(--text-xs)", color: "var(--fg-4)" }}>No event data</p>
      </div>
    );
  }

  return (
    <div className="flex items-end gap-px" style={{ height: "80px", width: "100%" }}>
      {points.map((p) => {
        const pct = (p.count / max) * 100;
        const label = p.hour.slice(11, 16); // "HH:MM"
        return (
          <div
            key={p.hour}
            className="flex-1 flex flex-col items-center justify-end gap-0.5"
            title={`${label} — ${p.count.toLocaleString()} events`}
            style={{ height: "100%" }}
          >
            <div
              className="w-full rounded-sm transition-all"
              style={{
                height: `${Math.max(pct, 2)}%`,
                background: "var(--primary)",
                opacity: 0.7,
                minHeight: "2px",
              }}
            />
          </div>
        );
      })}
    </div>
  );
}

// ── Top Alerting Hosts ───────────────────────────────────────────────────────

function TopHosts({ alerts }: { alerts: Alert[] }) {
  const hosts = useMemo(() => {
    const counts: Record<string, { hostname: string; count: number; maxSev: number }> = {};
    for (const a of alerts) {
      const key = a.agent_id;
      if (!counts[key]) counts[key] = { hostname: a.hostname ?? a.agent_id, count: 0, maxSev: 0 };
      counts[key].count++;
      if ((a.severity ?? 0) > counts[key].maxSev) counts[key].maxSev = a.severity ?? 0;
    }
    return Object.values(counts).sort((a, b) => b.count - a.count).slice(0, 5);
  }, [alerts]);

  const maxCount = Math.max(...hosts.map((h) => h.count), 1);

  if (hosts.length === 0) {
    return (
      <div className="flex items-center justify-center py-6">
        <p style={{ fontSize: "var(--text-xs)", color: "var(--fg-4)" }}>No alert data</p>
      </div>
    );
  }

  const sevColors = ["var(--fg-4)", "oklch(0.65 0.15 200)", "oklch(0.70 0.16 80)", "oklch(0.65 0.18 35)", "var(--sev-critical)"];

  return (
    <div className="flex flex-col gap-2">
      {hosts.map((h) => (
        <div key={h.hostname} className="flex items-center gap-2">
          <span
            className="shrink-0 font-mono truncate"
            style={{ fontSize: "var(--text-xs)", color: "var(--fg)", width: "120px" }}
            title={h.hostname}
          >
            {h.hostname}
          </span>
          <div className="flex-1 rounded overflow-hidden" style={{ height: "6px", background: "var(--surface-1)" }}>
            <div
              className="h-full rounded"
              style={{
                width: `${(h.count / maxCount) * 100}%`,
                background: sevColors[h.maxSev] ?? sevColors[0],
                transition: "width 0.3s ease",
              }}
            />
          </div>
          <span
            className="shrink-0 font-mono font-bold"
            style={{ fontSize: "var(--text-xs)", color: sevColors[h.maxSev] ?? "var(--fg-3)", width: "28px", textAlign: "right" }}
          >
            {h.count}
          </span>
        </div>
      ))}
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  // Stats (includes timeline + recent_alerts)
  const fetchStats = useCallback(() => api.get<DashboardStats>("/api/v1/dashboard"), []);
  const { data: stats, loading: statsLoading } = useApi(fetchStats);

  // Recent alerts (top 12, for the open-alerts panel)
  const fetchAlerts = useCallback(
    () => api.get<{ alerts?: Alert[] } | Alert[]>("/api/v1/alerts", { limit: 12, status: "open" })
      .then(r => Array.isArray(r) ? r : r.alerts ?? []),
    []
  );
  const { data: alerts, loading: alertsLoading } = useApi(fetchAlerts);

  // Live event stream (last 40, polled every 8s)
  const [events, setEvents] = useState<Event[]>([]);
  const streamRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadEvents = useCallback(async () => {
    try {
      const res = await api.get<{ events?: Event[] } | Event[]>("/api/v1/events", { limit: 40 });
      const list = Array.isArray(res) ? res : res.events ?? [];
      setEvents(prev => {
        if (prev.length === list.length && prev.every((e, i) => e.id === list[i]?.id)) return prev;
        return list.slice(0, 40);
      });
    } catch {/* ignore */}
  }, []);

  useEffect(() => {
    void loadEvents();

    const start = () => {
      if (streamRef.current) clearInterval(streamRef.current);
      streamRef.current = setInterval(() => void loadEvents(), 8_000);
    };
    const stop = () => {
      if (streamRef.current) { clearInterval(streamRef.current); streamRef.current = null; }
    };
    const onVisibility = () => document.hidden ? stop() : start();

    start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      stop();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [loadEvents]);

  const timeline = stats?.timeline ?? [];
  const recentAlerts = stats?.recent_alerts ?? [];

  return (
    <div style={{ width: "100%" }}>
      {/* Page header */}
      <div
        className="flex items-baseline justify-between"
        style={{ marginBottom: "var(--space-6)" }}
      >
        <h1 className="page-title">Situation Overview</h1>
        <span style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)" }}>
          <TrendingUp size={11} style={{ display: "inline", marginRight: "4px", verticalAlign: "middle" }} />
          auto-refresh every 8s
        </span>
      </div>

      {/* Stat bar */}
      <StatBar stats={stats ?? null} loading={statsLoading} />

      {/* XDR Summary widgets */}
      {(stats?.xdr?.sources_total ?? 0) > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3" style={{ marginBottom: "var(--space-5)" }}>
          {/* Source health */}
          <div
            style={{ background: "var(--surface-0)", border: "1px solid var(--border)", borderRadius: "10px", padding: "var(--space-3)" }}
            className="flex items-center gap-3"
          >
            <Network size={18} style={{ color: "oklch(0.62 0.14 200)", flexShrink: 0 }} />
            <div>
              <p style={{ fontSize: "var(--text-lg)", fontWeight: 700, color: "var(--fg)", lineHeight: 1 }}>
                {stats?.xdr?.sources_online ?? 0}<span style={{ color: "var(--fg-3)", fontWeight: 400, fontSize: "var(--text-sm)" }}>/{stats?.xdr?.sources_total ?? 0}</span>
              </p>
              <p style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)", marginTop: "2px" }}>Sources Online</p>
            </div>
          </div>

          {/* Asset coverage */}
          <div
            style={{ background: "var(--surface-0)", border: "1px solid var(--border)", borderRadius: "10px", padding: "var(--space-3)" }}
            className="flex items-center gap-3"
          >
            <Server size={18} style={{ color: "oklch(0.62 0.14 140)", flexShrink: 0 }} />
            <div>
              {(() => {
                const total = stats?.xdr?.total_assets ?? 0;
                const covered = stats?.xdr?.covered_assets ?? 0;
                const pct = total > 0 ? Math.round((covered / total) * 100) : 0;
                return (
                  <>
                    <p style={{ fontSize: "var(--text-lg)", fontWeight: 700, color: "var(--fg)", lineHeight: 1 }}>{pct}<span style={{ color: "var(--fg-3)", fontWeight: 400, fontSize: "var(--text-sm)" }}>%</span></p>
                    <p style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)", marginTop: "2px" }}>Asset Coverage</p>
                  </>
                );
              })()}
            </div>
          </div>

          {/* Top risky user */}
          <div
            style={{ background: "var(--surface-0)", border: "1px solid var(--border)", borderRadius: "10px", padding: "var(--space-3)" }}
            className="flex items-center gap-3 col-span-2"
          >
            <UserCheck size={18} style={{ color: "oklch(0.62 0.14 35)", flexShrink: 0 }} />
            <div className="min-w-0 flex-1">
              <p style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)", marginBottom: "4px" }}>Top Risk Users</p>
              {(stats?.xdr?.top_risky_users ?? []).length === 0 ? (
                <p style={{ fontSize: "var(--text-xs)", color: "var(--fg-4)" }}>No high-risk users</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {(stats?.xdr?.top_risky_users ?? []).slice(0, 3).map(u => (
                    <span key={u.canonical_uid} className="flex items-center gap-1.5 rounded-md px-2 py-0.5"
                      style={{ background: "var(--surface-1)", fontSize: "var(--text-xs)", color: u.risk_score >= 70 ? "var(--sev-critical)" : u.risk_score >= 40 ? "oklch(0.70 0.16 80)" : "var(--fg-2)" }}>
                      <Users size={10} />
                      <span className="truncate max-w-[120px]">{u.display_name || u.canonical_uid}</span>
                      <span style={{ fontWeight: 700 }}>{u.risk_score}</span>
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Timeline + Top hosts row */}
      <div className="flex flex-wrap gap-6" style={{ marginBottom: "var(--space-6)", alignItems: "flex-start" }}>
        {/* Event timeline */}
        <div className="flex-1" style={{ minWidth: "240px" }}>
          <div className="flex items-center justify-between" style={{ marginBottom: "var(--space-3)" }}>
            <span className="section-label">Event Activity (24h)</span>
          </div>
          <div
            style={{
              background: "var(--surface-0)",
              border: "1px solid var(--border)",
              borderRadius: "10px",
              padding: "var(--space-4) var(--space-4) var(--space-3)",
            }}
          >
            {statsLoading ? (
              <div className="animate-shimmer rounded" style={{ height: "80px" }} />
            ) : (
              <TimelineChart points={timeline} />
            )}
            <div className="flex justify-between mt-2" style={{ color: "var(--fg-4)", fontSize: "10px" }}>
              <span>24h ago</span>
              <span>now</span>
            </div>
          </div>
        </div>

        {/* Top alerting hosts */}
        <div style={{ width: "280px", minWidth: "220px", flexShrink: 0, flex: "0 0 280px" }}>
          <div className="flex items-center justify-between" style={{ marginBottom: "var(--space-3)" }}>
            <span className="section-label">Top Alerting Hosts</span>
            <Link
              href="/alerts"
              className="flex items-center gap-1 transition-fast"
              style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)", textDecoration: "none" }}
            >
              View all <ExternalLink size={10} />
            </Link>
          </div>
          <div
            style={{
              background: "var(--surface-0)",
              border: "1px solid var(--border)",
              borderRadius: "10px",
              padding: "var(--space-4)",
            }}
          >
            {statsLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 4 }).map((_, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <div className="animate-shimmer h-3 w-24 rounded" />
                    <div className="animate-shimmer h-2 flex-1 rounded" />
                    <div className="animate-shimmer h-3 w-6 rounded" />
                  </div>
                ))}
              </div>
            ) : (
              <TopHosts alerts={recentAlerts} />
            )}
          </div>
        </div>
      </div>

      {/* Two-column layout — open alerts + live signal */}
      <div className="flex flex-wrap gap-6" style={{ alignItems: "flex-start" }}>

        {/* Left — open alerts */}
        <div className="flex-1 min-w-0">
          <div
            className="flex items-center justify-between"
            style={{ marginBottom: "var(--space-3)" }}
          >
            <span className="section-label">Open Alerts</span>
            <Link
              href="/alerts"
              className="flex items-center gap-1 transition-fast"
              style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)", textDecoration: "none" }}
            >
              View all <ExternalLink size={10} />
            </Link>
          </div>

          <div
            style={{
              background: "var(--surface-0)",
              border: "1px solid var(--border)",
              borderRadius: "10px",
              overflow: "hidden",
              padding: "var(--space-2)",
            }}
          >
            {alertsLoading ? (
              Array.from({ length: 8 }).map((_, i) => <SkeletonAlertRow key={i} />)
            ) : !alerts?.length ? (
              <div
                className="flex flex-col items-center justify-center gap-2"
                style={{ padding: "var(--space-12) 0", textAlign: "center" }}
              >
                <ShieldAlert size={28} style={{ color: "var(--fg-4)" }} />
                <p style={{ fontSize: "var(--text-sm)", color: "var(--fg-3)" }}>No open alerts</p>
                <p style={{ fontSize: "var(--text-xs)", color: "var(--fg-4)", maxWidth: "28ch" }}>
                  TraceGuard monitors all endpoints continuously. Alerts surface when detection rules fire.
                </p>
              </div>
            ) : (
              alerts.map(a => <AlertRow key={a.id} alert={a} />)
            )}
          </div>
        </div>

        {/* Right — live event signal */}
        <div style={{ width: "280px", minWidth: "220px", flexShrink: 0, flex: "0 0 280px" }}>
          <div
            className="flex items-center justify-between"
            style={{ marginBottom: "var(--space-3)" }}
          >
            <span className="section-label">Live Signal</span>
            <span className="flex items-center gap-1" style={{ fontSize: "var(--text-xs)", color: "var(--status-online)" }}>
              <span className="status-dot status-dot-online" />
              live
            </span>
          </div>

          <div
            style={{
              background: "var(--surface-0)",
              border: "1px solid var(--border)",
              borderRadius: "10px",
              overflow: "hidden",
              padding: "var(--space-2)",
              height: "480px",
              overflowY: "auto",
            }}
          >
            {!events.length ? (
              <div
                style={{ padding: "var(--space-8) var(--space-3)", textAlign: "center" }}
              >
                <Activity size={22} style={{ color: "var(--fg-4)", margin: "0 auto var(--space-2)" }} />
                <p style={{ fontSize: "var(--text-xs)", color: "var(--fg-4)" }}>
                  Waiting for events…
                </p>
              </div>
            ) : (
              events.map(ev => <EventStreamItem key={ev.id} event={ev} />)
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
