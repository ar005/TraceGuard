"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { timeAgo, formatDate } from "@/lib/utils";
import type { Alert, Event } from "@/types";
import {
  ShieldAlert, MonitorCheck, Activity, TrendingUp,
  ExternalLink, Circle,
} from "lucide-react";

// ── Types ────────────────────────────────────────────────────────────────────

interface DashboardStats {
  total_agents?: number;
  online_agents?: number;
  open_alerts?: number;
  critical_alerts?: number;
  events_today?: number;
  total_events?: number;
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
      value: stats?.events_today ?? stats?.total_events ?? 0,
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

function EventStreamItem({ event }: { event: Event }) {
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
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  // Stats
  const fetchStats = useCallback(() => api.get<DashboardStats>("/api/v1/dashboard"), []);
  const { data: stats, loading: statsLoading } = useApi(fetchStats);

  // Recent alerts (top 12)
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
      setEvents(list.slice(0, 40));
    } catch {/* ignore */}
  }, []);

  useEffect(() => {
    void loadEvents();
    streamRef.current = setInterval(() => void loadEvents(), 8_000);
    return () => { if (streamRef.current) clearInterval(streamRef.current); };
  }, [loadEvents]);

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

      {/* Two-column layout — stacks on narrow screens */}
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
