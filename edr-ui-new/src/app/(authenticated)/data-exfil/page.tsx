"use client";

import { useCallback, useState } from "react";
import Link from "next/link";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn, timeAgo } from "@/lib/utils";

/* ---------- Types ---------- */
interface ExfilSignal {
  id: string;
  agent_id: string;
  hostname: string;
  signal_type: "usb_bulk_copy" | "large_outbound" | "cloud_upload";
  detail: unknown;
  bytes: number;
  detected_at: string;
  alert_id: string;
}

interface ExfilAgentStat {
  agent_id: string;
  hostname: string;
  event_count: number;
  total_bytes: number;
  last_seen: string;
}

type TimeRange = "24h" | "7d" | "30d";

/* ---------- Helpers ---------- */
function formatBytes(b: number): string {
  if (b >= 1_073_741_824) return `${(b / 1_073_741_824).toFixed(1)} GB`;
  if (b >= 1_048_576)     return `${(b / 1_048_576).toFixed(1)} MB`;
  if (b >= 1_024)         return `${(b / 1_024).toFixed(1)} KB`;
  return `${b} B`;
}

function signalTypeBadge(type: ExfilSignal["signal_type"]): string {
  switch (type) {
    case "usb_bulk_copy":   return "text-orange-400 bg-orange-500/10 border-orange-500/20";
    case "large_outbound":  return "text-red-400 bg-red-500/10 border-red-500/20";
    case "cloud_upload":    return "text-blue-400 bg-blue-500/10 border-blue-500/20";
  }
}

function signalTypeLabel(type: ExfilSignal["signal_type"]): string {
  switch (type) {
    case "usb_bulk_copy":  return "USB Bulk Copy";
    case "large_outbound": return "Large Outbound";
    case "cloud_upload":   return "Cloud Upload";
  }
}

const TIME_RANGE_HOURS: Record<TimeRange, number> = {
  "24h": 24,
  "7d": 168,
  "30d": 720,
};

/* ---------- Data Exfil Page ---------- */
export default function DataExfilPage() {
  const [timeRange, setTimeRange] = useState<TimeRange>("24h");
  const [agentFilter, setAgentFilter] = useState("");
  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  const hours = TIME_RANGE_HOURS[timeRange];

  /* Stats */
  const fetchStats = useCallback(
    (signal: AbortSignal) =>
      api.get<{ stats: ExfilAgentStat[] }>("/api/v1/dlp/stats", { hours }, signal),
    [hours]
  );
  const { data: statsData, loading: statsLoading, error: statsError } = useApi(fetchStats);

  /* Events */
  const fetchEvents = useCallback(
    (signal: AbortSignal) =>
      api.get<{ events: ExfilSignal[]; total: number }>("/api/v1/dlp/events", {
        limit: 100,
        offset: 0,
        agent_id: agentFilter || undefined,
      }, signal),
    [agentFilter]
  );
  const { data: eventsData, loading: eventsLoading, error: eventsError } = useApi(fetchEvents);

  const stats = statsData?.stats ?? [];
  const events = eventsData?.events ?? [];

  /* Summaries */
  const totalEvents = stats.reduce((s, a) => s + a.event_count, 0);
  const totalBytes  = stats.reduce((s, a) => s + a.total_bytes, 0);
  const uniqueAgents = stats.length;

  const usbCount      = events.filter((e) => e.signal_type === "usb_bulk_copy").length;
  const outboundCount = events.filter((e) => e.signal_type === "large_outbound").length;
  const cloudCount    = events.filter((e) => e.signal_type === "cloud_upload").length;

  return (
    <div className="animate-fade-in space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Data Exfiltration</h1>
          <p className="text-sm text-white/50 mt-0.5">USB bulk transfers, large outbound connections, and cloud upload detection</p>
        </div>
        <div className="flex items-center gap-1">
          {(["24h", "7d", "30d"] as TimeRange[]).map((r) => (
            <button
              key={r}
              onClick={() => setTimeRange(r)}
              className={cn(
                "px-3 py-1.5 text-xs rounded-lg border transition-colors",
                timeRange === r
                  ? "border-white/20 bg-white/[0.08] text-white"
                  : "border-white/10 text-white/40 hover:text-white/70 hover:bg-white/5"
              )}
            >
              {r}
            </button>
          ))}
        </div>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3">
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <p className="text-xs text-white/40 uppercase tracking-wider mb-1">Exfil Events</p>
          {statsLoading ? (
            <div className="h-7 w-10 rounded animate-pulse bg-white/5" />
          ) : (
            <p className="text-2xl font-semibold text-white">{totalEvents.toLocaleString()}</p>
          )}
        </div>

        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <p className="text-xs text-white/40 uppercase tracking-wider mb-1">Data Volume</p>
          {statsLoading ? (
            <div className="h-7 w-16 rounded animate-pulse bg-white/5" />
          ) : (
            <p className="text-2xl font-semibold text-white">{formatBytes(totalBytes)}</p>
          )}
        </div>

        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <p className="text-xs text-white/40 uppercase tracking-wider mb-1">Affected Agents</p>
          {statsLoading ? (
            <div className="h-7 w-8 rounded animate-pulse bg-white/5" />
          ) : (
            <p className={cn("text-2xl font-semibold", uniqueAgents > 0 ? "text-orange-400" : "text-white")}>
              {uniqueAgents}
            </p>
          )}
        </div>

        {/* Signal breakdown mini-stats */}
        <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-4">
          <p className="text-xs text-orange-400/60 uppercase tracking-wider mb-1">USB</p>
          <p className="text-2xl font-semibold text-orange-400">{usbCount}</p>
        </div>

        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4">
          <p className="text-xs text-red-400/60 uppercase tracking-wider mb-1">Outbound</p>
          <p className="text-2xl font-semibold text-red-400">{outboundCount}</p>
        </div>

        <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-4">
          <p className="text-xs text-blue-400/60 uppercase tracking-wider mb-1">Cloud</p>
          <p className="text-2xl font-semibold text-blue-400">{cloudCount}</p>
        </div>
      </div>

      {/* Errors */}
      {statsError && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">{statsError}</div>
      )}

      {/* Agents at Risk */}
      <div className="space-y-2">
        <h2 className="text-sm font-semibold text-white/70 uppercase tracking-wider">Agents at Risk</h2>
        {statsLoading ? (
          <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center text-white/30 text-sm">
            Loading…
          </div>
        ) : (
          <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-white/[0.06]">
                  <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Agent</th>
                  <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Hostname</th>
                  <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Events</th>
                  <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Total Data</th>
                  <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Last Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04]">
                {stats.map((stat) => (
                  <tr
                    key={stat.agent_id}
                    onClick={() => setAgentFilter(agentFilter === stat.agent_id ? "" : stat.agent_id)}
                    className={cn(
                      "cursor-pointer transition-colors",
                      agentFilter === stat.agent_id
                        ? "bg-white/[0.05]"
                        : "hover:bg-white/[0.03]"
                    )}
                  >
                    <td className="px-4 py-2.5 font-mono text-white/50">{stat.agent_id.slice(0, 12)}…</td>
                    <td className="px-4 py-2.5 font-medium text-white">{stat.hostname || "—"}</td>
                    <td className="px-4 py-2.5">
                      <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold bg-orange-500/10 text-orange-400 border border-orange-500/20">
                        {stat.event_count}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-white/70">{formatBytes(stat.total_bytes)}</td>
                    <td className="px-4 py-2.5 font-mono text-white/40">{timeAgo(stat.last_seen)}</td>
                  </tr>
                ))}
                {stats.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-10 text-center text-white/30">No exfiltration data for this time range</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
        {agentFilter && (
          <button
            onClick={() => setAgentFilter("")}
            className="text-xs text-white/30 hover:text-white/60 transition-colors"
          >
            ✕ Clear agent filter
          </button>
        )}
      </div>

      {/* Exfil Events */}
      <div className="space-y-2">
        <h2 className="text-sm font-semibold text-white/70 uppercase tracking-wider">
          Exfil Events
          {agentFilter && <span className="ml-2 text-white/30 normal-case font-normal">(filtered)</span>}
        </h2>

        {eventsError && (
          <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">{eventsError}</div>
        )}

        {eventsLoading && events.length === 0 ? (
          <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center text-white/30 text-sm">
            Loading…
          </div>
        ) : (
          <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-white/[0.06]">
                  <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Time</th>
                  <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Agent</th>
                  <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Type</th>
                  <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Data</th>
                  <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Detail</th>
                  <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Alert</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04]">
                {events.map((evt) => {
                  const isExpanded = expandedRow === evt.id;
                  return (
                    <>
                      <tr key={evt.id} className="hover:bg-white/[0.03] transition-colors">
                        <td className="px-4 py-2.5 font-mono text-white/40 whitespace-nowrap">{timeAgo(evt.detected_at)}</td>
                        <td className="px-4 py-2.5">
                          <p className="font-medium text-white">{evt.hostname || "—"}</p>
                          <p className="text-[10px] text-white/30 font-mono">{evt.agent_id.slice(0, 8)}…</p>
                        </td>
                        <td className="px-4 py-2.5">
                          <span className={cn(
                            "rounded px-1.5 py-0.5 text-[10px] font-semibold border",
                            signalTypeBadge(evt.signal_type)
                          )}>
                            {signalTypeLabel(evt.signal_type)}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 font-mono text-white/70">{formatBytes(evt.bytes)}</td>
                        <td className="px-4 py-2.5">
                          <button
                            onClick={() => setExpandedRow(isExpanded ? null : evt.id)}
                            className="px-2 py-0.5 text-[10px] rounded border border-white/10 text-white/40 hover:text-white/70 hover:bg-white/5 transition-colors"
                          >
                            {isExpanded ? "Hide" : "View"}
                          </button>
                        </td>
                        <td className="px-4 py-2.5">
                          {evt.alert_id ? (
                            <Link
                              href={`/alerts?id=${evt.alert_id}`}
                              className="px-2 py-0.5 text-[10px] rounded border border-white/10 text-white/40 hover:text-white/70 hover:bg-white/5 transition-colors inline-block"
                            >
                              Alert ↗
                            </Link>
                          ) : (
                            <span className="text-white/20">—</span>
                          )}
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr key={`${evt.id}-detail`} className="bg-white/[0.02]">
                          <td colSpan={6} className="px-4 py-3">
                            <pre className="rounded-lg bg-black/30 p-3 text-[10px] leading-relaxed overflow-x-auto max-h-48 text-white/60 font-mono">
                              {JSON.stringify(evt.detail, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </>
                  );
                })}
                {events.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-4 py-10 text-center text-white/30">No exfil events found</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
