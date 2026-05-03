"use client";

import { useCallback, useState } from "react";
import Link from "next/link";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn, timeAgo, severityLabel, severityBgClass } from "@/lib/utils";
import type { Alert, Event } from "@/types";

/* ---------- Types ---------- */
interface DnsStats {
  top_domains: { domain: string; count: number; agent_count: number }[];
  hours: number;
}

/* ---------- Helpers ---------- */
function extractDomain(event: Event): string {
  const p = event.payload as Record<string, unknown>;
  return (
    (typeof p?.query === "string" ? p.query : null) ||
    (typeof p?.name === "string" ? p.name : null) ||
    "—"
  );
}

function extractSrcIp(event: Event): string {
  const p = event.payload as Record<string, unknown>;
  return (
    (typeof p?.src_ip === "string" ? p.src_ip : null) ||
    (typeof p?.source_ip === "string" ? p.source_ip : null) ||
    "—"
  );
}

function severityDotClass(sev: number): string {
  switch (sev) {
    case 4: return "bg-red-500";
    case 3: return "bg-orange-500";
    case 2: return "bg-amber-500";
    case 1: return "bg-blue-500";
    default: return "bg-neutral-500";
  }
}

/* ---------- DNS Page ---------- */
export default function DnsPage() {
  const [agentIdFilter, setAgentIdFilter] = useState("");
  const [domainFilter, setDomainFilter] = useState("");
  const [appliedAgentId, setAppliedAgentId] = useState("");
  const [appliedDomain, setAppliedDomain] = useState("");
  const [limit, setLimit] = useState(100);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  function applyFilters() {
    setAppliedAgentId(agentIdFilter.trim());
    setAppliedDomain(domainFilter.trim());
    setLimit(100);
  }

  /* Stats */
  const { data: statsData, loading: statsLoading } = useApi(
    useCallback((signal: AbortSignal) =>
      api.get<DnsStats>("/api/v1/dns/stats", { hours: 24 }, signal),
      []
    )
  );

  /* Events */
  const fetchEvents = useCallback(
    (signal: AbortSignal) =>
      api.get<{ events: Event[]; total: number }>("/api/v1/dns/events", {
        limit,
        offset: 0,
        agent_id: appliedAgentId || undefined,
        domain: appliedDomain || undefined,
      }, signal),
    [limit, appliedAgentId, appliedDomain]
  );
  const { data: eventsData, loading: eventsLoading, error: eventsError } = useApi(fetchEvents);

  /* DNS Tunnel Alerts */
  const { data: tunnelData, loading: tunnelLoading } = useApi(
    useCallback((signal: AbortSignal) =>
      api.get<{ alerts: Alert[] }>("/api/v1/alerts", {
        rule_id_prefix: "rule-dns-tunnel",
        limit: 20,
      }, signal),
      []
    )
  );

  const events = eventsData?.events ?? [];
  const totalEvents = eventsData?.total ?? 0;
  const topDomains = statsData?.top_domains ?? [];
  const tunnelAlerts = tunnelData?.alerts ?? [];
  const maxDomainCount = topDomains.length > 0 ? topDomains[0].count : 1;

  return (
    <div className="animate-fade-in space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-white">DNS Intelligence</h1>
        <p className="text-sm text-white/50 mt-0.5">DNS tunneling detection and query analytics</p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <input
          type="text"
          placeholder="Agent ID…"
          value={agentIdFilter}
          onChange={(e) => setAgentIdFilter(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && applyFilters()}
          className="rounded-lg border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs text-white placeholder:text-white/30 outline-none focus:border-white/20 w-52"
        />
        <input
          type="text"
          placeholder="Domain filter…"
          value={domainFilter}
          onChange={(e) => setDomainFilter(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && applyFilters()}
          className="rounded-lg border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs text-white placeholder:text-white/30 outline-none focus:border-white/20 w-52"
        />
        <button
          onClick={applyFilters}
          className="px-3 py-1.5 text-xs rounded-lg border border-white/10 hover:bg-white/5 text-white/60 hover:text-white transition-colors"
        >
          Apply
        </button>
        {(appliedAgentId || appliedDomain) && (
          <button
            onClick={() => {
              setAgentIdFilter("");
              setDomainFilter("");
              setAppliedAgentId("");
              setAppliedDomain("");
            }}
            className="px-3 py-1.5 text-xs rounded-lg border border-white/10 hover:bg-white/5 text-white/40 hover:text-white/70 transition-colors"
          >
            Clear
          </button>
        )}
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-3">
        {/* Tunnel Detections */}
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <p className="text-xs text-white/40 uppercase tracking-wider mb-1">Tunnel Detections</p>
          {tunnelLoading ? (
            <div className="h-7 w-12 rounded animate-pulse bg-white/5" />
          ) : (
            <p className="text-2xl font-semibold text-red-400">{tunnelAlerts.length}</p>
          )}
        </div>

        {/* Top Domain */}
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <p className="text-xs text-white/40 uppercase tracking-wider mb-1">Top Domain</p>
          {statsLoading ? (
            <div className="h-7 w-36 rounded animate-pulse bg-white/5" />
          ) : (
            <p className="text-sm font-mono font-semibold text-white truncate">
              {topDomains[0]?.domain ?? "—"}
            </p>
          )}
          {topDomains[0] && (
            <p className="text-xs text-white/30 mt-0.5">{topDomains[0].count.toLocaleString()} queries</p>
          )}
        </div>

        {/* Queries Analysed */}
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <p className="text-xs text-white/40 uppercase tracking-wider mb-1">Queries Analysed</p>
          {eventsLoading && totalEvents === 0 ? (
            <div className="h-7 w-16 rounded animate-pulse bg-white/5" />
          ) : (
            <p className="text-2xl font-semibold text-white">{totalEvents.toLocaleString()}</p>
          )}
        </div>
      </div>

      {/* Two-column grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* DNS Events Table — col-span-2 */}
        <div className="lg:col-span-2 space-y-2">
          <h2 className="text-sm font-semibold text-white/70 uppercase tracking-wider">DNS Events</h2>

          {eventsError && (
            <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">
              {eventsError}
            </div>
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
                    <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Type</th>
                    <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Agent</th>
                    <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Hostname</th>
                    <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Domain</th>
                    <th className="text-xs font-medium text-white/40 uppercase tracking-wider px-4 py-3 text-left">Src IP</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.04]">
                  {events.map((evt) => {
                    const isExpanded = expandedRow === evt.id;
                    const domain = extractDomain(evt);
                    return (
                      <>
                        <tr
                          key={evt.id}
                          onClick={() => setExpandedRow(isExpanded ? null : evt.id)}
                          className="hover:bg-white/[0.03] transition-colors cursor-pointer"
                        >
                          <td className="px-4 py-2.5 font-mono text-white/40 whitespace-nowrap">{timeAgo(evt.timestamp)}</td>
                          <td className="px-4 py-2.5">
                            <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                              {evt.event_type}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 font-mono text-white/50 truncate max-w-[80px]">{evt.agent_id.slice(0, 8)}…</td>
                          <td className="px-4 py-2.5 text-white truncate max-w-[100px]">{evt.hostname || "—"}</td>
                          <td className="px-4 py-2.5 font-mono text-cyan-300 truncate max-w-[160px]">{domain}</td>
                          <td className="px-4 py-2.5 font-mono text-white/50">{extractSrcIp(evt)}</td>
                        </tr>
                        {isExpanded && (
                          <tr key={`${evt.id}-detail`} className="bg-white/[0.02]">
                            <td colSpan={6} className="px-4 py-3">
                              <pre className="rounded-lg bg-black/30 p-3 text-[10px] leading-relaxed overflow-x-auto max-h-48 text-white/60 font-mono">
                                {JSON.stringify(evt.payload, null, 2)}
                              </pre>
                            </td>
                          </tr>
                        )}
                      </>
                    );
                  })}
                  {events.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-10 text-center text-white/30">No DNS events found</td>
                    </tr>
                  )}
                </tbody>
              </table>

              {events.length >= limit && (
                <div className="border-t border-white/[0.06] p-3 flex justify-center">
                  <button
                    onClick={() => setLimit((l) => l + 100)}
                    className="px-3 py-1.5 text-xs rounded-lg border border-white/10 hover:bg-white/5 text-white/60 hover:text-white transition-colors"
                  >
                    Load more
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Top Queried Domains */}
        <div className="space-y-2">
          <h2 className="text-sm font-semibold text-white/70 uppercase tracking-wider">Top Queried Domains</h2>
          {statsLoading ? (
            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center text-white/30 text-sm">
              Loading…
            </div>
          ) : (
            <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden divide-y divide-white/[0.04]">
              {topDomains.slice(0, 15).map((item) => {
                const pct = Math.max(4, Math.round((item.count / maxDomainCount) * 100));
                return (
                  <button
                    key={item.domain}
                    onClick={() => {
                      setDomainFilter(item.domain);
                      setAppliedDomain(item.domain);
                    }}
                    className="w-full px-4 py-2.5 hover:bg-white/[0.03] transition-colors text-left"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-mono text-xs text-white truncate max-w-[150px]">{item.domain}</span>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className="text-[10px] text-white/30">{item.count.toLocaleString()}</span>
                        <span className="text-[10px] text-white/20">·</span>
                        <span className="text-[10px] text-white/30">{item.agent_count} agent{item.agent_count !== 1 ? "s" : ""}</span>
                      </div>
                    </div>
                    <div className="h-1 rounded-full bg-white/5 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-indigo-500/50"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </button>
                );
              })}
              {topDomains.length === 0 && (
                <div className="px-4 py-10 text-center text-white/30 text-xs">No domain data</div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* DNS Tunnel Alerts */}
      <div className="space-y-2">
        <h2 className="text-sm font-semibold text-white/70 uppercase tracking-wider">DNS Tunnel Alerts</h2>
        {tunnelLoading ? (
          <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center text-white/30 text-sm">
            Loading…
          </div>
        ) : tunnelAlerts.length === 0 ? (
          <div className="rounded-xl border border-white/10 bg-white/[0.02] p-6 text-center text-white/30 text-sm">
            No DNS tunnel alerts detected
          </div>
        ) : (
          <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden divide-y divide-white/[0.04]">
            {tunnelAlerts.map((alert) => (
              <div key={alert.id} className="flex items-center gap-3 px-4 py-3 hover:bg-white/[0.03] transition-colors">
                <span className={cn("h-2 w-2 rounded-full shrink-0", severityDotClass(alert.severity))} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium text-white truncate">{alert.title}</p>
                  <p className="text-[10px] text-white/40 mt-0.5">{alert.hostname || alert.agent_id}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className={cn(
                    "rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                    severityBgClass(alert.severity)
                  )}>
                    {severityLabel(alert.severity)}
                  </span>
                  <span className="text-[10px] text-white/30 font-mono">{timeAgo(alert.first_seen)}</span>
                  <span className={cn(
                    "rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                    alert.status === "open" ? "bg-red-500/15 text-red-400" :
                    alert.status === "investigating" ? "bg-amber-500/15 text-amber-400" :
                    "bg-emerald-500/15 text-emerald-400"
                  )}>
                    {alert.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
