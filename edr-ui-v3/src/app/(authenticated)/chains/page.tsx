"use client";

import { useState, useCallback } from "react";
import Link from "next/link";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn, timeAgo, formatDate } from "@/lib/utils";

/* ─── Types ──────────────────────────────────────────────────────────────── */

interface ChainSummary {
  id: string;
  agent_id: string;
  hostname: string;
  root_comm: string;
  root_cmdline: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  alert_count: number;
  is_active: boolean;
}

interface ChainEvent {
  id: string;
  event_type: string;
  timestamp: string;
  hostname: string;
  payload: Record<string, unknown>;
  chain_id: string;
}

/* ─── Helpers ────────────────────────────────────────────────────────────── */

function ActiveBadge({ active }: { active: boolean }) {
  return (
    <span
      className={cn(
        "px-1.5 py-0.5 rounded text-[10px] font-medium uppercase tracking-wide",
        active
          ? "bg-emerald-500/15 text-emerald-400"
          : "bg-neutral-500/15 text-neutral-400"
      )}
    >
      {active ? "Active" : "Ended"}
    </span>
  );
}

function AlertBadge({ count }: { count: number }) {
  if (count === 0) return <span className="text-neutral-500 text-xs">—</span>;
  return (
    <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-red-500/15 text-red-400">
      {count} alert{count !== 1 ? "s" : ""}
    </span>
  );
}

function SkeletonRow() {
  return (
    <tr className="border-b border-neutral-800/50">
      {[...Array(8)].map((_, i) => (
        <td key={i} className="px-3 py-3">
          <div className="h-3 bg-neutral-800 rounded animate-pulse w-3/4" />
        </td>
      ))}
    </tr>
  );
}

/** Format duration between two ISO timestamps as "Xh Ym" or "Xm Ys" */
function formatDuration(first: string, last: string): string {
  const ms = new Date(last).getTime() - new Date(first).getTime();
  if (ms < 0) return "—";
  const totalSec = Math.floor(ms / 1000);
  if (totalSec < 60) return `${totalSec}s`;
  const totalMin = Math.floor(totalSec / 60);
  if (totalMin < 60) {
    const s = totalSec % 60;
    return s > 0 ? `${totalMin}m ${s}s` : `${totalMin}m`;
  }
  const h = Math.floor(totalMin / 60);
  const m = totalMin % 60;
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

/** Extract event type badge color */
function eventTypeColor(evType: string): string {
  if (evType.startsWith("PROCESS")) return "bg-violet-500/15 text-violet-400";
  if (evType.startsWith("NET") || evType.startsWith("DNS")) return "bg-sky-500/15 text-sky-400";
  if (evType.startsWith("FILE") || evType.startsWith("FIM")) return "bg-amber-500/15 text-amber-400";
  if (evType.startsWith("AUTH") || evType.startsWith("LOGIN") || evType.startsWith("SUDO")) return "bg-orange-500/15 text-orange-400";
  if (evType.startsWith("YARA") || evType.startsWith("MEMORY")) return "bg-red-500/15 text-red-400";
  return "bg-neutral-500/15 text-neutral-400";
}

/** Extract a brief human-readable summary from an event payload */
function eventSummary(evType: string, payload: Record<string, unknown>): string {
  try {
    if (evType === "NET_CONNECT" || evType === "NET_ACCEPT") {
      const dst_ip = payload.dst_ip as string | undefined;
      const dst_port = payload.dst_port as number | undefined;
      if (dst_ip) return `${dst_ip}${dst_port ? `:${dst_port}` : ""}`;
    }
    if (evType === "NET_DNS") {
      const q = payload.dns_query as string | undefined;
      return q ?? "";
    }
    if (evType === "FILE_CREATE" || evType === "FILE_WRITE" || evType === "FILE_DELETE" || evType === "FILE_RENAME") {
      const path = payload.path as string | undefined;
      return path ?? "";
    }
    if (evType === "PROCESS_EXEC") {
      const proc = payload.process as Record<string, unknown> | undefined;
      const cmdline = proc?.cmdline as string | undefined;
      return cmdline ? cmdline.slice(0, 60) : "";
    }
    if (evType === "PROCESS_FORK") {
      const child = payload.child_pid as number | undefined;
      return child ? `child pid ${child}` : "";
    }
    if (evType === "TLS_SNI") {
      const domain = payload.domain as string | undefined;
      return domain ?? "";
    }
    if (evType === "YARA_MATCH") {
      return (payload.yara_rule as string | undefined) ?? "";
    }
  } catch {
    // ignore
  }
  return "";
}

/** Extract process comm from an event payload */
function processComm(payload: Record<string, unknown>): string {
  const proc = payload.process as Record<string, unknown> | undefined;
  return (proc?.comm as string | undefined) ?? "";
}

/* ─── Chain detail panel ─────────────────────────────────────────────────── */

function ChainDetail({
  chain,
  onClose,
}: {
  chain: ChainSummary;
  onClose: () => void;
}) {
  const fetchEvents = useCallback(
    (_signal: AbortSignal) =>
      api.get<{ events: ChainEvent[] }>(
        `/api/v1/chains/${chain.id}/events?limit=200`
      ),
    [chain.id]
  );
  const { data, loading } = useApi(fetchEvents);
  const events = data?.events ?? [];

  // Build simple process tree from PROCESS_EXEC events
  const processNames: string[] = [];
  for (const ev of events) {
    if (ev.event_type === "PROCESS_EXEC") {
      const proc = ev.payload?.process as Record<string, unknown> | undefined;
      const comm = (proc?.comm as string | undefined) ?? "";
      if (comm && !processNames.includes(comm)) {
        processNames.push(comm);
      }
    }
  }

  const duration = formatDuration(chain.first_seen, chain.last_seen);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-end">
      <div
        className="absolute inset-0 bg-black/40 backdrop-blur-sm"
        onClick={onClose}
      />
      <aside className="relative z-10 w-full max-w-2xl h-screen bg-neutral-950 border-l border-neutral-800 flex flex-col overflow-hidden">
        {/* Header */}
        <div className="px-5 py-4 border-b border-neutral-800 flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-xs text-neutral-400">{chain.id}</span>
              <ActiveBadge active={chain.is_active} />
              <AlertBadge count={chain.alert_count} />
            </div>
            <p className="mt-1 font-mono text-sm text-white truncate" title={chain.root_cmdline}>
              {chain.root_cmdline || chain.root_comm || "(unknown)"}
            </p>
            <p className="text-xs text-neutral-500 mt-0.5">{chain.hostname}</p>
          </div>
          <button
            onClick={onClose}
            className="shrink-0 text-neutral-400 hover:text-white transition-colors text-lg leading-none"
          >
            ✕
          </button>
        </div>

        {/* Stats bar */}
        <div className="grid grid-cols-4 divide-x divide-neutral-800 border-b border-neutral-800 text-xs">
          {[
            ["Events", chain.event_count.toLocaleString()],
            ["Duration", duration],
            ["First seen", timeAgo(chain.first_seen)],
            ["Last seen", timeAgo(chain.last_seen)],
          ].map(([label, value]) => (
            <div key={label} className="px-4 py-3">
              <p className="text-neutral-500 uppercase tracking-wide text-[10px]">{label}</p>
              <p className="text-white font-medium mt-0.5">{value}</p>
            </div>
          ))}
        </div>

        {/* Alert callout */}
        {chain.alert_count > 0 && (
          <div className="mx-5 mt-4 px-4 py-3 rounded-lg border border-red-500/30 bg-red-500/10 flex items-center justify-between gap-4">
            <p className="text-red-400 text-sm font-medium">
              ⚠ {chain.alert_count} alert{chain.alert_count !== 1 ? "s" : ""} triggered in this chain
            </p>
            <Link
              href={`/alerts?chain_id=${chain.id}`}
              className="shrink-0 text-xs px-3 py-1.5 rounded border border-red-500/40 text-red-400 hover:bg-red-500/15 transition-colors"
            >
              View alerts
            </Link>
          </div>
        )}

        {/* Process tree */}
        {processNames.length > 0 && (
          <div className="mx-5 mt-4">
            <p className="text-[10px] uppercase tracking-wide text-neutral-500 mb-2">Process chain</p>
            <div className="font-mono text-xs text-neutral-300 flex flex-wrap items-center gap-1">
              {processNames.map((name, i) => (
                <span key={i} className="flex items-center gap-1">
                  {i > 0 && <span className="text-neutral-600">→</span>}
                  <span className="px-1.5 py-0.5 rounded bg-violet-500/10 text-violet-300">{name}</span>
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Event timeline */}
        <div className="flex-1 overflow-y-auto mt-4">
          <p className="px-5 text-[10px] uppercase tracking-wide text-neutral-500 mb-2">Event timeline</p>
          {loading ? (
            <div className="p-6 text-center text-neutral-500 text-sm">Loading events…</div>
          ) : events.length === 0 ? (
            <div className="p-6 text-center text-neutral-500 text-sm">No events</div>
          ) : (
            <div className="divide-y divide-neutral-800/40">
              {events.map((ev) => {
                const summary = eventSummary(ev.event_type, ev.payload ?? {});
                const comm = processComm(ev.payload ?? {});
                return (
                  <div key={ev.id} className="px-5 py-2.5 hover:bg-neutral-800/20 flex items-start gap-3">
                    <div className="shrink-0 pt-0.5">
                      <span className={cn("px-1.5 py-0.5 rounded text-[10px] font-mono font-medium whitespace-nowrap", eventTypeColor(ev.event_type))}>
                        {ev.event_type}
                      </span>
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 text-xs">
                        <span className="text-neutral-500 whitespace-nowrap">{formatDate(ev.timestamp)}</span>
                        {comm && (
                          <span className="font-mono text-neutral-300 truncate">{comm}</span>
                        )}
                      </div>
                      {summary && (
                        <p className="text-neutral-500 text-xs font-mono truncate mt-0.5" title={summary}>
                          {summary}
                        </p>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </aside>
    </div>
  );
}

/* ─── Page ───────────────────────────────────────────────────────────────── */

const PAGE_SIZE = 50;

export default function ChainsPage() {
  const [page, setPage]               = useState(0);
  const [hostnameFilter, setHostname] = useState("");
  const [rootCommFilter, setRootComm] = useState("");
  const [activeFilter, setActive]     = useState<"" | "true" | "false">("");
  const [hasAlertsFilter, setHasAlerts] = useState(false);
  const [selected, setSelected]       = useState<ChainSummary | null>(null);

  const qs = new URLSearchParams({
    limit:  String(PAGE_SIZE),
    offset: String(page * PAGE_SIZE),
    ...(hostnameFilter   ? { hostname: hostnameFilter }   : {}),
    ...(rootCommFilter   ? { root_comm: rootCommFilter }  : {}),
    ...(activeFilter     ? { active: activeFilter }       : {}),
    ...(hasAlertsFilter  ? { has_alerts: "true" }         : {}),
  }).toString();

  const fetchChains = useCallback(
    (_signal: AbortSignal) =>
      api.get<{ chains: ChainSummary[]; total: number }>(
        `/api/v1/chains?${qs}`
      ),
    [qs]
  );
  const { data, loading, error } = useApi(fetchChains);

  const chains = data?.chains ?? [];
  const total  = data?.total  ?? 0;
  const pages  = Math.ceil(total / PAGE_SIZE);

  return (
    <div className="p-6 space-y-5">
      {/* Page header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-white">Execution Chains</h1>
          <p className="text-sm text-neutral-400 mt-0.5">
            Causal process chains across all endpoints
          </p>
        </div>
        <span className="text-xs text-neutral-500">{total.toLocaleString()} chains</span>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <input
          type="text"
          placeholder="Filter by hostname…"
          value={hostnameFilter}
          onChange={(e) => { setHostname(e.target.value); setPage(0); }}
          className="w-52 px-3 py-1.5 text-sm bg-neutral-900 border border-neutral-700 rounded text-white placeholder-neutral-500 focus:outline-none focus:border-neutral-500"
        />

        <input
          type="text"
          placeholder="Filter by process name / cmdline…"
          value={rootCommFilter}
          onChange={(e) => { setRootComm(e.target.value); setPage(0); }}
          className="w-64 px-3 py-1.5 text-sm bg-neutral-900 border border-neutral-700 rounded text-white placeholder-neutral-500 focus:outline-none focus:border-neutral-500"
        />

        {/* Active filter pills */}
        <div className="flex rounded overflow-hidden border border-neutral-700 text-xs">
          {(["", "true", "false"] as const).map((v) => (
            <button
              key={v}
              onClick={() => { setActive(v); setPage(0); }}
              className={cn(
                "px-3 py-1.5 transition-colors",
                activeFilter === v
                  ? "bg-neutral-700 text-white"
                  : "text-neutral-400 hover:text-white"
              )}
            >
              {v === "" ? "All" : v === "true" ? "Active" : "Ended"}
            </button>
          ))}
        </div>

        {/* Has-alerts filter pill */}
        <button
          onClick={() => { setHasAlerts((v) => !v); setPage(0); }}
          className={cn(
            "px-3 py-1.5 rounded border text-xs transition-colors",
            hasAlertsFilter
              ? "border-red-500/50 bg-red-500/15 text-red-400"
              : "border-neutral-700 text-neutral-400 hover:text-white"
          )}
        >
          ⚠ Has alerts
        </button>
      </div>

      {/* Table */}
      <div className="rounded-lg border border-neutral-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="border-b border-neutral-800 bg-neutral-900/50">
            <tr>
              <th className="px-3 py-2.5 text-left text-xs text-neutral-400 font-normal">Chain ID</th>
              <th className="px-3 py-2.5 text-left text-xs text-neutral-400 font-normal">Host</th>
              <th className="px-3 py-2.5 text-left text-xs text-neutral-400 font-normal">Root process</th>
              <th className="px-3 py-2.5 text-left text-xs text-neutral-400 font-normal">Status</th>
              <th className="px-3 py-2.5 text-left text-xs text-neutral-400 font-normal">Alerts</th>
              <th className="px-3 py-2.5 text-left text-xs text-neutral-400 font-normal">Events</th>
              <th className="px-3 py-2.5 text-left text-xs text-neutral-400 font-normal">Duration</th>
              <th className="px-3 py-2.5 text-left text-xs text-neutral-400 font-normal">Last seen</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              [...Array(10)].map((_, i) => <SkeletonRow key={i} />)
            ) : error ? (
              <tr>
                <td colSpan={8} className="px-3 py-8 text-center text-red-400 text-sm">
                  Failed to load chains
                </td>
              </tr>
            ) : chains.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-3 py-8 text-center text-neutral-500 text-sm">
                  No chains yet — they appear as agents report events
                </td>
              </tr>
            ) : (
              chains.map((chain) => (
                <tr
                  key={chain.id}
                  onClick={() => setSelected(chain)}
                  className="border-b border-neutral-800/50 hover:bg-neutral-800/30 cursor-pointer transition-colors"
                >
                  <td className="px-3 py-2.5 font-mono text-xs text-neutral-300">
                    {chain.id}
                  </td>
                  <td className="px-3 py-2.5 text-neutral-300">{chain.hostname}</td>
                  <td className="px-3 py-2.5 font-mono text-xs text-neutral-300 max-w-xs truncate" title={chain.root_cmdline}>
                    {chain.root_cmdline || chain.root_comm || <span className="text-neutral-500">—</span>}
                  </td>
                  <td className="px-3 py-2.5">
                    <ActiveBadge active={chain.is_active} />
                  </td>
                  <td className="px-3 py-2.5">
                    <AlertBadge count={chain.alert_count} />
                  </td>
                  <td className="px-3 py-2.5 text-neutral-400">
                    {chain.event_count.toLocaleString()}
                  </td>
                  <td className="px-3 py-2.5 text-neutral-400 text-xs whitespace-nowrap">
                    {formatDuration(chain.first_seen, chain.last_seen)}
                  </td>
                  <td className="px-3 py-2.5 text-neutral-400">
                    {timeAgo(chain.last_seen)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {pages > 1 && (
        <div className="flex items-center justify-between text-xs text-neutral-400">
          <span>
            {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of{" "}
            {total.toLocaleString()}
          </span>
          <div className="flex gap-2">
            <button
              disabled={page === 0}
              onClick={() => setPage((p) => p - 1)}
              className="px-3 py-1.5 rounded border border-neutral-700 disabled:opacity-40 hover:border-neutral-500 transition-colors"
            >
              Prev
            </button>
            <button
              disabled={page >= pages - 1}
              onClick={() => setPage((p) => p + 1)}
              className="px-3 py-1.5 rounded border border-neutral-700 disabled:opacity-40 hover:border-neutral-500 transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      )}

      {/* Detail panel */}
      {selected && (
        <ChainDetail chain={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}
