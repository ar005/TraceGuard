"use client";

import { useState, useCallback } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn } from "@/lib/utils";
import { Cloud, RefreshCw } from "lucide-react";

const EVENT_TYPE_COLORS: Record<string, string> = {
  CLOUD_API:      "text-neutral-400 bg-neutral-500/10 border-neutral-500/20",
  CLOUD_MUTATION: "text-amber-400 bg-amber-500/10 border-amber-500/20",
  AUTH_LOGIN:     "text-blue-400 bg-blue-500/10 border-blue-500/20",
  AUTH_LOGOFF:    "text-violet-400 bg-violet-500/10 border-violet-500/20",
  POLICY_CHANGE:  "text-red-400 bg-red-500/10 border-red-500/20",
};

interface XdrEvent {
  id: string;
  event_type: string;
  timestamp: string;
  source_type: string;
  source_id: string;
  user_uid: string;
  src_ip?: string;
  class_uid: number;
  payload: unknown;
  enrichments: unknown;
  raw_log: string;
}

const TYPE_FILTERS = ["", "CLOUD_API", "CLOUD_MUTATION", "AUTH_LOGIN", "AUTH_LOGOFF", "POLICY_CHANGE"];

export default function CloudEventsPage() {
  const [eventTypeFilter, setEventTypeFilter] = useState("");
  const [sourceId, setSourceId] = useState("");
  const [sourceIdInput, setSourceIdInput] = useState("");
  const [offset, setOffset] = useState(0);
  const [allEvents, setAllEvents] = useState<XdrEvent[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const limit = 100;

  const fetchEvents = useCallback(
    async (signal: AbortSignal) => {
      const res = await api.get<{ events?: XdrEvent[] }>(
        "/api/v1/xdr/events",
        { source_type: "cloud", limit, offset, event_type: eventTypeFilter || undefined, source_id: sourceId || undefined },
        signal
      );
      return res;
    },
    [eventTypeFilter, sourceId, offset]
  );

  const { data, loading, error, refetch } = useApi(fetchEvents);

  // Accumulate for load-more
  const [prevOffset, setPrevOffset] = useState(0);
  if (data && offset !== prevOffset) {
    setPrevOffset(offset);
    setAllEvents((prev) => (offset === 0 ? (data.events ?? []) : [...prev, ...(data.events ?? [])]));
  } else if (data && offset === 0 && allEvents.length === 0 && (data.events?.length ?? 0) > 0) {
    setAllEvents(data.events ?? []);
  }

  function applyFilters() {
    setSourceId(sourceIdInput);
    setOffset(0);
    setAllEvents([]);
  }

  function handleTypeFilter(t: string) {
    setEventTypeFilter(t);
    setOffset(0);
    setAllEvents([]);
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-semibold text-white flex items-center gap-2">
            <Cloud size={20} className="text-sky-400" /> Cloud Events
          </h1>
          <p className="text-sm text-white/50 mt-0.5">AWS CloudTrail · Azure Monitor · GCP Audit Log</p>
        </div>
        <button
          onClick={() => { setOffset(0); setAllEvents([]); refetch(); }}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg border border-white/10 hover:bg-white/5 text-white/60 hover:text-white transition-colors"
        >
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        {TYPE_FILTERS.map((t) => (
          <button
            key={t || "all"}
            onClick={() => handleTypeFilter(t)}
            className={cn(
              "px-3 py-1 text-xs font-medium rounded-lg border transition-colors",
              eventTypeFilter === t
                ? "border-blue-500 bg-blue-500/10 text-blue-400"
                : "border-white/10 text-white/40 hover:text-white hover:border-white/20"
            )}
          >
            {t || "All"}
          </button>
        ))}
        <div className="ml-auto flex items-center gap-2">
          <input
            value={sourceIdInput}
            onChange={(e) => setSourceIdInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && applyFilters()}
            placeholder="Source ID…"
            className="px-3 py-1 text-xs rounded-lg border border-white/10 bg-white/[0.03] text-white placeholder-white/30 focus:outline-none focus:border-white/20 w-44"
          />
          <button
            onClick={applyFilters}
            className="px-3 py-1 text-xs rounded-lg border border-white/10 hover:bg-white/5 text-white/60 hover:text-white transition-colors"
          >
            Filter
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 px-4 py-3 text-sm text-red-400">{error}</div>
      )}

      {/* Table */}
      <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/10">
              {["Time", "Type", "User", "Source", "Src IP", ""].map((h) => (
                <th key={h} className="text-left px-4 py-3 text-xs font-medium text-white/40 uppercase tracking-wider whitespace-nowrap">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.04]">
            {allEvents.map((ev) => (
              <>
                <tr
                  key={ev.id}
                  onClick={() => setExpanded((p) => (p === ev.id ? null : ev.id))}
                  className="hover:bg-white/[0.03] cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3 text-xs font-mono text-white/40 whitespace-nowrap">
                    {new Date(ev.timestamp).toLocaleString()}
                  </td>
                  <td className="px-4 py-3">
                    <span className={cn(
                      "inline-block px-2 py-0.5 rounded border text-xs font-mono font-semibold",
                      EVENT_TYPE_COLORS[ev.event_type] ?? "text-neutral-400 bg-neutral-500/10 border-neutral-500/20"
                    )}>
                      {ev.event_type}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-white/70 max-w-[160px] truncate">{ev.user_uid || "—"}</td>
                  <td className="px-4 py-3 text-xs font-mono text-white/40 max-w-[140px] truncate">
                    {ev.source_id || ev.source_type}
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-white/40">{ev.src_ip ?? "—"}</td>
                  <td className="px-4 py-3 text-white/30 text-xs">{expanded === ev.id ? "▲" : "▼"}</td>
                </tr>
                {expanded === ev.id && (
                  <tr key={ev.id + "-detail"} className="bg-black/20">
                    <td colSpan={6} className="px-4 py-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <p className="text-[10px] text-white/30 uppercase tracking-wider mb-1.5">Payload</p>
                          <pre className="text-xs text-white/60 bg-white/[0.03] rounded-lg p-3 overflow-auto max-h-48 border border-white/5">
                            {JSON.stringify(ev.payload, null, 2)}
                          </pre>
                        </div>
                        <div>
                          <p className="text-[10px] text-white/30 uppercase tracking-wider mb-1.5">Raw Log</p>
                          <pre className="text-xs text-white/40 bg-white/[0.03] rounded-lg p-3 overflow-auto max-h-48 border border-white/5 whitespace-pre-wrap break-all">
                            {ev.raw_log || "—"}
                          </pre>
                        </div>
                      </div>
                      <p className="text-[10px] text-white/20 font-mono mt-3">
                        OCSF class_uid: {ev.class_uid} · {ev.id}
                      </p>
                    </td>
                  </tr>
                )}
              </>
            ))}
            {!loading && allEvents.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-14 text-center text-white/30 text-sm">
                  No cloud events found.
                </td>
              </tr>
            )}
            {loading && allEvents.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-14 text-center text-white/30 text-sm">Loading…</td>
              </tr>
            )}
          </tbody>
        </table>

        {(data?.events?.length ?? 0) >= limit && (
          <div className="border-t border-white/10 px-4 py-3 text-center">
            <button
              onClick={() => setOffset((o) => o + limit)}
              disabled={loading}
              className="px-4 py-1.5 text-xs rounded-lg border border-white/10 hover:bg-white/5 text-white/50 hover:text-white disabled:opacity-40 transition-colors"
            >
              {loading ? "Loading…" : "Load more"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
