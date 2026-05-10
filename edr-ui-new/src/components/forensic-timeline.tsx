"use client";

import { useState, useMemo } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { ChevronDown, ChevronRight, Download } from "lucide-react";

export interface ForensicEvent {
  id: string;
  type: string;
  timestamp: string;
  agent_id: string;
  hostname: string;
  severity: number;
  payload: Record<string, unknown>;
  alert_id?: string;
  source: string;
}

interface ForensicTimelineResult {
  events: ForensicEvent[];
  total: number;
  has_more: boolean;
  cursor?: string;
}

interface Props {
  /** Provide incidentId OR agentId, not both */
  incidentId?: string;
  agentId?: string;
}

const EVENT_TYPES = [
  "PROCESS_EXEC", "NET_CONNECT", "NET_ACCEPT", "FILE_CREATE", "FILE_MODIFY", "FILE_DELETE",
  "LOGIN", "LOGOUT", "AUTH_FAIL", "DNS_QUERY", "USB_CONNECT", "REG_SET",
] as const;

const TYPE_META: Record<string, { lane: string; color: string; bg: string }> = {
  PROCESS_EXEC:  { lane: "Process",  color: "bg-orange-500",  bg: "bg-orange-500/10 border-orange-500/20 text-orange-300" },
  NET_CONNECT:   { lane: "Network",  color: "bg-purple-500",  bg: "bg-purple-500/10 border-purple-500/20 text-purple-300" },
  NET_ACCEPT:    { lane: "Network",  color: "bg-purple-400",  bg: "bg-purple-400/10 border-purple-400/20 text-purple-300" },
  FILE_CREATE:   { lane: "File",     color: "bg-yellow-500",  bg: "bg-yellow-500/10 border-yellow-500/20 text-yellow-300" },
  FILE_MODIFY:   { lane: "File",     color: "bg-yellow-400",  bg: "bg-yellow-400/10 border-yellow-400/20 text-yellow-300" },
  FILE_DELETE:   { lane: "File",     color: "bg-yellow-600",  bg: "bg-yellow-600/10 border-yellow-600/20 text-yellow-400" },
  LOGIN:         { lane: "Auth",     color: "bg-blue-500",    bg: "bg-blue-500/10 border-blue-500/20 text-blue-300" },
  LOGOUT:        { lane: "Auth",     color: "bg-blue-400",    bg: "bg-blue-400/10 border-blue-400/20 text-blue-300" },
  AUTH_FAIL:     { lane: "Auth",     color: "bg-red-500",     bg: "bg-red-500/10 border-red-500/20 text-red-300" },
  DNS_QUERY:     { lane: "DNS",      color: "bg-teal-500",    bg: "bg-teal-500/10 border-teal-500/20 text-teal-300" },
  USB_CONNECT:   { lane: "USB",      color: "bg-pink-500",    bg: "bg-pink-500/10 border-pink-500/20 text-pink-300" },
  REG_SET:       { lane: "Registry", color: "bg-slate-400",   bg: "bg-slate-400/10 border-slate-400/20 text-slate-300" },
};

function getMeta(type: string) {
  return TYPE_META[type] ?? { lane: "Other", color: "bg-white/30", bg: "bg-white/5 border-white/10 text-white/60" };
}

function severityBadge(sev: number) {
  if (sev >= 4) return "text-red-400";
  if (sev >= 3) return "text-orange-400";
  if (sev >= 2) return "text-yellow-400";
  return "text-white/30";
}

function formatTs(ts: string) {
  const d = new Date(ts);
  return d.toLocaleTimeString("en-GB", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatDate(ts: string) {
  return new Date(ts).toLocaleDateString("en-GB", { day: "2-digit", month: "short" });
}

function EventRow({ event }: { event: ForensicEvent }) {
  const [open, setOpen] = useState(false);
  const meta = getMeta(event.type);

  return (
    <div className="group">
      <div
        className="flex items-start gap-3 px-4 py-2 hover:bg-white/[0.02] cursor-pointer rounded-lg"
        onClick={() => setOpen(!open)}
      >
        {/* timeline dot */}
        <div className="flex flex-col items-center pt-1.5 shrink-0">
          <span className={`w-2 h-2 rounded-full ${meta.color}`} />
          <span className="w-px flex-1 bg-white/5 mt-1" />
        </div>

        {/* time */}
        <div className="w-20 shrink-0 text-xs font-mono text-white/40 pt-0.5">
          {formatTs(event.timestamp)}
        </div>

        {/* lane badge */}
        <span className={`shrink-0 rounded-md border px-1.5 py-0.5 text-[10px] font-medium ${meta.bg}`}>
          {meta.lane}
        </span>

        {/* type */}
        <span className="flex-1 text-xs text-white/70 pt-0.5 font-mono">{event.type}</span>

        {/* hostname */}
        <span className="text-xs text-white/30 pt-0.5 shrink-0 hidden sm:block">{event.hostname}</span>

        {/* severity */}
        {event.severity > 0 && (
          <span className={`text-xs pt-0.5 shrink-0 font-semibold ${severityBadge(event.severity)}`}>
            {["", "Info", "Low", "Med", "High", "Crit"][event.severity] ?? event.severity}
          </span>
        )}

        {/* alert link */}
        {event.alert_id && (
          <span className="shrink-0 text-[10px] rounded border border-red-500/30 text-red-400 px-1.5 py-0.5">
            ALERT
          </span>
        )}

        {/* expand chevron */}
        <span className="text-white/20 group-hover:text-white/40 transition-colors shrink-0 pt-0.5">
          {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </span>
      </div>

      {open && (
        <div className="mx-4 mb-2 rounded-lg bg-white/[0.02] border border-white/5 p-3">
          <pre className="text-[11px] text-white/60 font-mono whitespace-pre-wrap break-all leading-relaxed overflow-auto max-h-60">
            {JSON.stringify(event.payload, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

export function ForensicTimeline({ incidentId, agentId }: Props) {
  const [filterTypes, setFilterTypes] = useState<string[]>([]);
  const [limit] = useState(200);

  const endpoint = useMemo(() => {
    const base = incidentId
      ? `/incidents/${incidentId}/forensic-timeline`
      : `/agents/${agentId}/forensic-timeline`;
    const params = new URLSearchParams({ limit: String(limit) });
    filterTypes.forEach((t) => params.append("types[]", t));
    return `${base}?${params}`;
  }, [incidentId, agentId, filterTypes, limit]);

  const { data, loading, error, refetch } = useApi<ForensicTimelineResult>(
    (signal) => api.get(endpoint, {}, signal),
  );

  const events = data?.events ?? [];

  // Group events by date for date separators
  const grouped = useMemo(() => {
    const out: Array<{ date: string; events: ForensicEvent[] }> = [];
    let cur: { date: string; events: ForensicEvent[] } | null = null;
    for (const e of events) {
      const d = formatDate(e.timestamp);
      if (!cur || cur.date !== d) {
        cur = { date: d, events: [] };
        out.push(cur);
      }
      cur.events.push(e);
    }
    return out;
  }, [events]);

  const toggleType = (t: string) =>
    setFilterTypes((prev) =>
      prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t],
    );

  function exportCSV() {
    const rows = [
      ["timestamp", "type", "hostname", "agent_id", "severity", "alert_id"].join(","),
      ...events.map((e) =>
        [e.timestamp, e.type, e.hostname, e.agent_id, e.severity, e.alert_id ?? ""].join(","),
      ),
    ].join("\n");
    const blob = new Blob([rows], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `forensic-timeline-${Date.now()}.csv`;
    a.click();
  }

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-1 flex-wrap">
          {EVENT_TYPES.map((t) => (
            <button
              key={t}
              onClick={() => toggleType(t)}
              className={`rounded-md px-2 py-0.5 text-[10px] font-mono transition-colors border ${
                filterTypes.includes(t)
                  ? "bg-white/15 border-white/20 text-white"
                  : "border-white/8 text-white/30 hover:text-white/60 hover:border-white/15"
              }`}
            >
              {t}
            </button>
          ))}
          {filterTypes.length > 0 && (
            <button
              onClick={() => setFilterTypes([])}
              className="text-[10px] text-white/30 hover:text-white/60 ml-1 transition-colors"
            >
              clear
            </button>
          )}
        </div>
        <div className="flex items-center gap-2">
          {data && (
            <span className="text-xs text-white/30">
              {events.length} events{data.has_more ? " (more available)" : ""}
            </span>
          )}
          <button
            onClick={exportCSV}
            disabled={events.length === 0}
            className="flex items-center gap-1 text-xs rounded-lg border border-white/10 px-3 py-1.5 text-white/50 hover:text-white hover:border-white/20 transition-colors disabled:opacity-30"
          >
            <Download size={12} />
            CSV
          </button>
          <button
            onClick={() => refetch()}
            className="text-xs rounded-lg border border-white/10 px-3 py-1.5 text-white/50 hover:text-white hover:border-white/20 transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Timeline body */}
      <div className="rounded-xl border border-white/10 bg-white/[0.02]">
        {loading && (
          <div className="py-16 text-center text-white/30 text-sm">Loading timeline…</div>
        )}
        {error && (
          <div className="py-8 px-4 text-center text-sm text-red-400">{error}</div>
        )}
        {!loading && !error && events.length === 0 && (
          <div className="py-16 text-center text-white/30 text-sm">
            No events found for this {incidentId ? "incident" : "agent"} in the selected range.
          </div>
        )}
        {!loading && grouped.length > 0 && (
          <div className="py-2">
            {grouped.map(({ date, events: dayEvents }) => (
              <div key={date}>
                <div className="sticky top-0 z-10 px-4 py-1 text-[10px] font-medium text-white/30 bg-[#0d0d0f] border-b border-white/5">
                  {date} — {dayEvents.length} event{dayEvents.length !== 1 ? "s" : ""}
                </div>
                {dayEvents.map((e) => (
                  <EventRow key={e.id} event={e} />
                ))}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
