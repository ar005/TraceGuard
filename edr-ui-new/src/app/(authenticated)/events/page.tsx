"use client";

import { useCallback, useMemo, useState } from "react";
import { useApi } from "@/hooks/use-api";
import { useSSE } from "@/hooks/use-sse";
import { api } from "@/lib/api-client";
import { cn, formatDate, timeAgo, eventTypeColor } from "@/lib/utils";
import type { Event } from "@/types";

/* ---------- Constants ---------- */
const FILTERS = [
  { label: "All", value: "" },
  { label: "Process", value: "PROCESS_EXEC" },
  { label: "Command", value: "CMD_EXEC" },
  { label: "Network", value: "NET_CONNECT" },
  { label: "File", value: "FILE_WRITE" },
  { label: "Browser", value: "BROWSER_REQUEST" },
  { label: "DNS", value: "NET_DNS" },
] as const;

const TYPE_BADGE_COLORS: Record<string, string> = {
  PROCESS_EXEC: "bg-blue-500/15 text-blue-400",
  CMD_EXEC: "bg-purple-500/15 text-purple-400",
  CMD_HISTORY: "bg-purple-500/15 text-purple-400",
  NET_CONNECT: "bg-cyan-500/15 text-cyan-400",
  FILE_WRITE: "bg-amber-500/15 text-amber-400",
  BROWSER_REQUEST: "bg-pink-500/15 text-pink-400",
  NET_DNS: "bg-teal-500/15 text-teal-400",
};

const PAGE_SIZE = 50;

/* ---------- Helpers ---------- */
function badgeClass(type: string): string {
  return TYPE_BADGE_COLORS[type?.toUpperCase()] ?? "bg-neutral-500/15 text-neutral-400";
}

function extractSummary(evt: Event): string {
  const p = evt.payload ?? {};
  const type = evt.event_type?.toUpperCase();

  switch (type) {
    case "PROCESS_EXEC":
      return (p.cmdline as string) ?? (p.comm as string) ?? (p.path as string) ?? "—";
    case "CMD_EXEC":
    case "CMD_HISTORY":
      return (p.command as string) ?? (p.cmdline as string) ?? "—";
    case "NET_CONNECT": {
      const dst = p.dst_ip ?? p.dest_ip ?? p.remote_ip;
      const port = p.dst_port ?? p.dest_port ?? p.remote_port;
      if (dst && port) return `${dst}:${port}`;
      if (dst) return String(dst);
      return "—";
    }
    case "FILE_WRITE":
    case "FILE_OPEN":
    case "FILE_CREATE":
    case "FILE_DELETE":
      return (p.path as string) ?? (p.filename as string) ?? "—";
    case "BROWSER_REQUEST": {
      const url = (p.url as string) ?? "";
      const status = p.status_code;
      return status ? `${url} [${status}]` : url || "—";
    }
    case "NET_DNS":
      return (p.domain as string) ?? (p.query as string) ?? "—";
    default:
      return (p.cmdline as string) ?? (p.command as string) ?? (p.path as string) ?? "—";
  }
}

function severityDot(sev: number): string {
  switch (sev) {
    case 4:
      return "bg-red-500";
    case 3:
      return "bg-orange-500";
    case 2:
      return "bg-amber-500";
    case 1:
      return "bg-blue-500";
    default:
      return "bg-neutral-500";
  }
}

/* ---------- Skeleton ---------- */
function SkeletonRow() {
  return (
    <div className="flex items-center gap-3 px-3 py-2">
      <div className="animate-shimmer h-4 w-24 rounded" />
      <div className="animate-shimmer h-5 w-20 rounded" />
      <div className="animate-shimmer h-4 w-28 rounded" />
      <div className="animate-shimmer h-4 flex-1 rounded" />
      <div className="animate-shimmer h-3 w-3 rounded-full" />
    </div>
  );
}

/* ---------- Detail Drawer ---------- */
/* ---------- Process Tree in Event Detail ---------- */
interface ProcessNode {
  pid: number;
  ppid: number;
  comm: string;
  cmdline: string;
  uid: number;
  username: string;
  exe_path: string;
  start_time: string;
  children?: ProcessNode[];
}

function ProcessTreeNode({ node, depth }: { node: ProcessNode; depth: number }) {
  const indent = depth * 20;
  return (
    <>
      <div className="flex items-start gap-1 py-0.5" style={{ paddingLeft: `${indent}px` }}>
        <span style={{ color: "var(--muted)" }}>{depth > 0 ? "└─" : ""}</span>
        <span style={{ color: depth === 0 ? "var(--primary)" : "var(--fg)" }} className="font-semibold">
          {node.comm || "?"}
        </span>
        <span style={{ color: "var(--muted)" }}>(PID:{node.pid})</span>
        {node.username && <span style={{ color: "var(--muted)" }}>[{node.username}]</span>}
        {node.cmdline && (
          <span className="truncate" style={{ color: "var(--muted)", maxWidth: "250px" }} title={node.cmdline}>
            {node.cmdline.length > 60 ? node.cmdline.substring(0, 60) + "..." : node.cmdline}
          </span>
        )}
      </div>
      {node.children?.map((child, i) => (
        <ProcessTreeNode key={i} node={child} depth={depth + 1} />
      ))}
    </>
  );
}

function EventProcessTree({ event }: { event: Event }) {
  const [tree, setTree] = useState<ProcessNode[] | null>(null);
  const [loading, setLoading] = useState(false);

  const pid = (event.payload?.process as Record<string, unknown>)?.pid as number
    ?? event.payload?.pid as number
    ?? null;

  if (!pid || !event.agent_id) return null;
  if (event.event_type !== "PROCESS_EXEC" && event.event_type !== "PROCESS_FORK" && event.event_type !== "CMD_EXEC") return null;

  async function loadTree() {
    if (!pid) return;
    setLoading(true);
    try {
      const result = await api.get<{ tree?: ProcessNode[]; processes?: ProcessNode[] } | ProcessNode[]>(
        `/api/v1/processes/${pid}/tree`,
        { agent_id: event.agent_id, depth: 5 }
      );
      setTree(Array.isArray(result) ? result : result.tree ?? result.processes ?? []);
    } catch {
      setTree([]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <div className="flex items-center gap-2 mb-1">
        <div className="text-xs font-semibold" style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}>
          Process Tree
        </div>
        {!tree && (
          <button
            onClick={loadTree}
            disabled={loading}
            className="flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] font-medium transition-colors hover:bg-[var(--surface-2)] disabled:opacity-50"
            style={{ borderColor: "var(--border)", color: "var(--primary)" }}
          >
            {loading ? "Loading..." : `View (PID ${pid})`}
          </button>
        )}
      </div>
      {tree && tree.length > 0 && (
        <div
          className="rounded border p-3 font-mono text-[11px] leading-relaxed overflow-x-auto"
          style={{ background: "var(--surface-1)", borderColor: "var(--border)" }}
        >
          {tree.map((node, i) => (
            <ProcessTreeNode key={i} node={node} depth={0} />
          ))}
        </div>
      )}
      {tree && tree.length === 0 && (
        <p className="text-xs" style={{ color: "var(--muted)" }}>No process tree data available.</p>
      )}
    </div>
  );
}

function EventDetail({ event, onClose }: { event: Event; onClose: () => void }) {
  return (
    <div
      className="fixed inset-y-0 right-0 z-50 w-full max-w-lg border-l shadow-xl overflow-y-auto animate-fade-in"
      style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
    >
      <div className="flex items-center justify-between p-4 border-b" style={{ borderColor: "var(--border)" }}>
        <h3
          className="text-sm font-semibold"
          style={{ fontFamily: "var(--font-space-grotesk)" }}
        >
          Event Detail
        </h3>
        <button
          onClick={onClose}
          className="text-xs rounded px-2 py-1 hover:bg-[var(--surface-2)] transition-colors"
          style={{ color: "var(--muted)" }}
        >
          Close
        </button>
      </div>
      <div className="p-4 space-y-4">
        {/* Key fields */}
        <div className="space-y-2 text-xs">
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Event ID</span>
            <span className="font-mono" style={{ color: "var(--fg)" }}>{event.id}</span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Agent ID</span>
            <span className="font-mono" style={{ color: "var(--fg)" }}>{event.agent_id}</span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Type</span>
            <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase", badgeClass(event.event_type))}>
              {event.event_type}
            </span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Hostname</span>
            <span style={{ color: "var(--fg)" }}>{event.hostname}</span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Timestamp</span>
            <span className="font-mono" style={{ color: "var(--fg)" }}>
              {formatDate(event.timestamp)}
            </span>
          </div>
        </div>

        {/* Process Tree */}
        <EventProcessTree event={event} />

        {/* Full payload */}
        <div>
          <div
            className="text-xs font-semibold mb-1"
            style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}
          >
            Payload
          </div>
          <pre
            className="rounded p-3 text-[11px] leading-relaxed overflow-x-auto"
            style={{ background: "var(--surface-1)", color: "var(--fg)" }}
          >
            <code>{JSON.stringify(event.payload, null, 2)}</code>
          </pre>
        </div>
      </div>
    </div>
  );
}

/* ---------- Events Page ---------- */
export default function EventsPage() {
  const [filter, setFilter] = useState("");
  const [search, setSearch] = useState("");
  const [liveMode, setLiveMode] = useState(false);
  const [offset, setOffset] = useState(0);
  const [allEvents, setAllEvents] = useState<Event[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);

  /* API fetch */
  const fetchEvents = useCallback(
    () =>
      api
        .get<{ events?: Event[] } | Event[]>("/api/v1/events", {
          event_type: filter || undefined,
          search: search || undefined,
          limit: PAGE_SIZE,
          offset,
        })
        .then((r) => (Array.isArray(r) ? r : r.events ?? [])),
    [filter, search, offset]
  );

  const { data: fetchedEvents, loading, error } = useApi(fetchEvents);

  /* SSE live events */
  const { events: sseEvents, connected: sseConnected } = useSSE(
    liveMode ? "/api/v1/events/stream" : "",
    200
  );

  /* Merged events list */
  const displayEvents = useMemo(() => {
    if (liveMode && sseEvents.length > 0) {
      let merged = sseEvents;
      // Apply client-side filter on live events
      if (filter) {
        merged = merged.filter((e) => e.event_type?.toUpperCase() === filter.toUpperCase());
      }
      if (search) {
        const q = search.toLowerCase();
        merged = merged.filter(
          (e) =>
            e.hostname?.toLowerCase().includes(q) ||
            extractSummary(e).toLowerCase().includes(q) ||
            e.event_type?.toLowerCase().includes(q)
        );
      }
      return merged;
    }
    return fetchedEvents ?? allEvents;
  }, [liveMode, sseEvents, filter, search, fetchedEvents, allEvents]);

  /* Track accumulated events for load more */
  useMemo(() => {
    if (fetchedEvents && !liveMode) {
      if (offset === 0) {
        setAllEvents(fetchedEvents);
      } else {
        setAllEvents((prev) => {
          const ids = new Set(prev.map((e) => e.id));
          const newOnes = fetchedEvents.filter((e) => !ids.has(e.id));
          return [...prev, ...newOnes];
        });
      }
    }
  }, [fetchedEvents, offset, liveMode]);

  const handleFilterChange = (val: string) => {
    setFilter(val);
    setOffset(0);
    setAllEvents([]);
  };

  const handleSearchChange = (val: string) => {
    setSearch(val);
    setOffset(0);
    setAllEvents([]);
  };

  return (
    <div className="animate-fade-in space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <h1
          className="text-lg font-semibold"
          style={{ fontFamily: "var(--font-space-grotesk)" }}
        >
          Events
        </h1>

        {/* Live toggle */}
        <button
          onClick={() => setLiveMode(!liveMode)}
          className={cn(
            "flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs font-medium transition-colors",
            liveMode
              ? "border-emerald-500/50 text-emerald-400"
              : "hover:bg-[var(--surface-2)]"
          )}
          style={{
            borderColor: liveMode ? undefined : "var(--border)",
            color: liveMode ? undefined : "var(--muted)",
            background: liveMode ? "rgba(34,197,94,0.08)" : "var(--surface-0)",
          }}
        >
          <span className="relative flex h-2 w-2">
            {liveMode && sseConnected ? (
              <>
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
              </>
            ) : (
              <span className="relative inline-flex h-2 w-2 rounded-full bg-neutral-500" />
            )}
          </span>
          {liveMode ? "Live" : "Live"}
        </button>
      </div>

      {/* Filter pills + search */}
      <div className="flex flex-wrap items-center gap-2">
        {FILTERS.map((f) => (
          <button
            key={f.value}
            onClick={() => handleFilterChange(f.value)}
            className={cn(
              "rounded-full px-3 py-1 text-xs font-medium transition-colors",
              filter === f.value
                ? "text-[var(--primary-fg)]"
                : "hover:bg-[var(--surface-2)]"
            )}
            style={{
              background: filter === f.value ? "var(--primary)" : "var(--surface-1)",
              color: filter === f.value ? "var(--primary-fg)" : "var(--muted)",
            }}
          >
            {f.label}
          </button>
        ))}
        <div className="flex-1" />
        <input
          type="text"
          placeholder="Search events..."
          value={search}
          onChange={(e) => handleSearchChange(e.target.value)}
          className="rounded-md border px-3 py-1.5 text-xs w-56 outline-none focus-ring"
          style={{
            background: "var(--surface-0)",
            borderColor: "var(--border)",
            color: "var(--fg)",
          }}
        />
      </div>

      {/* Error state */}
      {error && !liveMode && (
        <div
          className="rounded-lg border p-4 text-center text-sm text-red-400"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
        >
          {error}
        </div>
      )}

      {/* Events table */}
      <div
        className="rounded-lg border overflow-hidden"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
      >
        {/* Table header */}
        <div
          className="grid grid-cols-[140px_120px_120px_1fr_40px] gap-2 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider border-b"
          style={{ color: "var(--muted-fg)", borderColor: "var(--border)", background: "var(--surface-1)" }}
        >
          <span>Time</span>
          <span>Type</span>
          <span>Host</span>
          <span>Summary</span>
          <span>Sev</span>
        </div>

        {/* Loading skeleton */}
        {loading && !liveMode && displayEvents.length === 0 && (
          <div>
            {Array.from({ length: 10 }).map((_, i) => (
              <SkeletonRow key={i} />
            ))}
          </div>
        )}

        {/* Rows */}
        {displayEvents.map((evt) => (
          <button
            key={evt.id}
            onClick={() => setSelectedEvent(selectedEvent?.id === evt.id ? null : evt)}
            className={cn(
              "grid grid-cols-[140px_120px_120px_1fr_40px] gap-2 px-3 py-2 text-xs w-full text-left transition-colors border-b last:border-b-0",
              selectedEvent?.id === evt.id
                ? "bg-[var(--surface-2)]"
                : "hover:bg-[var(--surface-1)]"
            )}
            style={{ borderColor: "var(--border-subtle)" }}
          >
            <span className="font-mono truncate" style={{ color: "var(--muted)" }}>
              {timeAgo(evt.timestamp)}
            </span>
            <span>
              <span
                className={cn(
                  "inline-flex rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                  badgeClass(evt.event_type)
                )}
              >
                {evt.event_type}
              </span>
            </span>
            <span className="truncate" style={{ color: "var(--fg)" }}>
              {evt.hostname}
            </span>
            <span className="truncate font-mono" style={{ color: "var(--fg)" }}>
              {extractSummary(evt)}
            </span>
            <span className="flex justify-center">
              <span className={cn("inline-block h-2.5 w-2.5 rounded-full", severityDot(evt.severity))} />
            </span>
          </button>
        ))}

        {/* Empty state */}
        {!loading && displayEvents.length === 0 && (
          <div className="py-12 text-center text-xs" style={{ color: "var(--muted)" }}>
            No events found
          </div>
        )}
      </div>

      {/* Load More */}
      {!liveMode && fetchedEvents && fetchedEvents.length === PAGE_SIZE && (
        <div className="flex justify-center">
          <button
            onClick={() => setOffset((prev) => prev + PAGE_SIZE)}
            disabled={loading}
            className="rounded-md border px-4 py-2 text-xs font-medium transition-colors hover:bg-[var(--surface-2)] disabled:opacity-50"
            style={{
              background: "var(--surface-0)",
              borderColor: "var(--border)",
              color: "var(--muted)",
            }}
          >
            {loading ? "Loading..." : "Load More"}
          </button>
        </div>
      )}

      {/* Detail drawer */}
      {selectedEvent && (
        <>
          <div
            className="fixed inset-0 z-40 bg-black/30"
            onClick={() => setSelectedEvent(null)}
          />
          <EventDetail event={selectedEvent} onClose={() => setSelectedEvent(null)} />
        </>
      )}
    </div>
  );
}
