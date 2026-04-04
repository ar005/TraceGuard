"use client";

import { useCallback, useRef, useState } from "react";
import { Download } from "lucide-react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { exportToCSV, exportToJSON } from "@/lib/export";
import {
  cn,
  formatDate,
  timeAgo,
  severityLabel,
  severityBgClass,
  eventTypeColor,
} from "@/lib/utils";
import type { Event } from "@/types";

/* ---------- Constants ---------- */
const QUICK_FILTERS = [
  { label: "Recent Alerts", value: "", search: "alert" },
  { label: "Process Events", value: "PROCESS_EXEC", search: "" },
  { label: "Network Events", value: "NET_CONNECT", search: "" },
  { label: "File Events", value: "FILE_WRITE", search: "" },
  { label: "Browser Events", value: "BROWSER_REQUEST", search: "" },
  { label: "Commands", value: "CMD_EXEC", search: "" },
] as const;

const TYPE_BADGE_COLORS: Record<string, string> = {
  PROCESS_EXEC: "bg-blue-500/15 text-blue-400",
  CMD_EXEC: "bg-purple-500/15 text-purple-400",
  CMD_HISTORY: "bg-purple-500/15 text-purple-400",
  NET_CONNECT: "bg-cyan-500/15 text-cyan-400",
  FILE_WRITE: "bg-amber-500/15 text-amber-400",
  FILE_OPEN: "bg-amber-500/15 text-amber-400",
  FILE_CREATE: "bg-amber-500/15 text-amber-400",
  FILE_DELETE: "bg-amber-500/15 text-amber-400",
  BROWSER_REQUEST: "bg-pink-500/15 text-pink-400",
  NET_DNS: "bg-teal-500/15 text-teal-400",
};

const PAGE_SIZE = 50;

/* ---------- Helpers ---------- */
function badgeClass(type: string): string {
  return (
    TYPE_BADGE_COLORS[type?.toUpperCase()] ??
    "bg-neutral-500/15 text-neutral-400"
  );
}

function extractSummary(evt: Event): string {
  const p = evt.payload ?? {};
  const type = evt.event_type?.toUpperCase();

  switch (type) {
    case "PROCESS_EXEC":
      return (
        (p.cmdline as string) ??
        (p.comm as string) ??
        (p.path as string) ??
        "\u2014"
      );
    case "CMD_EXEC":
    case "CMD_HISTORY":
      return (p.command as string) ?? (p.cmdline as string) ?? "\u2014";
    case "NET_CONNECT": {
      const dst = p.dst_ip ?? p.dest_ip ?? p.remote_ip;
      const port = p.dst_port ?? p.dest_port ?? p.remote_port;
      if (dst && port) return `${dst}:${port}`;
      if (dst) return String(dst);
      return "\u2014";
    }
    case "FILE_WRITE":
    case "FILE_OPEN":
    case "FILE_CREATE":
    case "FILE_DELETE":
      return (p.path as string) ?? (p.filename as string) ?? "\u2014";
    case "BROWSER_REQUEST": {
      const url = (p.url as string) ?? "";
      const status = p.status_code;
      return status ? `${url} [${status}]` : url || "\u2014";
    }
    case "NET_DNS":
      return (p.domain as string) ?? (p.query as string) ?? "\u2014";
    default:
      return (
        (p.cmdline as string) ??
        (p.command as string) ??
        (p.path as string) ??
        "\u2014"
      );
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
    <div className="flex items-center gap-3 px-4 py-3">
      <div className="animate-shimmer h-5 w-24 rounded" />
      <div className="animate-shimmer h-4 w-20 rounded" />
      <div className="animate-shimmer h-4 w-28 rounded" />
      <div className="animate-shimmer h-4 flex-1 rounded" />
      <div className="animate-shimmer h-3 w-3 rounded-full" />
    </div>
  );
}

/* ---------- Search Page ---------- */
export default function SearchPage() {
  const searchRef = useRef<HTMLInputElement>(null);
  const [search, setSearch] = useState("");
  const [eventType, setEventType] = useState("");
  const [hasSearched, setHasSearched] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [agentId, setAgentId] = useState("");
  const [hostname, setHostname] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [offset, setOffset] = useState(0);
  const [allEvents, setAllEvents] = useState<Event[]>([]);
  const [showExportMenu, setShowExportMenu] = useState(false);

  /* Build search trigger key: only fetch when user explicitly wants to */
  const [searchTrigger, setSearchTrigger] = useState(0);

  const fetchEvents = useCallback(() => {
    if (!hasSearched) {
      return Promise.resolve([] as Event[]);
    }
    return api
      .get<{ events?: Event[] } | Event[]>("/api/v1/events", {
        search: search || undefined,
        event_type: eventType || undefined,
        agent_id: agentId || undefined,
        hostname: hostname || undefined,
        since: since || undefined,
        until: until || undefined,
        limit: PAGE_SIZE,
        offset,
      })
      .then((r) => (Array.isArray(r) ? r : r.events ?? []));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchTrigger, offset]);

  const { data: fetchedEvents, loading, error } = useApi(fetchEvents);

  /* Accumulate for load-more */
  // Use a ref to avoid lint issues with useMemo side effects
  const prevFetchedRef = useRef<Event[] | null>(null);
  if (fetchedEvents && fetchedEvents !== prevFetchedRef.current) {
    prevFetchedRef.current = fetchedEvents;
    if (offset === 0) {
      if (allEvents.length > 0 || fetchedEvents.length > 0) {
        // Only update if changed
        const needsUpdate =
          allEvents.length !== fetchedEvents.length ||
          (fetchedEvents.length > 0 && allEvents[0]?.id !== fetchedEvents[0]?.id);
        if (needsUpdate) {
          setAllEvents(fetchedEvents);
        }
      }
    } else {
      const ids = new Set(allEvents.map((e) => e.id));
      const newOnes = fetchedEvents.filter((e) => !ids.has(e.id));
      if (newOnes.length > 0) {
        setAllEvents((prev) => [...prev, ...newOnes]);
      }
    }
  }

  function triggerSearch() {
    setHasSearched(true);
    setOffset(0);
    setAllEvents([]);
    prevFetchedRef.current = null;
    setSearchTrigger((t) => t + 1);
  }

  function handleSearchSubmit(e: React.FormEvent) {
    e.preventDefault();
    triggerSearch();
  }

  function handleQuickFilter(filter: (typeof QUICK_FILTERS)[number]) {
    setEventType(filter.value);
    if (filter.search) {
      setSearch(filter.search);
    }
    setHasSearched(true);
    setOffset(0);
    setAllEvents([]);
    prevFetchedRef.current = null;
    // Trigger fetch on next tick after state updates
    setTimeout(() => {
      setSearchTrigger((t) => t + 1);
    }, 0);
    searchRef.current?.focus();
  }

  function handleLoadMore() {
    setOffset((prev) => prev + PAGE_SIZE);
    setSearchTrigger((t) => t + 1);
  }

  const displayEvents = allEvents;

  return (
    <div className="animate-fade-in space-y-4">
      {/* Header */}
      <h1
        className="text-lg font-semibold"
        style={{ fontFamily: "var(--font-space-grotesk)" }}
      >
        Search
      </h1>

      {/* Search bar */}
      <form onSubmit={handleSearchSubmit}>
        <div className="flex gap-2">
          <input
            ref={searchRef}
            type="text"
            placeholder="Search across all events..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="flex-1 rounded-lg border px-4 py-3 text-sm outline-none focus-ring"
            style={{
              background: "var(--surface-0)",
              borderColor: "var(--border)",
              color: "var(--fg)",
            }}
          />
          <button
            type="submit"
            className="rounded-lg px-5 py-3 text-sm font-semibold transition-colors"
            style={{
              background: "var(--primary)",
              color: "var(--primary-fg)",
            }}
          >
            Search
          </button>
        </div>
      </form>

      {/* Quick filter chips */}
      <div className="flex flex-wrap items-center gap-2">
        {QUICK_FILTERS.map((f) => (
          <button
            key={f.label}
            onClick={() => handleQuickFilter(f)}
            className={cn(
              "rounded-full px-3 py-1 text-xs font-medium transition-colors",
              eventType === f.value && hasSearched
                ? ""
                : "hover:bg-[var(--surface-2)]"
            )}
            style={{
              background:
                eventType === f.value && hasSearched
                  ? "var(--primary)"
                  : "var(--surface-1)",
              color:
                eventType === f.value && hasSearched
                  ? "var(--primary-fg)"
                  : "var(--muted)",
            }}
          >
            {f.label}
          </button>
        ))}
      </div>

      {/* Advanced filters */}
      <div>
        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="text-xs font-medium transition-colors"
          style={{ color: "var(--muted)" }}
        >
          {showAdvanced ? "Hide" : "Show"} Advanced Filters
        </button>

        {showAdvanced && (
          <div
            className="mt-2 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 rounded-lg border p-3"
            style={{
              background: "var(--surface-0)",
              borderColor: "var(--border)",
            }}
          >
            <div>
              <label
                className="block text-[10px] font-semibold uppercase tracking-wider mb-1"
                style={{ color: "var(--muted)" }}
              >
                Agent ID
              </label>
              <input
                type="text"
                placeholder="Filter by agent ID"
                value={agentId}
                onChange={(e) => setAgentId(e.target.value)}
                className="w-full rounded border px-2 py-1.5 text-xs font-mono outline-none focus-ring"
                style={{
                  background: "var(--surface-1)",
                  borderColor: "var(--border)",
                  color: "var(--fg)",
                }}
              />
            </div>
            <div>
              <label
                className="block text-[10px] font-semibold uppercase tracking-wider mb-1"
                style={{ color: "var(--muted)" }}
              >
                Hostname
              </label>
              <input
                type="text"
                placeholder="Filter by hostname"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                className="w-full rounded border px-2 py-1.5 text-xs outline-none focus-ring"
                style={{
                  background: "var(--surface-1)",
                  borderColor: "var(--border)",
                  color: "var(--fg)",
                }}
              />
            </div>
            <div>
              <label
                className="block text-[10px] font-semibold uppercase tracking-wider mb-1"
                style={{ color: "var(--muted)" }}
              >
                Since
              </label>
              <input
                type="datetime-local"
                value={since}
                onChange={(e) => setSince(e.target.value)}
                className="w-full rounded border px-2 py-1.5 text-xs outline-none focus-ring"
                style={{
                  background: "var(--surface-1)",
                  borderColor: "var(--border)",
                  color: "var(--fg)",
                }}
              />
            </div>
            <div>
              <label
                className="block text-[10px] font-semibold uppercase tracking-wider mb-1"
                style={{ color: "var(--muted)" }}
              >
                Until
              </label>
              <input
                type="datetime-local"
                value={until}
                onChange={(e) => setUntil(e.target.value)}
                className="w-full rounded border px-2 py-1.5 text-xs outline-none focus-ring"
                style={{
                  background: "var(--surface-1)",
                  borderColor: "var(--border)",
                  color: "var(--fg)",
                }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Error state */}
      {error && (
        <div
          className="rounded-lg border p-4 text-center text-sm text-red-400"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
        >
          {error}
        </div>
      )}

      {/* Empty state — no search performed */}
      {!hasSearched && (
        <div
          className="rounded-lg border py-16 text-center"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
        >
          <p className="text-sm" style={{ color: "var(--muted)" }}>
            Start typing to search across all events
          </p>
          <p className="text-xs mt-1" style={{ color: "var(--muted-fg)" }}>
            Use quick filters above or enter a search term
          </p>
        </div>
      )}

      {/* Results */}
      {hasSearched && (
        <>
        {displayEvents.length > 0 && (
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono" style={{ color: "var(--muted)" }}>
              {displayEvents.length} results
            </span>
            <div className="relative">
              <button
                onClick={() => setShowExportMenu(!showExportMenu)}
                className="flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-2)]"
                style={{ borderColor: "var(--border)", color: "var(--muted)" }}
              >
                <Download size={12} />
                Export
              </button>
              {showExportMenu && (
                <div
                  className="absolute right-0 top-full mt-1 rounded border shadow-lg z-10 py-1 min-w-[120px]"
                  style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
                >
                  <button
                    onClick={() => { exportToCSV(displayEvents, "search-results.csv"); setShowExportMenu(false); }}
                    className="w-full text-left px-3 py-1.5 text-xs hover:bg-[var(--surface-1)] transition-colors"
                    style={{ color: "var(--fg)" }}
                  >
                    Export as CSV
                  </button>
                  <button
                    onClick={() => { exportToJSON(displayEvents, "search-results.json"); setShowExportMenu(false); }}
                    className="w-full text-left px-3 py-1.5 text-xs hover:bg-[var(--surface-1)] transition-colors"
                    style={{ color: "var(--fg)" }}
                  >
                    Export as JSON
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
        <div
          className="rounded-lg border overflow-hidden"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
        >
          {/* Table header */}
          <div
            className="grid grid-cols-[100px_120px_120px_1fr_32px] gap-2 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider border-b"
            style={{
              color: "var(--muted-fg)",
              borderColor: "var(--border)",
              background: "var(--surface-1)",
            }}
          >
            <span>Type</span>
            <span>Time</span>
            <span>Host</span>
            <span>Summary</span>
            <span>Sev</span>
          </div>

          {/* Loading skeleton */}
          {loading && displayEvents.length === 0 && (
            <div>
              {Array.from({ length: 10 }).map((_, i) => (
                <SkeletonRow key={i} />
              ))}
            </div>
          )}

          {/* Rows */}
          {displayEvents.map((evt) => (
            <div
              key={evt.id}
              className="grid grid-cols-[100px_120px_120px_1fr_32px] gap-2 px-3 py-2 text-xs transition-colors border-b last:border-b-0 hover:bg-[var(--surface-1)]"
              style={{ borderColor: "var(--border-subtle)" }}
            >
              {/* Event type badge */}
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

              {/* Timestamp */}
              <span className="font-mono truncate" style={{ color: "var(--muted)" }}>
                {timeAgo(evt.timestamp)}
              </span>

              {/* Hostname */}
              <span className="truncate" style={{ color: "var(--fg)" }}>
                {evt.hostname}
              </span>

              {/* Payload summary */}
              <span className="truncate font-mono" style={{ color: "var(--fg)" }}>
                {extractSummary(evt)}
              </span>

              {/* Severity */}
              <span className="flex justify-center items-center">
                <span
                  className={cn(
                    "inline-block h-2.5 w-2.5 rounded-full",
                    severityDot(evt.severity)
                  )}
                  title={severityLabel(evt.severity)}
                />
              </span>
            </div>
          ))}

          {/* Empty results */}
          {!loading && displayEvents.length === 0 && (
            <div
              className="py-12 text-center text-xs"
              style={{ color: "var(--muted)" }}
            >
              No events found matching your search
            </div>
          )}
        </div>
        </>
      )}

      {/* Load More */}
      {hasSearched && fetchedEvents && fetchedEvents.length === PAGE_SIZE && (
        <div className="flex justify-center">
          <button
            onClick={handleLoadMore}
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
    </div>
  );
}
