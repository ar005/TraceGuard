"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api-client";
import { cn, timeAgo, eventTypeColor } from "@/lib/utils";
import type { Event } from "@/types";

/* ---------- Constants ---------- */
const EXAMPLE_QUERIES = [
  {
    label: "Process executions of curl",
    query: `SELECT * FROM events WHERE event_type = 'PROCESS_EXEC' AND payload->>'comm' = 'curl' LIMIT 50`,
  },
  {
    label: "External network connections",
    query: `SELECT * FROM events WHERE event_type = 'NET_CONNECT' AND payload->>'is_private' = 'false' LIMIT 50`,
  },
  {
    label: "Browser form submissions",
    query: `SELECT * FROM events WHERE event_type = 'BROWSER_REQUEST' AND payload->>'is_form_submit' = 'true' LIMIT 50`,
  },
];

/* ---------- Helpers ---------- */
function summarizeEvent(evt: Event): string {
  const p = evt.payload ?? {};
  switch (evt.event_type?.toUpperCase()) {
    case "PROCESS_EXEC":
    case "PROCESS_EXIT":
      return [p.comm, ...(Array.isArray(p.args) ? p.args : [])].filter(Boolean).join(" ") || String(p.comm ?? "—");
    case "FILE_OPEN":
    case "FILE_CREATE":
    case "FILE_DELETE":
    case "FILE_RENAME":
      return String(p.path ?? p.filename ?? "—");
    case "NET_CONNECT":
    case "NET_ACCEPT":
      return `${p.dst_ip ?? p.dest_ip ?? "?"}:${p.dst_port ?? p.dest_port ?? "?"}`;
    case "DNS_QUERY":
      return String(p.query ?? p.domain ?? "—");
    case "BROWSER_REQUEST":
      return String(p.url ?? "—");
    default:
      return JSON.stringify(p).slice(0, 120);
  }
}

function SkeletonRow() {
  return (
    <div className="flex items-center gap-3 px-3 py-2">
      <div className="animate-shimmer h-4 w-20 rounded" />
      <div className="animate-shimmer h-5 w-24 rounded" />
      <div className="animate-shimmer h-4 w-28 rounded" />
      <div className="animate-shimmer h-4 w-64 rounded" />
    </div>
  );
}

/* ---------- Hunt Page ---------- */
export default function HuntPage() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<Event[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  async function runQuery() {
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    setResults(null);
    try {
      const r = await api.post<{ events?: Event[] } | Event[]>("/api/v1/hunt", {
        query: query.trim(),
      });
      const events = Array.isArray(r) ? r : r.events ?? [];
      setResults(events);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  /* Ctrl+Enter shortcut */
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        runQuery();
      }
    }
    const el = textareaRef.current;
    if (el) {
      el.addEventListener("keydown", handleKeyDown);
      return () => el.removeEventListener("keydown", handleKeyDown);
    }
  });

  return (
    <div className="animate-fade-in space-y-4">
      {/* Header */}
      <h1
        className="text-lg font-semibold"
        style={{ fontFamily: "var(--font-space-grotesk)" }}
      >
        Threat Hunt
      </h1>

      {/* Query input */}
      <div
        className="rounded-lg border overflow-hidden"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
      >
        <textarea
          ref={textareaRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          rows={5}
          placeholder="Enter SQL-like query..."
          className="w-full px-4 py-3 text-sm font-mono outline-none resize-y"
          style={{
            background: "hsl(220 20% 8%)",
            color: "var(--fg)",
            caretColor: "var(--primary)",
          }}
        />
        <div
          className="flex items-center justify-between px-4 py-2 border-t"
          style={{
            borderColor: "var(--border)",
            background: "var(--surface-1)",
          }}
        >
          <span className="text-[10px]" style={{ color: "var(--muted)" }}>
            Ctrl+Enter to run
          </span>
          <button
            onClick={runQuery}
            disabled={loading || !query.trim()}
            className="rounded-md px-4 py-1.5 text-xs font-medium transition-colors disabled:opacity-50"
            style={{
              background: "var(--primary)",
              color: "var(--primary-fg)",
            }}
          >
            {loading ? "Running..." : "Run Query"}
          </button>
        </div>
      </div>

      {/* Example queries */}
      <div>
        <div
          className="text-[10px] font-semibold uppercase tracking-wider mb-2"
          style={{ color: "var(--muted)" }}
        >
          Example Queries
        </div>
        <div className="flex flex-col gap-1.5">
          {EXAMPLE_QUERIES.map((eq, i) => (
            <button
              key={i}
              onClick={() => setQuery(eq.query)}
              className="text-left rounded-md border px-3 py-2 text-xs transition-colors hover:bg-[var(--surface-1)]"
              style={{
                background: "var(--surface-0)",
                borderColor: "var(--border)",
              }}
            >
              <div
                className="text-[10px] font-semibold mb-0.5"
                style={{ color: "var(--fg)" }}
              >
                {eq.label}
              </div>
              <div className="font-mono text-[11px] truncate" style={{ color: "var(--muted)" }}>
                {eq.query}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div
          className="rounded-lg border p-4 text-center text-sm text-red-400"
          style={{
            background: "var(--surface-0)",
            borderColor: "var(--border)",
          }}
        >
          {error}
        </div>
      )}

      {/* Results */}
      {loading && (
        <div
          className="rounded-lg border overflow-hidden"
          style={{
            background: "var(--surface-0)",
            borderColor: "var(--border)",
          }}
        >
          {Array.from({ length: 6 }).map((_, i) => (
            <SkeletonRow key={i} />
          ))}
        </div>
      )}

      {results !== null && !loading && (
        <div>
          {/* Results count */}
          <div className="flex items-center gap-2 mb-2">
            <span
              className="text-xs font-semibold"
              style={{
                fontFamily: "var(--font-space-grotesk)",
                color: "var(--fg)",
              }}
            >
              Results
            </span>
            <span
              className="rounded-full px-2 py-0.5 text-[10px] font-mono font-semibold"
              style={{
                background: "var(--primary)",
                color: "var(--primary-fg)",
              }}
            >
              {results.length}
            </span>
          </div>

          {results.length > 0 ? (
            <div
              className="rounded-lg border overflow-hidden"
              style={{
                background: "var(--surface-0)",
                borderColor: "var(--border)",
              }}
            >
              {/* Table header */}
              <div
                className="grid grid-cols-[120px_120px_120px_1fr] gap-2 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider border-b"
                style={{
                  color: "var(--muted-fg)",
                  borderColor: "var(--border)",
                  background: "var(--surface-1)",
                }}
              >
                <span>Time</span>
                <span>Type</span>
                <span>Host</span>
                <span>Summary</span>
              </div>

              {/* Rows */}
              {results.map((evt, i) => (
                <div
                  key={evt.id || i}
                  className="grid grid-cols-[120px_120px_120px_1fr] gap-2 px-3 py-2 text-xs border-b last:border-b-0 hover:bg-[var(--surface-1)] transition-colors"
                  style={{ borderColor: "var(--border-subtle)" }}
                >
                  {/* Time */}
                  <span
                    className="font-mono truncate"
                    style={{ color: "var(--muted)" }}
                  >
                    {timeAgo(evt.timestamp)}
                  </span>

                  {/* Type badge */}
                  <span className="flex items-center">
                    <span
                      className={cn(
                        "rounded px-1.5 py-0.5 text-[10px] font-mono font-semibold uppercase truncate",
                        eventTypeColor(evt.event_type)
                      )}
                      style={{ background: "var(--surface-2)" }}
                    >
                      {evt.event_type}
                    </span>
                  </span>

                  {/* Host */}
                  <span className="truncate" style={{ color: "var(--fg)" }}>
                    {evt.hostname || "—"}
                  </span>

                  {/* Summary */}
                  <span
                    className="truncate font-mono"
                    style={{ color: "var(--fg)" }}
                  >
                    {summarizeEvent(evt)}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div
              className="rounded-lg border py-12 text-center text-xs"
              style={{
                background: "var(--surface-0)",
                borderColor: "var(--border)",
                color: "var(--muted)",
              }}
            >
              No results found
            </div>
          )}
        </div>
      )}
    </div>
  );
}
