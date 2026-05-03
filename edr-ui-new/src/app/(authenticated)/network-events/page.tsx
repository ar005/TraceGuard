"use client";

import { useCallback, useMemo, useState } from "react";
import {
  Globe,
  RefreshCw,
  Search,
  ChevronDown,
  ChevronUp,
  ArrowRight,
  Shield,
  WifiOff,
  Clock,
} from "lucide-react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { timeAgo, formatDate } from "@/lib/utils";
import type { NetworkEvent } from "@/types";

// ── helpers ──────────────────────────────────────────────────────────────────

/** Map OCSF class_uid to a human label */
function classLabel(uid: number): string {
  switch (uid) {
    case 4001: return "Network Activity";
    case 4002: return "HTTP Activity";
    case 4003: return "DNS Activity";
    case 2004: return "Detection Finding";
    case 3002: return "Authentication";
    default:   return `Class ${uid}`;
  }
}

/** Map event_type to a color */
function eventTypeColor(et: string): string {
  switch (et) {
    case "NET_FLOW":    return "oklch(0.62 0.13 200)";
    case "NET_DNS":     return "oklch(0.65 0.14 260)";
    case "NET_HTTP":    return "oklch(0.65 0.14 140)";
    case "ALERT":       return "var(--sev-critical)";
    case "NET_CEF":     return "oklch(0.65 0.14 68)";
    case "NET_SYSLOG":  return "var(--fg-3)";
    case "NET_WEBHOOK": return "oklch(0.65 0.14 300)";
    default:            return "var(--fg-3)";
  }
}

const PAGE_SIZE = 100;

// ── component ─────────────────────────────────────────────────────────────────

export default function NetworkEventsPage() {
  const [search, setSearch]           = useState("");
  const [typeFilter, setTypeFilter]   = useState("");
  const [srcFilter, setSrcFilter]     = useState("");
  const [expandedId, setExpandedId]   = useState<string | null>(null);
  const [offset, setOffset]           = useState(0);
  const [allRows, setAllRows]         = useState<NetworkEvent[]>([]);
  const [loadingMore, setLoadingMore] = useState(false);

  const fetchEvents = useCallback(
    () =>
      api
        .get<{ events?: NetworkEvent[] } | NetworkEvent[]>("/api/v1/events", {
          event_type:  typeFilter || undefined,
          source_id:   srcFilter || undefined,
          search:      search.trim() || undefined,
          source_type: "network",
          limit:       PAGE_SIZE,
          offset:      0,
        })
        .then((r) => {
          const rows = Array.isArray(r) ? r : (r.events ?? []);
          setAllRows(rows);
          setOffset(rows.length);
          return rows;
        }),
    [typeFilter, srcFilter, search]
  );

  const { loading, refetch } = useApi(fetchEvents);

  async function loadMore() {
    setLoadingMore(true);
    try {
      const r = await api.get<{ events?: NetworkEvent[] } | NetworkEvent[]>("/api/v1/events", {
        event_type:  typeFilter || undefined,
        source_id:   srcFilter || undefined,
        search:      search.trim() || undefined,
        source_type: "network",
        limit:       PAGE_SIZE,
        offset,
      });
      const rows = Array.isArray(r) ? r : (r.events ?? []);
      setAllRows((prev) => [...prev, ...rows]);
      setOffset((o) => o + rows.length);
    } finally {
      setLoadingMore(false);
    }
  }

  function handleSearch(val: string) {
    setSearch(val);
    setAllRows([]);
    setOffset(0);
  }

  // Unique event types for filter pills
  const eventTypes = useMemo(
    () => [...new Set(allRows.map((e) => e.event_type))].sort(),
    [allRows]
  );

  // ── render ────────────────────────────────────────────────────────────────

  return (
    <div style={{ padding: "var(--space-6)" }}>
      {/* ── Header ── */}
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-3">
          <Globe size={22} color="var(--primary)" />
          <h1 className="page-title">Network Events</h1>
          {allRows.length > 0 && (
            <span
              style={{
                fontSize: "var(--text-xs)",
                background: "var(--surface-2)",
                color: "var(--fg-2)",
                borderRadius: 9999,
                padding: "2px 10px",
              }}
            >
              {allRows.length.toLocaleString()} loaded
            </span>
          )}
        </div>
        <button
          onClick={() => { setAllRows([]); setOffset(0); refetch(); }}
          className="flex items-center gap-1.5 transition-fast"
          style={{
            fontSize: "var(--text-sm)",
            color: "var(--fg-2)",
            background: "var(--surface-1)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            padding: "6px 12px",
            cursor: "pointer",
          }}
        >
          <RefreshCw size={13} />
          Refresh
        </button>
      </div>

      {/* ── Filters ── */}
      <div className="flex items-center gap-3 mb-4 flex-wrap">
        {/* Search */}
        <div className="relative" style={{ flexGrow: 1, maxWidth: 360 }}>
          <Search
            size={13}
            color="var(--fg-3)"
            style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)" }}
          />
          <input
            value={search}
            onChange={(e) => handleSearch(e.target.value)}
            placeholder="Search IPs, domains, hosts…"
            style={{
              background: "var(--surface-1)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              padding: "7px 10px 7px 30px",
              fontSize: "var(--text-sm)",
              color: "var(--fg)",
              width: "100%",
              outline: "none",
            }}
          />
        </div>

        {/* Event type filter */}
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          style={{
            background: "var(--surface-1)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            padding: "7px 10px",
            fontSize: "var(--text-sm)",
            color: typeFilter ? "var(--fg)" : "var(--fg-3)",
          }}
        >
          <option value="">All event types</option>
          {["NET_FLOW", "NET_DNS", "NET_HTTP", "ALERT", "NET_CEF", "NET_SYSLOG", "NET_WEBHOOK"].map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>

        {/* Source filter */}
        <input
          value={srcFilter}
          onChange={(e) => setSrcFilter(e.target.value)}
          placeholder="Filter by source ID…"
          style={{
            background: "var(--surface-1)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            padding: "7px 10px",
            fontSize: "var(--text-sm)",
            color: "var(--fg)",
            width: 200,
            outline: "none",
          }}
        />

        {/* Active type pills */}
        {eventTypes.slice(0, 6).map((t) => (
          <button
            key={t}
            onClick={() => setTypeFilter(typeFilter === t ? "" : t)}
            style={{
              fontSize: "var(--text-xs)",
              fontWeight: 500,
              color: typeFilter === t ? "var(--primary-fg)" : "var(--fg-2)",
              background: typeFilter === t ? "var(--primary)" : "var(--surface-2)",
              border: `1px solid ${typeFilter === t ? "var(--primary)" : "var(--border)"}`,
              borderRadius: 9999,
              padding: "3px 10px",
              cursor: "pointer",
            }}
          >
            {t}
          </button>
        ))}
      </div>

      {/* ── Table ── */}
      <div
        style={{
          background: "var(--surface-0)",
          border: "1px solid var(--border)",
          borderRadius: 10,
          overflow: "hidden",
        }}
      >
        {/* Column header */}
        <div
          className="grid"
          style={{
            gridTemplateColumns: "24px 130px 140px 24px 140px 110px 100px 1fr",
            padding: "8px 16px",
            borderBottom: "1px solid var(--border)",
            background: "var(--surface-1)",
          }}
        >
          {["", "Time", "Event Type", "", "Src IP", "Dst IP", "Source", "Payload Summary"].map((h, i) => (
            <span key={i} className="section-label" style={{ display: "flex", alignItems: "center" }}>
              {h}
            </span>
          ))}
        </div>

        {loading && (
          <div style={{ padding: "var(--space-8)", textAlign: "center", color: "var(--fg-3)", fontSize: "var(--text-sm)" }}>
            Loading events…
          </div>
        )}

        {!loading && allRows.length === 0 && (
          <div style={{ padding: "var(--space-10)", textAlign: "center" }}>
            <WifiOff size={32} color="var(--fg-4)" style={{ margin: "0 auto 12px" }} />
            <p style={{ fontSize: "var(--text-sm)", color: "var(--fg-3)" }}>No network events found.</p>
            <p style={{ fontSize: "var(--text-xs)", color: "var(--fg-4)", marginTop: 4 }}>
              Configure an XDR source and enable the NATS pipeline to collect network telemetry.
            </p>
          </div>
        )}

        {allRows.map((ev, idx) => {
          const isExpanded = expandedId === ev.id;
          const isLast = idx === allRows.length - 1;
          const payload = ev.payload ?? {};

          // Build a short payload summary
          const summaryParts: string[] = [];
          if (payload.query)       summaryParts.push(`query=${payload.query}`);
          if (payload.domain)      summaryParts.push(`domain=${payload.domain}`);
          if (payload.host)        summaryParts.push(`host=${payload.host}`);
          if (payload.uri)         summaryParts.push(`uri=${payload.uri}`);
          if (payload.method)      summaryParts.push(`${payload.method}`);
          if (payload.status_code) summaryParts.push(`${payload.status_code}`);
          if (payload.signature)   summaryParts.push(String(payload.signature));
          if (payload.proto)       summaryParts.push(`proto=${payload.proto}`);
          const summary = summaryParts.join(" · ") || ev.raw_log?.slice(0, 80) || "—";

          return (
            <div key={ev.id} style={{ borderBottom: isLast ? "none" : "1px solid var(--border)" }}>
              <div
                className="grid transition-fast"
                style={{
                  gridTemplateColumns: "24px 130px 140px 24px 140px 110px 100px 1fr",
                  padding: "9px 16px",
                  alignItems: "center",
                  cursor: "pointer",
                  background: isExpanded ? "var(--surface-1)" : "transparent",
                }}
                onClick={() => setExpandedId(isExpanded ? null : ev.id)}
              >
                <span style={{ color: "var(--fg-4)", display: "flex" }}>
                  {isExpanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                </span>

                {/* Timestamp */}
                <span
                  style={{
                    fontSize: "var(--text-xs)",
                    color: "var(--fg-3)",
                    fontVariantNumeric: "tabular-nums",
                    fontFamily: "var(--font-fira-code), monospace",
                  }}
                >
                  {timeAgo(ev.timestamp)}
                </span>

                {/* Event type badge */}
                <span
                  style={{
                    fontSize: "var(--text-xs)",
                    fontWeight: 600,
                    color: eventTypeColor(ev.event_type),
                    letterSpacing: "0.03em",
                  }}
                >
                  {ev.event_type}
                </span>

                {/* Arrow */}
                <ArrowRight size={11} color="var(--fg-4)" />

                {/* Src IP */}
                <span
                  style={{
                    fontSize: "var(--text-xs)",
                    fontFamily: "var(--font-fira-code), monospace",
                    color: "var(--fg-2)",
                  }}
                >
                  {ev.src_ip || "—"}
                </span>

                {/* Dst IP */}
                <span
                  style={{
                    fontSize: "var(--text-xs)",
                    fontFamily: "var(--font-fira-code), monospace",
                    color: "var(--fg-2)",
                  }}
                >
                  {ev.dst_ip || "—"}
                </span>

                {/* Source ID */}
                <span
                  style={{
                    fontSize: "var(--text-xs)",
                    color: "var(--fg-3)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {ev.source_id}
                </span>

                {/* Payload summary */}
                <span
                  style={{
                    fontSize: "var(--text-xs)",
                    color: "var(--fg-3)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {summary}
                </span>
              </div>

              {/* Expanded detail */}
              {isExpanded && (
                <div
                  style={{
                    padding: "12px 16px 16px 40px",
                    borderTop: "1px solid var(--border)",
                    background: "var(--surface-1)",
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr",
                    gap: 16,
                  }}
                >
                  {/* OCSF info */}
                  <div>
                    <p className="section-label" style={{ marginBottom: 8 }}>OCSF Classification</p>
                    <div
                      style={{
                        background: "var(--surface-2)",
                        border: "1px solid var(--border)",
                        borderRadius: 6,
                        padding: "10px 14px",
                        display: "flex",
                        flexDirection: "column",
                        gap: 7,
                      }}
                    >
                      <NetStatRow label="Class" value={`${classLabel(ev.class_uid)} (${ev.class_uid})`} />
                      <NetStatRow label="Event ID"    value={ev.id} mono />
                      <NetStatRow label="Source ID"   value={ev.source_id} mono />
                      <NetStatRow label="Source Type" value={ev.source_type} />
                      <NetStatRow label="Tenant"      value={ev.tenant_id} />
                      <NetStatRow label="Received"    value={formatDate(ev.received_at)} />
                    </div>
                  </div>

                  {/* Payload */}
                  <div>
                    <p className="section-label" style={{ marginBottom: 8 }}>Parsed Payload</p>
                    <pre
                      style={{
                        fontSize: "var(--text-xs)",
                        fontFamily: "var(--font-fira-code), monospace",
                        color: "var(--fg-2)",
                        background: "var(--surface-2)",
                        border: "1px solid var(--border)",
                        borderRadius: 6,
                        padding: "10px 12px",
                        overflowX: "auto",
                        margin: 0,
                        maxHeight: 200,
                        overflowY: "auto",
                      }}
                    >
                      {JSON.stringify(ev.payload ?? {}, null, 2)}
                    </pre>

                    {ev.enrichments && Object.keys(ev.enrichments).length > 0 && (
                      <>
                        <p className="section-label" style={{ marginBottom: 6, marginTop: 12 }}>Enrichments</p>
                        <pre
                          style={{
                            fontSize: "var(--text-xs)",
                            fontFamily: "var(--font-fira-code), monospace",
                            color: "oklch(0.65 0.14 200)",
                            background: "var(--surface-2)",
                            border: "1px solid var(--border)",
                            borderRadius: 6,
                            padding: "8px 12px",
                            overflowX: "auto",
                            margin: 0,
                          }}
                        >
                          {JSON.stringify(ev.enrichments, null, 2)}
                        </pre>
                      </>
                    )}
                  </div>

                  {/* Raw log */}
                  {ev.raw_log && (
                    <div style={{ gridColumn: "1 / -1" }}>
                      <p className="section-label" style={{ marginBottom: 6 }}>Raw Log</p>
                      <pre
                        style={{
                          fontSize: "var(--text-xs)",
                          fontFamily: "var(--font-fira-code), monospace",
                          color: "var(--fg-3)",
                          background: "var(--surface-2)",
                          border: "1px solid var(--border)",
                          borderRadius: 6,
                          padding: "8px 12px",
                          overflowX: "auto",
                          margin: 0,
                          whiteSpace: "pre-wrap",
                          wordBreak: "break-all",
                        }}
                      >
                        {ev.raw_log}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* ── Load more ── */}
      {allRows.length > 0 && allRows.length % PAGE_SIZE === 0 && (
        <div className="flex justify-center mt-4">
          <button
            onClick={loadMore}
            disabled={loadingMore}
            style={{
              fontSize: "var(--text-sm)",
              color: "var(--fg-2)",
              background: "var(--surface-1)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              padding: "7px 20px",
              cursor: loadingMore ? "not-allowed" : "pointer",
              opacity: loadingMore ? 0.6 : 1,
            }}
          >
            {loadingMore ? "Loading…" : `Load next ${PAGE_SIZE}`}
          </button>
        </div>
      )}

      {/* ── Info ── */}
      <div
        className="flex items-start gap-2 mt-4"
        style={{
          background: "var(--surface-1)",
          border: "1px solid var(--border)",
          borderRadius: 8,
          padding: "10px 14px",
          fontSize: "var(--text-xs)",
          color: "var(--fg-3)",
        }}
      >
        <Shield size={13} style={{ marginTop: 1, flexShrink: 0 }} color="var(--primary)" />
        <span>
          Network events are normalized to{" "}
          <strong style={{ color: "var(--fg-2)" }}>OCSF</strong> (Open Cybersecurity Schema Framework)
          class UIDs. Enrichments show IP → endpoint and identity correlations from the XDR stitcher.
        </span>
      </div>
    </div>
  );
}

function NetStatRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between items-start gap-4">
      <span style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)", flexShrink: 0 }}>{label}</span>
      <span
        style={{
          fontSize: "var(--text-xs)",
          color: "var(--fg-2)",
          fontFamily: mono ? "var(--font-fira-code), monospace" : undefined,
          textAlign: "right",
          wordBreak: "break-all",
        }}
      >
        {value}
      </span>
    </div>
  );
}
