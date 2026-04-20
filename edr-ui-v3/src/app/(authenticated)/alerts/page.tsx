"use client";

import { useCallback, useMemo, useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { timeAgo, formatDate } from "@/lib/utils";
import type { Alert, Event } from "@/types";
import {
  ChevronDown, ChevronRight, Sparkles, Tag, Clock,
  MonitorCheck, ArrowRight, RefreshCw, Search,
} from "lucide-react";

// ── Helpers ──────────────────────────────────────────────────────────────────

const SEV_LABELS = ["INFO", "LOW", "MED", "HIGH", "CRIT"] as const;
const SEV_NAMES  = ["info", "low", "medium", "high", "critical"] as const;

function sevLabel(n: number) { return SEV_LABELS[n] ?? "?"; }
function sevName(n: number)  { return SEV_NAMES[n]  ?? "info"; }

function statusStyle(s: string): React.CSSProperties {
  switch (s?.toLowerCase()) {
    case "open":
      return { background: "var(--sev-critical-bg)", color: "var(--sev-critical)" };
    case "investigating":
    case "in_progress":
      return { background: "var(--sev-medium-bg)", color: "var(--sev-medium)" };
    case "closed":
    case "resolved":
      return { background: "var(--sev-low-bg)", color: "var(--sev-low)" };
    default:
      return { background: "var(--surface-2)", color: "var(--fg-3)" };
  }
}

// ── AI explain stub ──────────────────────────────────────────────────────────

async function fetchAiExplanation(alert: Alert): Promise<string> {
  try {
    const res = await api.post<{ explanation?: string; response?: string; text?: string }>(
      "/api/v1/alerts/" + alert.id + "/explain",
      {}
    );
    return res.explanation ?? res.response ?? res.text ?? "No explanation available.";
  } catch {
    // Compose a local fallback explanation from the alert's own data
    const sev = SEV_LABELS[alert.severity ?? 0] ?? "UNKNOWN";
    const tactics = (alert.mitre_ids ?? []).join(", ") || "unknown";
    return [
      `This is a ${sev} severity alert triggered by rule "${alert.rule_name ?? "Unknown Rule"}".`,
      alert.description ? `\n\n${alert.description}` : "",
      tactics !== "unknown" ? `\n\nMITRE ATT&CK tactics: ${tactics}.` : "",
      "\n\nReview the event timeline below to understand the sequence of activity that triggered this rule.",
    ].join("").trim();
  }
}

// ── Filter bar ───────────────────────────────────────────────────────────────

const STATUS_OPTS = [
  { label: "All",           value: "" },
  { label: "Open",          value: "open" },
  { label: "Investigating", value: "investigating" },
  { label: "Closed",        value: "closed" },
];
const SEV_OPTS = [
  { label: "All",      value: -1 },
  { label: "Critical", value: 4 },
  { label: "High",     value: 3 },
  { label: "Medium",   value: 2 },
  { label: "Low",      value: 1 },
  { label: "Info",     value: 0 },
];

function FilterChip({
  label, active, onClick,
}: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "3px 10px",
        borderRadius: "20px",
        fontSize: "var(--text-xs)",
        fontWeight: active ? 600 : 400,
        fontFamily: "var(--font-archivo)",
        cursor: "pointer",
        border: "1px solid",
        transition: "all 0.12s",
        background: active ? "var(--primary)" : "transparent",
        borderColor: active ? "var(--primary)" : "var(--border)",
        color: active ? "var(--primary-fg)" : "var(--fg-2)",
      }}
    >
      {label}
    </button>
  );
}

// ── Expanded alert detail ─────────────────────────────────────────────────────

function AlertExpanded({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  const [aiText, setAiText] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiOpen, setAiOpen] = useState(false);

  const fetchEvents = useCallback(
    () => api.get<Event[]>(`/api/v1/alerts/${alert.id}/events`).catch(() => []),
    [alert.id]
  );
  const { data: events, loading: eventsLoading } = useApi(fetchEvents);

  const handleAiExplain = async () => {
    if (aiText) { setAiOpen(o => !o); return; }
    setAiOpen(true);
    setAiLoading(true);
    const text = await fetchAiExplanation(alert);
    setAiText(text);
    setAiLoading(false);
  };

  const handleStatusChange = async (status: string) => {
    try {
      await api.patch(`/api/v1/alerts/${alert.id}`, { status });
    } catch {/* ignore */}
  };

  return (
    <div
      style={{
        padding: "var(--space-4) var(--space-6) var(--space-4) 52px",
        borderTop: "1px solid var(--border)",
        background: "var(--surface-1)",
        display: "grid",
        gridTemplateColumns: "1fr 1fr",
        gap: "var(--space-6)",
      }}
    >
      {/* Left: meta + MITRE + AI */}
      <div>
        {/* Meta row */}
        <div className="flex flex-wrap gap-4" style={{ marginBottom: "var(--space-4)" }}>
          <span style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)" }}>
            <Clock size={10} style={{ display: "inline", marginRight: "3px", verticalAlign: "middle" }} />
            {formatDate(alert.first_seen)}
          </span>
          {alert.hostname && (
            <span style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)" }}>
              <MonitorCheck size={10} style={{ display: "inline", marginRight: "3px", verticalAlign: "middle" }} />
              {alert.hostname}
            </span>
          )}
          {alert.agent_id && (
            <span
              className="font-mono"
              style={{ fontSize: "var(--text-xs)", color: "var(--fg-4)" }}
            >
              {alert.agent_id.slice(0, 8)}
            </span>
          )}
        </div>

        {/* Description */}
        {alert.description && (
          <p style={{ fontSize: "var(--text-sm)", color: "var(--fg-2)", lineHeight: 1.6, marginBottom: "var(--space-4)", maxWidth: "60ch" }}>
            {alert.description}
          </p>
        )}

        {/* MITRE tags */}
        {!!alert.mitre_ids?.length && (
          <div style={{ marginBottom: "var(--space-4)" }}>
            <span className="section-label" style={{ marginBottom: "var(--space-2)", display: "block" }}>
              MITRE ATT&amp;CK
            </span>
            <div className="flex flex-wrap gap-1">
              {(alert.mitre_ids ?? []).map(t => (
                <span
                  key={t}
                  style={{
                    padding: "2px 8px",
                    borderRadius: "4px",
                    fontSize: "var(--text-xs)",
                    fontFamily: "var(--font-fira-code)",
                    background: "var(--surface-2)",
                    color: "var(--fg-2)",
                    border: "1px solid var(--border)",
                  }}
                >
                  {t}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* AI Explain */}
        <div>
          <button
            onClick={handleAiExplain}
            className="flex items-center gap-1 transition-fast"
            style={{
              background: "none",
              border: "none",
              padding: "0",
              cursor: "pointer",
              fontSize: "var(--text-xs)",
              color: "oklch(0.65 0.14 265)",
              fontFamily: "var(--font-onest)",
            }}
          >
            <Sparkles size={11} />
            {aiOpen ? "Hide explanation" : "Explain this alert"}
          </button>

          {aiOpen && (
            <div className="ai-explain" style={{ marginTop: "var(--space-2)" }}>
              {aiLoading ? (
                <div className="flex items-center gap-2" style={{ color: "oklch(0.65 0.14 265)" }}>
                  <span
                    className="inline-block w-3 h-3 rounded-full border border-t-transparent animate-spin"
                    style={{ borderColor: "currentColor", borderTopColor: "transparent" }}
                  />
                  <span>Generating explanation…</span>
                </div>
              ) : (
                <p style={{ margin: 0, whiteSpace: "pre-wrap" }}>{aiText}</p>
              )}
            </div>
          )}
        </div>

        {/* Status actions */}
        <div className="flex gap-2" style={{ marginTop: "var(--space-4)" }}>
          {["investigating", "closed"].map(s => (
            <button
              key={s}
              onClick={() => handleStatusChange(s)}
              className="transition-fast"
              style={{
                padding: "4px 12px",
                borderRadius: "6px",
                fontSize: "var(--text-xs)",
                fontWeight: 600,
                fontFamily: "var(--font-archivo)",
                cursor: "pointer",
                background: "var(--surface-2)",
                border: "1px solid var(--border)",
                color: "var(--fg-2)",
                textTransform: "capitalize",
              }}
            >
              Mark {s}
            </button>
          ))}
        </div>
      </div>

      {/* Right: event timeline */}
      <div>
        <span className="section-label" style={{ marginBottom: "var(--space-2)", display: "block" }}>
          Event Timeline
        </span>
        <div
          style={{
            background: "var(--surface-0)",
            border: "1px solid var(--border)",
            borderRadius: "8px",
            overflow: "hidden",
            maxHeight: "260px",
            overflowY: "auto",
          }}
        >
          {eventsLoading ? (
            Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 px-3 py-2">
                <div className="animate-shimmer h-3 w-24 rounded" />
                <div className="animate-shimmer h-3 flex-1 rounded" />
              </div>
            ))
          ) : !events?.length ? (
            <p style={{ padding: "var(--space-4)", fontSize: "var(--text-xs)", color: "var(--fg-4)" }}>
              No correlated events
            </p>
          ) : (
            events.map((ev, i) => (
              <div
                key={ev.id ?? i}
                className="flex items-start gap-3"
                style={{
                  padding: "6px var(--space-3)",
                  borderBottom: i < events.length - 1 ? "1px solid var(--border)" : "none",
                }}
              >
                <span
                  style={{
                    fontSize: "var(--text-xs)",
                    fontFamily: "var(--font-fira-code)",
                    color: "var(--fg-4)",
                    whiteSpace: "nowrap",
                    marginTop: "1px",
                    flexShrink: 0,
                  }}
                >
                  {timeAgo(ev.timestamp)}
                </span>
                <span
                  style={{
                    fontSize: "var(--text-xs)",
                    fontWeight: 600,
                    fontFamily: "var(--font-archivo)",
                    color: "var(--primary)",
                    whiteSpace: "nowrap",
                    flexShrink: 0,
                  }}
                >
                  {(ev.event_type ?? "EVT").replace(/_/g, "·")}
                </span>
                <span
                  style={{ fontSize: "var(--text-xs)", color: "var(--fg-2)", minWidth: 0 }}
                  className="truncate"
                >
                  {ev.hostname}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

// ── Alert row ─────────────────────────────────────────────────────────────────

function AlertRow({
  alert, expanded, onToggle,
}: { alert: Alert; expanded: boolean; onToggle: () => void }) {
  const sev = alert.severity ?? 0;
  const name = sevName(sev);

  return (
    <>
      <button
        onClick={onToggle}
        className={`w-full text-left flex items-center gap-3 transition-fast sev-row-${name}`}
        style={{
          padding: "7px var(--space-4)",
          borderRadius: expanded ? "8px 8px 0 0" : "8px",
          cursor: "pointer",
          background: expanded ? `var(--sev-${name}-bg)` : undefined,
          border: "none",
          display: "flex",
        }}
      >
        {/* Expand chevron */}
        <span style={{ color: "var(--fg-4)", flexShrink: 0 }}>
          {expanded
            ? <ChevronDown size={13} />
            : <ChevronRight size={13} />
          }
        </span>

        {/* Severity label — Archivo Black */}
        <span
          style={{
            fontFamily: "var(--font-archivo)",
            fontWeight: 900,
            fontSize: "var(--text-xs)",
            letterSpacing: "0.06em",
            color: `var(--sev-${name})`,
            width: "34px",
            flexShrink: 0,
          }}
        >
          {sevLabel(sev)}
        </span>

        {/* Rule name */}
        <span
          style={{
            fontSize: "var(--text-sm)",
            color: "var(--fg)",
            flex: 1,
            minWidth: 0,
            textAlign: "left",
          }}
          className="truncate"
        >
          {alert.rule_name ?? alert.title ?? "Alert"}
        </span>

        {/* Agent hostname */}
        {alert.hostname && (
          <span
            style={{
              fontSize: "var(--text-xs)",
              color: "var(--fg-3)",
              flexShrink: 0,
              fontFamily: "var(--font-fira-code)",
            }}
          >
            {alert.hostname}
          </span>
        )}

        {/* Status badge */}
        <span
          style={{
            ...statusStyle(alert.status ?? ""),
            padding: "2px 8px",
            borderRadius: "20px",
            fontSize: "var(--text-xs)",
            fontWeight: 600,
            fontFamily: "var(--font-archivo)",
            letterSpacing: "0.04em",
            flexShrink: 0,
          }}
        >
          {(alert.status ?? "open").toUpperCase()}
        </span>

        {/* Time */}
        <span
          style={{
            fontSize: "var(--text-xs)",
            color: "var(--fg-3)",
            flexShrink: 0,
            whiteSpace: "nowrap",
            minWidth: "60px",
            textAlign: "right",
          }}
        >
          {timeAgo(alert.first_seen)}
        </span>
      </button>

      {expanded && (
        <div
          style={{
            background: "var(--surface-1)",
            border: "1px solid var(--border)",
            borderTop: "none",
            borderRadius: "0 0 8px 8px",
            overflow: "hidden",
          }}
        >
          <AlertExpanded alert={alert} onClose={onToggle} />
        </div>
      )}
    </>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function AlertsPage() {
  const [statusFilter, setStatusFilter] = useState("");
  const [sevFilter, setSevFilter] = useState(-1);
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const fetchAlerts = useCallback(
    () => api.get<{ alerts?: Alert[] } | Alert[]>("/api/v1/alerts", {
      status: statusFilter || undefined,
      severity: sevFilter >= 0 ? sevFilter : undefined,
      limit: 200,
    }).then(r => Array.isArray(r) ? r : r.alerts ?? []),
    [statusFilter, sevFilter]
  );
  const { data: alerts, loading, refetch: refresh } = useApi(fetchAlerts);

  const displayed = useMemo(() => {
    const all = alerts ?? [];
    if (!searchQuery.trim()) return all;
    const q = searchQuery.toLowerCase();
    return all.filter(a =>
      (a.rule_name ?? "").toLowerCase().includes(q) ||
      (a.title ?? "").toLowerCase().includes(q) ||
      (a.hostname ?? "").toLowerCase().includes(q) ||
      (a.description ?? "").toLowerCase().includes(q)
    );
  }, [alerts, searchQuery]);

  const toggleRow = (id: string) =>
    setExpandedId(prev => prev === id ? null : id);

  return (
    <div style={{ width: "100%" }}>
      {/* Page header */}
      <div
        className="flex items-center justify-between"
        style={{ marginBottom: "var(--space-6)" }}
      >
        <div>
          <h1 className="page-title">Alerts</h1>
          {!loading && (
            <p style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)", marginTop: "2px" }}>
              {displayed.length} result{displayed.length !== 1 ? "s" : ""}
            </p>
          )}
        </div>
        <button
          onClick={() => refresh?.()}
          className="flex items-center gap-1 transition-fast"
          style={{
            background: "none",
            border: "1px solid var(--border)",
            borderRadius: "6px",
            padding: "5px 10px",
            fontSize: "var(--text-xs)",
            color: "var(--fg-2)",
            cursor: "pointer",
            fontFamily: "var(--font-onest)",
          }}
        >
          <RefreshCw size={11} /> Refresh
        </button>
      </div>

      {/* Filters + search */}
      <div
        className="flex flex-wrap items-center gap-3"
        style={{ marginBottom: "var(--space-4)" }}
      >
        {/* Search */}
        <div style={{ position: "relative", flexShrink: 0 }}>
          <Search
            size={13}
            style={{
              position: "absolute",
              left: "9px",
              top: "50%",
              transform: "translateY(-50%)",
              color: "var(--fg-4)",
              pointerEvents: "none",
            }}
          />
          <input
            type="search"
            placeholder="Search rule, host…"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            style={{
              background: "var(--surface-0)",
              border: "1px solid var(--border)",
              borderRadius: "6px",
              padding: "5px 10px 5px 28px",
              fontSize: "var(--text-xs)",
              color: "var(--fg)",
              fontFamily: "var(--font-onest)",
              outline: "none",
              width: "200px",
            }}
          />
        </div>

        <div style={{ width: "1px", background: "var(--border)", alignSelf: "stretch" }} />

        <div className="flex items-center gap-1">
          <span className="section-label" style={{ marginRight: "var(--space-2)" }}>Status</span>
          {STATUS_OPTS.map(o => (
            <FilterChip
              key={o.value}
              label={o.label}
              active={statusFilter === o.value}
              onClick={() => setStatusFilter(o.value)}
            />
          ))}
        </div>
        <div style={{ width: "1px", background: "var(--border)", alignSelf: "stretch" }} />
        <div className="flex items-center gap-1">
          <span className="section-label" style={{ marginRight: "var(--space-2)" }}>Severity</span>
          {SEV_OPTS.map(o => (
            <FilterChip
              key={o.value}
              label={o.label}
              active={sevFilter === o.value}
              onClick={() => setSevFilter(o.value)}
            />
          ))}
        </div>
      </div>

      {/* Column headers */}
      <div
        className="flex items-center gap-3"
        style={{
          padding: "4px var(--space-4)",
          marginBottom: "var(--space-1)",
        }}
      >
        <span style={{ width: "13px", flexShrink: 0 }} />
        <span className="section-label" style={{ width: "34px", flexShrink: 0 }}>SEV</span>
        <span className="section-label" style={{ flex: 1 }}>Rule</span>
        <span className="section-label" style={{ flexShrink: 0, minWidth: "80px" }}>Agent</span>
        <span className="section-label" style={{ flexShrink: 0, minWidth: "80px" }}>Status</span>
        <span className="section-label" style={{ flexShrink: 0, minWidth: "60px", textAlign: "right" }}>When</span>
      </div>

      {/* Alert rows */}
      <div className="flex flex-col gap-1">
        {loading ? (
          Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="animate-shimmer h-9 rounded-lg" />
          ))
        ) : !displayed.length ? (
          <div
            className="flex flex-col items-center"
            style={{
              padding: "var(--space-16) 0",
              background: "var(--surface-0)",
              borderRadius: "10px",
              border: "1px solid var(--border)",
              textAlign: "center",
            }}
          >
            <p style={{ fontSize: "var(--text-base)", color: "var(--fg-3)", fontWeight: 500 }}>
              No alerts match these filters
            </p>
            <p style={{ fontSize: "var(--text-sm)", color: "var(--fg-4)", maxWidth: "36ch", marginTop: "var(--space-2)" }}>
              TraceGuard evaluates every endpoint event against your detection rules. Alerts appear here when a rule fires.
            </p>
          </div>
        ) : (
          displayed.map(a => (
            <AlertRow
              key={a.id}
              alert={a}
              expanded={expandedId === a.id}
              onToggle={() => toggleRow(a.id)}
            />
          ))
        )}
      </div>
    </div>
  );
}
