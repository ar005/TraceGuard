"use client";

import { useState, useEffect, useCallback } from "react";
import { api } from "@/lib/api-client";

const EVENT_TYPE_COLORS: Record<string, string> = {
  CLOUD_API:      "#6b7280",
  CLOUD_MUTATION: "#f59e0b",
  AUTH_LOGIN:     "#3b82f6",
  AUTH_LOGOFF:    "#8b5cf6",
  POLICY_CHANGE:  "#ef4444",
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

function EventTypePill({ type }: { type: string }) {
  const color = EVENT_TYPE_COLORS[type] ?? "#6b7280";
  return (
    <span style={{
      display: "inline-block",
      padding: "2px 8px",
      borderRadius: 4,
      fontSize: 11,
      fontWeight: 600,
      background: color + "22",
      color,
      fontFamily: "monospace",
    }}>{type}</span>
  );
}

export default function CloudEventsPage() {
  const [events, setEvents] = useState<XdrEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [eventTypeFilter, setEventTypeFilter] = useState("");
  const [sourceId, setSourceId] = useState("");
  const limit = 100;

  const load = useCallback(async (off: number) => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({
        source_type: "cloud",
        limit: String(limit),
        offset: String(off),
      });
      if (eventTypeFilter) params.set("event_type", eventTypeFilter);
      if (sourceId) params.set("source_id", sourceId);
      const data = await api.get<{ events?: XdrEvent[] }>(`/api/v1/xdr/events?${params}`);
      if (off === 0) setEvents(data.events ?? []);
      else setEvents(prev => [...prev, ...(data.events ?? [])]);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load events");
    } finally {
      setLoading(false);
    }
  }, [api, eventTypeFilter, sourceId]);

  useEffect(() => { setOffset(0); load(0); }, [load]);

  const toggle = (id: string) => setExpanded(prev => prev === id ? null : id);

  return (
    <div style={{ padding: 24, maxWidth: 1400 }}>
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, marginBottom: 4 }}>Cloud Events</h1>
        <p style={{ color: "#6b7280", fontSize: 14 }}>
          AWS CloudTrail · Azure Monitor · GCP Audit Log
        </p>
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
        {["", "CLOUD_API", "CLOUD_MUTATION", "AUTH_LOGIN", "POLICY_CHANGE"].map(t => (
          <button key={t} onClick={() => setEventTypeFilter(t)} style={{
            padding: "4px 12px", borderRadius: 6, border: "1px solid",
            borderColor: eventTypeFilter === t ? "#3b82f6" : "#374151",
            background: eventTypeFilter === t ? "#1d4ed822" : "transparent",
            color: eventTypeFilter === t ? "#3b82f6" : "#9ca3af",
            cursor: "pointer", fontSize: 13,
          }}>{t || "All"}</button>
        ))}
        <input
          placeholder="Source ID filter"
          value={sourceId}
          onChange={e => setSourceId(e.target.value)}
          style={{
            padding: "4px 10px", borderRadius: 6, border: "1px solid #374151",
            background: "#111827", color: "#f3f4f6", fontSize: 13,
          }}
        />
      </div>

      {error && <div style={{ color: "#ef4444", marginBottom: 12 }}>{error}</div>}

      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #374151", color: "#9ca3af" }}>
              {["Time", "Event Type", "User", "Source", "Src IP", ""].map(h => (
                <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontWeight: 600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {events.map(ev => (
              <>
                <tr key={ev.id} onClick={() => toggle(ev.id)} style={{
                  borderBottom: "1px solid #1f2937", cursor: "pointer",
                  background: expanded === ev.id ? "#1f2937" : "transparent",
                }}>
                  <td style={{ padding: "8px 12px", color: "#9ca3af", fontFamily: "monospace", whiteSpace: "nowrap" }}>
                    {new Date(ev.timestamp).toLocaleString()}
                  </td>
                  <td style={{ padding: "8px 12px" }}>
                    <EventTypePill type={ev.event_type} />
                  </td>
                  <td style={{ padding: "8px 12px", color: "#d1d5db", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {ev.user_uid || "—"}
                  </td>
                  <td style={{ padding: "8px 12px", color: "#6b7280", fontFamily: "monospace", fontSize: 11 }}>
                    {ev.source_id || ev.source_type}
                  </td>
                  <td style={{ padding: "8px 12px", color: "#6b7280", fontFamily: "monospace" }}>
                    {ev.src_ip ?? "—"}
                  </td>
                  <td style={{ padding: "8px 12px", color: "#6b7280" }}>
                    {expanded === ev.id ? "▲" : "▼"}
                  </td>
                </tr>
                {expanded === ev.id && (
                  <tr key={ev.id + "-detail"} style={{ background: "#111827" }}>
                    <td colSpan={6} style={{ padding: 16 }}>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                        <div>
                          <div style={{ color: "#6b7280", fontSize: 11, marginBottom: 4 }}>PAYLOAD</div>
                          <pre style={{ margin: 0, fontSize: 12, color: "#d1d5db", overflow: "auto", maxHeight: 200 }}>
                            {JSON.stringify(ev.payload, null, 2)}
                          </pre>
                        </div>
                        <div>
                          <div style={{ color: "#6b7280", fontSize: 11, marginBottom: 4 }}>RAW LOG</div>
                          <pre style={{ margin: 0, fontSize: 11, color: "#9ca3af", overflow: "auto", maxHeight: 200, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                            {ev.raw_log || "—"}
                          </pre>
                        </div>
                      </div>
                      <div style={{ marginTop: 12, color: "#6b7280", fontSize: 11 }}>
                        OCSF class_uid: {ev.class_uid} · event_id: {ev.id}
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
            {!loading && events.length === 0 && (
              <tr>
                <td colSpan={6} style={{ padding: 40, textAlign: "center", color: "#6b7280" }}>
                  No cloud events found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {events.length > 0 && events.length % limit === 0 && (
        <div style={{ marginTop: 16, textAlign: "center" }}>
          <button onClick={() => { const next = offset + limit; setOffset(next); load(next); }}
            disabled={loading}
            style={{ padding: "8px 20px", borderRadius: 6, border: "1px solid #374151", background: "#1f2937", color: "#d1d5db", cursor: "pointer" }}>
            {loading ? "Loading…" : "Load more"}
          </button>
        </div>
      )}
    </div>
  );
}
