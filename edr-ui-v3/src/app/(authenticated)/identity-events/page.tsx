"use client";

import { useState, useEffect, useCallback } from "react";
import { api } from "@/lib/api-client";

const EVENT_TYPE_COLORS: Record<string, string> = {
  AUTH_LOGIN:     "#3b82f6",
  AUTH_LOGOFF:    "#8b5cf6",
  POLICY_CHANGE:  "#ef4444",
  IDENTITY_EVENT: "#6b7280",
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
  raw_log: string;
}

function EventTypePill({ type }: { type: string }) {
  const color = EVENT_TYPE_COLORS[type] ?? "#6b7280";
  return (
    <span style={{
      display: "inline-block", padding: "2px 8px", borderRadius: 4,
      fontSize: 11, fontWeight: 600, background: color + "22", color,
      fontFamily: "monospace",
    }}>{type}</span>
  );
}

export default function IdentityEventsPage() {
  const [events, setEvents] = useState<XdrEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [eventTypeFilter, setEventTypeFilter] = useState("");
  const limit = 100;

  const load = useCallback(async (off: number) => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({
        source_type: "identity",
        limit: String(limit),
        offset: String(off),
      });
      if (eventTypeFilter) params.set("event_type", eventTypeFilter);
      const data = await api.get<{ events?: XdrEvent[] }>(`/api/v1/xdr/events?${params}`);
      if (off === 0) setEvents(data.events ?? []);
      else setEvents(prev => [...prev, ...(data.events ?? [])]);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load events");
    } finally {
      setLoading(false);
    }
  }, [api, eventTypeFilter]);

  useEffect(() => { setOffset(0); load(0); }, [load]);

  const toggle = (id: string) => setExpanded(prev => prev === id ? null : id);

  return (
    <div style={{ padding: 24, maxWidth: 1400 }}>
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, marginBottom: 4 }}>Identity Events</h1>
        <p style={{ color: "#6b7280", fontSize: 14 }}>Okta System Log · Active Directory · LDAP</p>
      </div>

      <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
        {["", "AUTH_LOGIN", "AUTH_LOGOFF", "POLICY_CHANGE", "IDENTITY_EVENT"].map(t => (
          <button key={t} onClick={() => setEventTypeFilter(t)} style={{
            padding: "4px 12px", borderRadius: 6, border: "1px solid",
            borderColor: eventTypeFilter === t ? "#3b82f6" : "#374151",
            background: eventTypeFilter === t ? "#1d4ed822" : "transparent",
            color: eventTypeFilter === t ? "#3b82f6" : "#9ca3af",
            cursor: "pointer", fontSize: 13,
          }}>{t || "All"}</button>
        ))}
      </div>

      {error && <div style={{ color: "#ef4444", marginBottom: 12 }}>{error}</div>}

      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
        <thead>
          <tr style={{ borderBottom: "1px solid #374151", color: "#9ca3af" }}>
            {["Time", "Event Type", "User", "Src IP", "Source", ""].map(h => (
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
                <td style={{ padding: "8px 12px" }}><EventTypePill type={ev.event_type} /></td>
                <td style={{ padding: "8px 12px", color: "#d1d5db" }}>{ev.user_uid || "—"}</td>
                <td style={{ padding: "8px 12px", color: "#6b7280", fontFamily: "monospace" }}>{ev.src_ip ?? "—"}</td>
                <td style={{ padding: "8px 12px", color: "#6b7280", fontSize: 11 }}>{ev.source_id || ev.source_type}</td>
                <td style={{ padding: "8px 12px", color: "#6b7280" }}>{expanded === ev.id ? "▲" : "▼"}</td>
              </tr>
              {expanded === ev.id && (
                <tr key={ev.id + "-d"} style={{ background: "#111827" }}>
                  <td colSpan={6} style={{ padding: 16 }}>
                    <pre style={{ margin: 0, fontSize: 12, color: "#d1d5db", overflow: "auto", maxHeight: 200 }}>
                      {JSON.stringify(ev.payload, null, 2)}
                    </pre>
                  </td>
                </tr>
              )}
            </>
          ))}
          {!loading && events.length === 0 && (
            <tr>
              <td colSpan={6} style={{ padding: 40, textAlign: "center", color: "#6b7280" }}>No identity events found</td>
            </tr>
          )}
        </tbody>
      </table>

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
