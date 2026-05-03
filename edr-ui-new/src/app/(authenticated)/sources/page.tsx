"use client";

import { useCallback, useState } from "react";
import {
  Network,
  Plus,
  RefreshCw,
  Trash2,
  ToggleLeft,
  ToggleRight,
  AlertCircle,
  CheckCircle2,
  Clock,
  ChevronDown,
  ChevronUp,
  Zap,
} from "lucide-react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { timeAgo } from "@/lib/utils";
import type { XdrSource, XdrSourceHealth } from "@/types";

// ── helpers ──────────────────────────────────────────────────────────────────

const CONNECTOR_LABELS: Record<string, string> = {
  zeek:     "Zeek (TSV)",
  suricata: "Suricata (EVE)",
  syslog:   "Syslog / CEF",
  webhook:  "Webhook",
};

const SOURCE_TYPE_COLORS: Record<string, string> = {
  network:  "oklch(0.62 0.14 200)",
  cloud:    "oklch(0.62 0.14 240)",
  identity: "oklch(0.62 0.14 140)",
  email:    "oklch(0.62 0.14 68)",
  saas:     "oklch(0.62 0.14 300)",
};

function connectorDefaultConfig(connector: string): string {
  switch (connector) {
    case "zeek":     return JSON.stringify({ log_dir: "/opt/zeek/logs/current", poll_interval_ms: 500 }, null, 2);
    case "suricata": return JSON.stringify({ eve_log: "/var/log/suricata/eve.json", poll_interval_ms: 500 }, null, 2);
    case "syslog":   return JSON.stringify({ udp_addr: ":514", max_message_bytes: 65536 }, null, 2);
    case "webhook":  return JSON.stringify({ listen_addr: ":9000", path_prefix: "/webhook", secret: "" }, null, 2);
    default:         return "{}";
  }
}

// ── blank form state ──────────────────────────────────────────────────────────

const BLANK_FORM = {
  name: "",
  source_type: "network",
  connector: "zeek",
  enabled: true,
  config: connectorDefaultConfig("zeek"),
};

// ── component ─────────────────────────────────────────────────────────────────

export default function SourcesPage() {
  const [expandedId, setExpandedId]   = useState<string | null>(null);
  const [showForm, setShowForm]       = useState(false);
  const [form, setForm]               = useState(BLANK_FORM);
  const [formError, setFormError]     = useState("");
  const [saving, setSaving]           = useState(false);
  const [healthMap, setHealthMap]     = useState<Record<string, XdrSourceHealth>>({});
  const [checkingId, setCheckingId]   = useState<string | null>(null);

  const fetchSources = useCallback(
    (signal: AbortSignal) =>
      api
        .get<{ sources?: XdrSource[] } | XdrSource[]>("/api/v1/sources", undefined, signal)
        .then((r) => (Array.isArray(r) ? r : r.sources ?? [])),
    []
  );
  const { data: sources, loading, refetch } = useApi(fetchSources);

  // ── actions ──────────────────────────────────────────────────────────────

  async function handleToggle(src: XdrSource) {
    await api.put(`/api/v1/sources/${src.id}`, { ...src, enabled: !src.enabled });
    refetch();
  }

  async function handleDelete(id: string) {
    if (!confirm("Delete this source? Running connectors will stop.")) return;
    await api.del(`/api/v1/sources/${id}`);
    refetch();
  }

  async function handleCheckHealth(src: XdrSource) {
    setCheckingId(src.id);
    try {
      const h = await api.get<XdrSourceHealth>(`/api/v1/sources/${src.id}/health`);
      setHealthMap((m) => ({ ...m, [src.id]: h }));
    } finally {
      setCheckingId(null);
    }
  }

  async function handleCreate() {
    setFormError("");
    let parsed: unknown;
    try {
      parsed = JSON.parse(form.config);
    } catch {
      setFormError("Config must be valid JSON.");
      return;
    }
    if (!form.name.trim()) {
      setFormError("Name is required.");
      return;
    }
    setSaving(true);
    try {
      await api.post("/api/v1/sources", {
        name: form.name.trim(),
        source_type: form.source_type,
        connector: form.connector,
        enabled: form.enabled,
        config: parsed,
      });
      setShowForm(false);
      setForm(BLANK_FORM);
      refetch();
    } catch (e) {
      setFormError(e instanceof Error ? e.message : "Save failed.");
    } finally {
      setSaving(false);
    }
  }

  // ── render ────────────────────────────────────────────────────────────────

  const list = sources ?? [];

  return (
    <div style={{ padding: "var(--space-6)" }}>
      {/* ── Header ── */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Network size={22} color="var(--primary)" />
          <h1 className="page-title">XDR Sources</h1>
          <span
            style={{
              fontSize: "var(--text-xs)",
              background: "var(--surface-2)",
              color: "var(--fg-2)",
              borderRadius: 9999,
              padding: "2px 10px",
            }}
          >
            {list.length} configured
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={refetch}
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
          <button
            onClick={() => { setShowForm(true); setFormError(""); }}
            className="flex items-center gap-1.5 transition-fast"
            style={{
              fontSize: "var(--text-sm)",
              fontWeight: 600,
              color: "var(--primary-fg)",
              background: "var(--primary)",
              border: "none",
              borderRadius: 6,
              padding: "6px 14px",
              cursor: "pointer",
            }}
          >
            <Plus size={14} />
            Add Source
          </button>
        </div>
      </div>

      {/* ── Add Source Form ── */}
      {showForm && (
        <div
          style={{
            background: "var(--surface-1)",
            border: "1px solid var(--border-hi)",
            borderRadius: 10,
            padding: "var(--space-5)",
            marginBottom: "var(--space-5)",
          }}
        >
          <h2 style={{ fontSize: "var(--text-base)", fontWeight: 600, marginBottom: 16, color: "var(--fg)" }}>
            New Source
          </h2>
          <div className="grid gap-4" style={{ gridTemplateColumns: "1fr 1fr 1fr" }}>
            <label className="flex flex-col gap-1">
              <span style={{ fontSize: "var(--text-xs)", color: "var(--fg-2)", fontWeight: 500 }}>Name</span>
              <input
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="e.g. Prod Zeek"
                style={{
                  background: "var(--surface-2)",
                  border: "1px solid var(--border)",
                  borderRadius: 6,
                  padding: "6px 10px",
                  fontSize: "var(--text-sm)",
                  color: "var(--fg)",
                  outline: "none",
                }}
              />
            </label>
            <label className="flex flex-col gap-1">
              <span style={{ fontSize: "var(--text-xs)", color: "var(--fg-2)", fontWeight: 500 }}>Connector</span>
              <select
                value={form.connector}
                onChange={(e) =>
                  setForm((f) => ({
                    ...f,
                    connector: e.target.value,
                    config: connectorDefaultConfig(e.target.value),
                  }))
                }
                style={{
                  background: "var(--surface-2)",
                  border: "1px solid var(--border)",
                  borderRadius: 6,
                  padding: "6px 10px",
                  fontSize: "var(--text-sm)",
                  color: "var(--fg)",
                }}
              >
                {Object.entries(CONNECTOR_LABELS).map(([k, v]) => (
                  <option key={k} value={k}>{v}</option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span style={{ fontSize: "var(--text-xs)", color: "var(--fg-2)", fontWeight: 500 }}>Source Type</span>
              <select
                value={form.source_type}
                onChange={(e) => setForm((f) => ({ ...f, source_type: e.target.value }))}
                style={{
                  background: "var(--surface-2)",
                  border: "1px solid var(--border)",
                  borderRadius: 6,
                  padding: "6px 10px",
                  fontSize: "var(--text-sm)",
                  color: "var(--fg)",
                }}
              >
                {["network", "cloud", "identity", "email", "saas"].map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </label>
          </div>
          <label className="flex flex-col gap-1 mt-4">
            <span style={{ fontSize: "var(--text-xs)", color: "var(--fg-2)", fontWeight: 500 }}>
              Config (JSON)
            </span>
            <textarea
              value={form.config}
              onChange={(e) => setForm((f) => ({ ...f, config: e.target.value }))}
              rows={6}
              spellCheck={false}
              style={{
                background: "var(--surface-2)",
                border: "1px solid var(--border)",
                borderRadius: 6,
                padding: "8px 10px",
                fontSize: "var(--text-xs)",
                color: "var(--fg)",
                fontFamily: "var(--font-fira-code), monospace",
                resize: "vertical",
                outline: "none",
              }}
            />
          </label>
          {formError && (
            <p style={{ fontSize: "var(--text-xs)", color: "var(--sev-critical)", marginTop: 8 }}>{formError}</p>
          )}
          <div className="flex items-center gap-2 mt-4">
            <button
              onClick={handleCreate}
              disabled={saving}
              style={{
                fontSize: "var(--text-sm)",
                fontWeight: 600,
                color: "var(--primary-fg)",
                background: "var(--primary)",
                border: "none",
                borderRadius: 6,
                padding: "6px 16px",
                cursor: saving ? "not-allowed" : "pointer",
                opacity: saving ? 0.7 : 1,
              }}
            >
              {saving ? "Saving…" : "Create"}
            </button>
            <button
              onClick={() => { setShowForm(false); setFormError(""); }}
              style={{
                fontSize: "var(--text-sm)",
                color: "var(--fg-2)",
                background: "var(--surface-2)",
                border: "1px solid var(--border)",
                borderRadius: 6,
                padding: "6px 14px",
                cursor: "pointer",
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* ── Table ── */}
      <div
        style={{
          background: "var(--surface-0)",
          border: "1px solid var(--border)",
          borderRadius: 10,
          overflow: "hidden",
        }}
      >
        {/* Header row */}
        <div
          className="grid"
          style={{
            gridTemplateColumns: "28px 1fr 110px 110px 100px 120px 110px 80px",
            padding: "8px 16px",
            borderBottom: "1px solid var(--border)",
            background: "var(--surface-1)",
          }}
        >
          {["", "Name / Connector", "Type", "Status", "Events Today", "Last Seen", "Health", ""].map((h, i) => (
            <span
              key={i}
              className="section-label"
              style={{ display: "flex", alignItems: "center" }}
            >
              {h}
            </span>
          ))}
        </div>

        {loading && (
          <div style={{ padding: "var(--space-8)", textAlign: "center", color: "var(--fg-3)", fontSize: "var(--text-sm)" }}>
            Loading sources…
          </div>
        )}

        {!loading && list.length === 0 && (
          <div style={{ padding: "var(--space-10)", textAlign: "center" }}>
            <Network size={32} color="var(--fg-4)" style={{ margin: "0 auto 12px" }} />
            <p style={{ fontSize: "var(--text-sm)", color: "var(--fg-3)" }}>No sources configured.</p>
            <p style={{ fontSize: "var(--text-xs)", color: "var(--fg-4)", marginTop: 4 }}>
              Add a Zeek, Suricata, Syslog, or Webhook source to begin collecting network telemetry.
            </p>
          </div>
        )}

        {list.map((src, idx) => {
          const health = healthMap[src.id];
          const isExpanded = expandedId === src.id;
          const isLast = idx === list.length - 1;

          return (
            <div key={src.id} style={{ borderBottom: isLast ? "none" : "1px solid var(--border)" }}>
              {/* Main row */}
              <div
                className="grid transition-fast"
                style={{
                  gridTemplateColumns: "28px 1fr 110px 110px 100px 120px 110px 80px",
                  padding: "10px 16px",
                  alignItems: "center",
                  cursor: "pointer",
                  background: isExpanded ? "var(--surface-1)" : "transparent",
                }}
                onClick={() => setExpandedId(isExpanded ? null : src.id)}
              >
                {/* Expand toggle */}
                <span style={{ color: "var(--fg-3)", display: "flex" }}>
                  {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                </span>

                {/* Name / connector */}
                <div>
                  <div style={{ fontSize: "var(--text-sm)", fontWeight: 500, color: "var(--fg)" }}>
                    {src.name}
                  </div>
                  <div style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)", marginTop: 1 }}>
                    {CONNECTOR_LABELS[src.connector] ?? src.connector}
                  </div>
                </div>

                {/* Type badge */}
                <span
                  style={{
                    fontSize: "var(--text-xs)",
                    fontWeight: 500,
                    color: SOURCE_TYPE_COLORS[src.source_type] ?? "var(--fg-2)",
                    background: `${SOURCE_TYPE_COLORS[src.source_type] ?? "var(--fg-3)"}18`,
                    borderRadius: 4,
                    padding: "2px 8px",
                    display: "inline-block",
                  }}
                >
                  {src.source_type}
                </span>

                {/* Enabled status */}
                <div className="flex items-center gap-1.5">
                  <span
                    style={{
                      width: 7,
                      height: 7,
                      borderRadius: "50%",
                      background: src.enabled ? "oklch(0.62 0.16 145)" : "var(--fg-4)",
                      flexShrink: 0,
                    }}
                  />
                  <span style={{ fontSize: "var(--text-xs)", color: src.enabled ? "var(--fg-2)" : "var(--fg-4)" }}>
                    {src.enabled ? "Enabled" : "Disabled"}
                  </span>
                </div>

                {/* Events today */}
                <span style={{ fontSize: "var(--text-sm)", color: "var(--fg-2)", fontVariantNumeric: "tabular-nums" }}>
                  {src.events_today.toLocaleString()}
                </span>

                {/* Last seen */}
                <span style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)" }}>
                  {src.last_seen_at ? timeAgo(src.last_seen_at) : "—"}
                </span>

                {/* Health indicator */}
                <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                  {checkingId === src.id ? (
                    <span style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)" }}>Checking…</span>
                  ) : health ? (
                    <>
                      {health.status === "healthy" ? (
                        <CheckCircle2 size={13} color="oklch(0.62 0.16 145)" />
                      ) : (
                        <AlertCircle size={13} color="var(--sev-critical)" />
                      )}
                      <span
                        style={{
                          fontSize: "var(--text-xs)",
                          color: health.status === "healthy" ? "oklch(0.62 0.16 145)" : "var(--sev-critical)",
                        }}
                      >
                        {health.status}
                      </span>
                    </>
                  ) : (
                    <button
                      onClick={() => handleCheckHealth(src)}
                      style={{
                        fontSize: "var(--text-xs)",
                        color: "var(--fg-3)",
                        background: "transparent",
                        border: "none",
                        cursor: "pointer",
                        display: "flex",
                        alignItems: "center",
                        gap: 4,
                        padding: 0,
                      }}
                    >
                      <Zap size={12} />
                      Check
                    </button>
                  )}
                </div>

                {/* Actions */}
                <div
                  className="flex items-center gap-2 justify-end"
                  onClick={(e) => e.stopPropagation()}
                >
                  <button
                    title={src.enabled ? "Disable" : "Enable"}
                    onClick={() => handleToggle(src)}
                    style={{ background: "none", border: "none", cursor: "pointer", color: "var(--fg-3)", display: "flex" }}
                  >
                    {src.enabled ? <ToggleRight size={18} color="var(--primary)" /> : <ToggleLeft size={18} />}
                  </button>
                  <button
                    title="Delete"
                    onClick={() => handleDelete(src.id)}
                    style={{ background: "none", border: "none", cursor: "pointer", color: "var(--fg-3)", display: "flex" }}
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>

              {/* Expanded detail */}
              {isExpanded && (
                <div
                  style={{
                    padding: "12px 16px 16px 44px",
                    borderTop: "1px solid var(--border)",
                    background: "var(--surface-1)",
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr",
                    gap: 16,
                  }}
                >
                  {/* Config */}
                  <div>
                    <p className="section-label" style={{ marginBottom: 6 }}>Connector Config</p>
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
                      }}
                    >
                      {JSON.stringify(src.config, null, 2)}
                    </pre>
                  </div>

                  {/* Health detail */}
                  <div>
                    <p className="section-label" style={{ marginBottom: 6 }}>Health & Stats</p>
                    <div
                      style={{
                        background: "var(--surface-2)",
                        border: "1px solid var(--border)",
                        borderRadius: 6,
                        padding: "10px 14px",
                        display: "flex",
                        flexDirection: "column",
                        gap: 8,
                      }}
                    >
                      <Stat label="Source ID"    value={src.id} mono />
                      <Stat label="Events Today" value={src.events_today.toLocaleString()} />
                      <Stat label="Created"      value={src.created_at ? new Date(src.created_at).toLocaleString() : "—"} />
                      <Stat label="Last Updated" value={src.updated_at ? new Date(src.updated_at).toLocaleString() : "—"} />
                      {src.error_state && (
                        <Stat label="Error" value={src.error_state} error />
                      )}
                      {health && health.error && (
                        <Stat label="Health Error" value={health.error} error />
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* ── Info footer ── */}
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
        <Clock size={13} style={{ marginTop: 1, flexShrink: 0 }} />
        <span>
          Connectors start automatically when the NATS pipeline is enabled (
          <code style={{ fontFamily: "var(--font-fira-code)", color: "var(--fg-2)" }}>EDR_NATS_ENABLED=true</code>
          ). Events flow through the XDR pipeline → detection engine → alerts.
        </span>
      </div>
    </div>
  );
}

// ── Stat sub-component ────────────────────────────────────────────────────────

function Stat({
  label,
  value,
  mono,
  error,
}: {
  label: string;
  value: string;
  mono?: boolean;
  error?: boolean;
}) {
  return (
    <div className="flex justify-between items-start gap-4">
      <span style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)", flexShrink: 0 }}>{label}</span>
      <span
        style={{
          fontSize: "var(--text-xs)",
          color: error ? "var(--sev-critical)" : "var(--fg-2)",
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
