"use client";

import { useCallback, useState, useEffect } from "react";
import { Activity, BarChart3, ChevronDown, ChevronRight, Cpu, Database, Globe, HardDrive, Loader2, Radio, RefreshCw, Server, Shield, Zap } from "lucide-react";
import { api } from "@/lib/api-client";
import { cn } from "@/lib/utils";

/* ── Types ────────────────────────────────────────────────────── */

interface ParsedMetric {
  name: string;
  help: string;
  type: string; // counter, gauge, histogram
  samples: MetricSample[];
}

interface MetricSample {
  labels: Record<string, string>;
  value: number;
}

/* ── Prometheus text parser ───────────────────────────────────── */

function parsePrometheusText(text: string): ParsedMetric[] {
  const metrics: ParsedMetric[] = [];
  const lines = text.split("\n");
  let current: ParsedMetric | null = null;

  for (const line of lines) {
    if (line.startsWith("# HELP ")) {
      const rest = line.slice(7);
      const spaceIdx = rest.indexOf(" ");
      const name = rest.slice(0, spaceIdx);
      const help = rest.slice(spaceIdx + 1);
      current = { name, help, type: "", samples: [] };
      metrics.push(current);
    } else if (line.startsWith("# TYPE ")) {
      const rest = line.slice(7);
      const spaceIdx = rest.indexOf(" ");
      const type = rest.slice(spaceIdx + 1);
      if (current) current.type = type;
    } else if (line && !line.startsWith("#") && current) {
      // Parse: metric_name{label="val",...} value
      const braceOpen = line.indexOf("{");
      const braceClose = line.indexOf("}");
      let labels: Record<string, string> = {};
      let valueStr: string;

      if (braceOpen >= 0 && braceClose >= 0) {
        const labelStr = line.slice(braceOpen + 1, braceClose);
        labelStr.split(",").forEach((pair) => {
          const eq = pair.indexOf("=");
          if (eq >= 0) {
            const k = pair.slice(0, eq);
            const v = pair.slice(eq + 1).replace(/"/g, "");
            labels[k] = v;
          }
        });
        valueStr = line.slice(braceClose + 2).trim();
      } else {
        const parts = line.split(/\s+/);
        valueStr = parts[1] ?? "0";
      }

      const value = parseFloat(valueStr);
      if (!isNaN(value)) {
        current.samples.push({ labels, value });
      }
    }
  }

  return metrics;
}

/* ── Metric card ──────────────────────────────────────────────── */

function MetricCard({
  icon: Icon,
  label,
  value,
  unit,
  sub,
  color,
}: {
  icon: React.ComponentType<{ size?: number; className?: string }>;
  label: string;
  value: string | number;
  unit?: string;
  sub?: string;
  color?: string;
}) {
  return (
    <div
      className="flex items-start gap-3 rounded border p-3"
      style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
    >
      <div
        className="rounded p-1.5 shrink-0"
        style={{ background: `${color ?? "var(--primary)"}20`, color: color ?? "var(--primary)" }}
      >
        <Icon size={16} />
      </div>
      <div className="min-w-0">
        <div className="text-[10px] uppercase tracking-wider" style={{ color: "var(--muted)" }}>
          {label}
        </div>
        <div className="flex items-baseline gap-1">
          <span className="font-mono text-lg font-bold" style={{ color: "var(--fg)" }}>
            {typeof value === "number" ? value.toLocaleString() : value}
          </span>
          {unit && (
            <span className="text-[10px]" style={{ color: "var(--muted)" }}>
              {unit}
            </span>
          )}
        </div>
        {sub && (
          <div className="text-[10px]" style={{ color: "var(--muted)" }}>
            {sub}
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Helper to find metric value ──────────────────────────────── */

function findMetric(metrics: ParsedMetric[], name: string): number {
  const m = metrics.find((m) => m.name === name);
  if (!m || m.samples.length === 0) return 0;
  // Sum all samples for counters/gauges
  return m.samples.reduce((sum, s) => sum + s.value, 0);
}

function findGauge(metrics: ParsedMetric[], name: string): number {
  const m = metrics.find((m) => m.name === name);
  if (!m || m.samples.length === 0) return 0;
  return m.samples[0].value;
}

function findHistogramAvg(metrics: ParsedMetric[], name: string): number {
  const sumM = metrics.find((m) => m.name === name + "_sum" || m.name === name);
  const countM = metrics.find((m) => m.name === name + "_count" || m.name === name);
  if (!sumM || !countM) return 0;
  const sumSample = sumM.samples.find((s) => !s.labels.le);
  const countSample = countM.samples.find((s) => !s.labels.le);
  const sum = sumSample?.value ?? 0;
  const count = countSample?.value ?? 0;
  return count > 0 ? sum / count : 0;
}

/* ── Top event types breakdown ────────────────────────────────── */

function findByLabel(metrics: ParsedMetric[], name: string, labelKey: string): { label: string; value: number }[] {
  const m = metrics.find((m) => m.name === name);
  if (!m) return [];
  const grouped: Record<string, number> = {};
  for (const s of m.samples) {
    const key = s.labels[labelKey] ?? "unknown";
    grouped[key] = (grouped[key] ?? 0) + s.value;
  }
  return Object.entries(grouped)
    .map(([label, value]) => ({ label, value }))
    .sort((a, b) => b.value - a.value);
}

/* ── Database Size Section ────────────────────────────────────── */

interface AgentSize {
  agent_id: string;
  hostname: string;
  bytes: number;
  events: number;
}

interface DBSizeData {
  total_bytes: number;
  tables: Record<string, number>;
  by_agent: AgentSize[];
}

function formatSize(bytes: number, unit: "MB" | "GB"): string {
  if (unit === "GB") return (bytes / (1024 * 1024 * 1024)).toFixed(2);
  return (bytes / (1024 * 1024)).toFixed(2);
}

function DBSizeSection() {
  const [data, setData] = useState<DBSizeData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [unit, setUnit] = useState<"MB" | "GB">("MB");
  const [expanded, setExpanded] = useState(false);
  const [open, setOpen] = useState(false);

  async function fetchDBSize() {
    setLoading(true);
    setError("");
    try {
      const res = await api.get<DBSizeData>("/api/v1/metrics/db-size");
      setData(res);
      if (res.total_bytes > 1024 * 1024 * 1024) setUnit("GB");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load database size");
    } finally {
      setLoading(false);
    }
  }

  function handleToggle() {
    if (!open) {
      setOpen(true);
      if (!data) fetchDBSize();
    } else {
      setOpen(false);
    }
  }

  const maxAgentBytes = data?.by_agent[0]?.bytes ?? 1;

  return (
    <div>
      {/* Collapsed: just a clickable header bar */}
      <button
        onClick={handleToggle}
        className="w-full flex items-center justify-between rounded border p-3 transition-colors hover:bg-[var(--surface-1)]"
        style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
      >
        <div className="flex items-center gap-2.5">
          <div
            className="rounded p-1.5"
            style={{ background: "#8b5cf620", color: "#8b5cf6" }}
          >
            <HardDrive size={16} />
          </div>
          <span
            className="text-sm font-semibold"
            style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}
          >
            Database Size
          </span>
          {data && (
            <span className="font-mono text-xs" style={{ color: "var(--muted)" }}>
              — {formatSize(data.total_bytes, unit)} {unit}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {loading && <Loader2 size={14} className="animate-spin" style={{ color: "var(--muted)" }} />}
          {open ? <ChevronDown size={14} style={{ color: "var(--muted)" }} /> : <ChevronRight size={14} style={{ color: "var(--muted)" }} />}
        </div>
      </button>

      {/* Expanded content */}
      {open && error && (
        <div
          className="rounded border px-3 py-2 mt-2 text-xs"
          style={{ background: "oklch(0.45 0.15 25 / 0.1)", borderColor: "oklch(0.45 0.15 25 / 0.3)", color: "var(--destructive)" }}
        >
          {error}
        </div>
      )}

      {open && loading && !data && (
        <div className="mt-2 space-y-2">
          <div className="animate-shimmer h-16 rounded" />
          <div className="animate-shimmer h-10 rounded" />
        </div>
      )}

      {open && data && (
        <div className="mt-2 space-y-3">
          {/* Unit toggle + total */}
          <div className="flex items-center justify-between">
            <div className="flex items-baseline gap-2">
              <span className="font-mono text-2xl font-bold" style={{ color: "var(--fg)" }}>
                {formatSize(data.total_bytes, unit)}
              </span>
              <span className="text-xs" style={{ color: "var(--muted)" }}>{unit} total</span>
            </div>
            <div className="flex items-center gap-2">
              <div
                className="flex rounded-md overflow-hidden border text-[10px]"
                style={{ borderColor: "var(--border)" }}
              >
                {(["MB", "GB"] as const).map((u) => (
                  <button
                    key={u}
                    onClick={() => setUnit(u)}
                    className="px-2.5 py-1 font-medium transition-colors"
                    style={{
                      background: u === unit ? "var(--primary)" : "var(--surface-0)",
                      color: u === unit ? "var(--primary-fg)" : "var(--muted)",
                    }}
                  >
                    {u}
                  </button>
                ))}
              </div>
              <button
                onClick={fetchDBSize}
                disabled={loading}
                className="rounded border p-1.5 transition-colors hover:bg-[var(--surface-2)] disabled:opacity-50"
                style={{ borderColor: "var(--border)", color: "var(--muted)" }}
                title="Refresh"
              >
                <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
              </button>
            </div>
          </div>

          {/* Per-agent breakdown */}
          <div>
            <button
              onClick={() => setExpanded(!expanded)}
              className="flex items-center gap-1 text-xs font-medium mb-2 transition-colors hover:underline"
              style={{ color: "var(--muted)" }}
            >
              {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              By Agent ({data.by_agent.length})
            </button>

            {expanded && (
              <div
                className="rounded border divide-y"
                style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
              >
                {data.by_agent.map((ag) => (
                  <div
                    key={ag.agent_id}
                    className="flex items-center gap-3 px-3 py-2.5 text-xs"
                    style={{ borderColor: "var(--border)" }}
                  >
                    <Server size={12} style={{ color: "var(--muted)" }} className="shrink-0" />
                    <span className="font-medium truncate min-w-0" style={{ color: "var(--fg)" }}>
                      {ag.hostname}
                    </span>
                    <div className="flex-1 mx-2">
                      <div
                        className="h-1.5 rounded-full overflow-hidden"
                        style={{ background: "var(--surface-1)" }}
                      >
                        <div
                          className="h-full rounded-full transition-all"
                          style={{
                            width: `${Math.max(2, (ag.bytes / maxAgentBytes) * 100)}%`,
                            background: "#8b5cf6",
                          }}
                        />
                      </div>
                    </div>
                    <div className="text-right shrink-0 w-24">
                      <span className="font-mono font-bold" style={{ color: "var(--fg)" }}>
                        {formatSize(ag.bytes, unit)}
                      </span>
                      <span className="ml-1" style={{ color: "var(--muted)" }}>{unit}</span>
                    </div>
                    <span
                      className="font-mono text-[10px] shrink-0 w-20 text-right"
                      style={{ color: "var(--muted)" }}
                    >
                      {ag.events.toLocaleString()} events
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Table sizes */}
          <div>
            <div className="text-[10px] font-medium mb-1.5" style={{ color: "var(--muted)" }}>
              Table Sizes
            </div>
            <div
              className="rounded border divide-y"
              style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
            >
              {Object.entries(data.tables)
                .sort(([, a], [, b]) => b - a)
                .map(([table, bytes]) => (
                  <div
                    key={table}
                    className="flex items-center justify-between px-3 py-1.5 text-[11px]"
                    style={{ borderColor: "var(--border)" }}
                  >
                    <span className="font-mono" style={{ color: "var(--fg)" }}>{table}</span>
                    <span className="font-mono" style={{ color: "var(--muted)" }}>
                      {formatSize(bytes, unit)} {unit}
                    </span>
                  </div>
                ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Main page ────────────────────────────────────────────────── */

export default function MetricsPage() {
  const [metrics, setMetrics] = useState<ParsedMetric[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastFetch, setLastFetch] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // const fetchMetrics = useCallback(async () => {
  //   try {
  //     // Fetch raw Prometheus text from backend
  //     const baseUrl = process.env.NEXT_PUBLIC_BACKEND_URL ?? "http://localhost:8080";
  //     const resp = await fetch(`${baseUrl}/metrics/prometheus`, { signal: AbortSignal.timeout(10000) });
  //     if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  //     const text = await resp.text();
  //     const parsed = parsePrometheusText(text);
  //     setMetrics(parsed);
  //     setError("");
  //     setLastFetch(new Date());
  //   } catch (err) {
  //     setError(err instanceof Error ? err.message : "Failed to fetch metrics");
  //   } finally {
  //     setLoading(false);
  //   }
  // }, []);

  const BASE = "";

const fetchMetrics = useCallback(async () => {
  try {
    const resp = await fetch(`/api/v1/metrics/prometheus`, {
      signal: AbortSignal.timeout(10000),
    });

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    const text = await resp.text();
    const parsed = parsePrometheusText(text);

    setMetrics(parsed);
    setError("");
    setLastFetch(new Date());
  } catch (err) {
    setError(err instanceof Error ? err.message : "Failed to fetch metrics");
  } finally {
    setLoading(false);
  }
}, []);

  useEffect(() => {
    fetchMetrics();
  }, [fetchMetrics]);

  // Auto-refresh every 10s
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(fetchMetrics, 10000);
    return () => clearInterval(interval);
  }, [autoRefresh, fetchMetrics]);

  // Extract key metrics
  const eventsReceived = findMetric(metrics, "edr_events_received_total");
  const eventsStored = findMetric(metrics, "edr_events_stored_total");
  const eventsDropped = findMetric(metrics, "edr_events_dropped_total");
  const alertsFired = findMetric(metrics, "edr_alerts_fired_total");
  const agentsOnline = findGauge(metrics, "edr_agents_online");
  const agentsTotal = findGauge(metrics, "edr_agents_total");
  const grpcStreams = findGauge(metrics, "edr_grpc_streams_active");
  const heartbeats = findMetric(metrics, "edr_heartbeats_received_total");
  const sseClients = findGauge(metrics, "edr_sse_clients_connected");
  const apiRequests = findMetric(metrics, "edr_api_requests_total");
  const avgApiLatency = findHistogramAvg(metrics, "edr_api_request_duration_seconds");
  const avgDetectionTime = findHistogramAvg(metrics, "edr_detection_duration_seconds");

  // Breakdowns
  const eventsByType = findByLabel(metrics, "edr_events_received_total", "event_type");
  const alertsByRule = findByLabel(metrics, "edr_alerts_fired_total", "rule_id");
  const apiByPath = findByLabel(metrics, "edr_api_requests_total", "path");

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-heading text-xl font-bold flex items-center gap-2">
            <BarChart3 size={20} style={{ color: "var(--primary)" }} />
            System Metrics
          </h1>
          <p className="text-sm" style={{ color: "var(--muted)" }}>
            Real-time Prometheus metrics from the backend
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={cn(
              "flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-xs font-medium transition-colors",
              autoRefresh ? "border-emerald-500/30 text-emerald-400" : ""
            )}
            style={autoRefresh ? {} : { borderColor: "var(--border)", color: "var(--muted)" }}
          >
            <Radio size={12} className={autoRefresh ? "animate-pulse" : ""} />
            {autoRefresh ? "Auto-refresh ON" : "Auto-refresh OFF"}
          </button>
          <button
            onClick={fetchMetrics}
            className="flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-2)]"
            style={{ borderColor: "var(--border)", color: "var(--muted)" }}
          >
            <RefreshCw size={12} />
            Refresh
          </button>
        </div>
      </div>

      {lastFetch && (
        <div className="text-[10px] font-mono" style={{ color: "var(--muted)" }}>
          Last updated: {lastFetch.toLocaleTimeString()}
        </div>
      )}

      {error && (
        <div
          className="rounded border p-3 text-xs"
          style={{ background: "oklch(0.45 0.15 25 / 0.1)", borderColor: "oklch(0.45 0.15 25 / 0.3)", color: "var(--destructive)" }}
        >
          {error}
        </div>
      )}

      {loading && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="animate-shimmer h-20 rounded" />
          ))}
        </div>
      )}

      {!loading && (
        <>
          {/* Overview cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <MetricCard icon={Activity} label="Events Received" value={eventsReceived} color="#3b82f6" />
            <MetricCard icon={Database} label="Events Stored" value={eventsStored} color="#22c55e" />
            <MetricCard icon={Zap} label="Events Dropped" value={eventsDropped} color={eventsDropped > 0 ? "#ef4444" : "#6b7280"} />
            <MetricCard icon={Shield} label="Alerts Fired" value={alertsFired} color="#f97316" />
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <MetricCard icon={Server} label="Agents Online" value={agentsOnline} sub={`${agentsTotal} total`} color="#22c55e" />
            <MetricCard icon={Globe} label="gRPC Streams" value={grpcStreams} sub={`${heartbeats} heartbeats`} color="#8b5cf6" />
            <MetricCard icon={Radio} label="SSE Clients" value={sseClients} color="#06b6d4" />
            <MetricCard icon={Cpu} label="API Requests" value={apiRequests} sub={`avg ${(avgApiLatency * 1000).toFixed(1)}ms`} color="#e8a83e" />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <MetricCard
              icon={Zap}
              label="Avg Detection Time"
              value={(avgDetectionTime * 1000).toFixed(3)}
              unit="ms per event"
              color="#8b5cf6"
            />
            <MetricCard
              icon={Cpu}
              label="Avg API Latency"
              value={(avgApiLatency * 1000).toFixed(1)}
              unit="ms per request"
              color="#e8a83e"
            />
          </div>

          {/* Database Size */}
          <DBSizeSection />

          {/* Events by type */}
          {eventsByType.length > 0 && (
            <div>
              <h2
                className="text-sm font-semibold mb-3"
                style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}
              >
                Events by Type
              </h2>
              <div
                className="rounded border divide-y"
                style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
              >
                {eventsByType.slice(0, 15).map((row) => (
                  <div
                    key={row.label}
                    className="flex items-center justify-between px-3 py-2 text-xs"
                    style={{ borderColor: "var(--border)" }}
                  >
                    <span className="font-mono" style={{ color: "var(--fg)" }}>
                      {row.label}
                    </span>
                    <div className="flex items-center gap-3">
                      <div className="w-32 h-1.5 rounded-full overflow-hidden" style={{ background: "var(--surface-1)" }}>
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${Math.min(100, (row.value / (eventsByType[0]?.value || 1)) * 100)}%`,
                            background: "var(--primary)",
                          }}
                        />
                      </div>
                      <span className="font-mono font-bold w-16 text-right" style={{ color: "var(--fg)" }}>
                        {row.value.toLocaleString()}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Alerts by rule */}
          {alertsByRule.length > 0 && (
            <div>
              <h2
                className="text-sm font-semibold mb-3"
                style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}
              >
                Alerts by Rule
              </h2>
              <div
                className="rounded border divide-y"
                style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
              >
                {alertsByRule.slice(0, 10).map((row) => (
                  <div
                    key={row.label}
                    className="flex items-center justify-between px-3 py-2 text-xs"
                    style={{ borderColor: "var(--border)" }}
                  >
                    <span className="font-mono truncate" style={{ color: "var(--fg)" }}>
                      {row.label}
                    </span>
                    <span className="font-mono font-bold" style={{ color: "#f97316" }}>
                      {row.value.toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Top API paths */}
          {apiByPath.length > 0 && (
            <div>
              <h2
                className="text-sm font-semibold mb-3"
                style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}
              >
                Top API Endpoints
              </h2>
              <div
                className="rounded border divide-y"
                style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
              >
                {apiByPath.slice(0, 10).map((row) => (
                  <div
                    key={row.label}
                    className="flex items-center justify-between px-3 py-2 text-xs"
                    style={{ borderColor: "var(--border)" }}
                  >
                    <span className="font-mono" style={{ color: "var(--fg)" }}>
                      {row.label}
                    </span>
                    <span className="font-mono font-bold" style={{ color: "var(--muted)" }}>
                      {row.value.toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Raw metrics count */}
          <div className="text-[10px] font-mono" style={{ color: "var(--muted)" }}>
            {metrics.length} metric families · {metrics.reduce((s, m) => s + m.samples.length, 0)} samples · from /metrics/prometheus
          </div>
        </>
      )}
    </div>
  );
}
