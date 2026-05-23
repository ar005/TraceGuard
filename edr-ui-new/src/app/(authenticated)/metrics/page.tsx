"use client";

import { useCallback, useState, useEffect } from "react";
import {
  Activity, BarChart3, ChevronDown, ChevronRight, Cpu, Database,
  Globe, HardDrive, Loader2, Radio, RefreshCw, Server, Shield,
  Zap, Clock, TrendingUp, Users, Target, CheckCircle2,
} from "lucide-react";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer,
} from "recharts";
import { api } from "@/lib/api-client";
import { cn } from "@/lib/utils";

/* ── Types ────────────────────────────────────────────────────── */

interface ParsedMetric {
  name: string;
  help: string;
  type: string;
  samples: MetricSample[];
}

interface MetricSample {
  labels: Record<string, string>;
  value: number;
}

interface AlertTrendDay {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface RuleFireCount {
  rule_name: string;
  count: number;
}

interface AnalystLoad {
  assignee: string;
  open_count: number;
  total_7d: number;
}

interface SOCMetrics {
  mttr_hours: number;
  open_alert_age_hours: number;
  resolution_rate: number;
  fp_rate: number;
  total_alerts_7d: number;
  alert_trend: AlertTrendDay[];
  top_rules: RuleFireCount[];
  analyst_workload: AnalystLoad[];
  status_funnel: Record<string, number>;
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

/* ── Prometheus helpers ───────────────────────────────────────── */

function findMetric(metrics: ParsedMetric[], name: string): number {
  const m = metrics.find((m) => m.name === name);
  if (!m || m.samples.length === 0) return 0;
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

/* ── Shared card ──────────────────────────────────────────────── */

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
      <button
        onClick={handleToggle}
        className="w-full flex items-center justify-between rounded border p-3 transition-colors hover:bg-[var(--surface-1)]"
        style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
      >
        <div className="flex items-center gap-2.5">
          <div className="rounded p-1.5" style={{ background: "#8b5cf620", color: "#8b5cf6" }}>
            <HardDrive size={16} />
          </div>
          <span className="text-sm font-semibold" style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}>
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

      {open && error && (
        <div className="rounded border px-3 py-2 mt-2 text-xs" style={{ background: "oklch(0.45 0.15 25 / 0.1)", borderColor: "oklch(0.45 0.15 25 / 0.3)", color: "var(--destructive)" }}>
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
          <div className="flex items-center justify-between">
            <div className="flex items-baseline gap-2">
              <span className="font-mono text-2xl font-bold" style={{ color: "var(--fg)" }}>
                {formatSize(data.total_bytes, unit)}
              </span>
              <span className="text-xs" style={{ color: "var(--muted)" }}>{unit} total</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="flex rounded-md overflow-hidden border text-[10px]" style={{ borderColor: "var(--border)" }}>
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

          <div>
            <button
              onClick={() => setExpanded(!expanded)}
              className="flex items-center gap-1 text-xs font-medium mb-2 transition-colors hover:underline"
              style={{ color: "var(--muted)" }}
            >
              {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              By Agent ({(data.by_agent ?? []).length})
            </button>
            {expanded && (
              <div className="rounded border divide-y" style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}>
                {(data.by_agent ?? []).map((ag) => (
                  <div key={ag.agent_id} className="flex items-center gap-3 px-3 py-2.5 text-xs" style={{ borderColor: "var(--border)" }}>
                    <Server size={12} style={{ color: "var(--muted)" }} className="shrink-0" />
                    <span className="font-medium truncate min-w-0" style={{ color: "var(--fg)" }}>{ag.hostname}</span>
                    <div className="flex-1 mx-2">
                      <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "var(--surface-1)" }}>
                        <div
                          className="h-full rounded-full transition-all"
                          style={{ width: `${Math.max(2, (ag.bytes / maxAgentBytes) * 100)}%`, background: "#8b5cf6" }}
                        />
                      </div>
                    </div>
                    <div className="text-right shrink-0 w-24">
                      <span className="font-mono font-bold" style={{ color: "var(--fg)" }}>{formatSize(ag.bytes, unit)}</span>
                      <span className="ml-1" style={{ color: "var(--muted)" }}>{unit}</span>
                    </div>
                    <span className="font-mono text-[10px] shrink-0 w-20 text-right" style={{ color: "var(--muted)" }}>
                      {ag.events.toLocaleString()} events
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div>
            <div className="text-[10px] font-medium mb-1.5" style={{ color: "var(--muted)" }}>Table Sizes</div>
            <div className="rounded border divide-y" style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}>
              {Object.entries(data.tables)
                .sort(([, a], [, b]) => b - a)
                .map(([table, bytes]) => (
                  <div key={table} className="flex items-center justify-between px-3 py-1.5 text-[11px]" style={{ borderColor: "var(--border)" }}>
                    <span className="font-mono" style={{ color: "var(--fg)" }}>{table}</span>
                    <span className="font-mono" style={{ color: "var(--muted)" }}>{formatSize(bytes, unit)} {unit}</span>
                  </div>
                ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── SOC KPI card ─────────────────────────────────────────────── */

function KpiCard({
  icon: Icon,
  label,
  value,
  unit,
  sub,
  color,
  trend,
}: {
  icon: React.ComponentType<{ size?: number; className?: string }>;
  label: string;
  value: string;
  unit?: string;
  sub?: string;
  color: string;
  trend?: "good" | "warn" | "bad" | "neutral";
}) {
  const trendColor =
    trend === "good" ? "#22c55e" :
    trend === "warn" ? "#f59e0b" :
    trend === "bad"  ? "#ef4444" :
    "var(--muted)";

  return (
    <div
      className="rounded border p-4 flex flex-col gap-2"
      style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
    >
      <div className="flex items-center justify-between">
        <div className="rounded p-1.5" style={{ background: `${color}20`, color }}>
          <Icon size={15} />
        </div>
        {trend && trend !== "neutral" && (
          <div className="w-2 h-2 rounded-full" style={{ background: trendColor }} />
        )}
      </div>
      <div>
        <div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: "var(--muted)" }}>
          {label}
        </div>
        <div className="flex items-baseline gap-1">
          <span className="font-mono text-2xl font-bold" style={{ color: "var(--fg)" }}>{value}</span>
          {unit && <span className="text-xs" style={{ color: "var(--muted)" }}>{unit}</span>}
        </div>
        {sub && <div className="text-[10px] mt-0.5" style={{ color: "var(--muted)" }}>{sub}</div>}
      </div>
    </div>
  );
}

/* ── Custom chart tooltip ─────────────────────────────────────── */

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: { name: string; value: number; color: string }[]; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded border px-3 py-2 text-xs shadow-lg" style={{ background: "var(--surface-1)", borderColor: "var(--border)" }}>
      <div className="font-medium mb-1" style={{ color: "var(--fg)" }}>{label}</div>
      {payload.map((p) => (
        <div key={p.name} className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full" style={{ background: p.color }} />
          <span style={{ color: "var(--muted)" }}>{p.name}:</span>
          <span className="font-mono font-bold" style={{ color: "var(--fg)" }}>{p.value}</span>
        </div>
      ))}
    </div>
  );
}

/* ── SOC metrics tab ──────────────────────────────────────────── */

function SOCTab() {
  const [data, setData] = useState<SOCMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastFetch, setLastFetch] = useState<Date | null>(null);

  const fetchSOC = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const res = await api.get<SOCMetrics>("/api/v1/metrics/soc");
      setData(res);
      setLastFetch(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load SOC metrics");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchSOC(); }, [fetchSOC]);

  // Auto-refresh every 60s
  useEffect(() => {
    const id = setInterval(fetchSOC, 60_000);
    return () => clearInterval(id);
  }, [fetchSOC]);

  function fmtHours(h: number): string {
    if (h < 1) return `${Math.round(h * 60)}m`;
    if (h < 24) return `${h.toFixed(1)}h`;
    return `${(h / 24).toFixed(1)}d`;
  }

  const funnel = data?.status_funnel ?? {};
  const totalFunnel = Object.values(funnel).reduce((s, v) => s + v, 0);
  const funnelStages = [
    { key: "OPEN", label: "Open", color: "#ef4444" },
    { key: "INVESTIGATING", label: "Investigating", color: "#f59e0b" },
    { key: "CLOSED", label: "Closed", color: "#22c55e" },
    { key: "RESOLVED", label: "Resolved", color: "#3b82f6" },
  ];

  return (
    <div className="space-y-6">
      {/* Refresh header */}
      <div className="flex items-center justify-between">
        <div>
          {lastFetch && (
            <span className="text-[10px] font-mono" style={{ color: "var(--muted)" }}>
              Updated {lastFetch.toLocaleTimeString()}
            </span>
          )}
        </div>
        <button
          onClick={fetchSOC}
          disabled={loading}
          className="flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-2)] disabled:opacity-50"
          style={{ borderColor: "var(--border)", color: "var(--muted)" }}
        >
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="rounded border p-3 text-xs" style={{ background: "oklch(0.45 0.15 25 / 0.1)", borderColor: "oklch(0.45 0.15 25 / 0.3)", color: "var(--destructive)" }}>
          {error}
        </div>
      )}

      {loading && !data && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {Array.from({ length: 5 }).map((_, i) => <div key={i} className="animate-shimmer h-24 rounded" />)}
        </div>
      )}

      {data && (
        <>
          {/* KPI row */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <KpiCard
              icon={Clock}
              label="Avg MTTR"
              value={fmtHours(data.mttr_hours)}
              sub="closed alerts, last 30d"
              color="#3b82f6"
              trend={data.mttr_hours < 4 ? "good" : data.mttr_hours < 24 ? "warn" : "bad"}
            />
            <KpiCard
              icon={Activity}
              label="Open Alert Age"
              value={fmtHours(data.open_alert_age_hours)}
              sub="avg age of open alerts"
              color="#f59e0b"
              trend={data.open_alert_age_hours < 8 ? "good" : data.open_alert_age_hours < 48 ? "warn" : "bad"}
            />
            <KpiCard
              icon={CheckCircle2}
              label="Resolution Rate"
              value={`${data.resolution_rate.toFixed(0)}%`}
              sub="last 7 days"
              color="#22c55e"
              trend={data.resolution_rate >= 70 ? "good" : data.resolution_rate >= 40 ? "warn" : "bad"}
            />
            <KpiCard
              icon={Target}
              label="False Positive Rate"
              value={`${data.fp_rate.toFixed(0)}%`}
              sub="of closed, last 7d"
              color="#8b5cf6"
              trend={data.fp_rate <= 10 ? "good" : data.fp_rate <= 30 ? "warn" : "bad"}
            />
            <KpiCard
              icon={Shield}
              label="Alerts (7d)"
              value={data.total_alerts_7d.toLocaleString()}
              sub="total fired"
              color="#f97316"
              trend="neutral"
            />
          </div>

          {/* Alert trend + status funnel */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Stacked area trend */}
            <div
              className="col-span-2 rounded border p-4"
              style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
            >
              <div className="text-sm font-semibold mb-3" style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}>
                Alert Volume — Last 7 Days
              </div>
              <ResponsiveContainer width="100%" height={180}>
                <AreaChart data={data.alert_trend} margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
                  <defs>
                    {[
                      { key: "critical", color: "#ef4444" },
                      { key: "high", color: "#f97316" },
                      { key: "medium", color: "#f59e0b" },
                      { key: "low", color: "#3b82f6" },
                    ].map(({ key, color }) => (
                      <linearGradient key={key} id={`grad-${key}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor={color} stopOpacity={0.3} />
                        <stop offset="95%" stopColor={color} stopOpacity={0.05} />
                      </linearGradient>
                    ))}
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                  <XAxis dataKey="date" tick={{ fontSize: 10, fill: "var(--muted)" }} tickFormatter={(v) => v.slice(5)} />
                  <YAxis tick={{ fontSize: 10, fill: "var(--muted)" }} allowDecimals={false} />
                  <Tooltip content={<ChartTooltip />} />
                  <Area type="monotone" dataKey="critical" name="Critical" stackId="1" stroke="#ef4444" fill="url(#grad-critical)" strokeWidth={1.5} />
                  <Area type="monotone" dataKey="high" name="High" stackId="1" stroke="#f97316" fill="url(#grad-high)" strokeWidth={1.5} />
                  <Area type="monotone" dataKey="medium" name="Medium" stackId="1" stroke="#f59e0b" fill="url(#grad-medium)" strokeWidth={1.5} />
                  <Area type="monotone" dataKey="low" name="Low" stackId="1" stroke="#3b82f6" fill="url(#grad-low)" strokeWidth={1.5} />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            {/* Status funnel */}
            <div
              className="rounded border p-4 flex flex-col"
              style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
            >
              <div className="text-sm font-semibold mb-3" style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}>
                Alert Status Funnel
              </div>
              <div className="flex-1 flex flex-col justify-center gap-3">
                {funnelStages.map(({ key, label, color }) => {
                  const count = funnel[key] ?? 0;
                  const pct = totalFunnel > 0 ? (count / totalFunnel) * 100 : 0;
                  return (
                    <div key={key}>
                      <div className="flex justify-between text-[11px] mb-1">
                        <span style={{ color: "var(--muted)" }}>{label}</span>
                        <span className="font-mono font-bold" style={{ color: "var(--fg)" }}>{count.toLocaleString()}</span>
                      </div>
                      <div className="h-2 rounded-full overflow-hidden" style={{ background: "var(--surface-1)" }}>
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{ width: `${Math.max(pct > 0 ? 2 : 0, pct)}%`, background: color }}
                        />
                      </div>
                    </div>
                  );
                })}
                <div className="text-[10px] mt-1" style={{ color: "var(--muted)" }}>
                  {totalFunnel.toLocaleString()} total alerts
                </div>
              </div>
            </div>
          </div>

          {/* Top firing rules */}
          {(data.top_rules ?? []).length > 0 && (
            <div className="rounded border p-4" style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}>
              <div className="text-sm font-semibold mb-3" style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}>
                Top Firing Rules — Last 7 Days
              </div>
              <ResponsiveContainer width="100%" height={Math.max(120, (data.top_rules ?? []).length * 28)}>
                <BarChart
                  data={(data.top_rules ?? []).map((r) => ({ name: r.rule_name, count: r.count }))}
                  layout="vertical"
                  margin={{ top: 0, right: 8, left: 0, bottom: 0 }}
                >
                  <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="var(--border)" />
                  <XAxis type="number" tick={{ fontSize: 10, fill: "var(--muted)" }} allowDecimals={false} />
                  <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: "var(--muted)" }} width={160} />
                  <Tooltip content={<ChartTooltip />} />
                  <Bar dataKey="count" name="Fires" fill="#f97316" radius={[0, 3, 3, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Analyst workload + no-data state */}
          {(data.analyst_workload ?? []).length > 0 ? (
            <div className="rounded border" style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}>
              <div className="px-4 pt-4 pb-2">
                <div className="text-sm font-semibold flex items-center gap-2" style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}>
                  <Users size={15} style={{ color: "var(--primary)" }} />
                  Analyst Workload
                </div>
              </div>
              <div className="divide-y" style={{ borderColor: "var(--border)" }}>
                {(data.analyst_workload ?? []).map((a) => (
                  <div key={a.assignee} className="flex items-center gap-4 px-4 py-2.5 text-xs">
                    <span className="font-medium truncate min-w-0 flex-1" style={{ color: "var(--fg)" }}>{a.assignee}</span>
                    <div className="flex items-center gap-1.5">
                      <div className="w-2 h-2 rounded-full" style={{ background: "#ef4444" }} />
                      <span style={{ color: "var(--muted)" }}>Open:</span>
                      <span className="font-mono font-bold w-8 text-right" style={{ color: "var(--fg)" }}>{a.open_count}</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span style={{ color: "var(--muted)" }}>7d total:</span>
                      <span className="font-mono font-bold w-8 text-right" style={{ color: "var(--fg)" }}>{a.total_7d}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div
              className="rounded border px-4 py-6 text-center text-sm"
              style={{ borderColor: "var(--border)", background: "var(--surface-0)", color: "var(--muted)" }}
            >
              No alerts are currently assigned to analysts.
            </div>
          )}
        </>
      )}
    </div>
  );
}

/* ── Rule Effectiveness Tab ───────────────────────────────────── */

interface RuleRow {
  rule_id: string;
  rule_name: string;
  severity: number;
  enabled: boolean;
  total_fires: number;
  fires_7d: number;
  closed_count: number;
  fp_count: number;
  avg_mttr_hours: number;
  last_fired_at?: string;
  close_rate: number;
  fp_rate: number;
  label: string; // effective | noisy | stale | silent | active
}

const LABEL_STYLE: Record<string, { bg: string; color: string; text: string }> = {
  effective: { bg: "#22c55e20", color: "#22c55e", text: "Effective" },
  noisy:     { bg: "#f9731620", color: "#f97316", text: "Noisy" },
  stale:     { bg: "#6b728020", color: "#6b7280", text: "Stale" },
  silent:    { bg: "#8b5cf620", color: "#8b5cf6", text: "Silent" },
  active:    { bg: "#3b82f620", color: "#3b82f6", text: "Active" },
};

const SEV_COLOR: Record<number, string> = { 4: "#ef4444", 3: "#f97316", 2: "#f59e0b", 1: "#3b82f6" };

type SortKey = "fires_7d" | "total_fires" | "close_rate" | "fp_rate" | "avg_mttr_hours";
type FilterLabel = "all" | "noisy" | "silent" | "stale" | "effective";

function RuleEffectivenessTab() {
  const [rows, setRows] = useState<RuleRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("fires_7d");
  const [sortAsc, setSortAsc] = useState(false);
  const [filter, setFilter] = useState<FilterLabel>("all");
  const [lastFetch, setLastFetch] = useState<Date | null>(null);

  const fetchRules = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const res = await api.get<{ rules: RuleRow[] }>("/api/v1/metrics/rules");
      setRows(res.rules ?? []);
      setLastFetch(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load rule effectiveness");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchRules(); }, [fetchRules]);

  function toggleSort(key: SortKey) {
    if (sortKey === key) setSortAsc((v) => !v);
    else { setSortKey(key); setSortAsc(false); }
  }

  const filtered = rows.filter((r) => filter === "all" || r.label === filter);
  const sorted = [...filtered].sort((a, b) => {
    const d = (a[sortKey] as number) - (b[sortKey] as number);
    return sortAsc ? d : -d;
  });

  function fmtHours(h: number) {
    if (h <= 0) return "—";
    if (h < 1) return `${Math.round(h * 60)}m`;
    if (h < 24) return `${h.toFixed(1)}h`;
    return `${(h / 24).toFixed(1)}d`;
  }

  function fmtAge(iso?: string) {
    if (!iso) return "never";
    const diff = Date.now() - new Date(iso).getTime();
    const h = diff / 3_600_000;
    if (h < 1) return "<1h ago";
    if (h < 24) return `${Math.floor(h)}h ago`;
    return `${Math.floor(h / 24)}d ago`;
  }

  const counts = {
    noisy:     rows.filter((r) => r.label === "noisy").length,
    silent:    rows.filter((r) => r.label === "silent").length,
    stale:     rows.filter((r) => r.label === "stale").length,
    effective: rows.filter((r) => r.label === "effective").length,
  };

  const SortBtn = ({ col, label }: { col: SortKey; label: string }) => (
    <button
      onClick={() => toggleSort(col)}
      className="flex items-center gap-1 hover:opacity-80 transition-opacity"
      style={{ color: sortKey === col ? "var(--fg)" : "var(--muted)" }}
    >
      {label}
      <span className="text-[9px]">{sortKey === col ? (sortAsc ? "▲" : "▼") : "⇅"}</span>
    </button>
  );

  return (
    <div className="space-y-4">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          {lastFetch && (
            <span className="text-[10px] font-mono" style={{ color: "var(--muted)" }}>
              Updated {lastFetch.toLocaleTimeString()}
            </span>
          )}
          {/* Summary chips */}
          {!loading && rows.length > 0 && (
            <div className="flex items-center gap-1.5">
              {(["noisy", "silent", "stale", "effective"] as const).map((lbl) => counts[lbl] > 0 && (
                <button
                  key={lbl}
                  onClick={() => setFilter(filter === lbl ? "all" : lbl)}
                  className="text-[10px] px-2 py-0.5 rounded-full font-medium transition-opacity"
                  style={{
                    background: LABEL_STYLE[lbl].bg,
                    color: LABEL_STYLE[lbl].color,
                    opacity: filter !== "all" && filter !== lbl ? 0.4 : 1,
                  }}
                >
                  {counts[lbl]} {LABEL_STYLE[lbl].text}
                </button>
              ))}
            </div>
          )}
        </div>
        <button
          onClick={fetchRules}
          disabled={loading}
          className="flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-2)] disabled:opacity-50"
          style={{ borderColor: "var(--border)", color: "var(--muted)" }}
        >
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="rounded border p-3 text-xs" style={{ background: "oklch(0.45 0.15 25 / 0.1)", borderColor: "oklch(0.45 0.15 25 / 0.3)", color: "var(--destructive)" }}>
          {error}
        </div>
      )}

      {loading && (
        <div className="space-y-1.5">
          {Array.from({ length: 8 }).map((_, i) => <div key={i} className="animate-shimmer h-10 rounded" />)}
        </div>
      )}

      {!loading && sorted.length === 0 && (
        <div className="rounded border px-4 py-8 text-center text-sm" style={{ borderColor: "var(--border)", background: "var(--surface-0)", color: "var(--muted)" }}>
          {filter === "all" ? "No rules found." : `No ${filter} rules.`}
        </div>
      )}

      {!loading && sorted.length > 0 && (
        <div className="rounded border overflow-hidden" style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}>
          {/* Column headers */}
          <div
            className="grid text-[10px] uppercase tracking-wider px-3 py-2 border-b"
            style={{
              gridTemplateColumns: "minmax(0,2fr) 80px 80px 80px 80px 80px 80px 72px",
              borderColor: "var(--border)",
              background: "var(--surface-1)",
              color: "var(--muted)",
            }}
          >
            <span>Rule</span>
            <span>Status</span>
            <SortBtn col="fires_7d"      label="7d Fires" />
            <SortBtn col="total_fires"   label="Total" />
            <SortBtn col="close_rate"    label="Close%" />
            <SortBtn col="fp_rate"       label="FP%" />
            <SortBtn col="avg_mttr_hours" label="MTTR" />
            <span>Last Fired</span>
          </div>

          {/* Rows */}
          <div className="divide-y" style={{ borderColor: "var(--border)" }}>
            {sorted.map((r) => {
              const ls = LABEL_STYLE[r.label] ?? LABEL_STYLE.active;
              const sevColor = SEV_COLOR[r.severity] ?? "#6b7280";
              return (
                <div
                  key={r.rule_id}
                  className="grid items-center px-3 py-2.5 text-xs hover:bg-[var(--surface-1)] transition-colors"
                  style={{ gridTemplateColumns: "minmax(0,2fr) 80px 80px 80px 80px 80px 80px 72px" }}
                >
                  {/* Name + severity dot + enabled */}
                  <div className="flex items-center gap-2 min-w-0">
                    <div className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: sevColor }} />
                    <span className="truncate font-medium" style={{ color: r.enabled ? "var(--fg)" : "var(--muted)" }}>
                      {r.rule_name || r.rule_id}
                    </span>
                    {!r.enabled && (
                      <span className="text-[9px] px-1 rounded shrink-0" style={{ background: "var(--surface-2)", color: "var(--muted)" }}>off</span>
                    )}
                  </div>

                  {/* Label badge */}
                  <span
                    className="text-[10px] font-medium px-1.5 py-0.5 rounded-full w-fit"
                    style={{ background: ls.bg, color: ls.color }}
                  >
                    {ls.text}
                  </span>

                  {/* Fires 7d */}
                  <span className="font-mono font-bold" style={{ color: r.fires_7d > 0 ? "var(--fg)" : "var(--muted)" }}>
                    {r.fires_7d > 0 ? r.fires_7d.toLocaleString() : "—"}
                  </span>

                  {/* Total fires */}
                  <span className="font-mono" style={{ color: "var(--muted)" }}>
                    {r.total_fires > 0 ? r.total_fires.toLocaleString() : "—"}
                  </span>

                  {/* Close rate bar */}
                  <div className="flex items-center gap-1.5">
                    {r.total_fires > 0 ? (
                      <>
                        <div className="w-10 h-1.5 rounded-full overflow-hidden" style={{ background: "var(--surface-1)" }}>
                          <div
                            className="h-full rounded-full"
                            style={{
                              width: `${r.close_rate}%`,
                              background: r.close_rate >= 60 ? "#22c55e" : r.close_rate >= 30 ? "#f59e0b" : "#ef4444",
                            }}
                          />
                        </div>
                        <span className="font-mono text-[10px]" style={{ color: "var(--fg)" }}>{r.close_rate.toFixed(0)}%</span>
                      </>
                    ) : <span style={{ color: "var(--muted)" }}>—</span>}
                  </div>

                  {/* FP rate */}
                  <span className="font-mono" style={{ color: r.fp_rate > 40 ? "#ef4444" : r.fp_rate > 20 ? "#f59e0b" : "var(--muted)" }}>
                    {r.closed_count > 0 ? `${r.fp_rate.toFixed(0)}%` : "—"}
                  </span>

                  {/* Avg MTTR */}
                  <span className="font-mono" style={{ color: "var(--muted)" }}>
                    {fmtHours(r.avg_mttr_hours)}
                  </span>

                  {/* Last fired */}
                  <span style={{ color: "var(--muted)" }}>{fmtAge(r.last_fired_at)}</span>
                </div>
              );
            })}
          </div>

          <div className="px-3 py-2 text-[10px]" style={{ borderTop: `1px solid var(--border)`, color: "var(--muted)" }}>
            {sorted.length} of {rows.length} rules
            {filter !== "all" && (
              <button className="ml-2 underline" onClick={() => setFilter("all")}>show all</button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Main page ────────────────────────────────────────────────── */

type Tab = "system" | "soc" | "rules";

export default function MetricsPage() {
  const [tab, setTab] = useState<Tab>("soc");
  const [metrics, setMetrics] = useState<ParsedMetric[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastFetch, setLastFetch] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

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
    if (tab === "system") fetchMetrics();
  }, [tab, fetchMetrics]);

  useEffect(() => {
    if (!autoRefresh || tab !== "system") return;
    const interval = setInterval(fetchMetrics, 30000);
    return () => clearInterval(interval);
  }, [autoRefresh, fetchMetrics, tab]);

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
  const eventsByType = findByLabel(metrics, "edr_events_received_total", "event_type");
  const alertsByRule = findByLabel(metrics, "edr_alerts_fired_total", "rule_id");
  const apiByPath = findByLabel(metrics, "edr_api_requests_total", "path");

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-heading text-xl font-bold flex items-center gap-2">
            <BarChart3 size={20} style={{ color: "var(--primary)" }} />
            Metrics
          </h1>
          <p className="text-sm" style={{ color: "var(--muted)" }}>
            SOC performance and system telemetry
          </p>
        </div>
        {tab === "system" && (
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
        )}
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 rounded-lg p-1 w-fit" style={{ background: "var(--surface-1)" }}>
        {([
          { id: "soc" as Tab, label: "SOC Metrics", icon: TrendingUp },
          { id: "rules" as Tab, label: "Rule Effectiveness", icon: Target },
          { id: "system" as Tab, label: "System", icon: Cpu },
        ]).map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors"
            style={{
              background: tab === id ? "var(--surface-0)" : "transparent",
              color: tab === id ? "var(--fg)" : "var(--muted)",
              boxShadow: tab === id ? "0 1px 3px rgba(0,0,0,0.15)" : "none",
            }}
          >
            <Icon size={13} />
            {label}
          </button>
        ))}
      </div>

      {/* SOC tab */}
      {tab === "soc" && <SOCTab />}

      {/* Rule Effectiveness tab */}
      {tab === "rules" && <RuleEffectivenessTab />}

      {/* System tab */}
      {tab === "system" && (
        <div className="space-y-6">
          {lastFetch && (
            <div className="text-[10px] font-mono" style={{ color: "var(--muted)" }}>
              Last updated: {lastFetch.toLocaleTimeString()}
            </div>
          )}

          {error && (
            <div className="rounded border p-3 text-xs" style={{ background: "oklch(0.45 0.15 25 / 0.1)", borderColor: "oklch(0.45 0.15 25 / 0.3)", color: "var(--destructive)" }}>
              {error}
            </div>
          )}

          {loading && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {Array.from({ length: 8 }).map((_, i) => <div key={i} className="animate-shimmer h-20 rounded" />)}
            </div>
          )}

          {!loading && (
            <>
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
                <MetricCard icon={Zap} label="Avg Detection Time" value={(avgDetectionTime * 1000).toFixed(3)} unit="ms per event" color="#8b5cf6" />
                <MetricCard icon={Cpu} label="Avg API Latency" value={(avgApiLatency * 1000).toFixed(1)} unit="ms per request" color="#e8a83e" />
              </div>

              <DBSizeSection />

              {eventsByType.length > 0 && (
                <div>
                  <h2 className="text-sm font-semibold mb-3" style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}>
                    Events by Type
                  </h2>
                  <div className="rounded border divide-y" style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}>
                    {eventsByType.slice(0, 15).map((row) => (
                      <div key={row.label} className="flex items-center justify-between px-3 py-2 text-xs" style={{ borderColor: "var(--border)" }}>
                        <span className="font-mono" style={{ color: "var(--fg)" }}>{row.label}</span>
                        <div className="flex items-center gap-3">
                          <div className="w-32 h-1.5 rounded-full overflow-hidden" style={{ background: "var(--surface-1)" }}>
                            <div className="h-full rounded-full" style={{ width: `${Math.min(100, (row.value / (eventsByType[0]?.value || 1)) * 100)}%`, background: "var(--primary)" }} />
                          </div>
                          <span className="font-mono font-bold w-16 text-right" style={{ color: "var(--fg)" }}>{row.value.toLocaleString()}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {alertsByRule.length > 0 && (
                <div>
                  <h2 className="text-sm font-semibold mb-3" style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}>
                    Alerts by Rule
                  </h2>
                  <div className="rounded border divide-y" style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}>
                    {alertsByRule.slice(0, 10).map((row) => (
                      <div key={row.label} className="flex items-center justify-between px-3 py-2 text-xs" style={{ borderColor: "var(--border)" }}>
                        <span className="font-mono truncate" style={{ color: "var(--fg)" }}>{row.label}</span>
                        <span className="font-mono font-bold" style={{ color: "#f97316" }}>{row.value.toLocaleString()}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {apiByPath.length > 0 && (
                <div>
                  <h2 className="text-sm font-semibold mb-3" style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}>
                    Top API Endpoints
                  </h2>
                  <div className="rounded border divide-y" style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}>
                    {apiByPath.slice(0, 10).map((row) => (
                      <div key={row.label} className="flex items-center justify-between px-3 py-2 text-xs" style={{ borderColor: "var(--border)" }}>
                        <span className="font-mono" style={{ color: "var(--fg)" }}>{row.label}</span>
                        <span className="font-mono font-bold" style={{ color: "var(--muted)" }}>{row.value.toLocaleString()}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="text-[10px] font-mono" style={{ color: "var(--muted)" }}>
                {metrics.length} metric families · {metrics.reduce((s, m) => s + m.samples.length, 0)} samples · from /metrics/prometheus
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
