"use client";

import { useCallback, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  Circle,
  ChevronDown,
  ChevronRight,
  Save,
  Loader2,
  Package,
  ShieldAlert,
  Activity,
  Info,
  Search,
} from "lucide-react";
import { api } from "@/lib/api-client";
import { useApi } from "@/hooks/use-api";
import { cn, timeAgo, formatDate, eventTypeColor, severityBgClass } from "@/lib/utils";
import type { Agent, Event, Vulnerability, VulnStats } from "@/types";

/* ── Types ──────────────────────────────────────────────────── */

interface PackageInfo {
  name: string;
  version: string;
  architecture: string;
}

type TabId = "overview" | "events" | "packages" | "vulnerabilities";

/* ── Tab Button ─────────────────────────────────────────────── */

function TabButton({
  id,
  label,
  icon,
  active,
  onClick,
}: {
  id: TabId;
  label: string;
  icon: React.ReactNode;
  active: boolean;
  onClick: (id: TabId) => void;
}) {
  return (
    <button
      onClick={() => onClick(id)}
      className={cn(
        "flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium transition-colors border-b-2",
        active
          ? "border-[var(--primary)] text-[var(--primary)]"
          : "border-transparent hover:bg-[var(--surface-1)]"
      )}
      style={!active ? { color: "var(--muted)" } : {}}
    >
      {icon}
      {label}
    </button>
  );
}

/* ── Skeleton ───────────────────────────────────────────────── */

function Skeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-2">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="animate-shimmer h-8 rounded" />
      ))}
    </div>
  );
}

/* ── Overview Tab ───────────────────────────────────────────── */

function OverviewTab({ agent, events }: { agent: Agent; events: Event[] | null }) {
  const [tags, setTags] = useState(agent.tags?.join(", ") ?? "");
  const [env, setEnv] = useState(agent.env ?? "");
  const [notes, setNotes] = useState(agent.notes ?? "");
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState<string | null>(null);

  async function handleSave() {
    setSaving(true);
    setSaveMsg(null);
    try {
      const tagList = tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
      await api.patch(`/api/v1/agents/${agent.id}`, {
        tags: tagList,
        env,
        notes,
      });
      setSaveMsg("Saved");
      setTimeout(() => setSaveMsg(null), 2000);
    } catch (err) {
      setSaveMsg(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  // Event type breakdown
  const breakdown = useMemo(() => {
    if (!events || events.length === 0) return [];
    const counts: Record<string, number> = {};
    for (const e of events) {
      counts[e.event_type] = (counts[e.event_type] || 0) + 1;
    }
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    const max = sorted[0]?.[1] ?? 1;
    return sorted.map(([type, count]) => ({ type, count, pct: (count / max) * 100 }));
  }, [events]);

  const infoFields = [
    { label: "Agent ID", value: agent.id, mono: true },
    { label: "Hostname", value: agent.hostname },
    { label: "IP Address", value: agent.ip, mono: true },
    { label: "OS", value: agent.os },
    { label: "OS Version", value: agent.os_version },
    { label: "Agent Version", value: agent.agent_ver, mono: true },
    { label: "First Seen", value: formatDate(agent.first_seen) },
    { label: "Last Seen", value: formatDate(agent.last_seen) },
    { label: "Config Version", value: agent.config_ver || "\u2014", mono: true },
  ];

  return (
    <div className="space-y-6">
      {/* Info Grid */}
      <div>
        <h3
          className="text-xs font-semibold font-heading mb-3 uppercase tracking-wider"
          style={{ color: "var(--muted)" }}
        >
          Agent Information
        </h3>
        <div
          className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-1 rounded border p-4"
          style={{ borderColor: "var(--border)", background: "var(--surface-1)" }}
        >
          {infoFields.map((f) => (
            <div key={f.label} className="flex justify-between text-xs py-1.5">
              <span style={{ color: "var(--muted)" }}>{f.label}</span>
              <span
                className={f.mono ? "font-mono" : ""}
                style={{ color: "var(--fg)" }}
              >
                {f.value || "\u2014"}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Editable Fields */}
      <div>
        <h3
          className="text-xs font-semibold font-heading mb-3 uppercase tracking-wider"
          style={{ color: "var(--muted)" }}
        >
          Editable Properties
        </h3>
        <div
          className="rounded border p-4 space-y-3"
          style={{ borderColor: "var(--border)", background: "var(--surface-1)" }}
        >
          <div>
            <label className="block text-[10px] mb-1 uppercase tracking-wider" style={{ color: "var(--muted)" }}>
              Tags (comma-separated)
            </label>
            <input
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="production, web-server, us-east"
              className="w-full rounded border px-3 py-1.5 text-xs font-mono outline-none transition-colors"
              style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
            />
          </div>
          <div>
            <label className="block text-[10px] mb-1 uppercase tracking-wider" style={{ color: "var(--muted)" }}>
              Environment
            </label>
            <input
              value={env}
              onChange={(e) => setEnv(e.target.value)}
              placeholder="production"
              className="w-full rounded border px-3 py-1.5 text-xs outline-none transition-colors"
              style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
            />
          </div>
          <div>
            <label className="block text-[10px] mb-1 uppercase tracking-wider" style={{ color: "var(--muted)" }}>
              Notes
            </label>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={3}
              placeholder="Internal notes about this agent..."
              className="w-full rounded border px-3 py-1.5 text-xs outline-none transition-colors resize-y"
              style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
            />
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleSave}
              disabled={saving}
              className="flex items-center gap-1.5 rounded border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--primary)]/10 disabled:opacity-50"
              style={{ borderColor: "var(--primary)", color: "var(--primary)" }}
            >
              {saving ? <Loader2 size={12} className="animate-spin" /> : <Save size={12} />}
              {saving ? "Saving..." : "Save Changes"}
            </button>
            {saveMsg && (
              <span className="text-xs" style={{ color: saveMsg === "Saved" ? "#22c55e" : "var(--destructive)" }}>
                {saveMsg}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Event Type Breakdown */}
      <div>
        <h3
          className="text-xs font-semibold font-heading mb-3 uppercase tracking-wider"
          style={{ color: "var(--muted)" }}
        >
          Event Type Breakdown
        </h3>
        {!events ? (
          <Skeleton rows={4} />
        ) : breakdown.length === 0 ? (
          <div
            className="rounded border px-3 py-6 text-center text-xs"
            style={{ borderColor: "var(--border)", background: "var(--surface-1)", color: "var(--muted)" }}
          >
            No recent events for this agent
          </div>
        ) : (
          <div
            className="rounded border p-4 space-y-2"
            style={{ borderColor: "var(--border)", background: "var(--surface-1)" }}
          >
            {breakdown.map((b) => (
              <div key={b.type} className="flex items-center gap-3">
                <span className={cn("text-xs font-mono w-40 truncate", eventTypeColor(b.type))}>
                  {b.type}
                </span>
                <div className="flex-1 h-4 rounded overflow-hidden" style={{ background: "var(--surface-0)" }}>
                  <div
                    className="h-full rounded transition-all"
                    style={{
                      width: `${b.pct}%`,
                      background: "var(--primary)",
                      opacity: 0.6,
                    }}
                  />
                </div>
                <span className="text-xs font-mono w-10 text-right" style={{ color: "var(--fg)" }}>
                  {b.count}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Alerts link */}
      <div>
        <Link
          href="/alerts"
          className="inline-flex items-center gap-1.5 text-xs font-medium transition-colors hover:underline"
          style={{ color: "var(--primary)" }}
        >
          <ShieldAlert size={12} />
          View Alerts for this host
        </Link>
      </div>
    </div>
  );
}

/* ── Events Tab ─────────────────────────────────────────────── */

function EventsTab({ agentId }: { agentId: string }) {
  const [filter, setFilter] = useState("ALL");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const fetchEvents = useCallback(
    () =>
      api
        .get<{ events?: Event[] } | Event[]>("/api/v1/events", { agent_id: agentId, limit: 100 })
        .then((r) => (Array.isArray(r) ? r : r.events ?? [])),
    [agentId]
  );
  const { data: events, loading } = useApi(fetchEvents);

  const eventTypes = useMemo(() => {
    if (!events) return [];
    const types = new Set(events.map((e) => e.event_type));
    return Array.from(types).sort();
  }, [events]);

  const filtered = useMemo(() => {
    if (!events) return [];
    if (filter === "ALL") return events;
    return events.filter((e) => e.event_type === filter);
  }, [events, filter]);

  if (loading) return <Skeleton rows={8} />;

  return (
    <div className="space-y-3">
      {/* Filter pills */}
      <div className="flex flex-wrap gap-1.5">
        {["ALL", ...eventTypes].map((t) => (
          <button
            key={t}
            onClick={() => setFilter(t)}
            className={cn(
              "rounded-full px-2.5 py-1 text-[10px] font-medium transition-colors border",
              filter === t
                ? "border-[var(--primary)] text-[var(--primary)] bg-[var(--primary)]/10"
                : "border-[var(--border)] hover:bg-[var(--surface-1)]"
            )}
            style={filter !== t ? { color: "var(--muted)" } : {}}
          >
            {t === "ALL" ? "All" : t}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr
              className="text-left text-[10px] uppercase tracking-wider border-b"
              style={{ color: "var(--muted)", borderColor: "var(--border)" }}
            >
              <th className="pb-2 pr-4 w-6"></th>
              <th className="pb-2 pr-4">Time</th>
              <th className="pb-2 pr-4">Type</th>
              <th className="pb-2">Summary</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((e) => {
              const isExpanded = expandedId === e.id;
              const summary = eventSummary(e);
              return (
                <tr key={e.id} className="group">
                  <td colSpan={4} className="p-0">
                    <div
                      className="border-b cursor-pointer transition-colors hover:bg-[var(--surface-1)]"
                      style={{ borderColor: "var(--border)" }}
                      onClick={() => setExpandedId(isExpanded ? null : e.id)}
                    >
                      <div className="flex items-center py-2">
                        <div className="pr-2 pl-1">
                          {isExpanded ? (
                            <ChevronDown size={12} style={{ color: "var(--muted)" }} />
                          ) : (
                            <ChevronRight size={12} style={{ color: "var(--muted)" }} />
                          )}
                        </div>
                        <div className="pr-4 text-xs whitespace-nowrap" style={{ color: "var(--muted)" }}>
                          {timeAgo(e.timestamp)}
                        </div>
                        <div className="pr-4">
                          <span
                            className={cn(
                              "inline-block rounded-full px-2 py-0.5 text-[10px] font-medium",
                              eventTypeColor(e.event_type)
                            )}
                            style={{ background: "var(--surface-1)" }}
                          >
                            {e.event_type}
                          </span>
                        </div>
                        <div
                          className="flex-1 text-xs truncate font-mono"
                          style={{ color: "var(--fg)" }}
                        >
                          {summary}
                        </div>
                      </div>
                    </div>
                    {isExpanded && (
                      <div
                        className="px-4 py-3 border-b text-xs"
                        style={{
                          borderColor: "var(--border)",
                          background: "var(--surface-1)",
                        }}
                      >
                        <pre
                          className="font-mono text-[11px] whitespace-pre-wrap overflow-x-auto"
                          style={{ color: "var(--fg)" }}
                        >
                          {JSON.stringify(e.payload, null, 2)}
                        </pre>
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="py-12 text-center text-xs" style={{ color: "var(--muted)" }}>
            No events found
          </div>
        )}
      </div>
    </div>
  );
}

function eventSummary(e: Event): string {
  const p = e.payload ?? {};
  switch (e.event_type) {
    case "PROCESS_EXEC":
      return `${p.comm || p.filename || "?"} (pid ${p.pid ?? "?"})`;
    case "PROCESS_EXIT":
      return `pid ${p.pid ?? "?"} exited (code ${p.exit_code ?? "?"})`;
    case "FILE_OPEN":
    case "FILE_CREATE":
    case "FILE_DELETE":
    case "FILE_RENAME":
      return String(p.filename || p.path || "?");
    case "NET_CONNECT":
      return `${p.dest_ip ?? p.dst_ip ?? "?"}:${p.dest_port ?? p.dst_port ?? "?"}`;
    case "DNS_QUERY":
      return String(p.query || p.domain || "?");
    default:
      return Object.values(p).slice(0, 3).join(" | ") || "\u2014";
  }
}

/* ── Packages Tab ───────────────────────────────────────────── */

function PackagesTab({ agentId }: { agentId: string }) {
  const [search, setSearch] = useState("");

  const fetchPkgs = useCallback(
    () =>
      api
        .get<{ packages?: PackageInfo[] } | PackageInfo[]>(`/api/v1/agents/${agentId}/packages`)
        .then((r) => (Array.isArray(r) ? r : r.packages ?? [])),
    [agentId]
  );
  const { data: packages, loading } = useApi(fetchPkgs);

  const filtered = useMemo(() => {
    if (!packages) return [];
    if (!search.trim()) return packages;
    const q = search.toLowerCase();
    return packages.filter(
      (p) =>
        p.name?.toLowerCase().includes(q) ||
        p.version?.toLowerCase().includes(q)
    );
  }, [packages, search]);

  if (loading) return <Skeleton rows={8} />;

  return (
    <div className="space-y-3">
      {/* Search */}
      <div className="relative">
        <Search
          size={14}
          className="absolute left-3 top-1/2 -translate-y-1/2"
          style={{ color: "var(--muted)" }}
        />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search packages..."
          className="w-full rounded border pl-8 pr-3 py-1.5 text-xs outline-none transition-colors"
          style={{ background: "var(--surface-1)", borderColor: "var(--border)", color: "var(--fg)" }}
        />
      </div>

      {filtered.length === 0 && (
        <div
          className="rounded border px-3 py-12 text-center text-xs"
          style={{ borderColor: "var(--border)", background: "var(--surface-1)", color: "var(--muted)" }}
        >
          {packages && packages.length === 0
            ? "No package inventory available"
            : "No packages match your search"}
        </div>
      )}

      {filtered.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr
                className="text-left text-[10px] uppercase tracking-wider border-b"
                style={{ color: "var(--muted)", borderColor: "var(--border)" }}
              >
                <th className="pb-2 pr-4">Package Name</th>
                <th className="pb-2 pr-4">Version</th>
                <th className="pb-2">Architecture</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((p, i) => (
                <tr
                  key={`${p.name}-${i}`}
                  className="border-b transition-colors hover:bg-[var(--surface-1)]"
                  style={{ borderColor: "var(--border)" }}
                >
                  <td className="py-2 pr-4 text-xs font-medium" style={{ color: "var(--fg)" }}>
                    {p.name}
                  </td>
                  <td className="py-2 pr-4 text-xs font-mono" style={{ color: "var(--muted)" }}>
                    {p.version}
                  </td>
                  <td className="py-2 text-xs" style={{ color: "var(--muted)" }}>
                    {p.architecture || "\u2014"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ── Vulnerabilities Tab ────────────────────────────────────── */

function VulnerabilitiesTab({ agentId }: { agentId: string }) {
  const fetchVulns = useCallback(
    () =>
      api
        .get<{ vulnerabilities?: Vulnerability[]; stats?: VulnStats }>(`/api/v1/agents/${agentId}/vulnerabilities`)
        .then((r) => ({
          vulnerabilities: r.vulnerabilities ?? [],
          stats: r.stats ?? null,
        })),
    [agentId]
  );
  const { data, loading } = useApi(fetchVulns);

  if (loading) return <Skeleton rows={8} />;

  const vulns = data?.vulnerabilities ?? [];
  const stats = data?.stats;

  const sevBadge = (sev: string) => {
    const s = sev?.toLowerCase();
    const map: Record<string, string> = {
      critical: "bg-red-600/15 text-red-400",
      high: "bg-orange-500/15 text-orange-400",
      medium: "bg-amber-500/15 text-amber-400",
      low: "bg-blue-500/15 text-blue-400",
    };
    return map[s] ?? "bg-neutral-500/15 text-neutral-400";
  };

  return (
    <div className="space-y-4">
      {/* Stats bar */}
      {stats && (
        <div className="flex flex-wrap gap-3">
          {(
            [
              { label: "Critical", count: stats.critical, cls: "text-red-400 bg-red-600/10 border-red-600/20" },
              { label: "High", count: stats.high, cls: "text-orange-400 bg-orange-500/10 border-orange-500/20" },
              { label: "Medium", count: stats.medium, cls: "text-amber-400 bg-amber-500/10 border-amber-500/20" },
              { label: "Low", count: stats.low, cls: "text-blue-400 bg-blue-500/10 border-blue-500/20" },
            ] as const
          ).map((s) => (
            <div
              key={s.label}
              className={cn("rounded border px-3 py-2 text-center min-w-[80px]", s.cls)}
            >
              <div className="text-lg font-bold font-mono">{s.count}</div>
              <div className="text-[10px] uppercase tracking-wider">{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {vulns.length === 0 && (
        <div
          className="rounded border px-3 py-12 text-center text-xs"
          style={{ borderColor: "var(--border)", background: "var(--surface-1)", color: "var(--muted)" }}
        >
          No vulnerabilities detected
        </div>
      )}

      {vulns.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr
                className="text-left text-[10px] uppercase tracking-wider border-b"
                style={{ color: "var(--muted)", borderColor: "var(--border)" }}
              >
                <th className="pb-2 pr-4">CVE ID</th>
                <th className="pb-2 pr-4">Package</th>
                <th className="pb-2 pr-4">Version</th>
                <th className="pb-2 pr-4">Severity</th>
                <th className="pb-2">Fixed Version</th>
              </tr>
            </thead>
            <tbody>
              {vulns.map((v) => (
                <tr
                  key={v.id}
                  className="border-b transition-colors hover:bg-[var(--surface-1)]"
                  style={{ borderColor: "var(--border)" }}
                >
                  <td className="py-2 pr-4 text-xs font-mono" style={{ color: "var(--fg)" }}>
                    {v.cve_id}
                  </td>
                  <td className="py-2 pr-4 text-xs" style={{ color: "var(--fg)" }}>
                    {v.package_name}
                  </td>
                  <td className="py-2 pr-4 text-xs font-mono" style={{ color: "var(--muted)" }}>
                    {v.package_version}
                  </td>
                  <td className="py-2 pr-4">
                    <span
                      className={cn(
                        "inline-block rounded-full px-2 py-0.5 text-[10px] font-medium",
                        sevBadge(v.severity)
                      )}
                    >
                      {v.severity}
                    </span>
                  </td>
                  <td className="py-2 text-xs font-mono" style={{ color: "var(--muted)" }}>
                    {v.fixed_version || "\u2014"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ── Main Page ──────────────────────────────────────────────── */

export default function AgentDetailPage() {
  const params = useParams<{ id: string }>();
  const agentId = params.id;
  const [activeTab, setActiveTab] = useState<TabId>("overview");

  const fetchAgent = useCallback(
    () => api.get<Agent | { agent: Agent }>(`/api/v1/agents/${agentId}`).then((r) =>
      "agent" in r && typeof r === "object" && r !== null && !Array.isArray(r) && "agent" in (r as Record<string, unknown>)
        ? (r as { agent: Agent }).agent
        : (r as Agent)
    ),
    [agentId]
  );
  const { data: agent, loading, error } = useApi(fetchAgent);

  // Fetch last 200 events for overview breakdown (only when on overview tab)
  const fetchOverviewEvents = useCallback(
    () =>
      api
        .get<{ events?: Event[] } | Event[]>("/api/v1/events", { agent_id: agentId, limit: 200 })
        .then((r) => (Array.isArray(r) ? r : r.events ?? [])),
    [agentId]
  );
  const { data: overviewEvents } = useApi(fetchOverviewEvents);

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="animate-shimmer h-16 rounded" />
        <div className="animate-shimmer h-8 rounded w-1/3" />
        <Skeleton rows={6} />
      </div>
    );
  }

  if (error || !agent) {
    return (
      <div className="space-y-4">
        <Link
          href="/agents"
          className="inline-flex items-center gap-1 text-xs transition-colors hover:underline"
          style={{ color: "var(--primary)" }}
        >
          <ArrowLeft size={14} />
          Back to Agents
        </Link>
        <div
          className="rounded border px-4 py-12 text-center text-sm"
          style={{ borderColor: "var(--border)", background: "var(--surface-1)", color: "var(--muted)" }}
        >
          {error ?? "Agent not found"}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div>
        <Link
          href="/agents"
          className="inline-flex items-center gap-1 text-xs mb-3 transition-colors hover:underline"
          style={{ color: "var(--primary)" }}
        >
          <ArrowLeft size={14} />
          Back to Agents
        </Link>

        <div className="flex flex-wrap items-center gap-3">
          <h1 className="font-heading text-xl font-bold" style={{ color: "var(--fg)" }}>
            {agent.hostname}
          </h1>
          <div className="flex items-center gap-1.5">
            <Circle
              className={cn(
                "h-2.5 w-2.5 fill-current",
                agent.is_online ? "text-emerald-400" : "text-red-400"
              )}
            />
            <span className="text-xs font-medium" style={{ color: agent.is_online ? "#34d399" : "#f87171" }}>
              {agent.is_online ? "Online" : "Offline"}
            </span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-4 mt-1">
          <span className="text-xs font-mono" style={{ color: "var(--muted)" }}>
            {agent.ip}
          </span>
          <span className="text-xs" style={{ color: "var(--muted)" }}>
            {agent.agent_ver}
          </span>
          <span className="text-xs" style={{ color: "var(--muted)" }}>
            {agent.os} {agent.os_version}
          </span>
          <span className="text-xs" style={{ color: "var(--muted)" }}>
            Last seen {timeAgo(agent.last_seen)}
          </span>
        </div>
      </div>

      {/* Tab navigation */}
      <div className="flex border-b" style={{ borderColor: "var(--border)" }}>
        <TabButton
          id="overview"
          label="Overview"
          icon={<Info size={13} />}
          active={activeTab === "overview"}
          onClick={setActiveTab}
        />
        <TabButton
          id="events"
          label="Events"
          icon={<Activity size={13} />}
          active={activeTab === "events"}
          onClick={setActiveTab}
        />
        <TabButton
          id="packages"
          label="Packages"
          icon={<Package size={13} />}
          active={activeTab === "packages"}
          onClick={setActiveTab}
        />
        <TabButton
          id="vulnerabilities"
          label="Vulnerabilities"
          icon={<ShieldAlert size={13} />}
          active={activeTab === "vulnerabilities"}
          onClick={setActiveTab}
        />
      </div>

      {/* Tab content */}
      <div>
        {activeTab === "overview" && <OverviewTab agent={agent} events={overviewEvents} />}
        {activeTab === "events" && <EventsTab agentId={agentId} />}
        {activeTab === "packages" && <PackagesTab agentId={agentId} />}
        {activeTab === "vulnerabilities" && <VulnerabilitiesTab agentId={agentId} />}
      </div>
    </div>
  );
}
