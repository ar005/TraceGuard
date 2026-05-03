"use client";

import { useCallback, useMemo, useState, useEffect } from "react";
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
  Plus,
  X,
  BookOpen,
  Settings2,
  CalendarClock,
  Pencil,
  Trash2,
  Clock,
  CheckCircle2,
  PauseCircle,
  Play,
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

type TabId = "overview" | "events" | "packages" | "vulnerabilities" | "winevent-config" | "event-reference" | "tasks";

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
    (signal: AbortSignal) =>
      api
        .get<{ events?: Event[] } | Event[]>("/api/v1/events", { agent_id: agentId, limit: 100 }, signal)
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
    (signal: AbortSignal) =>
      api
        .get<{ packages?: PackageInfo[] } | PackageInfo[]>(`/api/v1/agents/${agentId}/packages`, undefined, signal)
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
    (signal: AbortSignal) =>
      api
        .get<{ vulnerabilities?: Vulnerability[]; stats?: VulnStats }>(`/api/v1/agents/${agentId}/vulnerabilities`, undefined, signal)
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

/* ── WinEvent Config Tab ───────────────────────────────────── */

const CHANNEL_PRESETS = [
  "Security",
  "System",
  "Application",
  "Microsoft-Windows-Sysmon/Operational",
  "Microsoft-Windows-PowerShell/Operational",
  "Microsoft-Windows-Windows Defender/Operational",
];

interface ChannelConfig {
  name: string;
  event_ids: number[];
}

function WinEventConfigTab({ agentId }: { agentId: string }) {
  const [channels, setChannels] = useState<ChannelConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    api
      .get<{ channels?: ChannelConfig[] }>(`/api/v1/agents/${agentId}/winevent-config`)
      .then((r) => {
        setChannels(r.channels ?? []);
      })
      .catch(() => {
        setChannels([]);
      })
      .finally(() => setLoading(false));
  }, [agentId]);

  function addChannel() {
    setChannels((prev) => [...prev, { name: "", event_ids: [] }]);
  }

  function removeChannel(idx: number) {
    setChannels((prev) => prev.filter((_, i) => i !== idx));
  }

  function updateChannelName(idx: number, name: string) {
    setChannels((prev) => prev.map((ch, i) => (i === idx ? { ...ch, name } : ch)));
  }

  function updateEventIds(idx: number, raw: string) {
    const ids = raw
      .split(",")
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => !isNaN(n));
    setChannels((prev) => prev.map((ch, i) => (i === idx ? { ...ch, event_ids: ids } : ch)));
  }

  async function handleSave() {
    setSaving(true);
    setSaveMsg(null);
    try {
      await api.patch(`/api/v1/agents/${agentId}/winevent-config`, { channels });
      setSaveMsg("Saved");
      setTimeout(() => setSaveMsg(null), 3000);
    } catch (err) {
      setSaveMsg(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <Skeleton rows={4} />;

  return (
    <div className="space-y-4">
      <div>
        <h3
          className="text-xs font-semibold font-heading mb-3 uppercase tracking-wider"
          style={{ color: "var(--muted)" }}
        >
          Channel Configuration
        </h3>

        <div className="space-y-3">
          {channels.map((ch, idx) => (
            <div
              key={idx}
              className="rounded border p-3 space-y-2"
              style={{ borderColor: "var(--border)", background: "var(--surface-1)" }}
            >
              <div className="flex items-center gap-2">
                <div className="flex-1">
                  <label className="block text-[10px] mb-1 uppercase tracking-wider" style={{ color: "var(--muted)" }}>
                    Channel Name
                  </label>
                  <div className="flex gap-2">
                    <input
                      value={ch.name}
                      onChange={(e) => updateChannelName(idx, e.target.value)}
                      list={`channel-presets-${idx}`}
                      placeholder="Select or type a channel name"
                      className="flex-1 rounded border px-3 py-1.5 text-xs font-mono outline-none transition-colors"
                      style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
                    />
                    <datalist id={`channel-presets-${idx}`}>
                      {CHANNEL_PRESETS.map((p) => (
                        <option key={p} value={p} />
                      ))}
                    </datalist>
                  </div>
                </div>
                <button
                  onClick={() => removeChannel(idx)}
                  className="mt-4 p-1.5 rounded hover:bg-red-500/10 transition-colors"
                  style={{ color: "#ef4444" }}
                  title="Remove channel"
                >
                  <X size={14} />
                </button>
              </div>
              <div>
                <label className="block text-[10px] mb-1 uppercase tracking-wider" style={{ color: "var(--muted)" }}>
                  Event IDs (comma-separated, empty = all events)
                </label>
                <input
                  value={ch.event_ids.join(", ")}
                  onChange={(e) => updateEventIds(idx, e.target.value)}
                  placeholder="e.g. 4624, 4625, 4688"
                  className="w-full rounded border px-3 py-1.5 text-xs font-mono outline-none transition-colors"
                  style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
                />
              </div>
            </div>
          ))}
        </div>

        <button
          onClick={addChannel}
          className="mt-3 flex items-center gap-1.5 rounded border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-1)]"
          style={{ borderColor: "var(--border)", color: "var(--primary)" }}
        >
          <Plus size={12} />
          Add Channel
        </button>
      </div>

      <div className="flex items-center gap-3">
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-1.5 rounded border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--primary)]/10 disabled:opacity-50"
          style={{ borderColor: "var(--primary)", color: "var(--primary)" }}
        >
          {saving ? <Loader2 size={12} className="animate-spin" /> : <Save size={12} />}
          {saving ? "Saving..." : "Save Configuration"}
        </button>
        {saveMsg && (
          <span className="text-xs" style={{ color: saveMsg === "Saved" ? "#22c55e" : "var(--destructive)" }}>
            {saveMsg}
          </span>
        )}
      </div>

      <div
        className="rounded border px-3 py-2 text-[10px] leading-relaxed"
        style={{ borderColor: "var(--border)", background: "var(--surface-1)", color: "var(--muted)" }}
      >
        Changes take effect on next agent config sync (within 60 seconds).
      </div>
    </div>
  );
}

/* ── Event Reference Data ──────────────────────────────────── */

interface EventRefEntry {
  id: number;
  channel: string;
  category: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
}

const EVENT_REFERENCE: EventRefEntry[] = [
  // Security Log
  { id: 4624, channel: "Security", category: "Authentication", description: "Successful logon", severity: "info" },
  { id: 4625, channel: "Security", category: "Authentication", description: "Failed logon", severity: "medium" },
  { id: 4634, channel: "Security", category: "Authentication", description: "Logoff", severity: "info" },
  { id: 4648, channel: "Security", category: "Authentication", description: "Logon using explicit credentials (runas)", severity: "medium" },
  { id: 4672, channel: "Security", category: "Authentication", description: "Special privileges assigned to new logon", severity: "medium" },
  { id: 4688, channel: "Security", category: "Process", description: "New process created", severity: "info" },
  { id: 4689, channel: "Security", category: "Process", description: "Process terminated", severity: "info" },
  { id: 4697, channel: "Security", category: "Service", description: "Service installed", severity: "high" },
  { id: 4698, channel: "Security", category: "Scheduled Task", description: "Scheduled task created", severity: "high" },
  { id: 4699, channel: "Security", category: "Scheduled Task", description: "Scheduled task deleted", severity: "medium" },
  { id: 4700, channel: "Security", category: "Scheduled Task", description: "Scheduled task enabled", severity: "medium" },
  { id: 4701, channel: "Security", category: "Scheduled Task", description: "Scheduled task disabled", severity: "low" },
  { id: 4702, channel: "Security", category: "Scheduled Task", description: "Scheduled task updated", severity: "medium" },
  { id: 4720, channel: "Security", category: "Account Mgmt", description: "User account created", severity: "high" },
  { id: 4722, channel: "Security", category: "Account Mgmt", description: "User account enabled", severity: "medium" },
  { id: 4723, channel: "Security", category: "Account Mgmt", description: "Password change attempted", severity: "medium" },
  { id: 4724, channel: "Security", category: "Account Mgmt", description: "Password reset attempted", severity: "medium" },
  { id: 4725, channel: "Security", category: "Account Mgmt", description: "User account disabled", severity: "medium" },
  { id: 4726, channel: "Security", category: "Account Mgmt", description: "User account deleted", severity: "high" },
  { id: 4728, channel: "Security", category: "Group Mgmt", description: "Member added to security-enabled global group", severity: "high" },
  { id: 4732, channel: "Security", category: "Group Mgmt", description: "Member added to security-enabled local group", severity: "high" },
  { id: 4733, channel: "Security", category: "Group Mgmt", description: "Member removed from security-enabled local group", severity: "medium" },
  { id: 4738, channel: "Security", category: "Account Mgmt", description: "User account changed", severity: "medium" },
  { id: 4740, channel: "Security", category: "Account Mgmt", description: "User account locked out", severity: "high" },
  { id: 4756, channel: "Security", category: "Group Mgmt", description: "Member added to universal group", severity: "high" },
  { id: 4757, channel: "Security", category: "Group Mgmt", description: "Member removed from universal group", severity: "medium" },
  { id: 4768, channel: "Security", category: "Kerberos", description: "Kerberos TGT requested", severity: "info" },
  { id: 4769, channel: "Security", category: "Kerberos", description: "Kerberos service ticket requested", severity: "info" },
  { id: 4771, channel: "Security", category: "Kerberos", description: "Kerberos pre-authentication failed", severity: "medium" },
  { id: 4776, channel: "Security", category: "Authentication", description: "NTLM authentication attempted", severity: "medium" },
  { id: 5140, channel: "Security", category: "File Share", description: "Network share accessed", severity: "low" },
  { id: 5145, channel: "Security", category: "File Share", description: "Network share object access checked", severity: "low" },
  { id: 5156, channel: "Security", category: "Firewall", description: "Windows Filtering Platform allowed connection", severity: "info" },
  { id: 5157, channel: "Security", category: "Firewall", description: "Windows Filtering Platform blocked connection", severity: "medium" },
  // System Log
  { id: 1074, channel: "System", category: "System", description: "System shutdown/restart initiated", severity: "medium" },
  { id: 6005, channel: "System", category: "System", description: "Event Log service started (system boot)", severity: "info" },
  { id: 6006, channel: "System", category: "System", description: "Event Log service stopped (system shutdown)", severity: "info" },
  { id: 6008, channel: "System", category: "System", description: "Unexpected shutdown", severity: "high" },
  { id: 7034, channel: "System", category: "Service", description: "Service crashed unexpectedly", severity: "high" },
  { id: 7036, channel: "System", category: "Service", description: "Service entered running/stopped state", severity: "info" },
  { id: 7040, channel: "System", category: "Service", description: "Service start type changed", severity: "medium" },
  { id: 7045, channel: "System", category: "Service", description: "New service installed", severity: "high" },
  // Sysmon
  { id: 1, channel: "Microsoft-Windows-Sysmon/Operational", category: "Process", description: "Process creation with full command line", severity: "info" },
  { id: 2, channel: "Microsoft-Windows-Sysmon/Operational", category: "File", description: "File creation time changed", severity: "medium" },
  { id: 3, channel: "Microsoft-Windows-Sysmon/Operational", category: "Network", description: "Network connection", severity: "info" },
  { id: 5, channel: "Microsoft-Windows-Sysmon/Operational", category: "Process", description: "Process terminated", severity: "info" },
  { id: 6, channel: "Microsoft-Windows-Sysmon/Operational", category: "Driver", description: "Driver loaded", severity: "medium" },
  { id: 7, channel: "Microsoft-Windows-Sysmon/Operational", category: "Module", description: "Image loaded (DLL)", severity: "info" },
  { id: 8, channel: "Microsoft-Windows-Sysmon/Operational", category: "Process", description: "CreateRemoteThread detected", severity: "high" },
  { id: 10, channel: "Microsoft-Windows-Sysmon/Operational", category: "Process", description: "Process accessed (OpenProcess)", severity: "high" },
  { id: 11, channel: "Microsoft-Windows-Sysmon/Operational", category: "File", description: "File created", severity: "info" },
  { id: 12, channel: "Microsoft-Windows-Sysmon/Operational", category: "Registry", description: "Registry object added/deleted", severity: "medium" },
  { id: 13, channel: "Microsoft-Windows-Sysmon/Operational", category: "Registry", description: "Registry value set", severity: "medium" },
  { id: 15, channel: "Microsoft-Windows-Sysmon/Operational", category: "File", description: "Alternate data stream created", severity: "high" },
  { id: 22, channel: "Microsoft-Windows-Sysmon/Operational", category: "DNS", description: "DNS query", severity: "info" },
  { id: 23, channel: "Microsoft-Windows-Sysmon/Operational", category: "File", description: "File delete archived", severity: "low" },
  { id: 25, channel: "Microsoft-Windows-Sysmon/Operational", category: "Process", description: "Process tampering", severity: "critical" },
  { id: 26, channel: "Microsoft-Windows-Sysmon/Operational", category: "File", description: "File delete logged", severity: "low" },
  // PowerShell
  { id: 4103, channel: "Microsoft-Windows-PowerShell/Operational", category: "PowerShell", description: "Module logging", severity: "low" },
  { id: 4104, channel: "Microsoft-Windows-PowerShell/Operational", category: "PowerShell", description: "Script block logging", severity: "medium" },
  { id: 4105, channel: "Microsoft-Windows-PowerShell/Operational", category: "PowerShell", description: "Command started", severity: "info" },
  { id: 4106, channel: "Microsoft-Windows-PowerShell/Operational", category: "PowerShell", description: "Command completed", severity: "info" },
  // Windows Defender
  { id: 1006, channel: "Microsoft-Windows-Windows Defender/Operational", category: "Defender", description: "Malware or unwanted software detected", severity: "critical" },
  { id: 1007, channel: "Microsoft-Windows-Windows Defender/Operational", category: "Defender", description: "Action taken to protect system", severity: "high" },
  { id: 1008, channel: "Microsoft-Windows-Windows Defender/Operational", category: "Defender", description: "Failed to take action on malware", severity: "critical" },
  { id: 1116, channel: "Microsoft-Windows-Windows Defender/Operational", category: "Defender", description: "Real-time protection detected malware", severity: "critical" },
  { id: 1117, channel: "Microsoft-Windows-Windows Defender/Operational", category: "Defender", description: "Real-time protection took action", severity: "high" },
  { id: 5001, channel: "Microsoft-Windows-Windows Defender/Operational", category: "Defender", description: "Real-time protection disabled", severity: "critical" },
];

/* ── Event Reference Tab ───────────────────────────────────── */

function EventReferenceTab({ agentId, agentOs }: { agentId: string; agentOs: string }) {
  const [search, setSearch] = useState("");
  const [addedMsg, setAddedMsg] = useState<string | null>(null);

  const filtered = useMemo(() => {
    if (!search.trim()) return EVENT_REFERENCE;
    const q = search.toLowerCase();
    return EVENT_REFERENCE.filter(
      (e) =>
        String(e.id).includes(q) ||
        e.channel.toLowerCase().includes(q) ||
        e.category.toLowerCase().includes(q) ||
        e.description.toLowerCase().includes(q)
    );
  }, [search]);

  async function handleQuickAdd(entry: EventRefEntry) {
    try {
      const res = await api.get<{ channels?: ChannelConfig[] }>(`/api/v1/agents/${agentId}/winevent-config`);
      const channels = res.channels ?? [];
      const existing = channels.find((ch) => ch.name === entry.channel);
      let updatedChannels: ChannelConfig[];
      if (existing) {
        if (existing.event_ids.length === 0) {
          // "all events" - no need to add
          setAddedMsg(`Channel "${entry.channel}" already monitors all events`);
          setTimeout(() => setAddedMsg(null), 3000);
          return;
        }
        if (existing.event_ids.includes(entry.id)) {
          setAddedMsg(`Event ${entry.id} already in "${entry.channel}"`);
          setTimeout(() => setAddedMsg(null), 3000);
          return;
        }
        updatedChannels = channels.map((ch) =>
          ch.name === entry.channel ? { ...ch, event_ids: [...ch.event_ids, entry.id] } : ch
        );
      } else {
        updatedChannels = [...channels, { name: entry.channel, event_ids: [entry.id] }];
      }
      await api.patch(`/api/v1/agents/${agentId}/winevent-config`, { channels: updatedChannels });
      setAddedMsg(`Added event ${entry.id} to "${entry.channel}"`);
      setTimeout(() => setAddedMsg(null), 3000);
    } catch (err) {
      setAddedMsg(err instanceof Error ? err.message : "Failed to add");
      setTimeout(() => setAddedMsg(null), 3000);
    }
  }

  const sevColor = (sev: string) => {
    switch (sev) {
      case "critical": return "bg-red-600/15 text-red-400";
      case "high": return "bg-orange-500/15 text-orange-400";
      case "medium": return "bg-amber-500/15 text-amber-400";
      case "low": return "bg-blue-500/15 text-blue-400";
      default: return "bg-neutral-500/15 text-neutral-400";
    }
  };

  const isWindows = agentOs.toLowerCase() === "windows";

  return (
    <div className="space-y-3">
      {!isWindows && (
        <div
          className="rounded border px-3 py-2 text-xs"
          style={{ borderColor: "var(--border)", background: "var(--surface-1)", color: "var(--muted)" }}
        >
          This agent runs {agentOs}. The event reference below documents Windows Event IDs for cross-reference purposes.
        </div>
      )}

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
          placeholder="Search by event ID, channel, category, or description..."
          className="w-full rounded border pl-8 pr-3 py-1.5 text-xs outline-none transition-colors"
          style={{ background: "var(--surface-1)", borderColor: "var(--border)", color: "var(--fg)" }}
        />
      </div>

      {addedMsg && (
        <div
          className="rounded border px-3 py-1.5 text-xs"
          style={{
            borderColor: addedMsg.includes("Failed") || addedMsg.includes("failed") ? "var(--destructive)" : "oklch(0.55 0.15 145 / 0.3)",
            background: addedMsg.includes("Failed") || addedMsg.includes("failed") ? "oklch(0.45 0.15 25 / 0.1)" : "oklch(0.55 0.15 145 / 0.1)",
            color: addedMsg.includes("Failed") || addedMsg.includes("failed") ? "var(--destructive)" : "#22c55e",
          }}
        >
          {addedMsg}
        </div>
      )}

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr
              className="text-left text-[10px] uppercase tracking-wider border-b"
              style={{ color: "var(--muted)", borderColor: "var(--border)" }}
            >
              <th className="pb-2 pr-4">Event ID</th>
              <th className="pb-2 pr-4">Channel</th>
              <th className="pb-2 pr-4">Category</th>
              <th className="pb-2 pr-4">Description</th>
              <th className="pb-2 pr-4">Severity</th>
              {isWindows && <th className="pb-2">Action</th>}
            </tr>
          </thead>
          <tbody>
            {filtered.map((e) => (
              <tr
                key={`${e.channel}-${e.id}`}
                className="border-b transition-colors hover:bg-[var(--surface-1)]"
                style={{ borderColor: "var(--border)" }}
              >
                <td className="py-2 pr-4 text-xs font-mono font-medium" style={{ color: "var(--fg)" }}>
                  {e.id}
                </td>
                <td className="py-2 pr-4 text-xs" style={{ color: "var(--muted)" }}>
                  {e.channel}
                </td>
                <td className="py-2 pr-4 text-xs" style={{ color: "var(--fg)" }}>
                  {e.category}
                </td>
                <td className="py-2 pr-4 text-xs" style={{ color: "var(--fg)" }}>
                  {e.description}
                </td>
                <td className="py-2 pr-4">
                  <span className={cn("inline-block rounded-full px-2 py-0.5 text-[10px] font-medium", sevColor(e.severity))}>
                    {e.severity}
                  </span>
                </td>
                {isWindows && (
                  <td className="py-2">
                    <button
                      onClick={() => handleQuickAdd(e)}
                      className="flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-medium transition-colors hover:bg-[var(--primary)]/10"
                      style={{ color: "var(--primary)" }}
                      title="Add to WinEvent config"
                    >
                      <Plus size={10} />
                      Add
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="py-12 text-center text-xs" style={{ color: "var(--muted)" }}>
            No events match your search
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Tasks Tab ──────────────────────────────────────────────── */

interface AgentTask {
  id: string;
  name: string;
  type: string;
  schedule: string;
  status: string;
  last_run_at: string | null;
  next_run_at: string | null;
  created_at: string;
  created_by: string;
}

interface TaskEvent {
  id: string;
  task_id: string;
  task_name: string;
  task_type: string;
  action: string;
  actor: string;
  detail: Record<string, unknown>;
  occurred_at: string;
}

const STATUS_ICON: Record<string, React.ReactNode> = {
  active:    <CheckCircle2 size={13} className="text-emerald-400" />,
  paused:    <PauseCircle  size={13} className="text-yellow-400" />,
  completed: <CheckCircle2 size={13} className="text-sky-400" />,
  deleted:   <X            size={13} className="text-red-400" />,
};

function TasksTab({ agentId }: { agentId: string }) {
  const { data: tasksData, loading: tasksLoading, refetch: refreshTasks } = useApi<{ tasks: AgentTask[]; total: number }>(
    (signal) => api.get(`/api/v1/agents/${agentId}/tasks`, {}, signal)
  );
  const { data: historyData, loading: historyLoading } = useApi<{ events: TaskEvent[]; total: number }>(
    (signal) => api.get(`/api/v1/agents/${agentId}/tasks/history`, { limit: 50 }, signal)
  );
  const [activeView, setActiveView] = useState<"tasks" | "history">("tasks");
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ name: "", type: "script", schedule: "", payload: "" });
  const [editId, setEditId] = useState<string | null>(null);
  const [editStatus, setEditStatus] = useState("");

  const tasks = tasksData?.tasks ?? [];
  const events = historyData?.events ?? [];

  async function handleCreate() {
    if (!form.name.trim()) return;
    setCreating(true);
    try {
      let payload = {};
      try { payload = JSON.parse(form.payload || "{}"); } catch { /* ignore */ }
      await api.post(`/api/v1/agents/${agentId}/tasks`, { name: form.name, type: form.type, schedule: form.schedule, payload });
      setForm({ name: "", type: "script", schedule: "", payload: "" });
      setShowCreate(false);
      refreshTasks();
    } finally {
      setCreating(false);
    }
  }

  async function handleStatusChange(taskId: string, status: string) {
    await api.put(`/api/v1/agents/${agentId}/tasks/${taskId}`, { status });
    setEditId(null);
    refreshTasks();
  }

  async function handleRun(taskId: string) {
    await api.post(`/api/v1/agents/${agentId}/tasks/${taskId}/run`, {});
    refreshTasks();
  }

  async function handleDelete(taskId: string) {
    if (!confirm("Delete this task?")) return;
    await api.del(`/api/v1/agents/${agentId}/tasks/${taskId}`);
    refreshTasks();
  }

  return (
    <div className="p-4 space-y-4">
      {/* Sub-nav */}
      <div className="flex items-center justify-between">
        <div className="flex gap-1 text-xs">
          {(["tasks", "history"] as const).map((v) => (
            <button
              key={v}
              onClick={() => setActiveView(v)}
              className={cn(
                "px-3 py-1 rounded-md font-medium transition-colors capitalize",
                activeView === v
                  ? "bg-[hsl(var(--primary)/.15)] text-[hsl(var(--primary))]"
                  : "text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--accent))]"
              )}
            >
              {v === "tasks" ? `Tasks (${tasks.length})` : "History"}
            </button>
          ))}
        </div>
        {activeView === "tasks" && (
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity"
          >
            <Plus size={13} /> New Task
          </button>
        )}
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="rounded-xl border p-4 space-y-3 text-sm" style={{ borderColor: "var(--border)", background: "var(--card)" }}>
          <p className="font-semibold text-xs uppercase tracking-wide" style={{ color: "var(--muted)" }}>New Scheduled Task</p>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="text-xs font-medium" style={{ color: "var(--muted)" }}>Name *</label>
              <input
                className="w-full px-3 py-1.5 rounded-lg border text-sm bg-transparent"
                style={{ borderColor: "var(--border)" }}
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="e.g. Daily log rotation"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium" style={{ color: "var(--muted)" }}>Type</label>
              <select
                className="w-full px-3 py-1.5 rounded-lg border text-sm bg-transparent"
                style={{ borderColor: "var(--border)" }}
                value={form.type}
                onChange={(e) => setForm({ ...form, type: e.target.value })}
              >
                <option value="script">Script</option>
                <option value="scan">Scan</option>
                <option value="collect">Collect</option>
                <option value="remediate">Remediate</option>
                <option value="custom">Custom</option>
              </select>
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium" style={{ color: "var(--muted)" }}>Schedule (cron)</label>
              <input
                className="w-full px-3 py-1.5 rounded-lg border text-sm bg-transparent"
                style={{ borderColor: "var(--border)" }}
                value={form.schedule}
                onChange={(e) => setForm({ ...form, schedule: e.target.value })}
                placeholder="e.g. 0 2 * * *"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium" style={{ color: "var(--muted)" }}>Payload (JSON)</label>
              <input
                className="w-full px-3 py-1.5 rounded-lg border text-sm bg-transparent"
                style={{ borderColor: "var(--border)" }}
                value={form.payload}
                onChange={(e) => setForm({ ...form, payload: e.target.value })}
                placeholder='{"cmd":"..."}'
              />
            </div>
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={() => setShowCreate(false)} className="px-3 py-1.5 rounded-lg text-xs border" style={{ borderColor: "var(--border)" }}>Cancel</button>
            <button
              onClick={handleCreate}
              disabled={creating || !form.name.trim()}
              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] disabled:opacity-50"
            >
              {creating ? <Loader2 size={13} className="animate-spin" /> : "Create"}
            </button>
          </div>
        </div>
      )}

      {/* Tasks table */}
      {activeView === "tasks" && (
        <div className="rounded-xl border overflow-hidden text-sm" style={{ borderColor: "var(--border)" }}>
          {tasksLoading ? (
            <div className="py-12 flex justify-center"><Loader2 size={20} className="animate-spin opacity-40" /></div>
          ) : tasks.length === 0 ? (
            <div className="py-12 text-center text-xs" style={{ color: "var(--muted)" }}>No scheduled tasks</div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b text-xs font-medium" style={{ borderColor: "var(--border)", color: "var(--muted)" }}>
                  <th className="px-4 py-2 text-left">Name</th>
                  <th className="px-4 py-2 text-left">Type</th>
                  <th className="px-4 py-2 text-left">Schedule</th>
                  <th className="px-4 py-2 text-left">Status</th>
                  <th className="px-4 py-2 text-left">Last Run</th>
                  <th className="px-4 py-2 text-left">Next Run</th>
                  <th className="px-4 py-2 text-left">Created By</th>
                  <th className="px-4 py-2" />
                </tr>
              </thead>
              <tbody>
                {tasks.map((t) => (
                  <tr key={t.id} className="border-b last:border-0 hover:bg-[hsl(var(--accent)/.4)] transition-colors" style={{ borderColor: "var(--border)" }}>
                    <td className="px-4 py-2.5 font-medium">{t.name}</td>
                    <td className="px-4 py-2.5">
                      <span className="px-2 py-0.5 rounded-full text-xs bg-[hsl(var(--primary)/.1)] text-[hsl(var(--primary))]">{t.type}</span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs" style={{ color: "var(--muted)" }}>{t.schedule || "—"}</td>
                    <td className="px-4 py-2.5">
                      {editId === t.id ? (
                        <select
                          className="text-xs border rounded px-1 py-0.5 bg-transparent"
                          style={{ borderColor: "var(--border)" }}
                          value={editStatus}
                          onChange={(e) => setEditStatus(e.target.value)}
                          onBlur={() => { if (editStatus) handleStatusChange(t.id, editStatus); else setEditId(null); }}
                          autoFocus
                        >
                          <option value="active">Active</option>
                          <option value="paused">Paused</option>
                          <option value="completed">Completed</option>
                        </select>
                      ) : (
                        <button
                          onClick={() => { setEditId(t.id); setEditStatus(t.status); }}
                          className="flex items-center gap-1.5 hover:opacity-80 transition-opacity"
                        >
                          {STATUS_ICON[t.status] ?? <Clock size={13} />}
                          <span className="text-xs capitalize">{t.status}</span>
                        </button>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-xs" style={{ color: "var(--muted)" }}>{t.last_run_at ? timeAgo(t.last_run_at) : "Never"}</td>
                    <td className="px-4 py-2.5 text-xs" style={{ color: "var(--muted)" }}>{t.next_run_at ? timeAgo(t.next_run_at) : "—"}</td>
                    <td className="px-4 py-2.5 text-xs" style={{ color: "var(--muted)" }}>{t.created_by}</td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => handleRun(t.id)}
                          title="Run now"
                          className="p-1 rounded hover:bg-emerald-500/10 text-emerald-400 transition-colors"
                        >
                          <Play size={13} />
                        </button>
                        <button onClick={() => handleDelete(t.id)} className="p-1 rounded hover:bg-red-500/10 text-red-400 transition-colors" title="Delete">
                          <Trash2 size={13} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* History table */}
      {activeView === "history" && (
        <div className="rounded-xl border overflow-hidden text-sm" style={{ borderColor: "var(--border)" }}>
          {historyLoading ? (
            <div className="py-12 flex justify-center"><Loader2 size={20} className="animate-spin opacity-40" /></div>
          ) : events.length === 0 ? (
            <div className="py-12 text-center text-xs" style={{ color: "var(--muted)" }}>No task history</div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b text-xs font-medium" style={{ borderColor: "var(--border)", color: "var(--muted)" }}>
                  <th className="px-4 py-2 text-left">Time</th>
                  <th className="px-4 py-2 text-left">Task</th>
                  <th className="px-4 py-2 text-left">Type</th>
                  <th className="px-4 py-2 text-left">Action</th>
                  <th className="px-4 py-2 text-left">Actor</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id} className="border-b last:border-0 hover:bg-[hsl(var(--accent)/.4)] transition-colors" style={{ borderColor: "var(--border)" }}>
                    <td className="px-4 py-2.5 text-xs" style={{ color: "var(--muted)" }}>{timeAgo(e.occurred_at)}</td>
                    <td className="px-4 py-2.5 font-medium">{e.task_name}</td>
                    <td className="px-4 py-2.5 text-xs">
                      <span className="px-2 py-0.5 rounded-full bg-[hsl(var(--primary)/.1)] text-[hsl(var(--primary))]">{e.task_type}</span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={cn(
                        "px-2 py-0.5 rounded-full text-xs font-medium",
                        e.action === "created" ? "bg-emerald-500/10 text-emerald-400" :
                        e.action === "deleted" ? "bg-red-500/10 text-red-400" :
                        e.action === "paused"  ? "bg-yellow-500/10 text-yellow-400" :
                        "bg-sky-500/10 text-sky-400"
                      )}>{e.action}</span>
                    </td>
                    <td className="px-4 py-2.5 text-xs" style={{ color: "var(--muted)" }}>{e.actor}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
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
    (signal: AbortSignal) => api.get<Agent | { agent: Agent }>(`/api/v1/agents/${agentId}`, undefined, signal).then((r) =>
      "agent" in r && typeof r === "object" && r !== null && !Array.isArray(r) && "agent" in (r as Record<string, unknown>)
        ? (r as { agent: Agent }).agent
        : (r as Agent)
    ),
    [agentId]
  );
  const { data: agent, loading, error } = useApi(fetchAgent);

  // Fetch last 200 events for overview breakdown (only when on overview tab)
  const fetchOverviewEvents = useCallback(
    (signal: AbortSignal) =>
      api
        .get<{ events?: Event[] } | Event[]>("/api/v1/events", { agent_id: agentId, limit: 200 }, signal)
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
      <div className="flex flex-wrap border-b" style={{ borderColor: "var(--border)" }}>
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
        {agent.os?.toLowerCase() === "windows" && (
          <TabButton
            id="winevent-config"
            label="WinEvent Config"
            icon={<Settings2 size={13} />}
            active={activeTab === "winevent-config"}
            onClick={setActiveTab}
          />
        )}
        <TabButton
          id="event-reference"
          label="Event Reference"
          icon={<BookOpen size={13} />}
          active={activeTab === "event-reference"}
          onClick={setActiveTab}
        />
        <TabButton
          id="tasks"
          label="Scheduled Tasks"
          icon={<CalendarClock size={13} />}
          active={activeTab === "tasks"}
          onClick={setActiveTab}
        />
      </div>

      {/* Tab content */}
      <div>
        {activeTab === "overview" && <OverviewTab agent={agent} events={overviewEvents} />}
        {activeTab === "events" && <EventsTab agentId={agentId} />}
        {activeTab === "packages" && <PackagesTab agentId={agentId} />}
        {activeTab === "vulnerabilities" && <VulnerabilitiesTab agentId={agentId} />}
        {activeTab === "winevent-config" && <WinEventConfigTab agentId={agentId} />}
        {activeTab === "event-reference" && <EventReferenceTab agentId={agentId} agentOs={agent.os ?? ""} />}
        {activeTab === "tasks" && <TasksTab agentId={agentId} />}
      </div>
    </div>
  );
}
