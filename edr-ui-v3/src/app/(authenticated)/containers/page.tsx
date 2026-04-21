"use client";

import { useCallback, useMemo, useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import {
  Box,
  ChevronDown,
  ChevronUp,
  Container,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { timeAgo } from "@/lib/utils";

// ─── Types ────────────────────────────────────────────────────────────────────

interface ContainerRecord {
  container_id: string;
  agent_id: string;
  hostname: string;
  runtime: string;
  image_name: string;
  pod_name: string;
  namespace: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
}

interface ContainerStats {
  total: number;
  by_runtime: Record<string, number>;
  by_namespace: Record<string, number>;
  pods: number;
  namespaces: number;
}

interface EventRecord {
  id: string;
  event_type: string;
  timestamp: string;
  severity: number;
  hostname: string;
}

interface Agent {
  id: string;
  hostname: string;
}

// ─── Runtime badges ───────────────────────────────────────────────────────────

const RUNTIME_STYLE: Record<string, string> = {
  docker:       "bg-blue-500/15 text-blue-400 border border-blue-500/30",
  containerd:   "bg-violet-500/15 text-violet-400 border border-violet-500/30",
  podman:       "bg-orange-500/15 text-orange-400 border border-orange-500/30",
  "cri-o":      "bg-teal-500/15 text-teal-400 border border-teal-500/30",
};

function RuntimeBadge({ runtime }: { runtime: string }) {
  const cls = RUNTIME_STYLE[runtime] ?? "bg-zinc-700/40 text-zinc-400 border border-zinc-600/40";
  return (
    <span className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium", cls)}>
      <Box className="h-3 w-3" />
      {runtime || "unknown"}
    </span>
  );
}

// ─── Expanded row ─────────────────────────────────────────────────────────────

function ExpandedContainer({ container }: { container: ContainerRecord }) {
  const fetchEvents = useCallback(
    () =>
      api
        .get<{ events?: EventRecord[]; total?: number }>(
          `/api/v1/containers/${encodeURIComponent(container.container_id)}/events?limit=20`
        )
        .then((r) => r.events ?? []),
    [container.container_id]
  );
  const { data: events, loading } = useApi(fetchEvents);

  const SEV_LABEL: Record<number, string> = { 0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical" };
  const SEV_CLS: Record<number, string> = {
    0: "text-zinc-400",
    1: "text-emerald-400",
    2: "text-amber-400",
    3: "text-orange-400",
    4: "text-rose-400",
  };

  return (
    <div className="px-6 pb-4 pt-2 bg-zinc-900/30 border-t border-zinc-800/50 grid grid-cols-2 gap-4 text-sm">
      {/* Metadata */}
      <div className="space-y-2">
        <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">Container Detail</p>
        <div className="grid grid-cols-[120px_1fr] gap-y-1.5 text-xs">
          <span className="text-zinc-500">Container ID</span>
          <span className="font-mono text-zinc-300 break-all">{container.container_id}</span>
          <span className="text-zinc-500">Image</span>
          <span className="font-mono text-zinc-300 break-all">{container.image_name || "—"}</span>
          <span className="text-zinc-500">Runtime</span>
          <span><RuntimeBadge runtime={container.runtime} /></span>
          <span className="text-zinc-500">Pod</span>
          <span className="text-zinc-300">{container.pod_name || "—"}</span>
          <span className="text-zinc-500">Namespace</span>
          <span className="text-zinc-300">{container.namespace || "—"}</span>
          <span className="text-zinc-500">Host</span>
          <span className="text-zinc-300">{container.hostname}</span>
          <span className="text-zinc-500">First seen</span>
          <span className="text-zinc-400">{timeAgo(container.first_seen)}</span>
          <span className="text-zinc-500">Last seen</span>
          <span className="text-zinc-400">{timeAgo(container.last_seen)}</span>
          <span className="text-zinc-500">Events</span>
          <span className="text-zinc-300">{container.event_count.toLocaleString()}</span>
        </div>
      </div>

      {/* Recent events */}
      <div>
        <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">Recent Events</p>
        {loading ? (
          <p className="text-xs text-zinc-500">Loading…</p>
        ) : (events ?? []).length === 0 ? (
          <p className="text-xs text-zinc-500">No events found.</p>
        ) : (
          <div className="space-y-1 max-h-48 overflow-y-auto pr-1">
            {(events ?? []).map((ev) => (
              <div key={ev.id} className="flex items-center gap-2 text-xs py-0.5">
                <span className={cn("w-16 font-medium", SEV_CLS[ev.severity] ?? "text-zinc-400")}>
                  {SEV_LABEL[ev.severity] ?? "info"}
                </span>
                <span className="font-mono text-zinc-300 flex-1">{ev.event_type}</span>
                <span className="text-zinc-500 shrink-0">{timeAgo(ev.timestamp)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function ContainersPage() {
  const [agentFilter, setAgentFilter] = useState("");
  const [runtimeFilter, setRuntimeFilter] = useState("");
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  /* Agents for filter dropdown */
  const fetchAgents = useCallback(
    () =>
      api
        .get<{ agents?: Agent[] } | Agent[]>("/api/v1/agents")
        .then((r) => (Array.isArray(r) ? r : r.agents ?? [])),
    []
  );
  const { data: agents } = useApi(fetchAgents);

  /* Stats */
  const fetchStats = useCallback(
    () => api.get<ContainerStats>("/api/v1/containers/stats"),
    []
  );
  const { data: stats, refetch: refetchStats } = useApi(fetchStats);

  /* Container list */
  const fetchContainers = useCallback(() => {
    const params = new URLSearchParams();
    if (agentFilter) params.set("agent_id", agentFilter);
    if (runtimeFilter) params.set("runtime", runtimeFilter);
    if (search) params.set("search", search);
    params.set("limit", "200");
    return api
      .get<{ containers?: ContainerRecord[]; total?: number }>(
        `/api/v1/containers?${params.toString()}`
      )
      .then((r) => r.containers ?? []);
  }, [agentFilter, runtimeFilter, search]);
  const { data: containers, loading, refetch } = useApi(fetchContainers);

  function handleRefresh() {
    refetch();
    refetchStats();
  }

  /* Runtime options from data */
  const runtimeOptions = useMemo(() => {
    if (!stats?.by_runtime) return [];
    return Object.keys(stats.by_runtime).sort();
  }, [stats]);

  const list = containers ?? [];

  return (
    <div className="animate-fade-in space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <h1
          className="text-lg font-semibold flex items-center gap-2"
          style={{ fontFamily: "var(--font-space-grotesk)" }}
        >
          <Container className="h-5 w-5 text-teal-400" />
          Containers
        </h1>
        <button
          onClick={handleRefresh}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-300 transition-colors"
        >
          <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
          Refresh
        </button>
      </div>

      {/* Stats chips */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Containers", value: stats?.total ?? 0, icon: Container, color: "text-teal-400" },
          { label: "K8s Pods", value: stats?.pods ?? 0, icon: Box, color: "text-violet-400" },
          { label: "Namespaces", value: stats?.namespaces ?? 0, icon: Shield, color: "text-blue-400" },
          {
            label: "Runtimes",
            value: Object.keys(stats?.by_runtime ?? {}).length,
            icon: ShieldAlert,
            color: "text-amber-400",
          },
        ].map(({ label, value, icon: Icon, color }) => (
          <div
            key={label}
            className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-3 flex items-center gap-3"
          >
            <Icon className={cn("h-5 w-5 shrink-0", color)} />
            <div>
              <p className="text-xl font-bold text-zinc-100 leading-none">{value}</p>
              <p className="text-[11px] text-zinc-500 mt-0.5">{label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Runtime breakdown */}
      {stats && Object.keys(stats.by_runtime).length > 0 && (
        <div className="flex flex-wrap gap-2">
          {Object.entries(stats.by_runtime).map(([rt, cnt]) => (
            <button
              key={rt}
              onClick={() => setRuntimeFilter(runtimeFilter === rt ? "" : rt)}
              className={cn(
                "flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium transition-colors",
                runtimeFilter === rt
                  ? "bg-teal-500/20 text-teal-300 border border-teal-500/40"
                  : "bg-zinc-800/60 text-zinc-400 border border-zinc-700/40 hover:border-zinc-600/60"
              )}
            >
              <RuntimeBadge runtime={rt} />
              <span className="text-zinc-400">{cnt}</span>
            </button>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-500 pointer-events-none" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search containers, images, pods…"
            className="pl-8 pr-3 py-1.5 rounded bg-zinc-800/70 border border-zinc-700/50 text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-zinc-500 w-64"
          />
        </div>

        <select
          value={agentFilter}
          onChange={(e) => setAgentFilter(e.target.value)}
          className="px-3 py-1.5 rounded bg-zinc-800/70 border border-zinc-700/50 text-xs text-zinc-300 focus:outline-none focus:border-zinc-500"
        >
          <option value="">All hosts</option>
          {(agents ?? []).map((a) => (
            <option key={a.id} value={a.id}>
              {a.hostname}
            </option>
          ))}
        </select>

        <select
          value={runtimeFilter}
          onChange={(e) => setRuntimeFilter(e.target.value)}
          className="px-3 py-1.5 rounded bg-zinc-800/70 border border-zinc-700/50 text-xs text-zinc-300 focus:outline-none focus:border-zinc-500"
        >
          <option value="">All runtimes</option>
          {runtimeOptions.map((rt) => (
            <option key={rt} value={rt}>
              {rt}
            </option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className="rounded-lg border border-zinc-800 overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-zinc-800 bg-zinc-900/60">
              {["Container ID", "Image", "Runtime", "Pod / Namespace", "Host", "Events", "Last Seen", ""].map(
                (h) => (
                  <th
                    key={h}
                    className="px-4 py-2.5 text-left text-[11px] font-medium text-zinc-500 uppercase tracking-wider"
                  >
                    {h}
                  </th>
                )
              )}
            </tr>
          </thead>
          <tbody>
            {loading && list.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-zinc-500">
                  Loading containers…
                </td>
              </tr>
            ) : list.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-zinc-500">
                  No containers observed yet. Container events appear when agents detect processes
                  running inside Docker / containerd / Kubernetes pods.
                </td>
              </tr>
            ) : (
              list.map((c) => {
                const rowKey = `${c.container_id}:${c.agent_id}`;
                const isOpen = expandedId === rowKey;
                return (
                  <>
                    <tr
                      key={rowKey}
                      className={cn(
                        "border-b border-zinc-800/60 transition-colors cursor-pointer",
                        isOpen ? "bg-zinc-800/30" : "hover:bg-zinc-800/20"
                      )}
                      onClick={() => setExpandedId(isOpen ? null : rowKey)}
                    >
                      {/* Container ID */}
                      <td className="px-4 py-2.5 font-mono text-zinc-300">
                        {c.container_id.length > 16
                          ? c.container_id.slice(0, 12) + "…"
                          : c.container_id}
                      </td>
                      {/* Image */}
                      <td className="px-4 py-2.5 font-mono text-zinc-400 max-w-[180px] truncate">
                        {c.image_name || <span className="text-zinc-600">—</span>}
                      </td>
                      {/* Runtime */}
                      <td className="px-4 py-2.5">
                        <RuntimeBadge runtime={c.runtime} />
                      </td>
                      {/* Pod / Namespace */}
                      <td className="px-4 py-2.5">
                        {c.pod_name ? (
                          <span className="text-zinc-300">{c.pod_name}</span>
                        ) : null}
                        {c.pod_name && c.namespace ? (
                          <span className="text-zinc-600 mx-1">/</span>
                        ) : null}
                        {c.namespace ? (
                          <span className="text-zinc-500">{c.namespace}</span>
                        ) : null}
                        {!c.pod_name && !c.namespace ? (
                          <span className="text-zinc-600">—</span>
                        ) : null}
                      </td>
                      {/* Host */}
                      <td className="px-4 py-2.5 text-zinc-400">{c.hostname}</td>
                      {/* Events */}
                      <td className="px-4 py-2.5 text-zinc-400 tabular-nums">
                        {c.event_count.toLocaleString()}
                      </td>
                      {/* Last seen */}
                      <td className="px-4 py-2.5 text-zinc-500">{timeAgo(c.last_seen)}</td>
                      {/* Expand toggle */}
                      <td className="px-4 py-2.5 text-zinc-500">
                        {isOpen ? (
                          <ChevronUp className="h-3.5 w-3.5" />
                        ) : (
                          <ChevronDown className="h-3.5 w-3.5" />
                        )}
                      </td>
                    </tr>
                    {isOpen && (
                      <tr key={`${rowKey}-expanded`}>
                        <td colSpan={8} className="p-0">
                          <ExpandedContainer container={c} />
                        </td>
                      </tr>
                    )}
                  </>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      <p className="text-xs text-zinc-600">
        {list.length > 0 && `Showing ${list.length} container${list.length !== 1 ? "s" : ""}`}
      </p>
    </div>
  );
}
