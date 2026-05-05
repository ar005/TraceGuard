"use client";

import { useCallback, useEffect, useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import {
  cn,
  formatDate,
  timeAgo,
  severityLabel,
  severityBgClass,
  statusColor,
} from "@/lib/utils";
import type { Alert, Event } from "@/types";

/* ---------- Constants ---------- */
const STATUS_FILTERS = [
  { label: "All", value: "" },
  { label: "Open", value: "open" },
  { label: "Investigating", value: "investigating" },
  { label: "Closed", value: "closed" },
] as const;

const SEVERITY_FILTERS = [
  { label: "All", value: -1 },
  { label: "Critical", value: 4 },
  { label: "High", value: 3 },
  { label: "Medium", value: 2 },
  { label: "Low", value: 1 },
  { label: "Info", value: 0 },
] as const;

const PAGE_SIZE = 25;

const STATUS_VALUES = ["open", "investigating", "closed"] as const;

/* ---------- Helpers ---------- */
function statusBadgeClass(status: string): string {
  switch (status?.toLowerCase()) {
    case "open":
      return "bg-red-500/15 text-red-400";
    case "investigating":
    case "in_progress":
      return "bg-amber-500/15 text-amber-400";
    case "closed":
    case "resolved":
      return "bg-emerald-500/15 text-emerald-400";
    default:
      return "bg-neutral-500/15 text-neutral-400";
  }
}

function severityDot(sev: number): string {
  switch (sev) {
    case 4:
      return "bg-red-500";
    case 3:
      return "bg-orange-500";
    case 2:
      return "bg-amber-500";
    case 1:
      return "bg-blue-500";
    default:
      return "bg-neutral-500";
  }
}

/* ---------- Skeleton ---------- */
function SkeletonRow() {
  return (
    <div className="flex items-center gap-3 px-3 py-2">
      <div className="animate-shimmer h-3 w-3 rounded-full" />
      <div className="animate-shimmer h-4 w-40 rounded" />
      <div className="animate-shimmer h-4 w-28 rounded" />
      <div className="animate-shimmer h-4 w-24 rounded" />
      <div className="animate-shimmer h-4 w-12 rounded" />
      <div className="animate-shimmer h-4 w-20 rounded" />
      <div className="animate-shimmer h-5 w-16 rounded" />
      <div className="animate-shimmer h-4 w-16 rounded" />
    </div>
  );
}

/* ---------- Process Tree Section ---------- */
interface ProcessNode {
  pid: number;
  ppid: number;
  comm: string;
  cmdline: string;
  uid: number;
  username: string;
  exe_path: string;
  start_time: string;
  children?: ProcessNode[];
}

function extractPidFromEvents(events: Event[]): number | null {
  for (const e of events) {
    const p = e.payload as Record<string, unknown>;
    // Try process.pid (nested)
    if (p.process && typeof p.process === "object") {
      const pid = (p.process as Record<string, unknown>).pid;
      if (typeof pid === "number" && pid > 0) return pid;
    }
    // Try top-level pid
    if (typeof p.pid === "number" && p.pid > 0) return p.pid;
  }
  return null;
}

function ProcessTreeSection({
  events,
  agentId,
  onTreeLoaded,
}: {
  events: Event[];
  agentId: string;
  onTreeLoaded?: (tree: ProcessNode[]) => void;
}) {
  const [tree, setTree] = useState<ProcessNode[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const pid = extractPidFromEvents(events);

  async function loadTree() {
    if (!pid || !agentId) return;
    setLoading(true);
    try {
      const result = await api.get<Record<string, unknown>>(
        `/api/v1/processes/${pid}/tree`,
        { agent_id: agentId, depth: 5 }
      );
      const nodes: ProcessNode[] = Array.isArray(result)
        ? result
        : (result.tree ?? result.processes ?? []) as ProcessNode[];
      setTree(nodes);
      setExpanded(true);
      onTreeLoaded?.(nodes);
    } catch {
      setTree([]);
    } finally {
      setLoading(false);
    }
  }

  if (!pid || !agentId) return null;

  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <div className="text-xs font-semibold" style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}>
          Process Tree
        </div>
        {!expanded && (
          <button
            onClick={loadTree}
            disabled={loading}
            className="flex items-center gap-1 rounded border px-2 py-1 text-[10px] font-medium transition-colors hover:bg-[var(--surface-2)] disabled:opacity-50"
            style={{ borderColor: "var(--border)", color: "var(--primary)" }}
          >
            {loading && (
              <svg className="h-3 w-3 animate-spin" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
            )}
            {loading ? "Loading..." : `Load Process Tree (PID ${pid})`}
          </button>
        )}
      </div>
      {expanded && tree && tree.length > 0 && (
        <div
          className="rounded border p-3 font-mono text-[11px] leading-relaxed overflow-x-auto"
          style={{ background: "var(--surface-1)", borderColor: "var(--border)" }}
        >
          {tree.map((node, i) => (
            <ProcessTreeNode key={i} node={node} depth={0} />
          ))}
        </div>
      )}
      {expanded && tree && tree.length === 0 && (
        <p className="text-xs" style={{ color: "var(--muted)" }}>No process tree data available for PID {pid}.</p>
      )}
    </div>
  );
}

function ProcessTreeNode({ node, depth }: { node: ProcessNode; depth: number }) {
  const indent = depth * 20;
  const isRoot = depth === 0;
  return (
    <>
      <div className="flex items-start gap-1 py-0.5" style={{ paddingLeft: `${indent}px` }}>
        <span style={{ color: "var(--muted)" }}>{depth > 0 ? "└─" : ""}</span>
        <span style={{ color: isRoot ? "var(--primary)" : "var(--fg)" }} className="font-semibold">
          {node.comm || "?"}
        </span>
        <span style={{ color: "var(--muted)" }}>(PID:{node.pid})</span>
        {node.username && <span style={{ color: "var(--muted)" }}>[{node.username}]</span>}
        {node.cmdline && (
          <span className="truncate" style={{ color: "var(--muted)", maxWidth: "250px" }} title={node.cmdline}>
            {node.cmdline.length > 60 ? node.cmdline.substring(0, 60) + "..." : node.cmdline}
          </span>
        )}
      </div>
      {node.children?.map((child, i) => (
        <ProcessTreeNode key={i} node={child} depth={depth + 1} />
      ))}
    </>
  );
}

function treeToText(nodes: ProcessNode[], depth: number = 0): string {
  let out = "";
  for (const n of nodes) {
    const indent = "  ".repeat(depth);
    const prefix = depth > 0 ? "└─ " : "";
    out += `${indent}${prefix}${n.comm} (PID:${n.pid}) [${n.username || "?"}] ${n.cmdline || ""}\n`;
    if (n.children?.length) out += treeToText(n.children, depth + 1);
  }
  return out;
}

/* ---------- Intel Context Card ---------- */
interface IntelContext {
  ioc_id?: string;
  ioc_type?: string;
  ioc_value?: string;
  ioc_source?: string;
  actor_id?: string;
  campaign_id?: string;
  vt_detections?: number;
  enriched_at?: string;
}

const IOC_TYPE_COLOR: Record<string, string> = {
  ip:           "bg-blue-500/15 text-blue-400",
  domain:       "bg-emerald-500/15 text-emerald-400",
  hash_sha256:  "bg-purple-500/15 text-purple-400",
  hash_md5:     "bg-purple-500/15 text-purple-300",
};

function IntelContextCard({ enrichments }: { enrichments: { intel_context?: IntelContext; [k: string]: unknown } }) {
  const ctx = enrichments.intel_context;
  const [actorName, setActorName] = useState<string | null>(null);
  const [campaignName, setCampaignName] = useState<string | null>(null);

  useEffect(() => {
    if (ctx?.actor_id) {
      api.get<{ name?: string; id: string }>(`/intel/actors/${ctx.actor_id}`)
        .then((r) => setActorName(r.name ?? ctx.actor_id ?? null))
        .catch(() => setActorName(ctx.actor_id ?? null));
    }
    if (ctx?.campaign_id) {
      api.get<{ name?: string; id: string }>(`/intel/campaigns/${ctx.campaign_id}`)
        .then((r) => setCampaignName(r.name ?? ctx.campaign_id ?? null))
        .catch(() => setCampaignName(ctx.campaign_id ?? null));
    }
  }, [ctx?.actor_id, ctx?.campaign_id]);

  if (!ctx?.ioc_value) return null;

  const vtPct = ctx.vt_detections != null ? Math.min(ctx.vt_detections, 100) : null;

  return (
    <div
      className="rounded-lg border p-3 space-y-2.5"
      style={{ background: "var(--surface-1)", borderColor: "var(--border)" }}
    >
      {/* Header */}
      <div className="flex items-center justify-between gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--muted)" }}>
          Intel Attribution
        </span>
        <a
          href={`/iocs?search=${encodeURIComponent(ctx.ioc_value)}`}
          className="text-[10px] text-blue-400/70 hover:text-blue-400 transition-colors"
        >
          View IOC →
        </a>
      </div>

      {/* IOC row */}
      <div className="flex items-center gap-2 flex-wrap">
        {ctx.ioc_type && (
          <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${IOC_TYPE_COLOR[ctx.ioc_type] ?? "bg-white/5 text-white/50"}`}>
            {ctx.ioc_type}
          </span>
        )}
        <span className="font-mono text-[11px] text-white/80 break-all">{ctx.ioc_value}</span>
        {ctx.ioc_source && (
          <span className="text-[10px] text-white/30">({ctx.ioc_source})</span>
        )}
      </div>

      {/* VT detection bar */}
      {vtPct != null && vtPct > 0 && (
        <div className="space-y-1">
          <div className="flex items-center justify-between text-[10px]">
            <span style={{ color: "var(--muted)" }}>VirusTotal</span>
            <span className="text-red-400 font-medium">{ctx.vt_detections} detections</span>
          </div>
          <div className="h-1.5 rounded-full bg-white/5">
            <div
              className="h-full rounded-full bg-red-500 transition-all"
              style={{ width: `${Math.min(vtPct, 100)}%` }}
            />
          </div>
        </div>
      )}

      {/* Actor / Campaign attribution */}
      {(actorName || campaignName) && (
        <div className="space-y-1 border-t border-white/8 pt-2">
          {actorName && (
            <div className="flex items-center justify-between text-[10px]">
              <span style={{ color: "var(--muted)" }}>Threat Actor</span>
              <a
                href={`/intel/actors?id=${ctx.actor_id}`}
                className="font-medium text-orange-400 hover:text-orange-300 transition-colors"
              >
                {actorName}
              </a>
            </div>
          )}
          {campaignName && (
            <div className="flex items-center justify-between text-[10px]">
              <span style={{ color: "var(--muted)" }}>Campaign</span>
              <a
                href={`/intel/campaigns?id=${ctx.campaign_id}`}
                className="font-medium text-amber-400 hover:text-amber-300 transition-colors"
              >
                {campaignName}
              </a>
            </div>
          )}
        </div>
      )}

      {/* TLP if rule_id contains ioc */}
      {ctx.ioc_id && !actorName && !campaignName && (
        <p className="text-[10px]" style={{ color: "var(--muted)" }}>
          No actor/campaign attribution found for this indicator.
        </p>
      )}
    </div>
  );
}

/* ---------- Alert Detail Drawer ---------- */
function AlertDetail({
  alert,
  onClose,
  onStatusChange,
}: {
  alert: Alert;
  onClose: () => void;
  onStatusChange: (id: string, status: string) => void;
}) {
  const [showStatusMenu, setShowStatusMenu] = useState(false);
  const [explaining, setExplaining] = useState(false);
  const [explanation, setExplanation] = useState<string | null>(null);
  const [assignee, setAssignee] = useState(alert.assignee ?? "");
  const [assigning, setAssigning] = useState(false);
  const [notes, setNotes] = useState(alert.notes ?? "");
  const [savingNotes, setSavingNotes] = useState(false);
  const [notesSaved, setNotesSaved] = useState(false);
  const [processTreeData, setProcessTreeData] = useState<ProcessNode[]>([]);
  const [expandedEvent, setExpandedEvent] = useState<Event | null>(null);

  // Enrichments
  const [enrichments, setEnrichments] = useState<{
    ioc_matches?: Array<Record<string, unknown>>;
    ti_data?: Record<string, unknown>;
    intel_context?: IntelContext;
    threat_intel?: Record<string, unknown>;
  } | null>(null);
  const [enrichmentsLoading, setEnrichmentsLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setEnrichments(null);
    setEnrichmentsLoading(true);
    api
      .get<{ alert_id: string; enrichments: Record<string, unknown> }>(
        `/api/v1/alerts/${alert.id}/enrichments`
      )
      .then((res) => {
        if (!cancelled) setEnrichments(res.enrichments ?? {});
      })
      .catch(() => {
        if (!cancelled) setEnrichments({});
      })
      .finally(() => {
        if (!cancelled) setEnrichmentsLoading(false);
      });
    return () => { cancelled = true; };
  }, [alert.id]);

  /* Fetch related events — try alert events endpoint first, fall back to querying by alert_id */
  const fetchEvents = useCallback(
    async (signal: AbortSignal) => {
      // Primary: get events linked to this alert
      const res = await api.get<{ events?: Event[]; total?: number } | Event[]>(
        `/api/v1/alerts/${alert.id}/events`,
        undefined,
        signal
      );
      const events = Array.isArray(res) ? res : res.events ?? [];
      if (events.length > 0) return events;

      // Fallback: query events table filtered by this agent around the alert time window
      const since = new Date(new Date(alert.first_seen).getTime() - 5 * 60 * 1000).toISOString();
      const until = new Date(new Date(alert.last_seen).getTime() + 5 * 60 * 1000).toISOString();
      const fallback = await api.get<{ events?: Event[] } | Event[]>("/api/v1/events", {
        agent_id: alert.agent_id,
        since,
        until,
        limit: 50,
      }, signal);
      return Array.isArray(fallback) ? fallback : fallback.events ?? [];
    },
    [alert.id, alert.agent_id, alert.first_seen, alert.last_seen]
  );
  const { data: relatedEvents, loading: eventsLoading } = useApi(fetchEvents);

  async function handleExplain() {
    setExplaining(true);
    try {
      // Include process tree context if available
      const body: Record<string, unknown> = {};
      if (processTreeData.length > 0) {
        body.process_tree = treeToText(processTreeData);
      }
      const result = await api.post<{ explanation: string }>(
        `/api/v1/alerts/${alert.id}/explain`,
        body
      );
      setExplanation(result.explanation ?? "No explanation returned.");
    } catch (err) {
      setExplanation(
        err instanceof Error ? err.message : "Failed to get explanation."
      );
    } finally {
      setExplaining(false);
    }
  }

  async function handleSaveNotes() {
    setSavingNotes(true);
    setNotesSaved(false);
    try {
      await api.patch(`/api/v1/alerts/${alert.id}`, { notes });
      setNotesSaved(true);
      setTimeout(() => setNotesSaved(false), 2000);
    } catch {
      // Silently handle
    } finally {
      setSavingNotes(false);
    }
  }

  async function handleAssign() {
    if (!assignee.trim()) return;
    setAssigning(true);
    try {
      await api.patch(`/api/v1/alerts/${alert.id}`, { assignee: assignee.trim() });
    } catch {
      // Silently handle
    } finally {
      setAssigning(false);
    }
  }

  return (
    <div
      className="fixed inset-y-0 right-0 z-50 w-full max-w-lg border-l shadow-xl overflow-y-auto animate-fade-in"
      style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between p-4 border-b"
        style={{ borderColor: "var(--border)" }}
      >
        <h3
          className="text-sm font-semibold"
          style={{ fontFamily: "var(--font-space-grotesk)" }}
        >
          Alert Detail
        </h3>
        <button
          onClick={onClose}
          className="text-xs rounded px-2 py-1 hover:bg-[var(--surface-2)] transition-colors"
          style={{ color: "var(--muted)" }}
        >
          Close
        </button>
      </div>

      <div className="p-4 space-y-5">
        {/* Title & description */}
        <div>
          <h4
            className="text-base font-semibold mb-1"
            style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}
          >
            {alert.title}
          </h4>
          {alert.description && (
            <p className="text-xs leading-relaxed" style={{ color: "var(--muted)" }}>
              {alert.description}
            </p>
          )}
        </div>

        {/* Key fields */}
        <div className="space-y-2 text-xs">
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Alert ID</span>
            <span className="font-mono" style={{ color: "var(--fg)" }}>
              {alert.id}
            </span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Severity</span>
            <span
              className={cn(
                "rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                severityBgClass(alert.severity)
              )}
            >
              {severityLabel(alert.severity)}
            </span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Status</span>
            <span
              className={cn(
                "rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                statusBadgeClass(alert.status)
              )}
            >
              {alert.status}
            </span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Rule</span>
            <span style={{ color: "var(--fg)" }}>{alert.rule_name || "—"}</span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Hostname</span>
            <span style={{ color: "var(--fg)" }}>{alert.hostname || "—"}</span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Hit Count</span>
            <span className="font-mono" style={{ color: "var(--fg)" }}>
              {alert.hit_count}
            </span>
          </div>
          {(alert.risk_score ?? 0) > 0 && (
            <div className="flex justify-between">
              <span style={{ color: "var(--muted)" }}>Risk Score</span>
              <span className={cn(
                "rounded px-1.5 py-0.5 text-[10px] font-bold font-mono",
                (alert.risk_score ?? 0) >= 80 ? "bg-red-500/20 text-red-400" :
                (alert.risk_score ?? 0) >= 60 ? "bg-orange-500/20 text-orange-400" :
                (alert.risk_score ?? 0) >= 40 ? "bg-amber-500/20 text-amber-400" :
                "bg-blue-500/20 text-blue-400"
              )}>
                {alert.risk_score}/100
              </span>
            </div>
          )}
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>First Seen</span>
            <span className="font-mono" style={{ color: "var(--fg)" }}>
              {formatDate(alert.first_seen)}
            </span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Last Seen</span>
            <span className="font-mono" style={{ color: "var(--fg)" }}>
              {formatDate(alert.last_seen)}
            </span>
          </div>
        </div>

        {/* MITRE ATT&CK IDs */}
        {alert.mitre_ids && alert.mitre_ids.length > 0 && (
          <div>
            <div
              className="text-[10px] font-semibold uppercase tracking-wider mb-1.5"
              style={{ color: "var(--muted)" }}
            >
              MITRE ATT&CK
            </div>
            <div className="flex flex-wrap gap-1.5">
              {alert.mitre_ids.map((id) => (
                <a
                  key={id}
                  href={`https://attack.mitre.org/techniques/${id.replace(".", "/")}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="rounded px-2 py-0.5 text-[10px] font-mono font-medium transition-colors hover:opacity-80"
                  style={{
                    background: "var(--surface-2)",
                    color: "var(--primary)",
                  }}
                >
                  {id}
                </a>
              ))}
            </div>
          </div>
        )}

        {/* Enrichments */}
        <div>
          <div
            className="text-[10px] font-semibold uppercase tracking-wider mb-2"
            style={{ color: "var(--muted)" }}
          >
            Threat Intelligence
          </div>
          {enrichmentsLoading && (
            <div className="animate-shimmer h-12 rounded" />
          )}
          {!enrichmentsLoading && enrichments?.intel_context && (
            <div className="mb-3">
              <IntelContextCard enrichments={enrichments} />
            </div>
          )}
          {!enrichmentsLoading && enrichments && (
            <div
              className="rounded border p-3 space-y-3"
              style={{ background: "var(--surface-1)", borderColor: "var(--border)" }}
            >
              {/* IOC matches */}
              {enrichments.ioc_matches && enrichments.ioc_matches.length > 0 ? (
                <div>
                  <div className="text-[10px] font-semibold mb-1.5" style={{ color: "var(--muted)" }}>
                    IOC Matches
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {enrichments.ioc_matches.map((match, i) => {
                      const label =
                        typeof match.value === "string"
                          ? match.value
                          : typeof match.ioc === "string"
                          ? match.ioc
                          : JSON.stringify(match);
                      return (
                        <span
                          key={i}
                          className="rounded px-2 py-0.5 text-[10px] font-mono font-semibold bg-red-500/15 text-red-400 border border-red-500/20"
                        >
                          {label}
                        </span>
                      );
                    })}
                  </div>
                </div>
              ) : null}

              {/* TI data */}
              {enrichments.ti_data && Object.keys(enrichments.ti_data).length > 0 ? (
                <div>
                  <div className="text-[10px] font-semibold mb-1.5" style={{ color: "var(--muted)" }}>
                    Threat Intelligence
                  </div>
                  <div className="space-y-1">
                    {Object.entries(enrichments.ti_data).map(([k, v]) => (
                      <div key={k} className="flex justify-between gap-2 text-[10px]">
                        <span className="capitalize shrink-0" style={{ color: "var(--muted)" }}>
                          {k.replace(/_/g, " ")}
                        </span>
                        <span className="font-mono truncate text-right" style={{ color: "var(--fg)" }}>
                          {typeof v === "object" ? JSON.stringify(v) : String(v)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}

              {/* Empty state */}
              {(!enrichments.ioc_matches || enrichments.ioc_matches.length === 0) &&
                (!enrichments.ti_data || Object.keys(enrichments.ti_data).length === 0) && (
                  <p className="text-[10px]" style={{ color: "var(--muted)" }}>
                    No threat intelligence matches for this alert.
                  </p>
                )}
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2">
          {/* Status dropdown */}
          <div className="relative">
            <button
              onClick={() => setShowStatusMenu(!showStatusMenu)}
              className="rounded border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-2)]"
              style={{
                background: "var(--surface-1)",
                borderColor: "var(--border)",
                color: "var(--fg)",
              }}
            >
              Update Status
            </button>
            {showStatusMenu && (
              <div
                className="absolute left-0 top-full mt-1 z-10 rounded border shadow-lg min-w-[140px]"
                style={{
                  background: "var(--surface-0)",
                  borderColor: "var(--border)",
                }}
              >
                {STATUS_VALUES.map((s) => (
                  <button
                    key={s}
                    onClick={() => {
                      onStatusChange(alert.id, s);
                      setShowStatusMenu(false);
                    }}
                    className="block w-full px-3 py-1.5 text-left text-xs capitalize transition-colors hover:bg-[var(--surface-2)]"
                    style={{ color: "var(--fg)" }}
                  >
                    {s}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Assign */}
          <div className="flex items-center gap-1">
            <input
              type="text"
              placeholder="Assignee"
              value={assignee}
              onChange={(e) => setAssignee(e.target.value)}
              className="rounded border px-2 py-1.5 text-xs w-28 outline-none focus-ring"
              style={{
                background: "var(--surface-1)",
                borderColor: "var(--border)",
                color: "var(--fg)",
              }}
            />
            <button
              onClick={handleAssign}
              disabled={assigning || !assignee.trim()}
              className="rounded border px-2 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-2)] disabled:opacity-50"
              style={{
                background: "var(--surface-1)",
                borderColor: "var(--border)",
                color: "var(--fg)",
              }}
            >
              {assigning ? "..." : "Assign"}
            </button>
          </div>
        </div>

        {/* Notes */}
        <div>
          <div className="flex items-center justify-between mb-1">
            <div className="text-xs font-semibold" style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}>
              Notes
            </div>
            <div className="flex items-center gap-2">
              {notesSaved && <span className="text-[10px]" style={{ color: "#22c55e" }}>Saved</span>}
              <button
                onClick={handleSaveNotes}
                disabled={savingNotes}
                className="rounded border px-2 py-1 text-[10px] font-medium transition-colors hover:bg-[var(--surface-2)] disabled:opacity-50"
                style={{ borderColor: "var(--border)", color: "var(--fg)" }}
              >
                {savingNotes ? "Saving..." : "Save"}
              </button>
            </div>
          </div>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={3}
            placeholder="Add investigation notes..."
            className="w-full rounded border px-3 py-2 text-xs outline-none resize-y"
            style={{
              background: "var(--surface-1)",
              borderColor: "var(--border)",
              color: "var(--fg)",
            }}
          />
        </div>

        {/* Process Tree */}
        <ProcessTreeSection
          events={relatedEvents ?? []}
          agentId={alert.agent_id}
          onTreeLoaded={(nodes) => setProcessTreeData(nodes)}
        />

        {/* AI Overview */}
        <div
          className="rounded border p-3"
          style={{ background: "var(--surface-1)", borderColor: "var(--border)" }}
        >
          <div className="flex items-center justify-between mb-2">
            <div className="text-xs font-semibold" style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}>
              AI Overview
            </div>
            <button
              onClick={handleExplain}
              disabled={explaining}
              className="flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-semibold transition-colors disabled:opacity-50"
              style={{
                background: "var(--primary)",
                color: "var(--primary-fg, #fff)",
              }}
            >
              {explaining && (
                <svg className="h-3 w-3 animate-spin" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              )}
              {explaining ? "Analyzing..." : explanation ? "Re-analyze" : "Explain with AI"}
            </button>
          </div>
          {!explanation && !explaining && (
            <p className="text-[10px]" style={{ color: "var(--muted)" }}>
              Click to get an AI-powered explanation of this alert{processTreeData.length > 0 ? " including process tree context" : ""}.
            </p>
          )}
          {explanation && (
            <div className="text-xs leading-relaxed whitespace-pre-wrap" style={{ color: "var(--fg)" }}>
              {explanation}
            </div>
          )}
        </div>

        {/* Related events */}
        <div>
          <div
            className="text-xs font-semibold mb-2"
            style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}
          >
            Related Events ({relatedEvents?.length ?? 0})
          </div>
          {eventsLoading && (
            <div className="space-y-2">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="animate-shimmer h-8 rounded" />
              ))}
            </div>
          )}
          {!eventsLoading && relatedEvents && relatedEvents.length > 0 && (
            <div
              className="rounded border divide-y"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-1)",
              }}
            >
              {relatedEvents.map((evt) => {
                const isExpanded = expandedEvent?.id === evt.id;
                return (
                  <div key={evt.id} style={{ borderColor: "var(--border)" }}>
                    <button
                      onClick={() => setExpandedEvent(isExpanded ? null : evt)}
                      className="w-full px-3 py-2 text-xs text-left transition-colors hover:bg-[var(--surface-2)]"
                      style={isExpanded ? { background: "var(--surface-2)" } : {}}
                    >
                      <div className="flex items-center gap-2">
                        <span className="font-mono shrink-0" style={{ color: "var(--muted)" }}>
                          {timeAgo(evt.timestamp)}
                        </span>
                        <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase shrink-0 bg-neutral-500/15 text-neutral-400">
                          {evt.event_type}
                        </span>
                        <span className="truncate" style={{ color: "var(--fg)" }}>
                          {evt.hostname}
                        </span>
                        <span className="ml-auto text-[10px]" style={{ color: "var(--muted)" }}>
                          {isExpanded ? "▲" : "▼"}
                        </span>
                      </div>
                    </button>
                    {/* Inline event detail */}
                    {isExpanded && (
                      <div
                        className="px-3 pb-3 animate-fade-in"
                        style={{ background: "var(--surface-2)" }}
                      >
                        <div className="space-y-2 text-[11px] pt-2">
                          <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                            <div>
                              <span style={{ color: "var(--muted)" }}>Event ID: </span>
                              <span className="font-mono" style={{ color: "var(--fg)" }}>{evt.id.slice(0, 12)}...</span>
                            </div>
                            <div>
                              <span style={{ color: "var(--muted)" }}>Agent: </span>
                              <span className="font-mono" style={{ color: "var(--fg)" }}>{evt.agent_id.slice(0, 12)}...</span>
                            </div>
                            <div>
                              <span style={{ color: "var(--muted)" }}>Time: </span>
                              <span className="font-mono" style={{ color: "var(--fg)" }}>{formatDate(evt.timestamp)}</span>
                            </div>
                            <div>
                              <span style={{ color: "var(--muted)" }}>Severity: </span>
                              <span style={{ color: "var(--fg)" }}>{severityLabel(evt.severity)}</span>
                            </div>
                          </div>
                          {/* Script details (if present) */}
                          {!!(evt.payload?.interpreter || evt.payload?.script_content) && (
                            <div>
                              <div className="text-[10px] font-semibold mb-1" style={{ color: "var(--muted)" }}>Script Execution</div>
                              <div className="space-y-1 text-[10px]">
                                {!!evt.payload.interpreter && (
                                  <div>
                                    <span style={{ color: "var(--muted)" }}>Interpreter: </span>
                                    <span className="font-mono font-medium" style={{ color: "var(--primary)" }}>{String(evt.payload.interpreter)}</span>
                                  </div>
                                )}
                                {!!evt.payload.script_path && (
                                  <div>
                                    <span style={{ color: "var(--muted)" }}>Script: </span>
                                    <span className="font-mono" style={{ color: "var(--fg)" }}>{String(evt.payload.script_path)}</span>
                                  </div>
                                )}
                                {!!evt.payload.script_content && (
                                  <pre
                                    className="rounded p-2 text-[10px] leading-relaxed overflow-x-auto max-h-40 overflow-y-auto mt-1"
                                    style={{ background: "hsl(220 20% 8%)", color: "#e2e8f0" }}
                                  >
                                    <code>{String(evt.payload.script_content)}</code>
                                  </pre>
                                )}
                              </div>
                            </div>
                          )}
                          <div>
                            <div className="text-[10px] font-semibold mb-1" style={{ color: "var(--muted)" }}>Payload</div>
                            <pre
                              className="rounded p-2 text-[10px] leading-relaxed overflow-x-auto max-h-48 overflow-y-auto"
                              style={{ background: "var(--bg, var(--surface-0))", color: "var(--fg)" }}
                            >
                              <code>{JSON.stringify(evt.payload, null, 2)}</code>
                            </pre>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
          {!eventsLoading && (!relatedEvents || relatedEvents.length === 0) && (
            <p className="text-xs" style={{ color: "var(--muted)" }}>
              No related events found.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

/* ---------- Alerts Page ---------- */
export default function AlertsPage() {
  const [statusFilter, setStatusFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState(-1);
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [allAlerts, setAllAlerts] = useState<Alert[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  /* API fetch */
  const fetchAlerts = useCallback(
    (signal: AbortSignal) =>
      api
        .get<{ alerts?: Alert[] } | Alert[]>("/api/v1/alerts", {
          status: statusFilter || undefined,
          severity: severityFilter >= 0 ? severityFilter : undefined,
          search: search || undefined,
          limit: PAGE_SIZE,
          offset,
        }, signal)
        .then((r) => (Array.isArray(r) ? r : r.alerts ?? [])),
    [statusFilter, severityFilter, search, offset]
  );

  const { data: fetchedAlerts, loading, error, refetch } = useApi(fetchAlerts);

  /* Accumulate alerts for load-more */
  useEffect(() => {
    if (fetchedAlerts) {
      if (offset === 0) {
        setAllAlerts(fetchedAlerts);
      } else {
        setAllAlerts((prev) => {
          const ids = new Set(prev.map((a) => a.id));
          const newOnes = fetchedAlerts.filter((a) => !ids.has(a.id));
          return [...prev, ...newOnes];
        });
      }
    }
  }, [fetchedAlerts, offset]);

  const displayAlerts = allAlerts;

  function handleStatusFilterChange(val: string) {
    setStatusFilter(val);
    setOffset(0);
    setAllAlerts([]);
  }

  function handleSeverityFilterChange(val: number) {
    setSeverityFilter(val);
    setOffset(0);
    setAllAlerts([]);
  }

  async function handleAlertStatusChange(id: string, status: string) {
    try {
      await api.patch(`/api/v1/alerts/${id}`, { status });
      // Update local state
      setAllAlerts((prev) =>
        prev.map((a) => (a.id === id ? { ...a, status } : a))
      );
      if (selectedAlert?.id === id) {
        setSelectedAlert((prev) => (prev ? { ...prev, status } : null));
      }
      refetch();
    } catch {
      // Silently handle
    }
  }

  return (
    <div className="animate-fade-in space-y-4">
      {/* Header */}
      <h1
        className="text-lg font-semibold"
        style={{ fontFamily: "var(--font-space-grotesk)" }}
      >
        Alerts
      </h1>

      {/* Search + filters */}
      <input
        type="text"
        placeholder="Search alerts by title, rule, or hostname..."
        value={search}
        onChange={(e) => { setSearch(e.target.value); setOffset(0); setAllAlerts([]); }}
        className="rounded-md border px-3 py-1.5 text-xs w-full max-w-md outline-none focus-ring"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
      />

      {/* Status filter pills */}
      <div className="flex flex-wrap items-center gap-2">
        <span
          className="text-[10px] font-semibold uppercase tracking-wider mr-1"
          style={{ color: "var(--muted)" }}
        >
          Status
        </span>
        {STATUS_FILTERS.map((f) => (
          <button
            key={f.value}
            onClick={() => handleStatusFilterChange(f.value)}
            className={cn(
              "rounded-full px-3 py-1 text-xs font-medium transition-colors"
            )}
            style={{
              background:
                statusFilter === f.value ? "var(--primary)" : "var(--surface-1)",
              color:
                statusFilter === f.value ? "var(--primary-fg)" : "var(--muted)",
            }}
          >
            {f.label}
          </button>
        ))}

        <span
          className="text-[10px] font-semibold uppercase tracking-wider ml-4 mr-1"
          style={{ color: "var(--muted)" }}
        >
          Severity
        </span>
        {SEVERITY_FILTERS.map((f) => (
          <button
            key={f.value}
            onClick={() => handleSeverityFilterChange(f.value)}
            className={cn(
              "rounded-full px-3 py-1 text-xs font-medium transition-colors"
            )}
            style={{
              background:
                severityFilter === f.value ? "var(--primary)" : "var(--surface-1)",
              color:
                severityFilter === f.value ? "var(--primary-fg)" : "var(--muted)",
            }}
          >
            {f.label}
          </button>
        ))}
      </div>

      {/* Error state */}
      {error && (
        <div
          className="rounded-lg border p-4 text-center text-sm text-red-400"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
        >
          {error}
        </div>
      )}

      {/* Alerts table */}
      <div
        className="rounded-lg border overflow-hidden"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
      >
        {/* Table header */}
        <div
          className="grid grid-cols-[32px_1fr_140px_120px_60px_100px_55px_80px_100px] gap-2 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider border-b"
          style={{
            color: "var(--muted-fg)",
            borderColor: "var(--border)",
            background: "var(--surface-1)",
          }}
        >
          <span>Sev</span>
          <span>Title</span>
          <span>Rule</span>
          <span>Host</span>
          <span>Hits</span>
          <span>MITRE</span>
          <span>Risk</span>
          <span>Status</span>
          <span>First Seen</span>
        </div>

        {/* Loading skeleton */}
        {loading && displayAlerts.length === 0 && (
          <div>
            {Array.from({ length: 8 }).map((_, i) => (
              <SkeletonRow key={i} />
            ))}
          </div>
        )}

        {/* Rows */}
        {displayAlerts.map((alert) => (
          <button
            key={alert.id}
            onClick={() =>
              setSelectedAlert(
                selectedAlert?.id === alert.id ? null : alert
              )
            }
            className={cn(
              "grid grid-cols-[32px_1fr_140px_120px_60px_100px_55px_80px_100px] gap-2 px-3 py-2 text-xs w-full text-left transition-colors border-b last:border-b-0",
              selectedAlert?.id === alert.id
                ? "bg-[var(--surface-2)]"
                : "hover:bg-[var(--surface-1)]"
            )}
            style={{ borderColor: "var(--border-subtle)" }}
          >
            {/* Severity dot */}
            <span className="flex items-center">
              <span
                className={cn(
                  "inline-block h-2.5 w-2.5 rounded-full",
                  severityDot(alert.severity)
                )}
              />
            </span>

            {/* Title */}
            <span className="truncate font-medium" style={{ color: "var(--fg)" }}>
              {alert.title}
            </span>

            {/* Rule Name */}
            <span className="truncate" style={{ color: "var(--muted)" }}>
              {alert.rule_name || "—"}
            </span>

            {/* Hostname */}
            <span className="truncate" style={{ color: "var(--fg)" }}>
              {alert.hostname || "—"}
            </span>

            {/* Hit Count */}
            <span className="flex items-center">
              <span
                className="rounded px-1.5 py-0.5 text-[10px] font-mono font-semibold bg-neutral-500/15 text-neutral-400"
              >
                {alert.hit_count}
              </span>
            </span>

            {/* MITRE IDs */}
            <span className="flex items-center gap-1 overflow-hidden">
              {alert.mitre_ids?.slice(0, 2).map((id) => (
                <span
                  key={id}
                  className="rounded px-1 py-0.5 text-[9px] font-mono truncate"
                  style={{
                    background: "var(--surface-2)",
                    color: "var(--primary)",
                  }}
                >
                  {id}
                </span>
              ))}
              {alert.mitre_ids && alert.mitre_ids.length > 2 && (
                <span
                  className="text-[9px] font-mono"
                  style={{ color: "var(--muted)" }}
                >
                  +{alert.mitre_ids.length - 2}
                </span>
              )}
            </span>

            {/* Risk Score */}
            <span className="flex items-center">
              {(alert.risk_score ?? 0) > 0 ? (
                <span className={cn(
                  "rounded px-1.5 py-0.5 text-[10px] font-bold font-mono",
                  (alert.risk_score ?? 0) >= 80 ? "bg-red-500/20 text-red-400" :
                  (alert.risk_score ?? 0) >= 60 ? "bg-orange-500/20 text-orange-400" :
                  (alert.risk_score ?? 0) >= 40 ? "bg-amber-500/20 text-amber-400" :
                  "bg-blue-500/20 text-blue-400"
                )}>
                  {alert.risk_score}
                </span>
              ) : (
                <span style={{ color: "var(--muted)" }}>—</span>
              )}
            </span>

            {/* Status */}
            <span className="flex items-center">
              <span
                className={cn(
                  "rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                  statusBadgeClass(alert.status)
                )}
              >
                {alert.status}
              </span>
            </span>

            {/* First Seen */}
            <span className="font-mono truncate" style={{ color: "var(--muted)" }}>
              {timeAgo(alert.first_seen)}
            </span>
          </button>
        ))}

        {/* Empty state */}
        {!loading && displayAlerts.length === 0 && (
          <div
            className="py-12 text-center text-xs"
            style={{ color: "var(--muted)" }}
          >
            No alerts found
          </div>
        )}
      </div>

      {/* Load More */}
      {fetchedAlerts && fetchedAlerts.length === PAGE_SIZE && (
        <div className="flex justify-center">
          <button
            onClick={() => setOffset((prev) => prev + PAGE_SIZE)}
            disabled={loading}
            className="rounded-md border px-4 py-2 text-xs font-medium transition-colors hover:bg-[var(--surface-2)] disabled:opacity-50"
            style={{
              background: "var(--surface-0)",
              borderColor: "var(--border)",
              color: "var(--muted)",
            }}
          >
            {loading ? "Loading..." : "Load More"}
          </button>
        </div>
      )}

      {/* Detail drawer */}
      {selectedAlert && (
        <>
          <div
            className="fixed inset-0 z-40 bg-black/30"
            onClick={() => setSelectedAlert(null)}
          />
          <AlertDetail
            alert={selectedAlert}
            onClose={() => setSelectedAlert(null)}
            onStatusChange={handleAlertStatusChange}
          />
        </>
      )}
    </div>
  );
}
