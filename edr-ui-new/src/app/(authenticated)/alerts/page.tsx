"use client";

import { useCallback, useMemo, useState } from "react";
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

  /* Fetch related events */
  const fetchEvents = useCallback(
    () =>
      api
        .get<{ events?: Event[] } | Event[]>(`/api/v1/alerts/${alert.id}/events`)
        .then((r) => (Array.isArray(r) ? r : r.events ?? [])),
    [alert.id]
  );
  const { data: relatedEvents, loading: eventsLoading } = useApi(fetchEvents);

  async function handleExplain() {
    setExplaining(true);
    try {
      const result = await api.post<{ explanation: string }>(
        `/api/v1/alerts/${alert.id}/explain`
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

        {/* Explain with AI */}
        <div>
          <button
            onClick={handleExplain}
            disabled={explaining}
            className="rounded border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-2)] disabled:opacity-50"
            style={{
              background: "var(--surface-1)",
              borderColor: "var(--border)",
              color: "var(--primary)",
            }}
          >
            {explaining ? "Analyzing..." : "Explain with AI"}
          </button>
          {explanation && (
            <div
              className="mt-2 rounded p-3 text-xs leading-relaxed"
              style={{ background: "var(--surface-1)", color: "var(--fg)" }}
            >
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
            Related Events
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
              {relatedEvents.map((evt) => (
                <div
                  key={evt.id}
                  className="px-3 py-2 text-xs"
                  style={{ borderColor: "var(--border-subtle)" }}
                >
                  <div className="flex items-center gap-2">
                    <span className="font-mono" style={{ color: "var(--muted)" }}>
                      {timeAgo(evt.timestamp)}
                    </span>
                    <span
                      className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase bg-neutral-500/15 text-neutral-400"
                    >
                      {evt.event_type}
                    </span>
                    <span className="truncate" style={{ color: "var(--fg)" }}>
                      {evt.hostname}
                    </span>
                  </div>
                </div>
              ))}
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
  const [offset, setOffset] = useState(0);
  const [allAlerts, setAllAlerts] = useState<Alert[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  /* API fetch */
  const fetchAlerts = useCallback(
    () =>
      api
        .get<{ alerts?: Alert[] } | Alert[]>("/api/v1/alerts", {
          status: statusFilter || undefined,
          severity: severityFilter >= 0 ? severityFilter : undefined,
          limit: PAGE_SIZE,
          offset,
        })
        .then((r) => (Array.isArray(r) ? r : r.alerts ?? [])),
    [statusFilter, severityFilter, offset]
  );

  const { data: fetchedAlerts, loading, error, refetch } = useApi(fetchAlerts);

  /* Accumulate alerts for load-more */
  useMemo(() => {
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
          className="grid grid-cols-[32px_1fr_140px_120px_60px_100px_80px_100px] gap-2 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider border-b"
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
              "grid grid-cols-[32px_1fr_140px_120px_60px_100px_80px_100px] gap-2 px-3 py-2 text-xs w-full text-left transition-colors border-b last:border-b-0",
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
