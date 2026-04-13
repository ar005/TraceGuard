"use client";

import { useCallback, useMemo, useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import {
  cn,
  severityLabel,
  severityBgClass,
  statusColor,
  timeAgo,
  formatDate,
} from "@/lib/utils";
import type { Alert, Incident } from "@/types";

/* ---------- Constants ---------- */
const STATUS_FILTERS = [
  { label: "All", value: "" },
  { label: "Open", value: "open" },
  { label: "Investigating", value: "investigating" },
  { label: "Closed", value: "closed" },
] as const;

const STATUS_VALUES = ["open", "investigating", "closed"] as const;

const PAGE_SIZE = 25;

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

function SkeletonRow() {
  return (
    <div className="flex items-center gap-3 px-3 py-2">
      <div className="animate-shimmer h-3 w-3 rounded-full" />
      <div className="animate-shimmer h-4 w-40 rounded" />
      <div className="animate-shimmer h-5 w-16 rounded" />
      <div className="animate-shimmer h-4 w-12 rounded" />
      <div className="animate-shimmer h-4 w-28 rounded" />
      <div className="animate-shimmer h-4 w-20 rounded" />
      <div className="animate-shimmer h-4 w-16 rounded" />
    </div>
  );
}

/* ---------- Incident Detail Drawer ---------- */
function IncidentDetail({
  incident,
  onClose,
  onStatusChange,
}: {
  incident: Incident;
  onClose: () => void;
  onStatusChange: (id: string, status: string) => void;
}) {
  const [showStatusMenu, setShowStatusMenu] = useState(false);
  const [notes, setNotes] = useState(incident.notes ?? "");
  const [savingNotes, setSavingNotes] = useState(false);

  /* Fetch related alerts */
  const fetchAlerts = useCallback(
    () =>
      api
        .get<{ alerts?: Alert[] } | Alert[]>(
          `/api/v1/incidents/${incident.id}/alerts`
        )
        .then((r) => (Array.isArray(r) ? r : r.alerts ?? [])),
    [incident.id]
  );
  const { data: relatedAlerts, loading: alertsLoading } = useApi(fetchAlerts);

  async function handleSaveNotes() {
    setSavingNotes(true);
    try {
      await api.patch(`/api/v1/incidents/${incident.id}`, { notes });
    } catch {
      // Silently handle
    } finally {
      setSavingNotes(false);
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
          Incident Detail
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
            style={{
              fontFamily: "var(--font-space-grotesk)",
              color: "var(--fg)",
            }}
          >
            {incident.title}
          </h4>
          {incident.description && (
            <p
              className="text-xs leading-relaxed"
              style={{ color: "var(--muted)" }}
            >
              {incident.description}
            </p>
          )}
        </div>

        {/* Key fields */}
        <div className="space-y-2 text-xs">
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Incident ID</span>
            <span className="font-mono" style={{ color: "var(--fg)" }}>
              {incident.id}
            </span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Severity</span>
            <span
              className={cn(
                "rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                severityBgClass(incident.severity)
              )}
            >
              {severityLabel(incident.severity)}
            </span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Status</span>
            <span
              className={cn(
                "rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                statusBadgeClass(incident.status)
              )}
            >
              {incident.status}
            </span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Alert Count</span>
            <span className="font-mono" style={{ color: "var(--fg)" }}>
              {incident.alert_count}
            </span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Hostnames</span>
            <span style={{ color: "var(--fg)" }}>
              {incident.hostnames?.join(", ") || "—"}
            </span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Assignee</span>
            <span style={{ color: "var(--fg)" }}>
              {incident.assignee || "—"}
            </span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>First Seen</span>
            <span className="font-mono" style={{ color: "var(--fg)" }}>
              {formatDate(incident.first_seen)}
            </span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Last Seen</span>
            <span className="font-mono" style={{ color: "var(--fg)" }}>
              {formatDate(incident.last_seen)}
            </span>
          </div>
        </div>

        {/* MITRE ATT&CK IDs */}
        {incident.mitre_ids && incident.mitre_ids.length > 0 && (
          <div>
            <div
              className="text-[10px] font-semibold uppercase tracking-wider mb-1.5"
              style={{ color: "var(--muted)" }}
            >
              MITRE ATT&CK
            </div>
            <div className="flex flex-wrap gap-1.5">
              {incident.mitre_ids.map((id) => (
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

        {/* Status update */}
        <div>
          <div
            className="text-[10px] font-semibold uppercase tracking-wider mb-1.5"
            style={{ color: "var(--muted)" }}
          >
            Update Status
          </div>
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
              {incident.status || "Set Status"}
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
                      onStatusChange(incident.id, s);
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
        </div>

        {/* Notes */}
        <div>
          <div
            className="text-[10px] font-semibold uppercase tracking-wider mb-1.5"
            style={{ color: "var(--muted)" }}
          >
            Notes
          </div>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={4}
            className="w-full rounded border px-3 py-2 text-xs font-mono outline-none resize-y focus-ring"
            style={{
              background: "var(--surface-1)",
              borderColor: "var(--border)",
              color: "var(--fg)",
            }}
            placeholder="Add investigation notes..."
          />
          <button
            onClick={handleSaveNotes}
            disabled={savingNotes}
            className="mt-1.5 rounded border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-2)] disabled:opacity-50"
            style={{
              background: "var(--surface-1)",
              borderColor: "var(--border)",
              color: "var(--primary)",
            }}
          >
            {savingNotes ? "Saving..." : "Save Notes"}
          </button>
        </div>

        {/* Related alerts */}
        <div>
          <div
            className="text-xs font-semibold mb-2"
            style={{
              fontFamily: "var(--font-space-grotesk)",
              color: "var(--fg)",
            }}
          >
            Related Alerts
          </div>
          {alertsLoading && (
            <div className="space-y-2">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="animate-shimmer h-8 rounded" />
              ))}
            </div>
          )}
          {!alertsLoading && relatedAlerts && relatedAlerts.length > 0 && (
            <div
              className="rounded border divide-y"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-1)",
              }}
            >
              {relatedAlerts.map((alert) => (
                <div
                  key={alert.id}
                  className="px-3 py-2 text-xs"
                  style={{ borderColor: "var(--border-subtle)" }}
                >
                  <div className="flex items-center gap-2">
                    <span
                      className={cn(
                        "inline-block h-2 w-2 rounded-full",
                        severityDot(alert.severity)
                      )}
                    />
                    <span
                      className="truncate font-medium"
                      style={{ color: "var(--fg)" }}
                    >
                      {alert.title}
                    </span>
                    <span
                      className={cn(
                        "rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                        statusBadgeClass(alert.status)
                      )}
                    >
                      {alert.status}
                    </span>
                    <span
                      className="font-mono ml-auto"
                      style={{ color: "var(--muted)" }}
                    >
                      {timeAgo(alert.last_seen)}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
          {!alertsLoading &&
            (!relatedAlerts || relatedAlerts.length === 0) && (
              <p className="text-xs" style={{ color: "var(--muted)" }}>
                No related alerts found.
              </p>
            )}
        </div>
      </div>
    </div>
  );
}

/* ---------- Incidents Page ---------- */
export default function IncidentsPage() {
  const [statusFilter, setStatusFilter] = useState("");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [allIncidents, setAllIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(
    null
  );

  /* API fetch */
  const fetchIncidents = useCallback(
    () =>
      api
        .get<{ incidents?: Incident[] } | Incident[]>("/api/v1/incidents", {
          status: statusFilter || undefined,
          search: search || undefined,
          limit: PAGE_SIZE,
          offset,
        })
        .then((r) => (Array.isArray(r) ? r : r.incidents ?? [])),
    [statusFilter, search, offset]
  );

  const {
    data: fetchedIncidents,
    loading,
    error,
    refetch,
  } = useApi(fetchIncidents);

  /* Accumulate for load-more */
  useMemo(() => {
    if (fetchedIncidents) {
      if (offset === 0) {
        setAllIncidents(fetchedIncidents);
      } else {
        setAllIncidents((prev) => {
          const ids = new Set(prev.map((i) => i.id));
          const newOnes = fetchedIncidents.filter((i) => !ids.has(i.id));
          return [...prev, ...newOnes];
        });
      }
    }
  }, [fetchedIncidents, offset]);

  const displayIncidents = allIncidents;

  function handleStatusFilterChange(val: string) {
    setStatusFilter(val);
    setOffset(0);
    setAllIncidents([]);
  }

  async function handleIncidentStatusChange(id: string, status: string) {
    try {
      await api.patch(`/api/v1/incidents/${id}`, { status });
      setAllIncidents((prev) =>
        prev.map((i) => (i.id === id ? { ...i, status } : i))
      );
      if (selectedIncident?.id === id) {
        setSelectedIncident((prev) => (prev ? { ...prev, status } : null));
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
        Incidents
      </h1>

      {/* Search */}
      <input
        type="text"
        placeholder="Search incidents by title, description, or hostname..."
        value={search}
        onChange={(e) => { setSearch(e.target.value); setOffset(0); setAllIncidents([]); }}
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
                statusFilter === f.value
                  ? "var(--primary)"
                  : "var(--surface-1)",
              color:
                statusFilter === f.value
                  ? "var(--primary-fg)"
                  : "var(--muted)",
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
          style={{
            background: "var(--surface-0)",
            borderColor: "var(--border)",
          }}
        >
          {error}
        </div>
      )}

      {/* Incidents table */}
      <div
        className="rounded-lg border overflow-hidden"
        style={{
          background: "var(--surface-0)",
          borderColor: "var(--border)",
        }}
      >
        {/* Table header */}
        <div
          className="grid grid-cols-[32px_1fr_90px_70px_140px_120px_100px] gap-2 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider border-b"
          style={{
            color: "var(--muted-fg)",
            borderColor: "var(--border)",
            background: "var(--surface-1)",
          }}
        >
          <span>Sev</span>
          <span>Title</span>
          <span>Status</span>
          <span>Alerts</span>
          <span>Hostnames</span>
          <span>MITRE</span>
          <span>Last Seen</span>
        </div>

        {/* Loading skeleton */}
        {loading && displayIncidents.length === 0 && (
          <div>
            {Array.from({ length: 8 }).map((_, i) => (
              <SkeletonRow key={i} />
            ))}
          </div>
        )}

        {/* Rows */}
        {displayIncidents.map((incident) => (
          <button
            key={incident.id}
            onClick={() =>
              setSelectedIncident(
                selectedIncident?.id === incident.id ? null : incident
              )
            }
            className={cn(
              "grid grid-cols-[32px_1fr_90px_70px_140px_120px_100px] gap-2 px-3 py-2 text-xs w-full text-left transition-colors border-b last:border-b-0",
              selectedIncident?.id === incident.id
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
                  severityDot(incident.severity)
                )}
              />
            </span>

            {/* Title */}
            <span
              className="truncate font-medium"
              style={{ color: "var(--fg)" }}
            >
              {incident.title}
            </span>

            {/* Status */}
            <span className="flex items-center">
              <span
                className={cn(
                  "rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                  statusBadgeClass(incident.status)
                )}
              >
                {incident.status}
              </span>
            </span>

            {/* Alert Count */}
            <span className="flex items-center">
              <span className="rounded px-1.5 py-0.5 text-[10px] font-mono font-semibold bg-neutral-500/15 text-neutral-400">
                {incident.alert_count}
              </span>
            </span>

            {/* Hostnames */}
            <span className="truncate" style={{ color: "var(--fg)" }}>
              {incident.hostnames?.join(", ") || "—"}
            </span>

            {/* MITRE IDs */}
            <span className="flex items-center gap-1 overflow-hidden">
              {incident.mitre_ids?.slice(0, 2).map((id) => (
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
              {incident.mitre_ids && incident.mitre_ids.length > 2 && (
                <span
                  className="text-[9px] font-mono"
                  style={{ color: "var(--muted)" }}
                >
                  +{incident.mitre_ids.length - 2}
                </span>
              )}
            </span>

            {/* Last Seen */}
            <span
              className="font-mono truncate"
              style={{ color: "var(--muted)" }}
            >
              {timeAgo(incident.last_seen)}
            </span>
          </button>
        ))}

        {/* Empty state */}
        {!loading && displayIncidents.length === 0 && (
          <div
            className="py-12 text-center text-xs"
            style={{ color: "var(--muted)" }}
          >
            No incidents found
          </div>
        )}
      </div>

      {/* Load More */}
      {fetchedIncidents && fetchedIncidents.length === PAGE_SIZE && (
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
      {selectedIncident && (
        <>
          <div
            className="fixed inset-0 z-40 bg-black/30"
            onClick={() => setSelectedIncident(null)}
          />
          <IncidentDetail
            incident={selectedIncident}
            onClose={() => setSelectedIncident(null)}
            onStatusChange={handleIncidentStatusChange}
          />
        </>
      )}
    </div>
  );
}
