"use client";

import { useCallback, useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import {
  cn,
  severityLabel,
  severityBgClass,
  eventTypeColor,
  timeAgo,
} from "@/lib/utils";
import type { Rule } from "@/types";

/* ---------- Helpers ---------- */
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
      <div className="animate-shimmer h-4 w-10 rounded" />
      <div className="animate-shimmer h-4 w-40 rounded" />
      <div className="animate-shimmer h-4 w-28 rounded" />
      <div className="animate-shimmer h-3 w-3 rounded-full" />
      <div className="animate-shimmer h-4 w-24 rounded" />
      <div className="animate-shimmer h-4 w-16 rounded" />
      <div className="animate-shimmer h-4 w-20 rounded" />
      <div className="animate-shimmer h-4 w-16 rounded" />
    </div>
  );
}

/* ---------- Inline Detail ---------- */
function RuleDetail({ rule }: { rule: Rule }) {
  return (
    <div
      className="px-6 py-4 text-xs space-y-3 border-b"
      style={{
        background: "var(--surface-1)",
        borderColor: "var(--border-subtle)",
      }}
    >
      {/* Description */}
      {rule.description && (
        <div>
          <div
            className="text-[10px] font-semibold uppercase tracking-wider mb-1"
            style={{ color: "var(--muted)" }}
          >
            Description
          </div>
          <p style={{ color: "var(--fg)" }}>{rule.description}</p>
        </div>
      )}

      {/* Conditions */}
      <div>
        <div
          className="text-[10px] font-semibold uppercase tracking-wider mb-1"
          style={{ color: "var(--muted)" }}
        >
          Conditions
        </div>
        <pre
          className="font-mono text-[11px] rounded p-3 overflow-x-auto"
          style={{ background: "var(--surface-2)", color: "var(--fg)" }}
        >
          {JSON.stringify(rule.conditions, null, 2)}
        </pre>
      </div>

      {/* Threshold settings */}
      {rule.rule_type === "threshold" && (
        <div>
          <div
            className="text-[10px] font-semibold uppercase tracking-wider mb-1"
            style={{ color: "var(--muted)" }}
          >
            Threshold Settings
          </div>
          <div className="space-y-1" style={{ color: "var(--fg)" }}>
            <div>
              Count: <span className="font-mono">{rule.threshold_count}</span>
            </div>
            <div>
              Window:{" "}
              <span className="font-mono">{rule.threshold_window_s}s</span>
            </div>
            {rule.group_by && (
              <div>
                Group By: <span className="font-mono">{rule.group_by}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* MITRE IDs */}
      {rule.mitre_ids && rule.mitre_ids.length > 0 && (
        <div>
          <div
            className="text-[10px] font-semibold uppercase tracking-wider mb-1"
            style={{ color: "var(--muted)" }}
          >
            MITRE ATT&CK
          </div>
          <div className="flex flex-wrap gap-1.5">
            {rule.mitre_ids.map((id) => (
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

      {/* Metadata */}
      <div className="flex gap-6" style={{ color: "var(--muted)" }}>
        <span>
          Author: <span style={{ color: "var(--fg)" }}>{rule.author || "—"}</span>
        </span>
        <span>
          Updated: <span style={{ color: "var(--fg)" }}>{timeAgo(rule.updated_at)}</span>
        </span>
      </div>
    </div>
  );
}

/* ---------- Rules Page ---------- */
export default function RulesPage() {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [togglingIds, setTogglingIds] = useState<Set<string>>(new Set());
  const [reloading, setReloading] = useState(false);

  const fetchRules = useCallback(
    () =>
      api
        .get<{ rules?: Rule[] } | Rule[]>("/api/v1/rules")
        .then((r) => (Array.isArray(r) ? r : r.rules ?? [])),
    []
  );

  const { data: rules, loading, error, refetch } = useApi(fetchRules);

  async function handleToggle(rule: Rule) {
    setTogglingIds((prev) => new Set(prev).add(rule.id));
    try {
      await api.patch(`/api/v1/rules/${rule.id}`, {
        enabled: !rule.enabled,
      });
      refetch();
    } catch {
      // Silently handle
    } finally {
      setTogglingIds((prev) => {
        const next = new Set(prev);
        next.delete(rule.id);
        return next;
      });
    }
  }

  async function handleDelete(rule: Rule) {
    if (!window.confirm(`Delete rule "${rule.name}"? This cannot be undone.`)) {
      return;
    }
    try {
      await api.del(`/api/v1/rules/${rule.id}`);
      refetch();
    } catch {
      // Silently handle
    }
  }

  async function handleReload() {
    setReloading(true);
    try {
      await api.post("/api/v1/rules/reload");
      refetch();
    } catch {
      // Silently handle
    } finally {
      setReloading(false);
    }
  }

  const displayRules = rules ?? [];

  return (
    <div className="animate-fade-in space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1
          className="text-lg font-semibold"
          style={{ fontFamily: "var(--font-space-grotesk)" }}
        >
          Detection Rules
        </h1>
        <button
          onClick={handleReload}
          disabled={reloading}
          className="rounded-md border px-4 py-2 text-xs font-medium transition-colors hover:bg-[var(--surface-2)] disabled:opacity-50"
          style={{
            background: "var(--surface-0)",
            borderColor: "var(--border)",
            color: "var(--primary)",
          }}
        >
          {reloading ? "Reloading..." : "Reload Rules"}
        </button>
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

      {/* Rules table */}
      <div
        className="rounded-lg border overflow-hidden"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
      >
        {/* Table header */}
        <div
          className="grid grid-cols-[56px_1fr_1.2fr_50px_140px_80px_120px_80px_40px] gap-2 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider border-b"
          style={{
            color: "var(--muted-fg)",
            borderColor: "var(--border)",
            background: "var(--surface-1)",
          }}
        >
          <span>Enabled</span>
          <span>Name</span>
          <span>Description</span>
          <span>Sev</span>
          <span>Event Types</span>
          <span>Type</span>
          <span>MITRE</span>
          <span>Author</span>
          <span />
        </div>

        {/* Loading skeleton */}
        {loading && displayRules.length === 0 && (
          <div>
            {Array.from({ length: 8 }).map((_, i) => (
              <SkeletonRow key={i} />
            ))}
          </div>
        )}

        {/* Rows */}
        {displayRules.map((rule) => (
          <div key={rule.id}>
            <div
              className={cn(
                "grid grid-cols-[56px_1fr_1.2fr_50px_140px_80px_120px_80px_40px] gap-2 px-3 py-2 text-xs items-center transition-colors border-b last:border-b-0 cursor-pointer",
                expandedId === rule.id
                  ? "bg-[var(--surface-2)]"
                  : "hover:bg-[var(--surface-1)]"
              )}
              style={{ borderColor: "var(--border-subtle)" }}
            >
              {/* Enabled toggle */}
              <span className="flex items-center" onClick={(e) => e.stopPropagation()}>
                <button
                  onClick={() => handleToggle(rule)}
                  disabled={togglingIds.has(rule.id)}
                  className={cn(
                    "relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full transition-colors duration-200 ease-in-out disabled:opacity-50",
                    rule.enabled ? "bg-emerald-500" : "bg-neutral-600"
                  )}
                  role="switch"
                  aria-checked={rule.enabled}
                >
                  <span
                    className={cn(
                      "pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow-sm transform transition-transform duration-200 ease-in-out mt-0.5",
                      rule.enabled ? "translate-x-4 ml-0.5" : "translate-x-0.5"
                    )}
                  />
                </button>
              </span>

              {/* Name */}
              <span
                className="truncate font-medium cursor-pointer"
                style={{ color: "var(--fg)" }}
                onClick={() =>
                  setExpandedId(expandedId === rule.id ? null : rule.id)
                }
              >
                {rule.name}
              </span>

              {/* Description */}
              <span
                className="truncate cursor-pointer"
                style={{ color: "var(--muted)" }}
                onClick={() =>
                  setExpandedId(expandedId === rule.id ? null : rule.id)
                }
              >
                {rule.description || "—"}
              </span>

              {/* Severity dot */}
              <span
                className="flex items-center cursor-pointer"
                onClick={() =>
                  setExpandedId(expandedId === rule.id ? null : rule.id)
                }
              >
                <span
                  className={cn(
                    "inline-block h-2.5 w-2.5 rounded-full",
                    severityDot(rule.severity)
                  )}
                  title={severityLabel(rule.severity)}
                />
              </span>

              {/* Event Types */}
              <span
                className="flex items-center gap-1 overflow-hidden cursor-pointer"
                onClick={() =>
                  setExpandedId(expandedId === rule.id ? null : rule.id)
                }
              >
                {rule.event_types?.slice(0, 2).map((et) => (
                  <span
                    key={et}
                    className={cn(
                      "rounded px-1 py-0.5 text-[9px] font-mono font-semibold uppercase truncate",
                      eventTypeColor(et)
                    )}
                    style={{ background: "var(--surface-2)" }}
                  >
                    {et}
                  </span>
                ))}
                {rule.event_types && rule.event_types.length > 2 && (
                  <span
                    className="text-[9px] font-mono"
                    style={{ color: "var(--muted)" }}
                  >
                    +{rule.event_types.length - 2}
                  </span>
                )}
              </span>

              {/* Rule Type */}
              <span
                className="cursor-pointer"
                onClick={() =>
                  setExpandedId(expandedId === rule.id ? null : rule.id)
                }
              >
                <span
                  className={cn(
                    "rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                    rule.rule_type === "threshold"
                      ? "bg-violet-500/15 text-violet-400"
                      : "bg-sky-500/15 text-sky-400"
                  )}
                >
                  {rule.rule_type || "match"}
                </span>
              </span>

              {/* MITRE IDs */}
              <span
                className="flex items-center gap-1 overflow-hidden cursor-pointer"
                onClick={() =>
                  setExpandedId(expandedId === rule.id ? null : rule.id)
                }
              >
                {rule.mitre_ids?.slice(0, 2).map((id) => (
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
                {rule.mitre_ids && rule.mitre_ids.length > 2 && (
                  <span
                    className="text-[9px] font-mono"
                    style={{ color: "var(--muted)" }}
                  >
                    +{rule.mitre_ids.length - 2}
                  </span>
                )}
              </span>

              {/* Author */}
              <span
                className="truncate cursor-pointer"
                style={{ color: "var(--muted)" }}
                onClick={() =>
                  setExpandedId(expandedId === rule.id ? null : rule.id)
                }
              >
                {rule.author || "—"}
              </span>

              {/* Delete button */}
              <span className="flex items-center" onClick={(e) => e.stopPropagation()}>
                <button
                  onClick={() => handleDelete(rule)}
                  className="rounded p-1 text-[10px] transition-colors hover:bg-red-500/15 text-red-400/60 hover:text-red-400"
                  title="Delete rule"
                >
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    width="14"
                    height="14"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <polyline points="3 6 5 6 21 6" />
                    <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
                  </svg>
                </button>
              </span>
            </div>

            {/* Expanded detail */}
            {expandedId === rule.id && <RuleDetail rule={rule} />}
          </div>
        ))}

        {/* Empty state */}
        {!loading && displayRules.length === 0 && (
          <div
            className="py-12 text-center text-xs"
            style={{ color: "var(--muted)" }}
          >
            No detection rules found
          </div>
        )}
      </div>
    </div>
  );
}
