"use client";

import { useCallback, useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn, timeAgo, eventTypeColor } from "@/lib/utils";
import type { SuppressionRule } from "@/types";

/* ---------- Constants ---------- */
const EVENT_TYPE_OPTIONS = [
  "PROCESS_EXEC",
  "CMD_EXEC",
  "NET_CONNECT",
  "FILE_WRITE",
  "BROWSER_REQUEST",
  "*",
] as const;

/* ---------- Skeleton ---------- */
function SkeletonRow() {
  return (
    <div className="flex items-center gap-3 px-3 py-2">
      <div className="animate-shimmer h-5 w-9 rounded-full" />
      <div className="animate-shimmer h-4 w-32 rounded" />
      <div className="animate-shimmer h-4 w-48 rounded" />
      <div className="animate-shimmer h-4 w-24 rounded" />
      <div className="animate-shimmer h-4 w-12 rounded" />
      <div className="animate-shimmer h-4 w-20 rounded" />
      <div className="animate-shimmer h-4 w-16 rounded" />
    </div>
  );
}

/* ---------- Create Suppression Form ---------- */
function CreateForm({ onSubmit, onCancel }: { onSubmit: (body: Record<string, unknown>) => void; onCancel: () => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [eventTypes, setEventTypes] = useState<string[]>([]);
  const [conditions, setConditions] = useState("[]");
  const [submitting, setSubmitting] = useState(false);

  const toggleEventType = (t: string) => {
    setEventTypes((prev) =>
      prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t]
    );
  };

  const handleSubmit = async () => {
    if (!name.trim()) return;
    setSubmitting(true);
    let parsedConditions;
    try {
      parsedConditions = JSON.parse(conditions);
    } catch {
      parsedConditions = [];
    }
    try {
      await onSubmit({
        name: name.trim(),
        description: description.trim(),
        event_types: eventTypes,
        conditions: parsedConditions,
        enabled: true,
      });
      setName("");
      setDescription("");
      setEventTypes([]);
      setConditions("[]");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="rounded-lg border p-4 space-y-3 animate-fade-in"
      style={{ background: "var(--surface-1)", borderColor: "var(--border)" }}
    >
      <div className="flex items-center gap-3 flex-wrap">
        <input
          type="text"
          placeholder="Suppression name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="rounded-md border px-3 py-1.5 text-xs flex-1 min-w-[200px] outline-none focus-ring"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
        />
        <input
          type="text"
          placeholder="Description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          className="rounded-md border px-3 py-1.5 text-xs flex-1 min-w-[200px] outline-none focus-ring"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
        />
      </div>

      {/* Event type chips */}
      <div>
        <div className="text-[10px] uppercase tracking-wider mb-1.5" style={{ color: "var(--muted)" }}>
          Event Types
        </div>
        <div className="flex flex-wrap gap-1.5">
          {EVENT_TYPE_OPTIONS.map((t) => (
            <button
              key={t}
              onClick={() => toggleEventType(t)}
              className={cn(
                "rounded-full px-2.5 py-1 text-[11px] font-medium transition-colors border",
                eventTypes.includes(t)
                  ? "border-emerald-500/50 bg-emerald-500/10"
                  : "hover:bg-[var(--surface-2)]"
              )}
              style={{
                borderColor: eventTypes.includes(t) ? undefined : "var(--border)",
                color: eventTypes.includes(t) ? "var(--fg)" : "var(--muted)",
              }}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {/* Conditions */}
      <div>
        <div className="text-[10px] uppercase tracking-wider mb-1.5" style={{ color: "var(--muted)" }}>
          Conditions (JSON)
        </div>
        <textarea
          placeholder={'[{"field": "payload.path", "op": "contains", "value": "/tmp"}]'}
          value={conditions}
          onChange={(e) => setConditions(e.target.value)}
          rows={3}
          className="w-full rounded-md border px-3 py-2 text-xs font-mono outline-none resize-none focus-ring"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
        />
      </div>

      <div className="flex gap-2">
        <button
          onClick={handleSubmit}
          disabled={submitting || !name.trim()}
          className="rounded-md px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50"
          style={{ background: "var(--primary)", color: "var(--primary-fg)" }}
        >
          {submitting ? "Creating..." : "Create Suppression"}
        </button>
        <button
          onClick={onCancel}
          className="rounded-md border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-2)]"
          style={{ borderColor: "var(--border)", color: "var(--muted)" }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

/* ---------- Suppressions Page ---------- */
export default function SuppressionsPage() {
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  /* Fetch suppressions */
  const fetchSuppressions = useCallback(
    () =>
      api
        .get<{ suppression_rules?: SuppressionRule[]; suppressions?: SuppressionRule[] } | SuppressionRule[]>("/api/v1/suppressions")
        .then((r) => {
          if (Array.isArray(r)) return r;
          return r.suppression_rules ?? r.suppressions ?? [];
        }),
    []
  );
  const { data: suppressions, loading, error, refetch } = useApi(fetchSuppressions);

  /* Actions */
  const handleCreate = async (body: Record<string, unknown>) => {
    await api.post("/api/v1/suppressions", body);
    setShowCreateForm(false);
    refetch();
  };

  const handleToggleEnabled = async (rule: SuppressionRule) => {
    await api.put(`/api/v1/suppressions/${rule.id}`, { ...rule, enabled: !rule.enabled });
    refetch();
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm("Delete this suppression rule?")) return;
    await api.del(`/api/v1/suppressions/${id}`);
    refetch();
  };

  const displayRules = (suppressions ?? []).filter((rule) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      rule.name?.toLowerCase().includes(q) ||
      rule.description?.toLowerCase().includes(q) ||
      rule.event_types?.some((t) => t.toLowerCase().includes(q)) ||
      rule.author?.toLowerCase().includes(q)
    );
  });

  return (
    <div className="animate-fade-in space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <h1
          className="text-lg font-semibold"
          style={{ fontFamily: "var(--font-space-grotesk)" }}
        >
          Suppressions
        </h1>
        <button
          onClick={() => setShowCreateForm(!showCreateForm)}
          className="rounded-md px-3 py-1.5 text-xs font-medium transition-colors"
          style={{ background: "var(--primary)", color: "var(--primary-fg)" }}
        >
          Create Suppression
        </button>
      </div>

      {/* Search */}
      <input
        type="text"
        placeholder="Search suppressions by name, description, or event type..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="rounded-md border px-3 py-1.5 text-xs w-full max-w-md outline-none focus-ring"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
      />

      {/* Create form */}
      {showCreateForm && (
        <CreateForm
          onSubmit={handleCreate}
          onCancel={() => setShowCreateForm(false)}
        />
      )}

      {/* Error state */}
      {error && (
        <div
          className="rounded-lg border p-4 text-center text-sm text-red-400"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
        >
          {error}
        </div>
      )}

      {/* Table */}
      <div
        className="rounded-lg border overflow-hidden"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
      >
        {/* Table header */}
        <div
          className="grid grid-cols-[60px_1fr_1fr_160px_70px_100px_80px_50px] gap-2 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider border-b"
          style={{ color: "var(--muted-fg)", borderColor: "var(--border)", background: "var(--surface-1)" }}
        >
          <span>Enabled</span>
          <span>Name</span>
          <span>Description</span>
          <span>Event Types</span>
          <span>Hits</span>
          <span>Last Hit</span>
          <span>Author</span>
          <span></span>
        </div>

        {/* Loading skeleton */}
        {loading && displayRules.length === 0 && (
          <div>
            {Array.from({ length: 6 }).map((_, i) => (
              <SkeletonRow key={i} />
            ))}
          </div>
        )}

        {/* Rows */}
        {displayRules.map((rule) => (
          <div key={rule.id}>
            <div
              className={cn(
                "grid grid-cols-[60px_1fr_1fr_160px_70px_100px_80px_50px] gap-2 px-3 py-2 text-xs items-center transition-colors border-b cursor-pointer",
                expandedId === rule.id
                  ? "bg-[var(--surface-2)]"
                  : "hover:bg-[var(--surface-1)]"
              )}
              style={{ borderColor: "var(--border-subtle)" }}
              onClick={() => setExpandedId(expandedId === rule.id ? null : rule.id)}
            >
              <span className="flex justify-center" onClick={(e) => e.stopPropagation()}>
                <button
                  onClick={() => handleToggleEnabled(rule)}
                  className={cn(
                    "relative inline-flex h-5 w-9 items-center rounded-full transition-colors",
                    rule.enabled ? "bg-emerald-500" : "bg-neutral-600"
                  )}
                >
                  <span
                    className={cn(
                      "inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform",
                      rule.enabled ? "translate-x-4" : "translate-x-0.5"
                    )}
                  />
                </button>
              </span>
              <span className="truncate font-medium" style={{ color: "var(--fg)" }}>
                {rule.name}
              </span>
              <span className="truncate" style={{ color: "var(--muted)" }}>
                {rule.description || "—"}
              </span>
              <span className="flex flex-wrap gap-1 overflow-hidden">
                {(rule.event_types ?? []).map((t) => (
                  <span
                    key={t}
                    className={cn("text-[10px] font-medium", eventTypeColor(t))}
                  >
                    {t}
                  </span>
                ))}
              </span>
              <span className="font-mono text-center" style={{ color: "var(--fg)" }}>
                {rule.hit_count ?? 0}
              </span>
              <span className="font-mono truncate" style={{ color: "var(--muted)" }}>
                {rule.last_hit_at ? timeAgo(rule.last_hit_at) : "Never"}
              </span>
              <span className="truncate" style={{ color: "var(--muted)" }}>
                {rule.author || "—"}
              </span>
              <span className="flex justify-center" onClick={(e) => e.stopPropagation()}>
                <button
                  onClick={() => handleDelete(rule.id)}
                  className="rounded p-1 text-red-400/60 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                  title="Delete suppression"
                >
                  <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                </button>
              </span>
            </div>

            {/* Expanded conditions */}
            {expandedId === rule.id && (
              <div
                className="px-6 py-3 border-b animate-fade-in"
                style={{ background: "var(--surface-1)", borderColor: "var(--border-subtle)" }}
              >
                <div
                  className="text-[10px] font-semibold uppercase tracking-wider mb-1"
                  style={{ color: "var(--muted)" }}
                >
                  Conditions
                </div>
                <pre
                  className="rounded p-3 text-[11px] leading-relaxed overflow-x-auto font-mono"
                  style={{ background: "var(--surface-0)", color: "var(--fg)" }}
                >
                  <code>{JSON.stringify(rule.conditions, null, 2)}</code>
                </pre>
              </div>
            )}
          </div>
        ))}

        {/* Empty state */}
        {!loading && displayRules.length === 0 && (
          <div className="py-12 text-center text-xs" style={{ color: "var(--muted)" }}>
            No suppression rules configured
          </div>
        )}
      </div>
    </div>
  );
}
