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
import type { Rule, RuleCondition, SequenceStep } from "@/types";

/* ---------- Constants ---------- */
const ALL_EVENT_TYPES = [
  "PROCESS_EXEC", "PROCESS_EXIT", "PROCESS_FORK", "PROCESS_PTRACE",
  "CMD_EXEC", "CMD_HISTORY",
  "NET_CONNECT", "NET_ACCEPT", "NET_DNS", "NET_CLOSE",
  "FILE_CREATE", "FILE_WRITE", "FILE_DELETE", "FILE_RENAME", "FILE_CHMOD",
  "LOGIN_SUCCESS", "LOGIN_FAILED", "SUDO_EXEC",
  "BROWSER_REQUEST", "KERNEL_MODULE_LOAD", "USB_CONNECT",
  "MEMORY_INJECT", "CRON_MODIFY", "PIPE_CREATE", "SHARE_MOUNT", "REG_SET", "FIM_VIOLATION",
] as const;

const SEVERITY_OPTIONS = [
  { label: "Info", value: 0, color: "bg-neutral-500" },
  { label: "Low", value: 1, color: "bg-blue-500" },
  { label: "Medium", value: 2, color: "bg-amber-500" },
  { label: "High", value: 3, color: "bg-orange-500" },
  { label: "Critical", value: 4, color: "bg-red-500" },
] as const;

const OPERATORS = [
  "eq", "ne", "in", "gt", "lt", "gte", "lte", "startswith", "contains", "regex",
] as const;

/* ---------- Rule Builder ---------- */
function RuleBuilder({
  onCreated,
  onCancel,
}: {
  onCreated: () => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [author, setAuthor] = useState("analyst");
  const [severity, setSeverity] = useState(2);
  const [enabled, setEnabled] = useState(true);
  const [eventTypes, setEventTypes] = useState<Set<string>>(new Set());
  const [conditions, setConditions] = useState<RuleCondition[]>([
    { field: "", op: "eq", value: "" },
  ]);
  const [ruleType, setRuleType] = useState<"match" | "threshold" | "sequence">("match");
  const [thresholdCount, setThresholdCount] = useState(5);
  const [thresholdWindow, setThresholdWindow] = useState(60);
  const [groupBy, setGroupBy] = useState("");
  const [seqWindow, setSeqWindow] = useState(120);
  const [seqBy, setSeqBy] = useState("chain_id");
  const [seqSteps, setSeqSteps] = useState<SequenceStep[]>([
    { event_type: "", conditions: [] },
    { event_type: "", conditions: [] },
  ]);
  const [mitreInput, setMitreInput] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  function toggleEventType(et: string) {
    setEventTypes((prev) => {
      const next = new Set(prev);
      if (next.has(et)) next.delete(et);
      else next.add(et);
      return next;
    });
  }

  function updateCondition(idx: number, field: keyof RuleCondition, value: string) {
    setConditions((prev) =>
      prev.map((c, i) => (i === idx ? { ...c, [field]: value } : c))
    );
  }

  function removeCondition(idx: number) {
    setConditions((prev) => prev.filter((_, i) => i !== idx));
  }

  function addCondition() {
    setConditions((prev) => [...prev, { field: "", op: "eq", value: "" }]);
  }

  async function handleSubmit() {
    setFormError(null);
    if (!name.trim()) {
      setFormError("Rule name is required.");
      return;
    }
    if (eventTypes.size === 0) {
      setFormError("Select at least one event type.");
      return;
    }

    const validConditions = conditions.filter((c) => c.field.trim() !== "");
    const mitreIds = mitreInput
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    const payload = {
      name: name.trim(),
      description: description.trim(),
      enabled,
      severity,
      event_types: Array.from(eventTypes),
      conditions: validConditions,
      mitre_ids: mitreIds,
      author: author.trim() || "analyst",
      rule_type: ruleType,
      threshold_count: ruleType === "threshold" ? thresholdCount : 0,
      threshold_window_s: ruleType === "threshold" ? thresholdWindow : 0,
      group_by: ruleType === "threshold" ? groupBy.trim() : "",
      sequence_steps: ruleType === "sequence" ? seqSteps : undefined,
      sequence_window_s: ruleType === "sequence" ? seqWindow : 0,
      sequence_by: ruleType === "sequence" ? seqBy : "",
    };

    setSubmitting(true);
    try {
      await api.post("/api/v1/rules", payload);
      setSuccessMsg("Rule created successfully.");
      setTimeout(() => {
        onCreated();
      }, 600);
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : "Failed to create rule.");
    } finally {
      setSubmitting(false);
    }
  }

  const sectionTitle =
    "text-[11px] font-semibold uppercase tracking-wider mb-2";

  return (
    <div
      className="rounded-lg border p-5 space-y-5 animate-fade-in"
      style={{
        background: "var(--surface-0)",
        borderColor: "var(--border)",
      }}
    >
      <div className="flex items-center justify-between">
        <h2
          className="text-base font-semibold"
          style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}
        >
          Create Detection Rule
        </h2>
        <button
          onClick={onCancel}
          className="rounded p-1 text-xs transition-colors hover:bg-[var(--surface-2)]"
          style={{ color: "var(--muted)" }}
        >
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>

      {/* Success message */}
      {successMsg && (
        <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-xs text-emerald-400">
          {successMsg}
        </div>
      )}

      {/* Error message */}
      {formError && (
        <div className="rounded-md border border-red-500/30 bg-red-500/10 px-4 py-2 text-xs text-red-400">
          {formError}
        </div>
      )}

      {/* 1. Basic Info */}
      <div>
        <div className={sectionTitle} style={{ color: "var(--muted)", fontFamily: "var(--font-space-grotesk)" }}>
          Basic Info
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label className="block text-[10px] font-medium mb-1" style={{ color: "var(--muted-fg)" }}>
              Name <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Suspicious curl execution"
              className="w-full rounded-md border px-3 py-1.5 text-xs outline-none transition-colors focus:border-[var(--primary)]"
              style={{
                background: "var(--surface-1)",
                borderColor: "var(--border)",
                color: "var(--fg)",
              }}
            />
          </div>
          <div>
            <label className="block text-[10px] font-medium mb-1" style={{ color: "var(--muted-fg)" }}>
              Author
            </label>
            <input
              type="text"
              value={author}
              onChange={(e) => setAuthor(e.target.value)}
              className="w-full rounded-md border px-3 py-1.5 text-xs outline-none transition-colors focus:border-[var(--primary)]"
              style={{
                background: "var(--surface-1)",
                borderColor: "var(--border)",
                color: "var(--fg)",
              }}
            />
          </div>
        </div>
        <div className="mt-3">
          <label className="block text-[10px] font-medium mb-1" style={{ color: "var(--muted-fg)" }}>
            Description
          </label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={2}
            placeholder="What does this rule detect?"
            className="w-full rounded-md border px-3 py-1.5 text-xs outline-none transition-colors focus:border-[var(--primary)] resize-y"
            style={{
              background: "var(--surface-1)",
              borderColor: "var(--border)",
              color: "var(--fg)",
            }}
          />
        </div>
        <div className="mt-3 flex items-center gap-6">
          <div>
            <label className="block text-[10px] font-medium mb-1.5" style={{ color: "var(--muted-fg)" }}>
              Severity
            </label>
            <div className="flex gap-1.5">
              {SEVERITY_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  onClick={() => setSeverity(opt.value)}
                  className={cn(
                    "rounded-full px-2.5 py-0.5 text-[10px] font-semibold transition-all",
                    severity === opt.value
                      ? `${opt.color} text-white shadow-sm`
                      : "text-neutral-400 hover:text-neutral-200"
                  )}
                  style={
                    severity !== opt.value
                      ? { background: "var(--surface-2)" }
                      : undefined
                  }
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="block text-[10px] font-medium mb-1.5" style={{ color: "var(--muted-fg)" }}>
              Enabled
            </label>
            <button
              onClick={() => setEnabled(!enabled)}
              className={cn(
                "relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full transition-colors duration-200 ease-in-out",
                enabled ? "bg-emerald-500" : "bg-neutral-600"
              )}
              role="switch"
              aria-checked={enabled}
            >
              <span
                className={cn(
                  "pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow-sm transform transition-transform duration-200 ease-in-out mt-0.5",
                  enabled ? "translate-x-4 ml-0.5" : "translate-x-0.5"
                )}
              />
            </button>
          </div>
        </div>
      </div>

      {/* 2. Event Types */}
      <div>
        <div className={sectionTitle} style={{ color: "var(--muted)", fontFamily: "var(--font-space-grotesk)" }}>
          Event Types <span className="text-red-400">*</span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {ALL_EVENT_TYPES.map((et) => {
            const selected = eventTypes.has(et);
            return (
              <button
                key={et}
                onClick={() => toggleEventType(et)}
                className={cn(
                  "rounded px-2 py-0.5 text-[9px] font-mono font-semibold uppercase transition-all",
                  selected
                    ? eventTypeColor(et)
                    : "text-neutral-500 hover:text-neutral-300"
                )}
                style={{
                  background: selected ? "var(--surface-2)" : "var(--surface-1)",
                  borderWidth: "1px",
                  borderStyle: "solid",
                  borderColor: selected ? "var(--primary)" : "transparent",
                }}
              >
                {et}
              </button>
            );
          })}
        </div>
      </div>

      {/* 3. Conditions */}
      <div>
        <div className={sectionTitle} style={{ color: "var(--muted)", fontFamily: "var(--font-space-grotesk)" }}>
          Conditions <span className="text-[9px] font-normal normal-case tracking-normal" style={{ color: "var(--muted)" }}>(AND logic)</span>
        </div>
        <div className="space-y-2">
          {conditions.map((cond, idx) => (
            <div key={idx} className="flex items-center gap-2">
              <input
                type="text"
                value={cond.field}
                onChange={(e) => updateCondition(idx, "field", e.target.value)}
                placeholder="process.comm, dst_port, path, domain"
                className="flex-1 rounded-md border px-3 py-1.5 text-xs font-mono outline-none transition-colors focus:border-[var(--primary)]"
                style={{
                  background: "var(--surface-1)",
                  borderColor: "var(--border)",
                  color: "var(--fg)",
                }}
              />
              <select
                value={cond.op}
                onChange={(e) => updateCondition(idx, "op", e.target.value)}
                className="rounded-md border px-2 py-1.5 text-xs font-mono outline-none transition-colors focus:border-[var(--primary)]"
                style={{
                  background: "var(--surface-1)",
                  borderColor: "var(--border)",
                  color: "var(--fg)",
                }}
              >
                {OPERATORS.map((op) => (
                  <option key={op} value={op}>
                    {op}
                  </option>
                ))}
              </select>
              <input
                type="text"
                value={cond.value as string}
                onChange={(e) => updateCondition(idx, "value", e.target.value)}
                placeholder="value"
                className="flex-1 rounded-md border px-3 py-1.5 text-xs font-mono outline-none transition-colors focus:border-[var(--primary)]"
                style={{
                  background: "var(--surface-1)",
                  borderColor: "var(--border)",
                  color: "var(--fg)",
                }}
              />
              <button
                onClick={() => removeCondition(idx)}
                disabled={conditions.length <= 1}
                className="rounded p-1 text-red-400/60 transition-colors hover:bg-red-500/15 hover:text-red-400 disabled:opacity-30 disabled:hover:bg-transparent"
                title="Remove condition"
              >
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              </button>
            </div>
          ))}
        </div>
        <button
          onClick={addCondition}
          className="mt-2 rounded-md border px-3 py-1 text-[10px] font-medium transition-colors hover:bg-[var(--surface-2)]"
          style={{
            borderColor: "var(--border)",
            color: "var(--primary)",
            background: "var(--surface-1)",
          }}
        >
          + Add Condition
        </button>
      </div>

      {/* 4. Rule Type */}
      <div>
        <div className={sectionTitle} style={{ color: "var(--muted)", fontFamily: "var(--font-space-grotesk)" }}>
          Rule Type
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setRuleType("match")}
            className={cn(
              "rounded-md px-3 py-1 text-xs font-semibold transition-all",
              ruleType === "match"
                ? "bg-sky-500/15 text-sky-400"
                : "text-neutral-400 hover:text-neutral-200"
            )}
            style={
              ruleType !== "match"
                ? { background: "var(--surface-1)" }
                : undefined
            }
          >
            Match
          </button>
          <button
            onClick={() => setRuleType("threshold")}
            className={cn(
              "rounded-md px-3 py-1 text-xs font-semibold transition-all",
              ruleType === "threshold"
                ? "bg-violet-500/15 text-violet-400"
                : "text-neutral-400 hover:text-neutral-200"
            )}
            style={
              ruleType !== "threshold"
                ? { background: "var(--surface-1)" }
                : undefined
            }
          >
            Threshold
          </button>
          <button
            onClick={() => setRuleType("sequence")}
            className={cn(
              "rounded-md px-3 py-1 text-xs font-semibold transition-all",
              ruleType === "sequence"
                ? "bg-fuchsia-500/15 text-fuchsia-400"
                : "text-neutral-400 hover:text-neutral-200"
            )}
            style={
              ruleType !== "sequence"
                ? { background: "var(--surface-1)" }
                : undefined
            }
          >
            Sequence
          </button>
        </div>
        {ruleType === "threshold" && (
          <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="block text-[10px] font-medium mb-1" style={{ color: "var(--muted-fg)" }}>
                Threshold Count
              </label>
              <input
                type="number"
                min={1}
                value={thresholdCount}
                onChange={(e) => setThresholdCount(parseInt(e.target.value) || 0)}
                className="w-full rounded-md border px-3 py-1.5 text-xs font-mono outline-none transition-colors focus:border-[var(--primary)]"
                style={{
                  background: "var(--surface-1)",
                  borderColor: "var(--border)",
                  color: "var(--fg)",
                }}
              />
            </div>
            <div>
              <label className="block text-[10px] font-medium mb-1" style={{ color: "var(--muted-fg)" }}>
                Window (seconds)
              </label>
              <input
                type="number"
                min={1}
                value={thresholdWindow}
                onChange={(e) => setThresholdWindow(parseInt(e.target.value) || 0)}
                className="w-full rounded-md border px-3 py-1.5 text-xs font-mono outline-none transition-colors focus:border-[var(--primary)]"
                style={{
                  background: "var(--surface-1)",
                  borderColor: "var(--border)",
                  color: "var(--fg)",
                }}
              />
            </div>
            <div>
              <label className="block text-[10px] font-medium mb-1" style={{ color: "var(--muted-fg)" }}>
                Group By
              </label>
              <input
                type="text"
                value={groupBy}
                onChange={(e) => setGroupBy(e.target.value)}
                placeholder="agent_id, dst_ip, process.pid"
                className="w-full rounded-md border px-3 py-1.5 text-xs font-mono outline-none transition-colors focus:border-[var(--primary)]"
                style={{
                  background: "var(--surface-1)",
                  borderColor: "var(--border)",
                  color: "var(--fg)",
                }}
              />
            </div>
          </div>
        )}
        {ruleType === "sequence" && (
          <div className="mt-3 space-y-4">
            {/* Sequence window + group-by */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-[10px] font-medium mb-1" style={{ color: "var(--muted-fg)" }}>
                  Sequence Window (seconds)
                </label>
                <input
                  type="number"
                  min={1}
                  value={seqWindow}
                  onChange={(e) => setSeqWindow(parseInt(e.target.value) || 0)}
                  className="w-full rounded-md border px-3 py-1.5 text-xs font-mono outline-none transition-colors focus:border-[var(--primary)]"
                  style={{
                    background: "var(--surface-1)",
                    borderColor: "var(--border)",
                    color: "var(--fg)",
                  }}
                />
              </div>
              <div>
                <label className="block text-[10px] font-medium mb-1" style={{ color: "var(--muted-fg)" }}>
                  Group By
                </label>
                <select
                  value={seqBy}
                  onChange={(e) => setSeqBy(e.target.value)}
                  className="w-full rounded-md border px-3 py-1.5 text-xs font-mono outline-none transition-colors focus:border-[var(--primary)]"
                  style={{
                    background: "var(--surface-1)",
                    borderColor: "var(--border)",
                    color: "var(--fg)",
                  }}
                >
                  <option value="chain_id">chain_id</option>
                  <option value="agent_id">agent_id</option>
                  <option value="user_uid">user_uid</option>
                </select>
              </div>
            </div>

            {/* Sequence steps */}
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--muted)" }}>
                Steps (in order)
              </div>
              <div className="space-y-2">
                {seqSteps.map((step, si) => (
                  <div
                    key={si}
                    className="rounded-md border p-3 space-y-2"
                    style={{ background: "var(--surface-1)", borderColor: "var(--border)" }}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-semibold" style={{ color: "var(--muted)" }}>
                        Step {si + 1}
                      </span>
                      <button
                        onClick={() =>
                          setSeqSteps((prev) => prev.filter((_, i) => i !== si))
                        }
                        disabled={seqSteps.length <= 2}
                        className="rounded p-0.5 text-red-400/60 hover:text-red-400 hover:bg-red-500/15 disabled:opacity-30 disabled:hover:bg-transparent transition-colors"
                        title="Remove step"
                      >
                        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                      </button>
                    </div>
                    <input
                      type="text"
                      value={step.event_type}
                      onChange={(e) =>
                        setSeqSteps((prev) =>
                          prev.map((s, i) =>
                            i === si ? { ...s, event_type: e.target.value } : s
                          )
                        )
                      }
                      placeholder="Event type, e.g. PROCESS_EXEC"
                      className="w-full rounded-md border px-3 py-1.5 text-xs font-mono outline-none transition-colors focus:border-[var(--primary)]"
                      style={{
                        background: "var(--surface-2)",
                        borderColor: "var(--border)",
                        color: "var(--fg)",
                      }}
                    />
                    <textarea
                      value={
                        step.conditions.length > 0
                          ? JSON.stringify(step.conditions, null, 2)
                          : ""
                      }
                      onChange={(e) => {
                        try {
                          const parsed = e.target.value.trim()
                            ? JSON.parse(e.target.value)
                            : [];
                          setSeqSteps((prev) =>
                            prev.map((s, i) =>
                              i === si ? { ...s, conditions: parsed } : s
                            )
                          );
                        } catch {
                          // ignore parse errors while user is typing
                        }
                      }}
                      rows={3}
                      placeholder={`Conditions JSON (optional):\n[{"field":"process.comm","op":"eq","value":"bash"}]`}
                      className="w-full rounded-md border px-3 py-1.5 text-xs font-mono outline-none transition-colors focus:border-[var(--primary)] resize-y"
                      style={{
                        background: "var(--surface-2)",
                        borderColor: "var(--border)",
                        color: "var(--fg)",
                      }}
                    />
                  </div>
                ))}
              </div>
              <button
                onClick={() =>
                  setSeqSteps((prev) => [...prev, { event_type: "", conditions: [] }])
                }
                className="mt-2 rounded-md border px-3 py-1 text-[10px] font-medium transition-colors hover:bg-[var(--surface-2)]"
                style={{
                  borderColor: "var(--border)",
                  color: "var(--primary)",
                  background: "var(--surface-1)",
                }}
              >
                + Add Step
              </button>
            </div>
          </div>
        )}
      </div>

      {/* 5. MITRE ATT&CK IDs */}
      <div>
        <div className={sectionTitle} style={{ color: "var(--muted)", fontFamily: "var(--font-space-grotesk)" }}>
          MITRE ATT&CK IDs
        </div>
        <input
          type="text"
          value={mitreInput}
          onChange={(e) => setMitreInput(e.target.value)}
          placeholder="T1059.004, T1055, T1071.001"
          className="w-full max-w-md rounded-md border px-3 py-1.5 text-xs font-mono outline-none transition-colors focus:border-[var(--primary)]"
          style={{
            background: "var(--surface-1)",
            borderColor: "var(--border)",
            color: "var(--fg)",
          }}
        />
      </div>

      {/* 6. Actions */}
      <div className="flex items-center gap-3 pt-2 border-t" style={{ borderColor: "var(--border)" }}>
        <button
          onClick={handleSubmit}
          disabled={submitting}
          className="rounded-md px-5 py-2 text-xs font-semibold text-white transition-colors disabled:opacity-50 flex items-center gap-2"
          style={{ background: "var(--primary)" }}
        >
          {submitting && (
            <svg className="animate-spin h-3.5 w-3.5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
            </svg>
          )}
          {submitting ? "Creating..." : "Create Rule"}
        </button>
        <button
          onClick={onCancel}
          className="rounded-md border px-4 py-2 text-xs font-medium transition-colors hover:bg-[var(--surface-2)]"
          style={{
            borderColor: "var(--border)",
            color: "var(--muted)",
            background: "var(--surface-0)",
          }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

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

      {/* Sequence settings */}
      {rule.rule_type === "sequence" && (
        <div>
          <div
            className="text-[10px] font-semibold uppercase tracking-wider mb-2"
            style={{ color: "var(--muted)" }}
          >
            Sequence Steps
          </div>
          <div className="space-y-1 mb-2" style={{ color: "var(--fg)" }}>
            <div>
              Window:{" "}
              <span className="font-mono">{rule.sequence_window_s ?? 0}s</span>
            </div>
            {rule.sequence_by && (
              <div>
                Group By: <span className="font-mono">{rule.sequence_by}</span>
              </div>
            )}
          </div>
          {rule.sequence_steps && rule.sequence_steps.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              {rule.sequence_steps.map((step, idx) => (
                <div key={idx} className="flex items-center gap-1.5">
                  <span
                    className="rounded px-2 py-0.5 text-[10px] font-mono font-semibold"
                    style={{ background: "var(--surface-2)", color: "var(--primary)" }}
                  >
                    {idx + 1}. {step.event_type || "ANY"}
                    {step.conditions && step.conditions.length > 0 && (
                      <span className="opacity-60">
                        {" "}({step.conditions.map((c) => `${c.field} ${c.op} ${c.value}`).join(", ")})
                      </span>
                    )}
                  </span>
                  {idx < (rule.sequence_steps?.length ?? 0) - 1 && (
                    <span style={{ color: "var(--muted)" }}>→</span>
                  )}
                </div>
              ))}
            </div>
          )}
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
  const [showBuilder, setShowBuilder] = useState(false);
  const [search, setSearch] = useState("");

  const fetchRules = useCallback(
    (signal: AbortSignal) =>
      api
        .get<{ rules?: Rule[] } | Rule[]>("/api/v1/rules", undefined, signal)
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

  const displayRules = (rules ?? []).filter((r) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return r.name?.toLowerCase().includes(q) || r.description?.toLowerCase().includes(q) || r.event_types?.some((t: string) => t.toLowerCase().includes(q));
  });

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
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowBuilder(true)}
            disabled={showBuilder}
            className="rounded-md px-4 py-2 text-xs font-semibold text-white transition-colors disabled:opacity-50"
            style={{ background: "var(--primary)" }}
          >
            + Create Rule
          </button>
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
      </div>

      {/* Search */}
      <input
        type="text"
        placeholder="Search rules by name, description, or event type..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="rounded-md border px-3 py-1.5 text-xs w-full max-w-md outline-none focus-ring"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
      />

      {/* Rule Builder */}
      {showBuilder && (
        <RuleBuilder
          onCreated={() => {
            setShowBuilder(false);
            refetch();
          }}
          onCancel={() => setShowBuilder(false)}
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
                      : rule.rule_type === "sequence"
                      ? "bg-fuchsia-500/15 text-fuchsia-400"
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
