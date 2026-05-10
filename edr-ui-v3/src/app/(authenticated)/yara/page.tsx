"use client";

import { useCallback, useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn, severityLabel, severityBgClass, timeAgo } from "@/lib/utils";
import type { YARARule } from "@/types";

const SEVERITY_OPTIONS = [
  { label: "Info", value: 0 },
  { label: "Low", value: 1 },
  { label: "Medium", value: 2 },
  { label: "High", value: 3 },
  { label: "Critical", value: 4 },
] as const;

const RULE_TEMPLATE = `rule ExampleRule {
  meta:
    description = "Detects suspicious pattern"
    author = "analyst"
    severity = "high"
  strings:
    $s1 = "suspicious_string" ascii nocase
    $hex1 = { 4D 5A 90 00 }
  condition:
    any of them
}`;

/* ── Editor modal ─────────────────────────────────────────────────────────── */
function RuleEditor({
  rule,
  onSaved,
  onCancel,
}: {
  rule: YARARule | null;
  onSaved: () => void;
  onCancel: () => void;
}) {
  const isNew = rule === null;
  const [name, setName] = useState(rule?.name ?? "");
  const [description, setDescription] = useState(rule?.description ?? "");
  const [author, setAuthor] = useState(rule?.author ?? "analyst");
  const [severity, setSeverity] = useState<number>(rule?.severity ?? 2);
  const [enabled, setEnabled] = useState(rule?.enabled ?? true);
  const [mitreInput, setMitreInput] = useState(
    (rule?.mitre_ids ?? []).join(", ")
  );
  const [tagsInput, setTagsInput] = useState((rule?.tags ?? []).join(", "));
  const [ruleText, setRuleText] = useState(rule?.rule_text ?? RULE_TEMPLATE);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit() {
    if (!name.trim()) { setError("Name is required"); return; }
    if (!ruleText.trim()) { setError("Rule text is required"); return; }
    setSubmitting(true);
    setError("");
    try {
      const payload = {
        name: name.trim(),
        description: description.trim(),
        author: author.trim(),
        severity,
        enabled,
        mitre_ids: mitreInput.split(",").map((s) => s.trim()).filter(Boolean),
        tags: tagsInput.split(",").map((s) => s.trim()).filter(Boolean),
        rule_text: ruleText,
      };
      if (isNew) {
        await api.post("/api/v1/yara/rules", payload);
      } else {
        await api.put(`/api/v1/yara/rules/${rule!.id}`, payload);
      }
      onSaved();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-neutral-900 border border-neutral-700 rounded-lg w-full max-w-3xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-neutral-700">
          <h2 className="font-semibold text-sm">
            {isNew ? "New YARA Rule" : `Edit: ${rule!.name}`}
          </h2>
          <button onClick={onCancel} className="text-neutral-400 hover:text-white text-lg leading-none">&times;</button>
        </div>
        <div className="p-4 space-y-4">
          {error && (
            <div className="bg-red-900/40 border border-red-700 text-red-300 text-xs p-2 rounded">
              {error}
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-neutral-400 mb-1">Name *</label>
              <input
                className="w-full bg-neutral-800 border border-neutral-600 rounded px-2 py-1.5 text-sm"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="DetectMimikatz"
              />
            </div>
            <div>
              <label className="block text-xs text-neutral-400 mb-1">Author</label>
              <input
                className="w-full bg-neutral-800 border border-neutral-600 rounded px-2 py-1.5 text-sm"
                value={author}
                onChange={(e) => setAuthor(e.target.value)}
              />
            </div>
          </div>

          <div>
            <label className="block text-xs text-neutral-400 mb-1">Description</label>
            <input
              className="w-full bg-neutral-800 border border-neutral-600 rounded px-2 py-1.5 text-sm"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-xs text-neutral-400 mb-1">Severity</label>
              <select
                className="w-full bg-neutral-800 border border-neutral-600 rounded px-2 py-1.5 text-sm"
                value={severity}
                onChange={(e) => setSeverity(Number(e.target.value))}
              >
                {SEVERITY_OPTIONS.map((s) => (
                  <option key={s.value} value={s.value}>{s.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-neutral-400 mb-1">MITRE IDs (comma-sep)</label>
              <input
                className="w-full bg-neutral-800 border border-neutral-600 rounded px-2 py-1.5 text-sm"
                value={mitreInput}
                onChange={(e) => setMitreInput(e.target.value)}
                placeholder="T1055, T1059"
              />
            </div>
            <div>
              <label className="block text-xs text-neutral-400 mb-1">Tags (comma-sep)</label>
              <input
                className="w-full bg-neutral-800 border border-neutral-600 rounded px-2 py-1.5 text-sm"
                value={tagsInput}
                onChange={(e) => setTagsInput(e.target.value)}
                placeholder="malware, credential"
              />
            </div>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="enabled"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="rounded"
            />
            <label htmlFor="enabled" className="text-sm">Enabled</label>
          </div>

          <div>
            <label className="block text-xs text-neutral-400 mb-1">Rule Text *</label>
            <textarea
              className="w-full bg-neutral-950 border border-neutral-600 rounded px-3 py-2 text-xs font-mono h-64 resize-y"
              value={ruleText}
              onChange={(e) => setRuleText(e.target.value)}
              spellCheck={false}
            />
          </div>
        </div>

        <div className="flex justify-end gap-2 p-4 border-t border-neutral-700">
          <button
            onClick={onCancel}
            className="px-3 py-1.5 text-sm text-neutral-400 hover:text-white border border-neutral-600 rounded"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={submitting}
            className="px-3 py-1.5 text-sm bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded font-medium"
          >
            {submitting ? "Saving…" : isNew ? "Create Rule" : "Save Changes"}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ── Main page ────────────────────────────────────────────────────────────── */
export default function YARARulesPage() {
  const fetchRules = useCallback(
    () => api.get<{ rules: YARARule[] }>("/api/v1/yara/rules"),
    []
  );
  const { data, loading, error, refetch } = useApi(fetchRules);
  const [editing, setEditing] = useState<YARARule | null>(null);
  const [showEditor, setShowEditor] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);

  const rules = data?.rules ?? [];

  function openNew() {
    setEditing(null);
    setShowEditor(true);
  }

  function openEdit(rule: YARARule) {
    setEditing(rule);
    setShowEditor(true);
  }

  async function toggleEnabled(rule: YARARule) {
    try {
      await api.put(`/api/v1/yara/rules/${rule.id}`, {
        ...rule,
        enabled: !rule.enabled,
      });
      refetch();
    } catch {
      // silent
    }
  }

  async function handleDelete(id: string) {
    if (!confirm("Delete this YARA rule?")) return;
    setDeleting(id);
    try {
      await api.del(`/api/v1/yara/rules/${id}`);
      refetch();
    } finally {
      setDeleting(null);
    }
  }

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">YARA Rules</h1>
          <p className="text-xs text-neutral-400 mt-0.5">
            Rules are pushed to agents every 10 minutes and matched against written/created executables.
          </p>
        </div>
        <button
          onClick={openNew}
          className="px-3 py-1.5 text-sm bg-blue-600 hover:bg-blue-500 rounded font-medium"
        >
          + New Rule
        </button>
      </div>

      {loading && (
        <div className="text-neutral-400 text-sm">Loading…</div>
      )}

      {error && (
        <div className="bg-red-900/30 border border-red-700 text-red-300 text-sm p-3 rounded">
          {error}
        </div>
      )}

      {!loading && rules.length === 0 && !error && (
        <div className="text-neutral-500 text-sm">No YARA rules yet. Click &ldquo;+ New Rule&rdquo; to add one.</div>
      )}

      <div className="space-y-2">
        {rules.map((rule) => (
          <div
            key={rule.id}
            className={cn(
              "bg-neutral-900 border rounded-lg p-4",
              rule.enabled ? "border-neutral-700" : "border-neutral-800 opacity-60"
            )}
          >
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-sm font-medium">{rule.name}</span>
                  <span
                    className={cn(
                      "text-xs px-1.5 py-0.5 rounded font-medium",
                      severityBgClass(rule.severity)
                    )}
                  >
                    {severityLabel(rule.severity)}
                  </span>
                  {!rule.enabled && (
                    <span className="text-xs px-1.5 py-0.5 rounded bg-neutral-700 text-neutral-400">
                      disabled
                    </span>
                  )}
                  {rule.tags?.map((t) => (
                    <span key={t} className="text-xs px-1.5 py-0.5 rounded bg-neutral-800 text-neutral-400">
                      {t}
                    </span>
                  ))}
                </div>
                {rule.description && (
                  <p className="text-xs text-neutral-400 mt-1">{rule.description}</p>
                )}
                <div className="flex items-center gap-3 mt-2 text-xs text-neutral-500">
                  {rule.author && <span>by {rule.author}</span>}
                  {rule.mitre_ids?.length > 0 && (
                    <span>{rule.mitre_ids.join(", ")}</span>
                  )}
                  <span>updated {timeAgo(rule.updated_at)}</span>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => toggleEnabled(rule)}
                  className={cn(
                    "text-xs px-2 py-1 rounded border",
                    rule.enabled
                      ? "border-green-700 text-green-400 hover:bg-green-900/30"
                      : "border-neutral-600 text-neutral-400 hover:bg-neutral-800"
                  )}
                >
                  {rule.enabled ? "Enabled" : "Disabled"}
                </button>
                <button
                  onClick={() => openEdit(rule)}
                  className="text-xs px-2 py-1 rounded border border-neutral-600 text-neutral-300 hover:bg-neutral-800"
                >
                  Edit
                </button>
                <button
                  onClick={() => handleDelete(rule.id)}
                  disabled={deleting === rule.id}
                  className="text-xs px-2 py-1 rounded border border-red-800 text-red-400 hover:bg-red-900/30 disabled:opacity-50"
                >
                  {deleting === rule.id ? "…" : "Delete"}
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {showEditor && (
        <RuleEditor
          rule={editing}
          onSaved={() => {
            setShowEditor(false);
            refetch();
          }}
          onCancel={() => setShowEditor(false)}
        />
      )}
    </div>
  );
}
