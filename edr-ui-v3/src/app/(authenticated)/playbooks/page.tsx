"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { timeAgo } from "@/lib/utils";
import { Plus, Play, Pencil, Trash2, ChevronDown, ChevronRight, CheckCircle2, XCircle } from "lucide-react";
import Link from "next/link";

interface PlaybookAction {
  type: string;
  config: Record<string, unknown>;
}

interface Playbook {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  trigger_type: string;
  trigger_filter: {
    min_severity?: number;
    rule_ids?: string[];
    event_types?: string[];
    source_types?: string[];
  };
  actions: PlaybookAction[];
  run_count: number;
  last_run_at?: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

const ACTION_TYPES = ["slack", "pagerduty", "webhook", "email", "isolate_host", "block_ip", "update_alert"];

const TRIGGER_TYPES = [
  { value: "alert", label: "Alert" },
  { value: "xdr_event", label: "XDR Event" },
];

const SEV_OPTIONS = [
  { value: 0, label: "Any" },
  { value: 1, label: "Low (1+)" },
  { value: 2, label: "Medium (2+)" },
  { value: 3, label: "High (3+)" },
  { value: 4, label: "Critical only" },
];

function defaultConfig(type: string): Record<string, unknown> {
  switch (type) {
    case "slack": return { webhook_url: "", channel: "", username: "TraceGuard" };
    case "pagerduty": return { integration_key: "", severity: "error" };
    case "webhook": return { url: "", headers: {} };
    case "email": return { smtp_host: "", smtp_port: 587, from: "", to: [], tls: false };
    case "isolate_host": return { agent_id: "" };
    case "block_ip": return { ip: "", agent_id: "" };
    case "update_alert": return { status: "IN_PROGRESS", assignee: "" };
    default: return {};
  }
}

function StatusBadge({ enabled }: { enabled: boolean }) {
  return enabled ? (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-emerald-500/15 text-emerald-400">
      <CheckCircle2 size={10} /> Enabled
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-neutral-700 text-neutral-400">
      <XCircle size={10} /> Disabled
    </span>
  );
}

function ActionEditor({
  action,
  onChange,
  onRemove,
}: {
  action: PlaybookAction;
  onChange: (a: PlaybookAction) => void;
  onRemove: () => void;
}) {
  const [open, setOpen] = useState(true);

  function setType(type: string) {
    onChange({ type, config: defaultConfig(type) });
  }

  function setConfigKey(k: string, v: unknown) {
    onChange({ ...action, config: { ...action.config, [k]: v } });
  }

  return (
    <div className="border border-neutral-700 rounded-lg overflow-hidden">
      <div
        className="flex items-center gap-2 px-3 py-2 bg-neutral-800 cursor-pointer select-none"
        onClick={() => setOpen((o) => !o)}
      >
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        <span className="font-mono text-xs text-cyan-400">{action.type || "pick type"}</span>
        <span className="ml-auto text-neutral-500 hover:text-red-400" onClick={(e) => { e.stopPropagation(); onRemove(); }}>
          <Trash2 size={13} />
        </span>
      </div>
      {open && (
        <div className="p-3 space-y-2 bg-neutral-900">
          <div>
            <label className="text-xs text-neutral-400 mb-1 block">Action type</label>
            <select
              value={action.type}
              onChange={(e) => setType(e.target.value)}
              className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm"
            >
              <option value="">-- select --</option>
              {ACTION_TYPES.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          {Object.entries(action.config).map(([k, v]) => (
            <div key={k}>
              <label className="text-xs text-neutral-400 mb-1 block">{k}</label>
              {Array.isArray(v) ? (
                <input
                  type="text"
                  value={(v as string[]).join(", ")}
                  onChange={(e) => setConfigKey(k, e.target.value.split(",").map((s) => s.trim()).filter(Boolean))}
                  placeholder="comma-separated"
                  className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm"
                />
              ) : typeof v === "boolean" ? (
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={v}
                    onChange={(e) => setConfigKey(k, e.target.checked)}
                    className="rounded"
                  />
                  <span className="text-sm text-neutral-300">{k}</span>
                </label>
              ) : typeof v === "number" ? (
                <input
                  type="number"
                  value={v}
                  onChange={(e) => setConfigKey(k, Number(e.target.value))}
                  className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm"
                />
              ) : (
                <input
                  type="text"
                  value={String(v)}
                  onChange={(e) => setConfigKey(k, e.target.value)}
                  className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm"
                />
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function PlaybookModal({
  initial,
  onSave,
  onClose,
}: {
  initial?: Partial<Playbook>;
  onSave: (data: Partial<Playbook>) => Promise<void>;
  onClose: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [triggerType, setTriggerType] = useState(initial?.trigger_type ?? "alert");
  const [minSev, setMinSev] = useState(initial?.trigger_filter?.min_severity ?? 0);
  const [actions, setActions] = useState<PlaybookAction[]>(
    initial?.actions ?? [{ type: "slack", config: defaultConfig("slack") }]
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function handleSave() {
    if (!name.trim()) { setError("Name is required"); return; }
    setSaving(true);
    setError("");
    try {
      await onSave({
        name: name.trim(),
        description,
        enabled,
        trigger_type: triggerType,
        trigger_filter: minSev > 0 ? { min_severity: minSev } : {},
        actions,
      });
      onClose();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-neutral-900 border border-neutral-700 rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between px-5 py-4 border-b border-neutral-800">
          <h2 className="font-semibold text-sm">{initial?.id ? "Edit Playbook" : "New Playbook"}</h2>
          <button onClick={onClose} className="text-neutral-400 hover:text-white text-lg leading-none">&times;</button>
        </div>
        <div className="overflow-y-auto flex-1 p-5 space-y-4">
          {error && <p className="text-xs text-red-400 bg-red-500/10 px-3 py-2 rounded">{error}</p>}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-neutral-400 mb-1 block">Name *</label>
              <input value={name} onChange={(e) => setName(e.target.value)}
                className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm" />
            </div>
            <div>
              <label className="text-xs text-neutral-400 mb-1 block">Trigger type</label>
              <select value={triggerType} onChange={(e) => setTriggerType(e.target.value)}
                className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm">
                {TRIGGER_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
            </div>
          </div>

          <div>
            <label className="text-xs text-neutral-400 mb-1 block">Description</label>
            <input value={description} onChange={(e) => setDescription(e.target.value)}
              className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm" />
          </div>

          {triggerType === "alert" && (
            <div>
              <label className="text-xs text-neutral-400 mb-1 block">Minimum severity</label>
              <select value={minSev} onChange={(e) => setMinSev(Number(e.target.value))}
                className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm">
                {SEV_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
          )}

          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} className="rounded" />
            <span className="text-sm text-neutral-300">Enabled</span>
          </label>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-neutral-400 uppercase tracking-wider">Actions</span>
              <button
                onClick={() => setActions([...actions, { type: "slack", config: defaultConfig("slack") }])}
                className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
              >
                <Plus size={12} /> Add action
              </button>
            </div>
            {actions.map((a, i) => (
              <ActionEditor
                key={i}
                action={a}
                onChange={(updated) => setActions(actions.map((x, j) => j === i ? updated : x))}
                onRemove={() => setActions(actions.filter((_, j) => j !== i))}
              />
            ))}
            {actions.length === 0 && (
              <p className="text-xs text-neutral-500 text-center py-4">No actions — add at least one.</p>
            )}
          </div>
        </div>
        <div className="flex justify-end gap-2 px-5 py-3 border-t border-neutral-800">
          <button onClick={onClose} className="px-3 py-1.5 text-sm rounded border border-neutral-700 hover:bg-neutral-800">Cancel</button>
          <button onClick={handleSave} disabled={saving}
            className="px-4 py-1.5 text-sm rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 font-medium">
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function PlaybooksPage() {
  const { data, loading, error, refetch } = useApi<{ playbooks: Playbook[] }>(
    () => api.get<{ playbooks: Playbook[] }>("/api/v1/playbooks")
  );
  const [modal, setModal] = useState<{ open: boolean; pb?: Playbook }>({ open: false });
  const [testing, setTesting] = useState<string | null>(null);
  const [testMsg, setTestMsg] = useState("");

  const playbooks = data?.playbooks ?? [];

  async function handleCreate(payload: Partial<Playbook>) {
    await api.post("/api/v1/playbooks", payload);
    refetch();
  }

  async function handleUpdate(id: string, payload: Partial<Playbook>) {
    await api.put(`/api/v1/playbooks/${id}`, payload);
    refetch();
  }

  async function handleDelete(id: string) {
    if (!confirm("Delete this playbook?")) return;
    await api.del(`/api/v1/playbooks/${id}`);
    refetch();
  }

  async function handleTest(id: string, name: string) {
    setTesting(id);
    setTestMsg("");
    try {
      await api.post(`/api/v1/playbooks/${id}/test`, {});
      setTestMsg(`Test triggered for "${name}"`);
    } catch (e: unknown) {
      setTestMsg(e instanceof Error ? e.message : "Test failed");
    } finally {
      setTesting(null);
      setTimeout(() => setTestMsg(""), 4000);
    }
  }

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Playbooks</h1>
          <p className="text-xs text-neutral-400 mt-0.5">Automated response chains triggered by alerts or XDR events</p>
        </div>
        <div className="flex items-center gap-3">
          <Link href="/playbooks/runs"
            className="px-3 py-1.5 text-sm rounded border border-neutral-700 hover:bg-neutral-800">
            Run history
          </Link>
          <button
            onClick={() => setModal({ open: true })}
            className="flex items-center gap-2 px-3 py-1.5 text-sm rounded bg-cyan-600 hover:bg-cyan-500 font-medium"
          >
            <Plus size={15} /> New Playbook
          </button>
        </div>
      </div>

      {testMsg && (
        <div className="text-xs px-3 py-2 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300">{testMsg}</div>
      )}

      {loading && <p className="text-sm text-neutral-400">Loading…</p>}
      {error && <p className="text-sm text-red-400">{error}</p>}

      {!loading && playbooks.length === 0 && (
        <div className="text-center py-16 text-neutral-500">
          <p className="text-sm">No playbooks yet.</p>
          <button onClick={() => setModal({ open: true })}
            className="mt-3 text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 mx-auto">
            <Plus size={12} /> Create your first playbook
          </button>
        </div>
      )}

      <div className="space-y-2">
        {playbooks.map((pb) => (
          <div key={pb.id} className="bg-neutral-900 border border-neutral-800 rounded-xl p-4">
            <div className="flex items-start gap-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-medium text-sm">{pb.name}</span>
                  <StatusBadge enabled={pb.enabled} />
                  <span className="text-xs px-1.5 py-0.5 rounded bg-neutral-800 text-neutral-400 font-mono">
                    {pb.trigger_type}
                  </span>
                  {pb.trigger_filter?.min_severity != null && pb.trigger_filter.min_severity > 0 && (
                    <span className="text-xs text-amber-400">sev≥{pb.trigger_filter.min_severity}</span>
                  )}
                </div>
                {pb.description && (
                  <p className="text-xs text-neutral-400 mt-1">{pb.description}</p>
                )}
                <div className="flex items-center gap-4 mt-2 text-xs text-neutral-500">
                  <span>{pb.actions?.length ?? 0} action{(pb.actions?.length ?? 0) !== 1 ? "s" : ""}</span>
                  <span>{pb.run_count} run{pb.run_count !== 1 ? "s" : ""}</span>
                  {pb.last_run_at && <span>last {timeAgo(pb.last_run_at)}</span>}
                  <span>by {pb.created_by ?? "system"}</span>
                </div>
                {pb.actions && pb.actions.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {pb.actions.map((a, i) => (
                      <span key={i} className="text-xs font-mono px-1.5 py-0.5 rounded bg-neutral-800 text-cyan-400">
                        {a.type}
                      </span>
                    ))}
                  </div>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => handleTest(pb.id, pb.name)}
                  disabled={testing === pb.id}
                  title="Test fire with dummy alert"
                  className="p-1.5 rounded hover:bg-neutral-800 text-neutral-400 hover:text-cyan-400 disabled:opacity-40"
                >
                  <Play size={14} />
                </button>
                <button
                  onClick={() => setModal({ open: true, pb })}
                  className="p-1.5 rounded hover:bg-neutral-800 text-neutral-400 hover:text-white"
                >
                  <Pencil size={14} />
                </button>
                <button
                  onClick={() => handleDelete(pb.id)}
                  className="p-1.5 rounded hover:bg-neutral-800 text-neutral-400 hover:text-red-400"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {modal.open && (
        <PlaybookModal
          initial={modal.pb}
          onSave={modal.pb ? (p) => handleUpdate(modal.pb!.id, p) : handleCreate}
          onClose={() => setModal({ open: false })}
        />
      )}
    </div>
  );
}
