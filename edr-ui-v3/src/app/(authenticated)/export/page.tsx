"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { Plus, Pencil, Trash2, CheckCircle2, XCircle } from "lucide-react";

interface ExportDestination {
  id?: string;
  name: string;
  dest_type: string;
  config: Record<string, unknown>;
  enabled: boolean;
  filter_sev: number;
  filter_types: string[];
  created_at?: string;
  updated_at?: string;
}

const DEST_TYPES = ["slack", "pagerduty", "webhook", "syslog_cef", "email"];

const SEV_OPTIONS = [
  { value: 0, label: "All severities" },
  { value: 1, label: "Low (1+)" },
  { value: 2, label: "Medium (2+)" },
  { value: 3, label: "High (3+)" },
  { value: 4, label: "Critical only" },
];

const SOURCE_TYPE_OPTIONS = ["endpoint", "okta", "cloudtrail", "azure", "gcp", "network"];

function defaultConfig(type: string): Record<string, unknown> {
  switch (type) {
    case "slack": return { webhook_url: "", channel: "", username: "TraceGuard" };
    case "pagerduty": return { integration_key: "", severity: "error" };
    case "webhook": return { url: "", headers: {} };
    case "syslog_cef": return { host: "", port: 514, protocol: "udp", facility: 16 };
    case "email": return { smtp_host: "", smtp_port: 587, from: "", to: [], tls: false, username: "", password: "" };
    default: return {};
  }
}

const DEST_TYPE_LABELS: Record<string, string> = {
  slack: "Slack",
  pagerduty: "PagerDuty",
  webhook: "Webhook",
  syslog_cef: "Syslog / CEF",
  email: "Email (SMTP)",
};

function DestTypeBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    slack: "bg-purple-500/15 text-purple-400",
    pagerduty: "bg-green-500/15 text-green-400",
    webhook: "bg-blue-500/15 text-blue-400",
    syslog_cef: "bg-amber-500/15 text-amber-400",
    email: "bg-neutral-700 text-neutral-300",
  };
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${colors[type] ?? "bg-neutral-800 text-neutral-400"}`}>
      {DEST_TYPE_LABELS[type] ?? type}
    </span>
  );
}

function ConfigFields({
  config,
  onChange,
}: {
  config: Record<string, unknown>;
  onChange: (c: Record<string, unknown>) => void;
}) {
  function set(k: string, v: unknown) {
    onChange({ ...config, [k]: v });
  }

  return (
    <div className="space-y-2">
      {Object.entries(config).map(([k, v]) => (
        <div key={k}>
          <label className="text-xs text-neutral-400 mb-1 block">{k}</label>
          {Array.isArray(v) ? (
            <input
              type="text"
              value={(v as string[]).join(", ")}
              onChange={(e) => set(k, e.target.value.split(",").map((s) => s.trim()).filter(Boolean))}
              placeholder="comma-separated"
              className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm"
            />
          ) : typeof v === "boolean" ? (
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={v} onChange={(e) => set(k, e.target.checked)} className="rounded" />
              <span className="text-sm text-neutral-300">{k}</span>
            </label>
          ) : typeof v === "number" ? (
            <input
              type="number"
              value={v}
              onChange={(e) => set(k, Number(e.target.value))}
              className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm"
            />
          ) : (
            <input
              type={k === "password" ? "password" : "text"}
              value={String(v)}
              onChange={(e) => set(k, e.target.value)}
              className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm"
            />
          )}
        </div>
      ))}
    </div>
  );
}

function DestModal({
  initial,
  onSave,
  onClose,
}: {
  initial?: ExportDestination;
  onSave: (d: ExportDestination) => Promise<void>;
  onClose: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [destType, setDestType] = useState(initial?.dest_type ?? "slack");
  const [config, setConfig] = useState<Record<string, unknown>>(
    initial?.config ?? defaultConfig("slack")
  );
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [filterSev, setFilterSev] = useState(initial?.filter_sev ?? 0);
  const [filterTypes, setFilterTypes] = useState<string[]>(initial?.filter_types ?? []);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  function handleTypeChange(t: string) {
    setDestType(t);
    setConfig(defaultConfig(t));
  }

  async function handleSave() {
    if (!name.trim()) { setError("Name is required"); return; }
    setSaving(true); setError("");
    try {
      await onSave({ ...initial, name: name.trim(), dest_type: destType, config, enabled, filter_sev: filterSev, filter_types: filterTypes });
      onClose();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  function toggleType(t: string) {
    setFilterTypes((prev) => prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t]);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-neutral-900 border border-neutral-700 rounded-xl w-full max-w-lg max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between px-5 py-4 border-b border-neutral-800">
          <h2 className="font-semibold text-sm">{initial?.id ? "Edit Destination" : "New Export Destination"}</h2>
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
              <label className="text-xs text-neutral-400 mb-1 block">Type</label>
              <select value={destType} onChange={(e) => handleTypeChange(e.target.value)}
                className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm">
                {DEST_TYPES.map((t) => <option key={t} value={t}>{DEST_TYPE_LABELS[t]}</option>)}
              </select>
            </div>
          </div>

          <ConfigFields config={config} onChange={setConfig} />

          <div>
            <label className="text-xs text-neutral-400 mb-1 block">Minimum severity filter</label>
            <select value={filterSev} onChange={(e) => setFilterSev(Number(e.target.value))}
              className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm">
              {SEV_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>

          <div>
            <label className="text-xs text-neutral-400 mb-2 block">Source type filter <span className="text-neutral-600">(empty = all)</span></label>
            <div className="flex flex-wrap gap-2">
              {SOURCE_TYPE_OPTIONS.map((t) => (
                <button
                  key={t}
                  onClick={() => toggleType(t)}
                  className={`px-2 py-1 rounded text-xs font-mono border transition-colors ${
                    filterTypes.includes(t)
                      ? "bg-cyan-600 border-cyan-500 text-white"
                      : "bg-neutral-800 border-neutral-700 text-neutral-400 hover:border-neutral-600"
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>

          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} className="rounded" />
            <span className="text-sm text-neutral-300">Enabled</span>
          </label>
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

export default function ExportPage() {
  const { data, loading, error, refetch } = useApi<{ destinations: ExportDestination[] }>(
    () => api.get<{ destinations: ExportDestination[] }>("/api/v1/export")
  );
  const [modal, setModal] = useState<{ open: boolean; dest?: ExportDestination }>({ open: false });

  const destinations = data?.destinations ?? [];

  async function handleCreate(d: ExportDestination) {
    await api.post("/api/v1/export", d);
    refetch();
  }

  async function handleUpdate(id: string, d: ExportDestination) {
    await api.put(`/api/v1/export/${id}`, d);
    refetch();
  }

  async function handleDelete(id: string) {
    if (!confirm("Delete this export destination?")) return;
    await api.del(`/api/v1/export/${id}`);
    refetch();
  }

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Export / SIEM Integration</h1>
          <p className="text-xs text-neutral-400 mt-0.5">Forward alerts and XDR events to external platforms</p>
        </div>
        <button
          onClick={() => setModal({ open: true })}
          className="flex items-center gap-2 px-3 py-1.5 text-sm rounded bg-cyan-600 hover:bg-cyan-500 font-medium"
        >
          <Plus size={15} /> Add Destination
        </button>
      </div>

      {loading && <p className="text-sm text-neutral-400">Loading…</p>}
      {error && <p className="text-sm text-red-400">{error}</p>}

      {!loading && destinations.length === 0 && (
        <div className="text-center py-16 text-neutral-500">
          <p className="text-sm">No export destinations configured.</p>
          <p className="text-xs mt-1">Add Slack, PagerDuty, Syslog/CEF, webhook, or email destinations.</p>
        </div>
      )}

      <div className="space-y-3">
        {destinations.map((d) => (
          <div key={d.id} className="bg-neutral-900 border border-neutral-800 rounded-xl p-4">
            <div className="flex items-start gap-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-medium text-sm">{d.name}</span>
                  <DestTypeBadge type={d.dest_type} />
                  {d.enabled ? (
                    <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                      <CheckCircle2 size={10} /> Active
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-xs text-neutral-500">
                      <XCircle size={10} /> Disabled
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-3 mt-1.5 text-xs text-neutral-500">
                  {d.filter_sev > 0 && <span>sev≥{d.filter_sev}</span>}
                  {d.filter_types && d.filter_types.length > 0 && (
                    <span>types: {d.filter_types.join(", ")}</span>
                  )}
                  {(!d.filter_sev || d.filter_sev === 0) && (!d.filter_types || d.filter_types.length === 0) && (
                    <span>all events</span>
                  )}
                </div>
                <div className="mt-2 text-xs text-neutral-600 font-mono truncate">
                  {d.dest_type === "syslog_cef" && d.config
                    ? `${(d.config as Record<string,unknown>).host}:${(d.config as Record<string,unknown>).port} (${(d.config as Record<string,unknown>).protocol})`
                    : d.dest_type === "email" && d.config
                    ? `→ ${(d.config as Record<string, unknown[]>).to?.join(", ")}`
                    : d.dest_type === "slack" && d.config
                    ? (d.config as Record<string, unknown>).channel as string
                    : d.dest_type === "webhook" && d.config
                    ? (d.config as Record<string, unknown>).url as string
                    : ""}
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => setModal({ open: true, dest: d })}
                  className="p-1.5 rounded hover:bg-neutral-800 text-neutral-400 hover:text-white"
                >
                  <Pencil size={14} />
                </button>
                <button
                  onClick={() => handleDelete(d.id!)}
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
        <DestModal
          initial={modal.dest}
          onSave={modal.dest?.id
            ? (d) => handleUpdate(modal.dest!.id!, d)
            : handleCreate}
          onClose={() => setModal({ open: false })}
        />
      )}
    </div>
  );
}
