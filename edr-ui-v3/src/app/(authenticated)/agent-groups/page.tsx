"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn } from "@/lib/utils";
import { Plus, Pencil, Trash2, Users, Tag, Sliders, Save, Loader2, ChevronDown } from "lucide-react";

interface AgentGroup {
  id: string;
  name: string;
  description: string;
  color: string;
  tag_filter: string[];
  env_filter: string;
  created_at: string;
  updated_at: string;
}

interface GroupMember {
  id: string;
  hostname: string;
  os: string;
  ip: string;
  is_online: boolean;
  tags: string[];
  env: string;
}

// ── Fleet config types & monitor definitions ──────────────────────────────
interface MonitorDef {
  key: string;
  label: string;
  os: "linux" | "windows" | "both";
  fields?: { key: string; label: string; type: "text" | "number" | "boolean"; placeholder?: string }[];
}

const MONITOR_DEFS: MonitorDef[] = [
  { key: "process",  label: "Process",           os: "both",    fields: [{ key: "max_ancestry_depth", label: "Max ancestry depth", type: "number" }] },
  { key: "network",  label: "Network",            os: "both",    fields: [{ key: "ignore_localhost", label: "Ignore localhost", type: "boolean" }] },
  { key: "file",     label: "File",               os: "both",    fields: [{ key: "watch_paths", label: "Watch paths (comma-sep)", type: "text", placeholder: "/etc,/tmp,/home" }, { key: "hash_on_write", label: "Hash on write", type: "boolean" }] },
  { key: "registry", label: "Registry",           os: "both",    fields: [{ key: "extra_paths", label: "Extra paths (comma-sep)", type: "text" }] },
  { key: "dns",      label: "DNS",                os: "windows" },
  { key: "auth",     label: "Auth / Login",       os: "both" },
  { key: "command",  label: "Command",            os: "windows" },
  { key: "browser",  label: "Browser",            os: "both",    fields: [{ key: "listen_addr", label: "Listen addr", type: "text", placeholder: "127.0.0.1:9999" }] },
  { key: "kmod",     label: "Kernel Modules",     os: "linux",   fields: [{ key: "poll_interval_s", label: "Poll interval (s)", type: "number" }] },
  { key: "driver",   label: "Driver Load",        os: "windows", fields: [{ key: "poll_interval_s", label: "Poll interval (s)", type: "number" }] },
  { key: "usb",      label: "USB",                os: "both",    fields: [{ key: "poll_interval_s", label: "Poll interval (s)", type: "number" }] },
  { key: "pipe",     label: "Named Pipes",        os: "both",    fields: [{ key: "poll_interval_s", label: "Poll interval (s)", type: "number" }] },
  { key: "share",    label: "Network Shares",     os: "both",    fields: [{ key: "poll_interval_s", label: "Poll interval (s)", type: "number" }] },
  { key: "memmon",   label: "Memory Injection",   os: "both",    fields: [{ key: "poll_interval_s", label: "Poll interval (s)", type: "number" }] },
  { key: "cronmon",  label: "Cron Monitor",       os: "linux",   fields: [{ key: "watch_paths", label: "Watch paths (comma-sep)", type: "text" }] },
  { key: "tlssni",   label: "TLS SNI",            os: "linux" },
  { key: "schtask",  label: "Scheduled Tasks",    os: "windows", fields: [{ key: "poll_interval_s", label: "Poll interval (s)", type: "number" }] },
  { key: "fim",      label: "File Integrity",     os: "windows", fields: [{ key: "watch_paths", label: "Watch paths (comma-sep)", type: "text" }, { key: "poll_interval_s", label: "Poll interval (s)", type: "number" }] },
  { key: "yara",     label: "YARA Scanner",       os: "linux",   fields: [{ key: "worker_count", label: "Worker count", type: "number" }] },
  { key: "vuln",     label: "Vulnerability Scan", os: "both" },
];

type MonitorCfg = { enabled: boolean } & Record<string, unknown>;
type FleetCfg = Record<string, MonitorCfg>;

// ── Fleet push modal ───────────────────────────────────────────────────────
function FleetPushModal({ group, onClose }: { group: AgentGroup; onClose: () => void }) {
  const [osFilter, setOsFilter] = useState<"both" | "linux" | "windows">("both");
  const [cfg, setCfg] = useState<FleetCfg>({});
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<{ pushed?: number; error?: string } | null>(null);

  const visibleMonitors = MONITOR_DEFS.filter(
    (m) => osFilter === "both" || m.os === "both" || m.os === osFilter
  );

  function getMonitorCfg(key: string): MonitorCfg {
    return (cfg[key] as MonitorCfg) ?? { enabled: false };
  }

  function setEnabled(key: string, val: boolean) {
    setCfg((prev) => ({ ...prev, [key]: { ...getMonitorCfg(key), enabled: val } }));
  }

  function setField(monKey: string, fieldKey: string, val: unknown) {
    setCfg((prev) => ({ ...prev, [monKey]: { ...getMonitorCfg(monKey), [fieldKey]: val } }));
  }

  async function handlePush() {
    setSaving(true);
    setResult(null);
    try {
      const res = await api.post<{ pushed: number }>(`/api/v1/agent-groups/${group.id}/fleet-config`, cfg);
      setResult({ pushed: res.pushed });
    } catch (err) {
      setResult({ error: err instanceof Error ? err.message : "Push failed" });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-neutral-900 border border-neutral-700 rounded-xl w-full max-w-xl flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-neutral-800 shrink-0">
          <div>
            <h2 className="font-semibold text-sm flex items-center gap-2">
              <Sliders size={14} /> Push Fleet Config
            </h2>
            <p className="text-xs text-neutral-400 mt-0.5">Group: <span className="text-white">{group.name}</span></p>
          </div>
          <button onClick={onClose} className="text-neutral-400 hover:text-white text-lg leading-none">&times;</button>
        </div>

        {/* OS filter */}
        <div className="px-5 pt-3 pb-2 shrink-0 flex items-center gap-2">
          <span className="text-xs text-neutral-400">Show monitors for:</span>
          {(["both", "linux", "windows"] as const).map((o) => (
            <button
              key={o}
              onClick={() => setOsFilter(o)}
              className={cn(
                "px-2.5 py-1 rounded text-xs font-medium border transition-colors",
                osFilter === o
                  ? "bg-cyan-600 border-cyan-500 text-white"
                  : "border-neutral-700 text-neutral-400 hover:border-neutral-500"
              )}
            >
              {o === "both" ? "All" : o.charAt(0).toUpperCase() + o.slice(1)}
            </button>
          ))}
        </div>

        {/* Monitor matrix */}
        <div className="overflow-y-auto flex-1 px-5 pb-2">
          <div className="rounded border overflow-hidden border-neutral-800">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-neutral-800 border-b border-neutral-700">
                  <th className="text-left px-2 py-2 font-medium w-7"></th>
                  <th className="text-left px-3 py-2 font-medium">Monitor</th>
                  <th className="text-left px-3 py-2 font-medium text-neutral-400 text-xs font-normal">OS</th>
                  <th className="text-left px-3 py-2 font-medium w-20">Enabled</th>
                </tr>
              </thead>
              <tbody>
                {visibleMonitors.map((mon) => {
                  const monCfg = getMonitorCfg(mon.key);
                  const isExpanded = expanded[mon.key];
                  const hasFields = mon.fields && mon.fields.length > 0;
                  return (
                    <>
                      <tr
                        key={mon.key}
                        style={{ borderBottom: isExpanded ? "none" : "1px solid #262626" }}
                      >
                        <td className="px-2 py-2 text-center">
                          {hasFields && (
                            <button
                              onClick={() => setExpanded((p) => ({ ...p, [mon.key]: !p[mon.key] }))}
                              className="text-neutral-500 hover:text-neutral-300"
                            >
                              <ChevronDown size={12} className={cn("transition-transform", isExpanded && "rotate-180")} />
                            </button>
                          )}
                        </td>
                        <td className="px-3 py-2 font-medium text-neutral-200">{mon.label}</td>
                        <td className="px-3 py-2 text-neutral-500 font-mono">{mon.os}</td>
                        <td className="px-3 py-2">
                          <button
                            role="switch"
                            aria-checked={!!monCfg.enabled}
                            onClick={() => setEnabled(mon.key, !monCfg.enabled)}
                            className={cn(
                              "relative inline-flex h-4 w-7 shrink-0 cursor-pointer rounded-full transition-colors",
                              monCfg.enabled ? "bg-blue-500" : "bg-neutral-600"
                            )}
                          >
                            <span className={cn(
                              "pointer-events-none inline-block h-3 w-3 rounded-full bg-white shadow transition-transform mt-0.5",
                              monCfg.enabled ? "translate-x-3.5" : "translate-x-0.5"
                            )} />
                          </button>
                        </td>
                      </tr>
                      {hasFields && isExpanded && (
                        <tr key={`${mon.key}-fields`} style={{ borderBottom: "1px solid #262626", background: "#171717" }}>
                          <td />
                          <td colSpan={3} className="px-3 pb-3 pt-1">
                            <div className="flex flex-wrap gap-4">
                              {mon.fields!.map((f) => (
                                <div key={f.key} className="flex flex-col gap-1 min-w-[160px]">
                                  <label className="text-xs text-neutral-400">{f.label}</label>
                                  {f.type === "boolean" ? (
                                    <button
                                      role="switch"
                                      aria-checked={!!monCfg[f.key]}
                                      onClick={() => setField(mon.key, f.key, !monCfg[f.key])}
                                      className={cn(
                                        "self-start relative inline-flex h-4 w-7 shrink-0 cursor-pointer rounded-full transition-colors",
                                        monCfg[f.key] ? "bg-blue-500" : "bg-neutral-600"
                                      )}
                                    >
                                      <span className={cn("pointer-events-none inline-block h-3 w-3 rounded-full bg-white shadow transition-transform mt-0.5", monCfg[f.key] ? "translate-x-3.5" : "translate-x-0.5")} />
                                    </button>
                                  ) : f.type === "number" ? (
                                    <input
                                      type="number"
                                      value={monCfg[f.key] != null ? String(monCfg[f.key]) : ""}
                                      onChange={(e) => setField(mon.key, f.key, parseInt(e.target.value, 10) || 0)}
                                      placeholder={f.placeholder}
                                      className="px-2 py-1 rounded border border-neutral-700 bg-neutral-800 text-xs w-24 text-neutral-200"
                                    />
                                  ) : (
                                    <input
                                      type="text"
                                      value={Array.isArray(monCfg[f.key]) ? (monCfg[f.key] as string[]).join(",") : String(monCfg[f.key] ?? "")}
                                      onChange={(e) => {
                                        const v = e.target.value;
                                        const isArray = f.key.includes("paths");
                                        setField(mon.key, f.key, isArray ? v.split(",").map((s) => s.trim()).filter(Boolean) : v);
                                      }}
                                      placeholder={f.placeholder}
                                      className="px-2 py-1 rounded border border-neutral-700 bg-neutral-800 text-xs w-48 text-neutral-200"
                                    />
                                  )}
                                </div>
                              ))}
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-neutral-800 shrink-0 space-y-2">
          {result && (
            <p className={cn("text-xs px-3 py-2 rounded", result.error ? "bg-red-500/10 text-red-400" : "bg-emerald-500/10 text-emerald-400")}>
              {result.error ?? `Pushed to ${result.pushed} agent${result.pushed !== 1 ? "s" : ""} — they will reload on next heartbeat`}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <button onClick={onClose} className="px-3 py-1.5 text-sm rounded border border-neutral-700 hover:bg-neutral-800">
              {result?.pushed != null ? "Close" : "Cancel"}
            </button>
            {!result?.pushed && (
              <button
                onClick={handlePush}
                disabled={saving}
                className="flex items-center gap-1.5 px-4 py-1.5 text-sm rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 font-medium"
              >
                {saving ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}
                Push to Group
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Preset colours ─────────────────────────────────────────────────────────
const PRESET_COLORS = [
  "#6366f1", "#8b5cf6", "#ec4899", "#ef4444",
  "#f97316", "#eab308", "#22c55e", "#14b8a6",
  "#06b6d4", "#3b82f6",
];

function GroupModal({
  initial,
  onSave,
  onClose,
}: {
  initial?: Partial<AgentGroup>;
  onSave: (data: Partial<AgentGroup>) => Promise<void>;
  onClose: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [color, setColor] = useState(initial?.color ?? PRESET_COLORS[0]);
  const [tagFilterInput, setTagFilterInput] = useState((initial?.tag_filter ?? []).join(", "));
  const [envFilter, setEnvFilter] = useState(initial?.env_filter ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function handleSave() {
    if (!name.trim()) { setError("Name is required"); return; }
    setSaving(true);
    setError("");
    const tagFilter = tagFilterInput.split(",").map((t) => t.trim()).filter(Boolean);
    try {
      await onSave({ name: name.trim(), description, color, tag_filter: tagFilter, env_filter: envFilter });
      onClose();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-neutral-900 border border-neutral-700 rounded-xl w-full max-w-lg">
        <div className="flex items-center justify-between px-5 py-4 border-b border-neutral-800">
          <h2 className="font-semibold text-sm">{initial?.id ? "Edit Group" : "New Agent Group"}</h2>
          <button onClick={onClose} className="text-neutral-400 hover:text-white text-lg leading-none">&times;</button>
        </div>
        <div className="p-5 space-y-4">
          {error && <p className="text-xs text-red-400 bg-red-500/10 px-3 py-2 rounded">{error}</p>}

          <div>
            <label className="text-xs text-neutral-400 mb-1 block">Name *</label>
            <input value={name} onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Production Servers"
              className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm" />
          </div>

          <div>
            <label className="text-xs text-neutral-400 mb-1 block">Description</label>
            <input value={description} onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional description"
              className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm" />
          </div>

          <div>
            <label className="text-xs text-neutral-400 mb-2 block">Color</label>
            <div className="flex gap-2 flex-wrap">
              {PRESET_COLORS.map((c) => (
                <button
                  key={c}
                  type="button"
                  onClick={() => setColor(c)}
                  className={`w-6 h-6 rounded-full border-2 transition-transform ${
                    color === c ? "border-white scale-110" : "border-transparent hover:scale-105"
                  }`}
                  style={{ backgroundColor: c }}
                />
              ))}
            </div>
          </div>

          <div className="bg-neutral-800/60 border border-neutral-700 rounded-lg p-3 space-y-3">
            <p className="text-xs font-semibold text-neutral-400 uppercase tracking-wider">Membership filter</p>
            <p className="text-xs text-neutral-500">Agents are dynamically included when they match all conditions below.</p>

            <div>
              <label className="text-xs text-neutral-400 mb-1 block flex items-center gap-1.5">
                <Tag size={11} /> Required tags (all-of, comma-separated)
              </label>
              <input
                value={tagFilterInput}
                onChange={(e) => setTagFilterInput(e.target.value)}
                placeholder="e.g. production, linux"
                className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm"
              />
              <p className="text-xs text-neutral-600 mt-1">Agent must carry every listed tag.</p>
            </div>

            <div>
              <label className="text-xs text-neutral-400 mb-1 block">Environment</label>
              <input
                value={envFilter}
                onChange={(e) => setEnvFilter(e.target.value)}
                placeholder="e.g. production  (leave blank to match any)"
                className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm"
              />
            </div>
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

function MembersPanel({ groupId, onClose }: { groupId: string; onClose: () => void }) {
  const { data, loading } = useApi<{ agents: GroupMember[] }>(
    () => api.get<{ agents: GroupMember[] }>(`/api/v1/agent-groups/${groupId}/members`)
  );
  const agents = data?.agents ?? [];

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/60 p-4">
      <div className="bg-neutral-900 border border-neutral-700 rounded-xl w-full max-w-lg max-h-[80vh] flex flex-col">
        <div className="flex items-center justify-between px-5 py-4 border-b border-neutral-800">
          <h2 className="font-semibold text-sm">Group Members</h2>
          <button onClick={onClose} className="text-neutral-400 hover:text-white text-lg leading-none">&times;</button>
        </div>
        <div className="overflow-y-auto flex-1 p-4">
          {loading && <p className="text-sm text-neutral-400 text-center py-8">Loading…</p>}
          {!loading && agents.length === 0 && (
            <p className="text-sm text-neutral-500 text-center py-8">No agents match this group&apos;s filter.</p>
          )}
          <div className="space-y-1.5">
            {agents.map((a) => (
              <div key={a.id} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-neutral-800">
                <span className={`w-2 h-2 rounded-full shrink-0 ${a.is_online ? "bg-emerald-400" : "bg-neutral-600"}`} />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium truncate">{a.hostname}</div>
                  <div className="text-xs text-neutral-400">{a.ip} · {a.os}</div>
                </div>
                <div className="flex gap-1 flex-wrap justify-end">
                  {a.tags?.slice(0, 3).map((t) => (
                    <span key={t} className="text-xs font-mono px-1.5 py-0.5 rounded bg-neutral-700 text-neutral-300">{t}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="px-5 py-3 border-t border-neutral-800 text-xs text-neutral-500">
          {agents.length} agent{agents.length !== 1 ? "s" : ""} match
        </div>
      </div>
    </div>
  );
}

export default function AgentGroupsPage() {
  const { data, loading, error, refetch } = useApi<{ groups: AgentGroup[] }>(
    () => api.get<{ groups: AgentGroup[] }>("/api/v1/agent-groups")
  );
  const groups = data?.groups ?? [];
  const [modal, setModal] = useState<{ open: boolean; group?: AgentGroup }>({ open: false });
  const [membersGroupId, setMembersGroupId] = useState<string | null>(null);
  const [fleetPushGroup, setFleetPushGroup] = useState<AgentGroup | null>(null);

  async function handleCreate(payload: Partial<AgentGroup>) {
    await api.post("/api/v1/agent-groups", payload);
    refetch();
  }

  async function handleUpdate(id: string, payload: Partial<AgentGroup>) {
    await api.put(`/api/v1/agent-groups/${id}`, payload);
    refetch();
  }

  async function handleDelete(id: string, name: string) {
    if (!confirm(`Delete group "${name}"? Playbooks using this group will no longer filter by it.`)) return;
    await api.del(`/api/v1/agent-groups/${id}`);
    refetch();
  }

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold flex items-center gap-2"><Users size={18} /> Agent Groups</h1>
          <p className="text-xs text-neutral-400 mt-0.5">
            Dynamic groups based on agent tags and environment — use them to scope playbook auto-triggers to specific hosts.
          </p>
        </div>
        <button
          onClick={() => setModal({ open: true })}
          className="flex items-center gap-2 px-3 py-1.5 text-sm rounded bg-cyan-600 hover:bg-cyan-500 font-medium"
        >
          <Plus size={15} /> New Group
        </button>
      </div>

      {loading && <p className="text-sm text-neutral-400">Loading…</p>}
      {error && <p className="text-sm text-red-400">{error}</p>}

      {!loading && groups.length === 0 && (
        <div className="text-center py-16 text-neutral-500 border border-dashed border-neutral-800 rounded-xl">
          <Users size={32} className="mx-auto mb-3 opacity-30" />
          <p className="text-sm">No agent groups yet.</p>
          <p className="text-xs mt-1 text-neutral-600">Groups let you restrict playbook triggers to specific hosts — e.g. only isolate production servers.</p>
          <button onClick={() => setModal({ open: true })}
            className="mt-4 text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 mx-auto">
            <Plus size={12} /> Create first group
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {groups.map((g) => (
          <div key={g.id} className="bg-neutral-900 border border-neutral-800 rounded-xl p-4 flex flex-col gap-3">
            <div className="flex items-start gap-2">
              <span className="w-3 h-3 rounded-full mt-1 shrink-0" style={{ backgroundColor: g.color }} />
              <div className="flex-1 min-w-0">
                <div className="font-medium text-sm truncate">{g.name}</div>
                {g.description && <p className="text-xs text-neutral-400 mt-0.5 truncate">{g.description}</p>}
              </div>
            </div>

            <div className="space-y-1.5 text-xs">
              {g.tag_filter.length > 0 && (
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span className="text-neutral-500 shrink-0">tags:</span>
                  {g.tag_filter.map((t) => (
                    <span key={t} className="font-mono px-1.5 py-0.5 rounded bg-neutral-800 text-neutral-300">{t}</span>
                  ))}
                </div>
              )}
              {g.env_filter && (
                <div className="flex items-center gap-1.5">
                  <span className="text-neutral-500">env:</span>
                  <span className="font-mono px-1.5 py-0.5 rounded bg-neutral-800 text-emerald-300">{g.env_filter}</span>
                </div>
              )}
              {g.tag_filter.length === 0 && !g.env_filter && (
                <span className="text-neutral-600 italic">matches all agents</span>
              )}
            </div>

            <div className="flex items-center gap-1 mt-auto pt-1 border-t border-neutral-800">
              <button
                onClick={() => setMembersGroupId(g.id)}
                className="flex items-center gap-1 text-xs text-neutral-400 hover:text-cyan-400 px-2 py-1 rounded hover:bg-neutral-800"
              >
                <Users size={11} /> Members
              </button>
              <button
                onClick={() => setFleetPushGroup(g)}
                className="flex items-center gap-1 text-xs text-neutral-400 hover:text-violet-400 px-2 py-1 rounded hover:bg-neutral-800"
              >
                <Sliders size={11} /> Push Config
              </button>
              <div className="flex items-center gap-1 ml-auto">
                <button onClick={() => setModal({ open: true, group: g })}
                  className="p-1.5 rounded hover:bg-neutral-800 text-neutral-400 hover:text-white">
                  <Pencil size={13} />
                </button>
                <button onClick={() => handleDelete(g.id, g.name)}
                  className="p-1.5 rounded hover:bg-neutral-800 text-neutral-400 hover:text-red-400">
                  <Trash2 size={13} />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {modal.open && (
        <GroupModal
          initial={modal.group}
          onSave={modal.group ? (p) => handleUpdate(modal.group!.id, p) : handleCreate}
          onClose={() => setModal({ open: false })}
        />
      )}

      {membersGroupId && (
        <MembersPanel groupId={membersGroupId} onClose={() => setMembersGroupId(null)} />
      )}

      {fleetPushGroup && (
        <FleetPushModal group={fleetPushGroup} onClose={() => setFleetPushGroup(null)} />
      )}
    </div>
  );
}
