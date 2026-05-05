"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { timeAgo } from "@/lib/utils";
import {
  Share2, Plus, Trash2, Play, RefreshCw, ChevronDown, ChevronRight,
  CheckCircle2, XCircle, Clock, Download,
} from "lucide-react";

interface PushTarget {
  type: "misp";
  url: string;
  key: string;
}

interface SharingGroup {
  id: string;
  name: string;
  description: string;
  push_targets: PushTarget[];
  tlp_floor: string;
  created_at: string;
  updated_at: string;
}

interface SharingRun {
  id: string;
  group_id: string;
  started_at: string;
  finished_at?: string;
  exported: number;
  error: string;
}

const TLP_STYLES: Record<string, string> = {
  WHITE: "border-white/20 text-white/70 bg-white/5",
  GREEN: "border-emerald-500/30 text-emerald-400 bg-emerald-500/10",
  AMBER: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  RED:   "border-red-500/30 text-red-400 bg-red-500/10",
};

const TLP_OPTIONS = ["WHITE", "GREEN", "AMBER", "RED"];

function TLPBadge({ tlp }: { tlp: string }) {
  return (
    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-bold tracking-wider ${TLP_STYLES[tlp] ?? TLP_STYLES.AMBER}`}>
      TLP:{tlp}
    </span>
  );
}

function RunRow({ run }: { run: SharingRun }) {
  const ok = !run.error && !!run.finished_at;
  const failed = !!run.error;
  const running = !run.finished_at;

  return (
    <div className="flex items-center gap-3 px-3 py-2 text-xs border-b border-white/5 last:border-0">
      <span className="shrink-0">
        {running ? <Clock size={11} className="text-blue-400" /> :
         ok      ? <CheckCircle2 size={11} className="text-emerald-400" /> :
                   <XCircle size={11} className="text-red-400" />}
      </span>
      <span className="text-white/40 w-24 shrink-0">{timeAgo(run.started_at)}</span>
      {ok && <span className="text-emerald-400">{run.exported} exported</span>}
      {running && <span className="text-blue-400/70">running…</span>}
      {failed && <span className="text-red-400 truncate">{run.error}</span>}
    </div>
  );
}

function GroupCard({ group, onRefresh }: { group: SharingGroup; onRefresh: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const [pushing, setPushing] = useState(false);
  const [pushResult, setPushResult] = useState<{ exported: number } | null>(null);
  const [editing, setEditing] = useState(false);

  const { data: runsData, refetch: refetchRuns } = useApi<{ runs: SharingRun[] }>(
    (signal) => api.get(`/intel/sharing-groups/${group.id}/runs`, { limit: "10" }, signal),
  );

  async function push() {
    setPushing(true);
    setPushResult(null);
    try {
      const res = await api.post<{ exported: number }>(`/intel/sharing-groups/${group.id}/push`);
      setPushResult(res);
      refetchRuns();
    } finally {
      setPushing(false);
    }
  }

  async function del() {
    if (!confirm(`Delete sharing group "${group.name}"?`)) return;
    await api.del(`/intel/sharing-groups/${group.id}`);
    onRefresh();
  }

  const targets: PushTarget[] = Array.isArray(group.push_targets) ? group.push_targets : [];

  if (editing) {
    return (
      <GroupForm
        initial={group}
        onSave={async (body) => {
          await api.put(`/intel/sharing-groups/${group.id}`, body);
          setEditing(false);
          onRefresh();
        }}
        onCancel={() => setEditing(false)}
      />
    );
  }

  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3">
        <button onClick={() => setExpanded(!expanded)} className="text-white/30 hover:text-white/60 transition-colors">
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </button>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <p className="text-sm font-medium text-white">{group.name}</p>
            <TLPBadge tlp={group.tlp_floor} />
          </div>
          {group.description && <p className="text-xs text-white/40 mt-0.5 truncate">{group.description}</p>}
        </div>
        <div className="flex items-center gap-2 shrink-0 text-xs text-white/30">
          <span>{targets.length} target{targets.length !== 1 ? "s" : ""}</span>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {pushResult && (
            <span className="text-[10px] text-emerald-400">{pushResult.exported} pushed</span>
          )}
          <button
            onClick={push}
            disabled={pushing || targets.length === 0}
            className="flex items-center gap-1 rounded-lg border border-white/15 bg-white/[0.04] px-2.5 py-1 text-[10px] text-white/70 hover:bg-white/[0.08] transition-colors disabled:opacity-40"
          >
            {pushing ? <RefreshCw size={10} className="animate-spin" /> : <Play size={10} />}
            {pushing ? "Pushing…" : "Push"}
          </button>
          <button onClick={() => setEditing(true)} className="rounded-lg border border-white/10 px-2 py-1 text-[10px] text-white/40 hover:text-white transition-colors">
            Edit
          </button>
          <button onClick={del} className="rounded-lg border border-red-500/20 px-2 py-1 text-[10px] text-red-400/60 hover:text-red-400 transition-colors">
            <Trash2 size={10} />
          </button>
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="border-t border-white/5 px-4 py-3 space-y-3">
          {/* Targets */}
          {targets.length > 0 ? (
            <div className="space-y-1.5">
              <p className="text-[10px] font-medium text-white/30 uppercase tracking-wider">Push Targets</p>
              {targets.map((t, i) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <span className="rounded border border-white/10 bg-white/5 px-1.5 py-0.5 text-[10px] text-white/50 uppercase">{t.type}</span>
                  <span className="font-mono text-white/60 truncate">{t.url}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-white/25">No push targets configured.</p>
          )}

          {/* Run history */}
          <div>
            <p className="text-[10px] font-medium text-white/30 uppercase tracking-wider mb-1.5">Push History</p>
            {runsData?.runs && runsData.runs.length > 0 ? (
              <div className="rounded-lg border border-white/8 overflow-hidden">
                {runsData.runs.map((r) => <RunRow key={r.id} run={r} />)}
              </div>
            ) : (
              <p className="text-xs text-white/25">No runs yet.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function GroupForm({
  initial,
  onSave,
  onCancel,
}: {
  initial?: SharingGroup;
  onSave: (body: object) => Promise<void>;
  onCancel: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [tlpFloor, setTlpFloor] = useState(initial?.tlp_floor ?? "AMBER");
  const [targets, setTargets] = useState<PushTarget[]>(
    Array.isArray(initial?.push_targets) ? initial.push_targets : []
  );
  const [saving, setSaving] = useState(false);

  function addTarget() {
    setTargets((t) => [...t, { type: "misp", url: "", key: "" }]);
  }
  function removeTarget(i: number) {
    setTargets((t) => t.filter((_, idx) => idx !== i));
  }
  function updateTarget(i: number, field: keyof PushTarget, val: string) {
    setTargets((t) => t.map((item, idx) => idx === i ? { ...item, [field]: val } : item));
  }

  async function save() {
    if (!name.trim()) return;
    setSaving(true);
    try {
      await onSave({ name, description, tlp_floor: tlpFloor, push_targets: targets });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="rounded-xl border border-white/15 bg-white/[0.03] p-4 space-y-4">
      <p className="text-sm font-medium text-white">{initial ? "Edit Sharing Group" : "New Sharing Group"}</p>

      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <label className="text-[10px] text-white/40 uppercase tracking-wider">Name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="ISAC Partners"
            className="w-full rounded-lg border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs text-white placeholder-white/20 outline-none focus:border-white/25" />
        </div>
        <div className="space-y-1">
          <label className="text-[10px] text-white/40 uppercase tracking-wider">TLP Floor</label>
          <div className="flex gap-1.5">
            {TLP_OPTIONS.map((t) => (
              <button key={t} onClick={() => setTlpFloor(t)}
                className={`flex-1 rounded-lg border py-1.5 text-[10px] font-bold transition-colors ${tlpFloor === t ? TLP_STYLES[t] : "border-white/8 text-white/20 hover:text-white/40"}`}>
                {t}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="space-y-1">
        <label className="text-[10px] text-white/40 uppercase tracking-wider">Description</label>
        <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional"
          className="w-full rounded-lg border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs text-white placeholder-white/20 outline-none focus:border-white/25" />
      </div>

      {/* Push targets */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <label className="text-[10px] text-white/40 uppercase tracking-wider">Push Targets</label>
          <button onClick={addTarget} className="flex items-center gap-1 text-[10px] text-white/40 hover:text-white transition-colors">
            <Plus size={10} /> Add
          </button>
        </div>
        {targets.map((t, i) => (
          <div key={i} className="flex items-center gap-2">
            <span className="rounded border border-white/10 bg-white/5 px-1.5 py-1 text-[10px] text-white/40 uppercase">MISP</span>
            <input value={t.url} onChange={(e) => updateTarget(i, "url", e.target.value)} placeholder="https://misp.example.com"
              className="flex-1 rounded-lg border border-white/10 bg-white/[0.04] px-2.5 py-1 text-xs text-white placeholder-white/20 outline-none focus:border-white/25 font-mono" />
            <input value={t.key} onChange={(e) => updateTarget(i, "key", e.target.value)} placeholder="API key"
              type="password"
              className="w-32 rounded-lg border border-white/10 bg-white/[0.04] px-2.5 py-1 text-xs text-white placeholder-white/20 outline-none focus:border-white/25" />
            <button onClick={() => removeTarget(i)} className="text-red-400/50 hover:text-red-400 transition-colors">
              <Trash2 size={12} />
            </button>
          </div>
        ))}
        {targets.length === 0 && (
          <p className="text-[10px] text-white/20">No targets — STIX export only.</p>
        )}
      </div>

      <div className="flex gap-2">
        <button onClick={save} disabled={saving || !name.trim()}
          className="rounded-lg border border-white/20 bg-white/[0.06] px-4 py-1.5 text-xs text-white hover:bg-white/10 transition-colors disabled:opacity-40">
          {saving ? "Saving…" : "Save"}
        </button>
        <button onClick={onCancel}
          className="rounded-lg border border-white/10 px-4 py-1.5 text-xs text-white/50 hover:text-white transition-colors">
          Cancel
        </button>
      </div>
    </div>
  );
}

function STIXExportBar() {
  const [tlp, setTlp] = useState("AMBER");
  const [days, setDays] = useState(30);
  const [exporting, setExporting] = useState(false);

  async function exportSTIX() {
    setExporting(true);
    try {
      const blob = await fetch(
        `/api/v1/intel/export/stix?tlp=${tlp}&days=${days}`,
        { credentials: "include" }
      ).then((r) => r.blob());
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `traceguard-intel-${tlp.toLowerCase()}-${days}d.stix.json`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <p className="text-sm font-semibold text-white">STIX 2.1 Export</p>
          <p className="text-xs text-white/40 mt-0.5">Download all eligible IOCs as a STIX 2.1 bundle.</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-white/40">TLP</span>
            {TLP_OPTIONS.map((t) => (
              <button key={t} onClick={() => setTlp(t)}
                className={`rounded-lg border px-2 py-0.5 text-[10px] font-bold transition-colors ${tlp === t ? TLP_STYLES[t] : "border-white/8 text-white/20 hover:text-white/40"}`}>
                {t}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-white/40">Days</span>
            {[7, 30, 90].map((d) => (
              <button key={d} onClick={() => setDays(d)}
                className={`rounded-lg border px-2 py-0.5 text-xs transition-colors ${days === d ? "border-white/20 bg-white/[0.06] text-white" : "border-white/8 text-white/30 hover:text-white/60"}`}>
                {d}d
              </button>
            ))}
          </div>
          <button onClick={exportSTIX} disabled={exporting}
            className="flex items-center gap-1.5 rounded-lg border border-white/20 bg-white/[0.06] px-4 py-1.5 text-xs text-white hover:bg-white/10 transition-colors disabled:opacity-40">
            {exporting ? <RefreshCw size={12} className="animate-spin" /> : <Download size={12} />}
            {exporting ? "Exporting…" : "Export STIX"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function SharingPage() {
  const [showForm, setShowForm] = useState(false);

  const { data, loading, error, refetch } = useApi<{ groups: SharingGroup[] }>(
    (signal) => api.get("/intel/sharing-groups", {}, signal),
  );

  const groups = data?.groups ?? [];

  async function create(body: object) {
    await api.post("/intel/sharing-groups", body);
    setShowForm(false);
    refetch();
  }

  return (
    <div className="space-y-5 max-w-4xl">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Intel Sharing</h1>
          <p className="text-sm text-white/50 mt-0.5">
            Push IOCs to MISP and export STIX 2.1 bundles for partner sharing.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="flex items-center gap-1.5 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-white/60 hover:text-white transition-colors">
            <RefreshCw size={13} />
          </button>
          <button onClick={() => setShowForm(true)}
            className="flex items-center gap-1.5 rounded-lg border border-white/20 bg-white/[0.06] px-3 py-1.5 text-xs text-white hover:bg-white/10 transition-colors">
            <Plus size={13} /> New Group
          </button>
        </div>
      </div>

      {/* STIX export */}
      <STIXExportBar />

      {/* New group form */}
      {showForm && (
        <GroupForm onSave={create} onCancel={() => setShowForm(false)} />
      )}

      {/* Loading / error */}
      {loading && <div className="rounded-xl border border-white/10 bg-white/[0.02] p-10 text-center text-white/30 text-sm">Loading…</div>}
      {error && <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">{error}</div>}

      {/* Groups */}
      {groups.length > 0 && (
        <div className="space-y-3">
          {groups.map((g) => <GroupCard key={g.id} group={g} onRefresh={refetch} />)}
        </div>
      )}

      {!loading && groups.length === 0 && !showForm && (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center space-y-2">
          <Share2 size={28} className="mx-auto text-white/20" />
          <p className="text-white/30 text-sm">No sharing groups yet.</p>
          <p className="text-white/20 text-xs">Create a group, add MISP targets, and push IOCs to partners.</p>
        </div>
      )}
    </div>
  );
}
