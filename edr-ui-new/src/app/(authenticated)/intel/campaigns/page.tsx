"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import {
  Flag, Plus, X, RefreshCw, Database, Edit2, Trash2,
  Calendar, Target, ChevronDown, ChevronUp,
} from "lucide-react";

interface Campaign {
  id: string;
  name: string;
  actor_id?: string;
  actor_name?: string;
  start_date?: string;
  end_date?: string;
  targets: string[];
  techniques: string[];
  description: string;
  ioc_count: number;
  created_at: string;
}

interface Actor {
  id: string;
  name: string;
}

function dateRange(start?: string, end?: string) {
  if (!start && !end) return null;
  const s = start ? start.slice(0, 7) : "?";
  const e = end ? end.slice(0, 7) : "ongoing";
  return `${s} → ${e}`;
}

function CampaignForm({
  initial,
  actors,
  onSave,
  onCancel,
}: {
  initial?: Partial<Campaign>;
  actors: Actor[];
  onSave: (data: Record<string, unknown>) => Promise<void>;
  onCancel: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [actorId, setActorId] = useState(initial?.actor_id ?? "");
  const [startDate, setStartDate] = useState(initial?.start_date?.slice(0, 10) ?? "");
  const [endDate, setEndDate] = useState(initial?.end_date?.slice(0, 10) ?? "");
  const [targets, setTargets] = useState((initial?.targets ?? []).join(", "));
  const [techniques, setTechniques] = useState((initial?.techniques ?? []).join(", "));
  const [description, setDescription] = useState(initial?.description ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError("");
    try {
      await onSave({
        name,
        actor_id: actorId || null,
        start_date: startDate || null,
        end_date: endDate || null,
        targets: targets.split(",").map((s) => s.trim()).filter(Boolean),
        techniques: techniques.split(",").map((s) => s.trim()).filter(Boolean),
        description,
      });
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  const field = "rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-sm text-white placeholder-white/20 focus:outline-none focus:border-white/20 w-full";

  return (
    <form onSubmit={handleSubmit} className="space-y-3">
      <input className={field} placeholder="Campaign name *" value={name} onChange={(e) => setName(e.target.value)} required />
      <select className={field} value={actorId} onChange={(e) => setActorId(e.target.value)}>
        <option value="">— No actor attribution —</option>
        {actors.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
      </select>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-[10px] text-white/30 uppercase tracking-wider block mb-1">Start date</label>
          <input type="date" className={field} value={startDate} onChange={(e) => setStartDate(e.target.value)} />
        </div>
        <div>
          <label className="text-[10px] text-white/30 uppercase tracking-wider block mb-1">End date</label>
          <input type="date" className={field} value={endDate} onChange={(e) => setEndDate(e.target.value)} />
        </div>
      </div>
      <input className={field} placeholder="Target industries (e.g. Finance, Healthcare)" value={targets} onChange={(e) => setTargets(e.target.value)} />
      <input className={field} placeholder="MITRE techniques (e.g. T1566, T1059.001)" value={techniques} onChange={(e) => setTechniques(e.target.value)} />
      <textarea className={`${field} resize-none`} rows={3} placeholder="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
      {error && <p className="text-red-400 text-xs">{error}</p>}
      <div className="flex gap-2 justify-end">
        <button type="button" onClick={onCancel} className="rounded-lg border border-white/10 px-3 py-1.5 text-xs text-white/50 hover:text-white transition-colors">
          Cancel
        </button>
        <button type="submit" disabled={saving} className="rounded-lg bg-white/10 border border-white/20 px-3 py-1.5 text-xs text-white hover:bg-white/15 transition-colors disabled:opacity-50">
          {saving ? "Saving…" : "Save"}
        </button>
      </div>
    </form>
  );
}

function CampaignRow({
  campaign,
  actors,
  onDeleted,
  onUpdated,
}: {
  campaign: Campaign;
  actors: Actor[];
  onDeleted: () => void;
  onUpdated: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [editing, setEditing] = useState(false);
  const [iocs, setIocs] = useState<{ id: string; type: string; value: string }[] | null>(null);
  const [loadingIocs, setLoadingIocs] = useState(false);

  async function loadDetail() {
    if (iocs !== null) { setExpanded(!expanded); return; }
    setExpanded(true);
    setLoadingIocs(true);
    try {
      const data = await api.get(`/intel/campaigns/${campaign.id}`);
      setIocs((data as { iocs: { id: string; type: string; value: string }[] }).iocs ?? []);
    } finally {
      setLoadingIocs(false);
    }
  }

  async function handleUpdate(body: Record<string, unknown>) {
    await api.put(`/intel/campaigns/${campaign.id}`, body);
    setEditing(false);
    onUpdated();
  }

  async function handleDelete() {
    if (!confirm("Delete this campaign?")) return;
    await api.del(`/intel/campaigns/${campaign.id}`);
    onDeleted();
  }

  const range = dateRange(campaign.start_date, campaign.end_date);

  return (
    <div className={`rounded-xl border bg-white/[0.02] transition-colors ${expanded ? "border-white/20" : "border-white/8"}`}>
      <div className="flex items-start gap-3 p-4">
        <button onClick={loadDetail} className="flex-1 text-left min-w-0">
          <div className="flex items-center gap-3">
            <p className="text-sm font-semibold text-white/90">{campaign.name}</p>
            {campaign.actor_name && (
              <span className="text-[10px] rounded border border-violet-500/30 bg-violet-500/10 text-violet-400 px-1.5 py-0.5">{campaign.actor_name}</span>
            )}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-3 text-[11px] text-white/40">
            {range && (
              <span className="flex items-center gap-1">
                <Calendar size={10} /> {range}
              </span>
            )}
            {campaign.targets?.length > 0 && (
              <span className="flex items-center gap-1">
                <Target size={10} /> {campaign.targets.slice(0, 2).join(", ")}{campaign.targets.length > 2 ? ` +${campaign.targets.length - 2}` : ""}
              </span>
            )}
            {campaign.ioc_count > 0 && (
              <span className="flex items-center gap-1">
                <Database size={10} /> {campaign.ioc_count} IOCs
              </span>
            )}
          </div>
          {campaign.techniques?.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1">
              {campaign.techniques.slice(0, 5).map((t) => (
                <span key={t} className="rounded border border-white/8 bg-white/[0.03] px-1 py-0.5 text-[9px] font-mono text-white/40">{t}</span>
              ))}
              {campaign.techniques.length > 5 && <span className="text-[9px] text-white/20">+{campaign.techniques.length - 5}</span>}
            </div>
          )}
        </button>

        <div className="flex items-center gap-1.5 shrink-0">
          <button onClick={() => { setEditing(!editing); setExpanded(false); }} className="text-white/30 hover:text-white transition-colors p-1"><Edit2 size={13} /></button>
          <button onClick={handleDelete} className="text-white/30 hover:text-red-400 transition-colors p-1"><Trash2 size={13} /></button>
          <button onClick={loadDetail} className="text-white/30 hover:text-white transition-colors p-1">
            {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>
      </div>

      {editing && (
        <div className="border-t border-white/8 p-4">
          <CampaignForm
            initial={campaign}
            actors={actors}
            onSave={handleUpdate}
            onCancel={() => setEditing(false)}
          />
        </div>
      )}

      {expanded && !editing && (
        <div className="border-t border-white/8 p-4 space-y-3">
          {campaign.description && (
            <p className="text-xs text-white/50 leading-relaxed border-l-2 border-white/10 pl-3">{campaign.description}</p>
          )}
          {loadingIocs && <p className="text-white/30 text-xs">Loading IOCs…</p>}
          {iocs && iocs.length === 0 && <p className="text-white/20 text-xs">No IOCs linked to this campaign yet.</p>}
          {iocs && iocs.length > 0 && (
            <div className="rounded-lg border border-white/8 overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-white/5 text-white/30">
                    <th className="px-3 py-1.5 text-left font-normal">Type</th>
                    <th className="px-3 py-1.5 text-left font-normal">Value</th>
                  </tr>
                </thead>
                <tbody>
                  {iocs.slice(0, 15).map((ioc) => (
                    <tr key={ioc.id} className="border-b border-white/5 hover:bg-white/[0.02]">
                      <td className="px-3 py-1.5 font-mono text-white/40 text-[10px] uppercase">{ioc.type}</td>
                      <td className="px-3 py-1.5 font-mono text-white/70 truncate max-w-[300px]">{ioc.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function CampaignsPage() {
  const [creating, setCreating] = useState(false);

  const { data, loading, error, refetch } = useApi<{ campaigns: Campaign[]; total: number }>(
    (signal) => api.get("/intel/campaigns", {}, signal),
  );
  const { data: actorData } = useApi<{ actors: Actor[] }>(
    (signal) => api.get("/intel/actors", {}, signal),
  );

  const campaigns = data?.campaigns ?? [];
  const actors = actorData?.actors ?? [];

  async function handleCreate(body: Record<string, unknown>) {
    await api.post("/intel/campaigns", body);
    setCreating(false);
    refetch();
  }

  return (
    <div className="space-y-5 max-w-4xl">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Campaigns</h1>
          <p className="text-sm text-white/50 mt-0.5">Targeted operations with actor attribution and MITRE techniques</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="flex items-center gap-1.5 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-white/60 hover:text-white transition-colors">
            <RefreshCw size={13} />
          </button>
          <button
            onClick={() => setCreating(true)}
            className="flex items-center gap-1.5 rounded-lg border border-white/20 bg-white/[0.06] px-3 py-1.5 text-xs text-white hover:bg-white/10 transition-colors"
          >
            <Plus size={13} /> New Campaign
          </button>
        </div>
      </div>

      {loading && <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center text-white/30 text-sm">Loading…</div>}
      {error && <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">{error}</div>}

      {creating && (
        <div className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
          <div className="flex items-center justify-between mb-4">
            <p className="text-sm font-semibold text-white">New Campaign</p>
            <button onClick={() => setCreating(false)} className="text-white/30 hover:text-white transition-colors"><X size={15} /></button>
          </div>
          <CampaignForm actors={actors} onSave={handleCreate} onCancel={() => setCreating(false)} />
        </div>
      )}

      {!loading && !error && campaigns.length === 0 && !creating && (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center space-y-2">
          <Flag size={28} className="mx-auto text-white/20" />
          <p className="text-white/30 text-sm">No campaigns yet.</p>
          <p className="text-white/20 text-xs">Create campaigns to group related IOCs and track actor operations over time.</p>
        </div>
      )}

      <div className="space-y-3">
        {campaigns.map((c) => (
          <CampaignRow
            key={c.id}
            campaign={c}
            actors={actors}
            onDeleted={refetch}
            onUpdated={refetch}
          />
        ))}
      </div>
    </div>
  );
}
