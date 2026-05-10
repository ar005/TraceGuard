"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import {
  Users, Plus, X, ChevronRight, RefreshCw, Shield,
  Globe, Target, Database, AlertTriangle, Edit2, Trash2,
} from "lucide-react";

interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  country: string;
  motivation: string;
  description: string;
  mitre_groups: string[];
  ioc_count: number;
  campaign_count: number;
  created_at: string;
  updated_at: string;
}

interface ActorDetail extends ThreatActor {
  iocs: { id: string; type: string; value: string; severity: number }[];
  campaigns: { id: string; name: string; start_date?: string; end_date?: string }[];
}

interface ActorsResponse {
  actors: ThreatActor[];
  total: number;
}

const MOTIVATIONS = ["unknown", "espionage", "financial", "hacktivism", "destruction", "cyber-warfare"];

const MOTIVATION_COLORS: Record<string, string> = {
  espionage: "text-violet-400 border-violet-500/30 bg-violet-500/10",
  financial: "text-amber-400 border-amber-500/30 bg-amber-500/10",
  hacktivism: "text-cyan-400 border-cyan-500/30 bg-cyan-500/10",
  destruction: "text-red-400 border-red-500/30 bg-red-500/10",
  "cyber-warfare": "text-orange-400 border-orange-500/30 bg-orange-500/10",
  unknown: "text-white/30 border-white/10 bg-white/5",
};

const COUNTRY_FLAGS: Record<string, string> = {
  CN: "🇨🇳", RU: "🇷🇺", KP: "🇰🇵", IR: "🇮🇷", US: "🇺🇸",
  UK: "🇬🇧", IN: "🇮🇳", BR: "🇧🇷", DE: "🇩🇪", FR: "🇫🇷",
};

function MotivationBadge({ m }: { m: string }) {
  return (
    <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium capitalize ${MOTIVATION_COLORS[m] ?? MOTIVATION_COLORS.unknown}`}>
      {m}
    </span>
  );
}

function ActorForm({
  initial,
  onSave,
  onCancel,
}: {
  initial?: Partial<ThreatActor>;
  onSave: (data: Record<string, unknown>) => Promise<void>;
  onCancel: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [aliases, setAliases] = useState((initial?.aliases ?? []).join(", "));
  const [country, setCountry] = useState(initial?.country ?? "");
  const [motivation, setMotivation] = useState(initial?.motivation ?? "unknown");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [mitreGroups, setMitreGroups] = useState((initial?.mitre_groups ?? []).join(", "));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError("");
    try {
      await onSave({
        name,
        aliases: aliases.split(",").map((s) => s.trim()).filter(Boolean),
        country,
        motivation,
        description,
        mitre_groups: mitreGroups.split(",").map((s) => s.trim()).filter(Boolean),
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
      <input className={field} placeholder="Actor name *" value={name} onChange={(e) => setName(e.target.value)} required />
      <input className={field} placeholder="Aliases (comma separated)" value={aliases} onChange={(e) => setAliases(e.target.value)} />
      <div className="grid grid-cols-2 gap-3">
        <input className={field} placeholder="Country code (e.g. CN)" value={country} onChange={(e) => setCountry(e.target.value.toUpperCase())} maxLength={2} />
        <select className={field} value={motivation} onChange={(e) => setMotivation(e.target.value)}>
          {MOTIVATIONS.map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
      </div>
      <input className={field} placeholder="MITRE group IDs (e.g. G0007, G0032)" value={mitreGroups} onChange={(e) => setMitreGroups(e.target.value)} />
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

function ActorDetail({ actorId, onClose, onDeleted }: { actorId: string; onClose: () => void; onDeleted: () => void }) {
  const [editing, setEditing] = useState(false);
  const { data, loading, error, refetch } = useApi<{ actor: ActorDetail; iocs: ActorDetail["iocs"]; campaigns: ActorDetail["campaigns"] }>(
    (signal) => api.get(`/intel/actors/${actorId}`, {}, signal),
  );

  async function handleUpdate(body: Record<string, unknown>) {
    await api.put(`/intel/actors/${actorId}`, body);
    setEditing(false);
    refetch();
  }

  async function handleDelete() {
    if (!confirm("Delete this actor? IOC attributions will be cleared.")) return;
    await api.del(`/intel/actors/${actorId}`);
    onDeleted();
  }

  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.03] p-5 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-white">{data?.actor?.name ?? "Actor Detail"}</h3>
        <div className="flex items-center gap-2">
          {data && !editing && (
            <>
              <button onClick={() => setEditing(true)} className="text-white/30 hover:text-white transition-colors"><Edit2 size={14} /></button>
              <button onClick={handleDelete} className="text-white/30 hover:text-red-400 transition-colors"><Trash2 size={14} /></button>
            </>
          )}
          <button onClick={onClose} className="text-white/30 hover:text-white transition-colors"><X size={15} /></button>
        </div>
      </div>

      {loading && <p className="text-white/30 text-sm">Loading…</p>}
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {data && !editing && (
        <>
          <div className="grid grid-cols-2 gap-4 text-xs">
            <div className="space-y-2">
              {data.actor.country && (
                <div className="flex items-center gap-2">
                  <Globe size={12} className="text-white/30" />
                  <span className="text-white/60">{COUNTRY_FLAGS[data.actor.country] ?? ""} {data.actor.country}</span>
                </div>
              )}
              <div className="flex items-center gap-2">
                <Target size={12} className="text-white/30" />
                <MotivationBadge m={data.actor.motivation} />
              </div>
              {data.actor.aliases?.length > 0 && (
                <div className="text-white/40">
                  Also known as: <span className="text-white/60">{data.actor.aliases.join(", ")}</span>
                </div>
              )}
              {data.actor.mitre_groups?.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {data.actor.mitre_groups.map((g) => (
                    <span key={g} className="rounded border border-white/10 bg-white/5 px-1.5 py-0.5 text-[10px] font-mono text-white/50">{g}</span>
                  ))}
                </div>
              )}
            </div>
            <div className="grid grid-cols-2 gap-2">
              {[
                { label: "IOCs", value: data.actor.ioc_count, icon: Database },
                { label: "Campaigns", value: data.actor.campaign_count, icon: Shield },
              ].map(({ label, value, icon: Icon }) => (
                <div key={label} className="rounded-lg border border-white/8 bg-white/[0.02] p-2 text-center">
                  <Icon size={12} className="mx-auto text-white/30 mb-1" />
                  <p className="text-lg font-bold text-white tabular-nums">{value}</p>
                  <p className="text-[10px] text-white/30">{label}</p>
                </div>
              ))}
            </div>
          </div>

          {data.actor.description && (
            <p className="text-xs text-white/50 leading-relaxed border-l-2 border-white/10 pl-3">{data.actor.description}</p>
          )}

          {data.campaigns.length > 0 && (
            <div className="space-y-1">
              <p className="text-[10px] font-medium text-white/30 uppercase tracking-wider">Campaigns</p>
              {data.campaigns.map((c) => (
                <div key={c.id} className="flex items-center justify-between text-xs rounded-lg border border-white/8 bg-white/[0.02] px-3 py-1.5">
                  <span className="text-white/70">{c.name}</span>
                  {c.start_date && <span className="text-white/30">{c.start_date?.slice(0, 7)}</span>}
                </div>
              ))}
            </div>
          )}

          {data.iocs.length > 0 && (
            <div className="space-y-1">
              <p className="text-[10px] font-medium text-white/30 uppercase tracking-wider">Recent IOCs ({data.iocs.length})</p>
              <div className="rounded-lg border border-white/8 overflow-hidden">
                <table className="w-full text-xs">
                  <tbody>
                    {data.iocs.slice(0, 10).map((ioc) => (
                      <tr key={ioc.id} className="border-b border-white/5">
                        <td className="px-3 py-1.5 font-mono text-white/50 text-[10px] uppercase">{ioc.type}</td>
                        <td className="px-3 py-1.5 font-mono text-white/70 truncate max-w-[200px]">{ioc.value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}

      {editing && data && (
        <ActorForm
          initial={data.actor}
          onSave={handleUpdate}
          onCancel={() => setEditing(false)}
        />
      )}
    </div>
  );
}

export default function ActorsPage() {
  const [selectedActor, setSelectedActor] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [search, setSearch] = useState("");

  const { data, loading, error, refetch } = useApi<ActorsResponse>(
    (signal) => api.get("/intel/actors", {}, signal),
  );

  const actors = (data?.actors ?? []).filter(
    (a) => !search || a.name.toLowerCase().includes(search.toLowerCase()) ||
      a.aliases?.some((al) => al.toLowerCase().includes(search.toLowerCase()))
  );

  async function handleCreate(body: Record<string, unknown>) {
    await api.post("/intel/actors", body);
    setCreating(false);
    refetch();
  }

  return (
    <div className="space-y-5 max-w-5xl">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Threat Actors</h1>
          <p className="text-sm text-white/50 mt-0.5">Track groups, TTPs, and IOC attributions</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="flex items-center gap-1.5 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-white/60 hover:text-white transition-colors">
            <RefreshCw size={13} />
          </button>
          <button
            onClick={() => { setCreating(true); setSelectedActor(null); }}
            className="flex items-center gap-1.5 rounded-lg border border-white/20 bg-white/[0.06] px-3 py-1.5 text-xs text-white hover:bg-white/10 transition-colors"
          >
            <Plus size={13} /> New Actor
          </button>
        </div>
      </div>

      {/* Search */}
      <input
        className="w-full rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-sm text-white placeholder-white/20 focus:outline-none focus:border-white/20"
        placeholder="Search by name or alias…"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />

      {loading && (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center text-white/30 text-sm">Loading…</div>
      )}
      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">{error}</div>
      )}

      {creating && (
        <div className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
          <p className="text-sm font-semibold text-white mb-4">New Threat Actor</p>
          <ActorForm onSave={handleCreate} onCancel={() => setCreating(false)} />
        </div>
      )}

      {!loading && !error && actors.length === 0 && !creating && (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center space-y-2">
          <Users size={28} className="mx-auto text-white/20" />
          <p className="text-white/30 text-sm">No threat actors yet.</p>
          <p className="text-white/20 text-xs">Create actors and link IOCs to build your attribution graph.</p>
        </div>
      )}

      {actors.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          {actors.map((actor) => (
            <button
              key={actor.id}
              onClick={() => {
                setCreating(false);
                setSelectedActor(selectedActor === actor.id ? null : actor.id);
              }}
              className={`rounded-xl border p-4 text-left transition-all hover:border-white/20 bg-white/[0.02] ${
                selectedActor === actor.id ? "border-white/20 ring-1 ring-white/10" : "border-white/8"
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <p className="text-sm font-semibold text-white/90 truncate">{actor.name}</p>
                {actor.country && (
                  <span className="text-lg shrink-0">{COUNTRY_FLAGS[actor.country] ?? <Globe size={14} />}</span>
                )}
              </div>
              {actor.aliases?.length > 0 && (
                <p className="text-[10px] text-white/30 mt-0.5 truncate">{actor.aliases.join(", ")}</p>
              )}
              <div className="mt-3 flex items-center justify-between">
                <MotivationBadge m={actor.motivation} />
                <div className="flex items-center gap-3 text-[10px] text-white/40">
                  <span><span className="text-white/60 font-semibold">{actor.ioc_count}</span> IOCs</span>
                  <span><span className="text-white/60 font-semibold">{actor.campaign_count}</span> campaigns</span>
                </div>
              </div>
              {actor.mitre_groups?.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {actor.mitre_groups.slice(0, 3).map((g) => (
                    <span key={g} className="rounded border border-white/8 bg-white/[0.03] px-1 py-0.5 text-[9px] font-mono text-white/30">{g}</span>
                  ))}
                  {actor.mitre_groups.length > 3 && <span className="text-[9px] text-white/20">+{actor.mitre_groups.length - 3}</span>}
                </div>
              )}
              {selectedActor !== actor.id && (
                <div className="mt-2 flex items-center gap-1 text-[10px] text-white/25">
                  <ChevronRight size={10} /> View detail
                </div>
              )}
            </button>
          ))}
        </div>
      )}

      {selectedActor && (
        <ActorDetail
          actorId={selectedActor}
          onClose={() => setSelectedActor(null)}
          onDeleted={() => { setSelectedActor(null); refetch(); }}
        />
      )}

      {/* Stats summary */}
      {actors.length > 0 && (
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: "Total actors", value: data?.total ?? 0 },
            { label: "With IOCs", value: actors.filter((a) => a.ioc_count > 0).length },
            { label: "With campaigns", value: actors.filter((a) => a.campaign_count > 0).length },
          ].map(({ label, value }) => (
            <div key={label} className="rounded-xl border border-white/8 bg-white/[0.02] p-3 text-center">
              <p className="text-xl font-bold text-white tabular-nums">{value}</p>
              <p className="text-[10px] text-white/30 mt-0.5">{label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Warning if no actors have IOCs */}
      {!loading && actors.length > 0 && actors.every((a) => a.ioc_count === 0) && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-xs text-amber-300/80">
          <AlertTriangle size={12} className="mt-0.5 shrink-0 text-amber-500" />
          No IOCs are attributed yet — open an actor and link IOCs from the IOC list.
        </div>
      )}
    </div>
  );
}
