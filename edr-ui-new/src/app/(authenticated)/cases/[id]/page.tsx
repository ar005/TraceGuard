"use client";

import { useState, useCallback } from "react";
import { useParams } from "next/navigation";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { timeAgo, severityLabel, severityBgClass } from "@/lib/utils";
import { ArrowLeft, Plus, Trash2, Pencil, Link2, X, Check, Sparkles } from "lucide-react";
import Link from "next/link";

interface Case {
  id: string;
  title: string;
  description: string;
  status: string;
  severity: number;
  assignee: string;
  tags: string[];
  mitre_ids: string[];
  alert_count: number;
  created_by: string;
  created_at: string;
  updated_at: string;
  closed_at?: string;
}

interface CaseNote {
  id: string;
  case_id: string;
  body: string;
  author: string;
  created_at: string;
  updated_at: string;
}

interface Alert {
  id: string;
  title: string;
  severity: number;
  status: string;
  hostname: string;
  rule_name: string;
  last_seen: string;
}

interface CaseDetail {
  case: Case;
  notes: CaseNote[];
  alerts: Alert[];
}

const STATUSES = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"];

const STATUS_STYLE: Record<string, string> = {
  OPEN:          "bg-red-500/15 text-red-400 border-red-500/30",
  INVESTIGATING: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  CONTAINED:     "bg-blue-500/15 text-blue-400 border-blue-500/30",
  RESOLVED:      "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  CLOSED:        "bg-white/5 text-white/40 border-white/10",
};

function EditField({ label, value, onSave }: { label: string; value: string; onSave: (v: string) => Promise<void> }) {
  const [editing, setEditing] = useState(false);
  const [val, setVal] = useState(value);
  const [saving, setSaving] = useState(false);

  async function save() {
    setSaving(true);
    try { await onSave(val); setEditing(false); } finally { setSaving(false); }
  }

  return (
    <div>
      <span className="text-xs text-white/40">{label}</span>
      {editing ? (
        <div className="flex items-center gap-1 mt-0.5">
          <input
            value={val}
            onChange={(e) => setVal(e.target.value)}
            className="flex-1 bg-white/5 border border-white/15 rounded px-2 py-1 text-sm text-white focus:outline-none focus:border-white/30"
          />
          <button onClick={save} disabled={saving} className="p-1 text-emerald-400 hover:text-emerald-300">
            <Check size={14} />
          </button>
          <button onClick={() => { setVal(value); setEditing(false); }} className="p-1 text-white/40 hover:text-white/70">
            <X size={14} />
          </button>
        </div>
      ) : (
        <div className="flex items-center gap-1 group mt-0.5">
          <span className="text-sm text-white/80">{value || <span className="text-white/20 italic">none</span>}</span>
          <button
            onClick={() => setEditing(true)}
            className="opacity-0 group-hover:opacity-100 p-0.5 text-white/30 hover:text-white/60 transition-opacity"
          >
            <Pencil size={12} />
          </button>
        </div>
      )}
    </div>
  );
}

function NoteComposer({ caseID, onAdded }: { caseID: string; onAdded: () => void }) {
  const [body, setBody] = useState("");
  const [saving, setSaving] = useState(false);

  async function submit() {
    if (!body.trim()) return;
    setSaving(true);
    try {
      await api.post(`/api/v1/cases/${caseID}/notes`, { body: body.trim() });
      setBody("");
      onAdded();
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-2">
      <textarea
        value={body}
        onChange={(e) => setBody(e.target.value)}
        placeholder="Add a note… (Markdown supported)"
        rows={3}
        className="w-full bg-white/[0.03] border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-white/20 resize-none focus:border-white/20 focus:outline-none"
      />
      <div className="flex justify-end">
        <button
          onClick={submit}
          disabled={saving || !body.trim()}
          className="px-3 py-1.5 text-sm rounded-lg bg-[hsl(var(--primary)/.9)] hover:bg-[hsl(var(--primary))] disabled:opacity-40 font-medium flex items-center gap-1.5 text-white transition-colors"
        >
          <Plus size={13} /> {saving ? "Adding…" : "Add Note"}
        </button>
      </div>
    </div>
  );
}

function LinkAlertModal({ caseID, onLinked, onClose }: { caseID: string; onLinked: () => void; onClose: () => void }) {
  const [alertID, setAlertID] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function handleLink() {
    if (!alertID.trim()) { setError("Alert ID required"); return; }
    setSaving(true); setError("");
    try {
      await api.post(`/api/v1/cases/${caseID}/alerts`, { alert_id: alertID.trim() });
      onLinked();
      onClose();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to link");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[hsl(var(--card))] border border-[hsl(var(--border))] rounded-xl w-full max-w-sm shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[hsl(var(--border))]">
          <h2 className="font-semibold text-sm">Link Alert to Case</h2>
          <button onClick={onClose} className="text-white/40 hover:text-white text-xl leading-none">&times;</button>
        </div>
        <div className="p-5 space-y-3">
          {error && <p className="text-xs text-red-400 bg-red-500/10 px-3 py-2 rounded-lg">{error}</p>}
          <div>
            <label className="text-xs text-white/40 mb-1 block">Alert ID</label>
            <input
              value={alertID}
              onChange={(e) => setAlertID(e.target.value)}
              autoFocus
              placeholder="alert-…"
              className="w-full bg-white/[0.03] border border-white/10 rounded-lg px-3 py-1.5 text-sm font-mono text-white focus:outline-none focus:border-white/20"
            />
          </div>
        </div>
        <div className="flex justify-end gap-2 px-5 py-3 border-t border-[hsl(var(--border))]">
          <button onClick={onClose} className="px-3 py-1.5 text-sm rounded-lg border border-white/10 hover:bg-white/5 text-white/60 hover:text-white transition-colors">
            Cancel
          </button>
          <button
            onClick={handleLink}
            disabled={saving}
            className="px-4 py-1.5 text-sm rounded-lg bg-[hsl(var(--primary)/.9)] hover:bg-[hsl(var(--primary))] disabled:opacity-50 font-medium text-white transition-colors"
          >
            {saving ? "Linking…" : "Link Alert"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function CaseDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [linkModalOpen, setLinkModalOpen] = useState(false);
  const [narrativeLoading, setNarrativeLoading] = useState(false);
  const [narrative, setNarrative] = useState("");

  const fetchCase = useCallback(
    (signal: AbortSignal) => api.get<CaseDetail>(`/api/v1/cases/${id}`, undefined, signal),
    [id]
  );
  const { data, loading, error, refetch } = useApi(fetchCase);

  const cs = data?.case;
  const notes = data?.notes ?? [];
  const alerts = data?.alerts ?? [];

  async function updateField(field: string, value: unknown) {
    if (!cs) return;
    await api.put(`/api/v1/cases/${id}`, { ...cs, [field]: value });
    refetch();
  }

  async function handleGenerateNarrative() {
    setNarrativeLoading(true);
    try {
      const res = await api.post<{ narrative: string }>(`/api/v1/cases/${id}/summarise`, {});
      setNarrative(res.narrative);
    } catch {
      setNarrative("AI narrative unavailable — check LLM settings.");
    } finally {
      setNarrativeLoading(false);
    }
  }

  async function deleteNote(noteID: string) {
    if (!confirm("Delete this note?")) return;
    await api.del(`/api/v1/cases/${id}/notes/${noteID}`);
    refetch();
  }

  async function unlinkAlert(alertID: string) {
    if (!confirm("Unlink this alert from the case?")) return;
    await api.del(`/api/v1/cases/${id}/alerts/${alertID}`);
    refetch();
  }

  if (loading) return <div className="p-8 text-sm text-white/40">Loading…</div>;
  if (error || !cs) return <div className="p-8 text-sm text-red-400">{error ?? "Case not found"}</div>;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start gap-3">
        <Link href="/cases" className="mt-0.5 text-white/40 hover:text-white/70 transition-colors">
          <ArrowLeft size={18} />
        </Link>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-xl font-semibold text-white">{cs.title}</h1>
            <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-semibold border ${STATUS_STYLE[cs.status] ?? "bg-white/5 text-white/40 border-white/10"}`}>
              {cs.status}
            </span>
          </div>
          {cs.description && <p className="text-sm text-white/50 mt-1">{cs.description}</p>}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: notes + linked alerts */}
        <div className="lg:col-span-2 space-y-6">

          {/* Notes */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white/70 uppercase tracking-wider">Notes</h2>
              <button
                onClick={handleGenerateNarrative}
                disabled={narrativeLoading}
                className="flex items-center gap-1 text-xs text-violet-400 hover:text-violet-300 disabled:opacity-40 transition-colors"
              >
                <Sparkles size={11} />
                {narrativeLoading ? "Generating…" : "AI Narrative"}
              </button>
            </div>

            {narrative && (
              <div className="rounded-xl border border-violet-500/20 bg-violet-500/5 p-4">
                <div className="flex items-center gap-1.5 mb-2 text-xs text-violet-400">
                  <Sparkles size={11} /> AI-generated narrative
                </div>
                <p className="text-sm text-white/70 leading-relaxed whitespace-pre-wrap">{narrative}</p>
              </div>
            )}

            <NoteComposer caseID={id} onAdded={refetch} />

            {notes.length === 0 && (
              <p className="text-xs text-white/25 text-center py-6">No notes yet.</p>
            )}

            <div className="space-y-3">
              {[...notes].reverse().map((note) => (
                <div key={note.id} className="rounded-xl border border-white/10 bg-white/[0.02] p-4 group">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-white/40">
                      <span className="text-white/60 font-medium">{note.author || "system"}</span>
                      {" · "}{timeAgo(note.created_at)}
                      {note.updated_at !== note.created_at && " (edited)"}
                    </span>
                    <button
                      onClick={() => deleteNote(note.id)}
                      className="opacity-0 group-hover:opacity-100 p-1 text-white/30 hover:text-red-400 transition-opacity"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                  <p className="text-sm text-white/80 whitespace-pre-wrap leading-relaxed">{note.body}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Linked Alerts */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white/70 uppercase tracking-wider">
                Linked Alerts <span className="text-white/30 font-normal">({alerts.length})</span>
              </h2>
              <button
                onClick={() => setLinkModalOpen(true)}
                className="flex items-center gap-1 text-xs text-[hsl(var(--primary))] hover:text-[hsl(var(--primary)/.8)] transition-colors"
              >
                <Link2 size={12} /> Link alert
              </button>
            </div>

            {alerts.length === 0 && (
              <p className="text-xs text-white/25 text-center py-6">No alerts linked yet.</p>
            )}

            <div className="space-y-2">
              {alerts.map((a) => (
                <div key={a.id} className="flex items-center gap-3 rounded-xl border border-white/10 bg-white/[0.02] px-4 py-2.5">
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${severityBgClass(a.severity)}`} />
                  <div className="flex-1 min-w-0">
                    <Link
                      href={`/alerts?id=${a.id}`}
                      className="text-sm font-medium text-white hover:text-[hsl(var(--primary))] transition-colors truncate block"
                    >
                      {a.title}
                    </Link>
                    <span className="text-xs text-white/40">{a.hostname} · {a.rule_name} · {timeAgo(a.last_seen)}</span>
                  </div>
                  <span className="text-xs text-white/40 shrink-0">{severityLabel(a.severity)}</span>
                  <button
                    onClick={() => unlinkAlert(a.id)}
                    className="p-1 text-white/20 hover:text-red-400 shrink-0 transition-colors"
                  >
                    <X size={13} />
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: metadata */}
        <div className="space-y-4">
          <div className="rounded-xl border border-white/10 bg-white/[0.02] p-5 space-y-4">
            <h2 className="text-xs font-semibold text-white/40 uppercase tracking-wider">Details</h2>

            <div>
              <span className="text-xs text-white/40 block mb-1.5">Status</span>
              <div className="flex flex-wrap gap-1">
                {STATUSES.map((s) => (
                  <button
                    key={s}
                    onClick={() => updateField("status", s)}
                    className={`px-2 py-0.5 rounded-lg text-xs font-medium border transition-colors ${
                      cs.status === s
                        ? STATUS_STYLE[s] ?? "bg-white/10 text-white border-white/20"
                        : "bg-white/[0.03] border-white/10 text-white/40 hover:border-white/20 hover:text-white/60"
                    }`}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <span className="text-xs text-white/40 block mb-1.5">Severity</span>
              <div className="flex gap-1">
                {[1, 2, 3, 4].map((v) => (
                  <button
                    key={v}
                    onClick={() => updateField("severity", v)}
                    className={`px-2 py-0.5 rounded-lg text-xs font-medium border transition-colors ${
                      cs.severity === v
                        ? "bg-white/10 text-white border-white/20"
                        : "bg-white/[0.03] border-white/10 text-white/40 hover:border-white/20"
                    }`}
                  >
                    {severityLabel(v)}
                  </button>
                ))}
              </div>
            </div>

            <EditField
              label="Assignee"
              value={cs.assignee}
              onSave={(v) => updateField("assignee", v)}
            />

            <div>
              <span className="text-xs text-white/40 block mb-1.5">MITRE ATT&amp;CK</span>
              <div className="flex flex-wrap gap-1">
                {(cs.mitre_ids ?? []).map((m) => (
                  <span key={m} className="px-1.5 py-0.5 rounded bg-white/5 text-xs font-mono text-violet-400">{m}</span>
                ))}
                {(cs.mitre_ids ?? []).length === 0 && <span className="text-xs text-white/20 italic">none</span>}
              </div>
            </div>

            <div>
              <span className="text-xs text-white/40 block mb-1.5">Tags</span>
              <div className="flex flex-wrap gap-1">
                {(cs.tags ?? []).map((t) => (
                  <span key={t} className="px-1.5 py-0.5 rounded bg-white/5 text-xs text-white/60">{t}</span>
                ))}
                {(cs.tags ?? []).length === 0 && <span className="text-xs text-white/20 italic">none</span>}
              </div>
            </div>

            <div className="pt-3 border-t border-white/10 text-xs text-white/30 space-y-1.5">
              <div>Created by <span className="text-white/50">{cs.created_by || "system"}</span></div>
              <div>Opened {timeAgo(cs.created_at)}</div>
              {cs.closed_at && <div>Closed {timeAgo(cs.closed_at)}</div>}
              <div className="font-mono text-white/20 truncate">{cs.id}</div>
            </div>
          </div>
        </div>
      </div>

      {linkModalOpen && (
        <LinkAlertModal caseID={id} onLinked={refetch} onClose={() => setLinkModalOpen(false)} />
      )}
    </div>
  );
}
