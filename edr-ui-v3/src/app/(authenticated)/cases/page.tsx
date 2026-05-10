"use client";

import { useState, useCallback } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { timeAgo } from "@/lib/utils";
import { Plus, FolderOpen, ChevronRight } from "lucide-react";
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

const STATUSES = ["", "OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"];

const STATUS_STYLE: Record<string, string> = {
  OPEN:          "bg-red-500/15 text-red-400",
  INVESTIGATING: "bg-amber-500/15 text-amber-400",
  CONTAINED:     "bg-blue-500/15 text-blue-400",
  RESOLVED:      "bg-emerald-500/15 text-emerald-400",
  CLOSED:        "bg-neutral-700 text-neutral-400",
};

const SEV_LABEL: Record<number, { label: string; cls: string }> = {
  1: { label: "Low",      cls: "text-blue-400" },
  2: { label: "Medium",   cls: "text-amber-400" },
  3: { label: "High",     cls: "text-orange-400" },
  4: { label: "Critical", cls: "text-red-400" },
};

function NewCaseModal({ onSave, onClose }: { onSave: (d: Partial<Case>) => Promise<void>; onClose: () => void }) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState(2);
  const [assignee, setAssignee] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function handleSave() {
    if (!title.trim()) { setError("Title is required"); return; }
    setSaving(true); setError("");
    try {
      await onSave({ title: title.trim(), description, severity, assignee, tags: [], mitre_ids: [] });
      onClose();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-neutral-900 border border-neutral-700 rounded-xl w-full max-w-md">
        <div className="flex items-center justify-between px-5 py-4 border-b border-neutral-800">
          <h2 className="font-semibold text-sm">New Case</h2>
          <button onClick={onClose} className="text-neutral-400 hover:text-white text-lg leading-none">&times;</button>
        </div>
        <div className="p-5 space-y-3">
          {error && <p className="text-xs text-red-400 bg-red-500/10 px-3 py-2 rounded">{error}</p>}
          <div>
            <label className="text-xs text-neutral-400 mb-1 block">Title *</label>
            <input value={title} onChange={(e) => setTitle(e.target.value)} autoFocus
              className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm" />
          </div>
          <div>
            <label className="text-xs text-neutral-400 mb-1 block">Description</label>
            <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={3}
              className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm resize-none" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-neutral-400 mb-1 block">Severity</label>
              <select value={severity} onChange={(e) => setSeverity(Number(e.target.value))}
                className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm">
                <option value={1}>Low</option>
                <option value={2}>Medium</option>
                <option value={3}>High</option>
                <option value={4}>Critical</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-neutral-400 mb-1 block">Assignee</label>
              <input value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder="username"
                className="w-full bg-neutral-800 border border-neutral-700 rounded px-2 py-1.5 text-sm" />
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-2 px-5 py-3 border-t border-neutral-800">
          <button onClick={onClose} className="px-3 py-1.5 text-sm rounded border border-neutral-700 hover:bg-neutral-800">Cancel</button>
          <button onClick={handleSave} disabled={saving}
            className="px-4 py-1.5 text-sm rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 font-medium">
            {saving ? "Creating…" : "Create Case"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function CasesPage() {
  const [statusFilter, setStatusFilter] = useState("");
  const [showModal, setShowModal] = useState(false);

  const fetchCases = useCallback(
    () => api.get<{ cases: Case[]; total: number }>(`/api/v1/cases?limit=100${statusFilter ? `&status=${statusFilter}` : ""}`),
    [statusFilter]
  );
  const { data, loading, error, refetch } = useApi(fetchCases);
  const cases = data?.cases ?? [];

  async function handleCreate(payload: Partial<Case>) {
    await api.post("/api/v1/cases", payload);
    refetch();
  }

  const openCount   = cases.filter((c) => c.status === "OPEN").length;
  const activeCount = cases.filter((c) => c.status === "INVESTIGATING" || c.status === "CONTAINED").length;

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Cases</h1>
          <p className="text-xs text-neutral-400 mt-0.5">Investigation workflow — group alerts, track status, document findings</p>
        </div>
        <button onClick={() => setShowModal(true)}
          className="flex items-center gap-2 px-3 py-1.5 text-sm rounded bg-cyan-600 hover:bg-cyan-500 font-medium">
          <Plus size={15} /> New Case
        </button>
      </div>

      {!loading && cases.length > 0 && (
        <div className="flex gap-5 text-sm">
          <span className="text-red-400">{openCount} open</span>
          <span className="text-neutral-500">·</span>
          <span className="text-amber-400">{activeCount} active</span>
          <span className="text-neutral-500">·</span>
          <span className="text-neutral-400">{data?.total ?? cases.length} total</span>
        </div>
      )}

      {/* Status filter pills */}
      <div className="flex flex-wrap gap-2">
        {STATUSES.map((s) => (
          <button key={s}
            onClick={() => setStatusFilter(s)}
            className={`px-3 py-1 rounded-full text-xs font-medium border transition-colors ${
              statusFilter === s
                ? "bg-cyan-600 border-cyan-500 text-white"
                : "bg-neutral-800 border-neutral-700 text-neutral-400 hover:border-neutral-600"
            }`}
          >
            {s || "All"}
          </button>
        ))}
      </div>

      {loading && <p className="text-sm text-neutral-400">Loading…</p>}
      {error && <p className="text-sm text-red-400">{error}</p>}

      {!loading && cases.length === 0 && (
        <div className="text-center py-16 text-neutral-500">
          <FolderOpen size={32} className="mx-auto mb-3 opacity-30" />
          <p className="text-sm">No cases{statusFilter ? ` with status "${statusFilter}"` : ""}.</p>
        </div>
      )}

      <div className="space-y-2">
        {cases.map((c) => {
          const sev = SEV_LABEL[c.severity];
          return (
            <Link key={c.id} href={`/cases/${c.id}`}
              className="flex items-center gap-3 bg-neutral-900 border border-neutral-800 hover:border-neutral-700 rounded-xl p-4 transition-colors group">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-medium text-sm group-hover:text-cyan-300 transition-colors">{c.title}</span>
                  <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${STATUS_STYLE[c.status] ?? "bg-neutral-800 text-neutral-400"}`}>
                    {c.status}
                  </span>
                  {sev && <span className={`text-xs font-medium ${sev.cls}`}>{sev.label}</span>}
                </div>
                {c.description && (
                  <p className="text-xs text-neutral-400 mt-0.5 truncate">{c.description}</p>
                )}
                <div className="flex items-center gap-3 mt-1.5 text-xs text-neutral-500">
                  <span>{c.alert_count} alert{c.alert_count !== 1 ? "s" : ""}</span>
                  {c.assignee && <span>→ {c.assignee}</span>}
                  {c.mitre_ids && c.mitre_ids.length > 0 && (
                    <span className="font-mono">{c.mitre_ids.slice(0, 3).join(", ")}{c.mitre_ids.length > 3 ? "…" : ""}</span>
                  )}
                  <span>updated {timeAgo(c.updated_at)}</span>
                </div>
              </div>
              <ChevronRight size={16} className="text-neutral-600 group-hover:text-neutral-400 shrink-0" />
            </Link>
          );
        })}
      </div>

      {showModal && (
        <NewCaseModal onSave={handleCreate} onClose={() => setShowModal(false)} />
      )}
    </div>
  );
}
