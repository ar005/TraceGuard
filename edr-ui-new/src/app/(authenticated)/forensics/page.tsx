"use client";

import { useCallback, useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn, formatDate } from "@/lib/utils";
import {
  Archive, Download, HardDrive, Loader2, Plus, RefreshCw,
  CheckCircle2, AlertCircle, Clock, X, FileCode, Cpu, FolderSearch,
} from "lucide-react";
import type { Agent } from "@/types";

interface ForensicsJob {
  id: string;
  agent_id: string;
  hostname: string;
  job_type: "artifacts" | "process_memory" | "file" | "full";
  status: "pending" | "collecting" | "ready" | "failed";
  params: Record<string, unknown>;
  bundle_size: number;
  error_msg?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

const TYPE_META: Record<string, { label: string; icon: React.ElementType; color: string; desc: string }> = {
  artifacts:      { label: "Artifacts",       icon: FolderSearch, color: "text-sky-400",    desc: "Logs, cron, bash history, /tmp, network state" },
  process_memory: { label: "Process Memory",  icon: Cpu,          color: "text-purple-400", desc: "Proc filesystem snapshot for a specific PID" },
  file:           { label: "File Download",   icon: FileCode,     color: "text-amber-400",  desc: "Download a specific file by path" },
  full:           { label: "Full Collection", icon: HardDrive,    color: "text-red-400",    desc: "Artifacts + proc snapshot for all running PIDs" },
};

const STATUS_META: Record<string, { label: string; color: string; icon: React.ElementType }> = {
  pending:    { label: "Pending",    color: "text-amber-400",  icon: Clock },
  collecting: { label: "Collecting", color: "text-sky-400",    icon: Loader2 },
  ready:      { label: "Ready",      color: "text-green-400",  icon: CheckCircle2 },
  failed:     { label: "Failed",     color: "text-red-400",    icon: AlertCircle },
};

function formatBytes(b: number): string {
  if (b === 0) return "—";
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / (1024 * 1024)).toFixed(1)} MB`;
}

export default function ForensicsPage() {
  const [showForm, setShowForm] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState("");
  const [jobType, setJobType] = useState<ForensicsJob["job_type"]>("artifacts");
  const [paramPID, setParamPID] = useState("");
  const [paramPath, setParamPath] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);

  const fetchAgents = useCallback(
    (s: AbortSignal) =>
      api
        .get<{ agents?: Agent[] } | Agent[]>("/api/v1/agents", undefined, s)
        .then((r) => (Array.isArray(r) ? r : (r as { agents?: Agent[] }).agents ?? [])),
    []
  );
  const { data: agents } = useApi(fetchAgents);

  const fetchJobs = useCallback(
    (s: AbortSignal) =>
      api
        .get<{ jobs: ForensicsJob[] }>("/api/v1/forensics/jobs", undefined, s)
        .then((r) => r.jobs ?? []),
    []
  );
  const { data: jobs, loading, refetch } = useApi(fetchJobs);

  const showToast = (msg: string, ok: boolean) => {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 3500);
  };

  const handleSubmit = async () => {
    if (!selectedAgent || !jobType) return;
    const params: Record<string, unknown> = {};
    if (jobType === "process_memory" && paramPID) params.pid = parseInt(paramPID, 10);
    if (jobType === "file" && paramPath) params.path = paramPath;

    setSubmitting(true);
    try {
      await api.post(`/api/v1/agents/${selectedAgent}/forensics/collect`, {
        job_type: jobType,
        params,
      });
      showToast("Collection job created — agent will upload bundle within 60s", true);
      setShowForm(false);
      setParamPID("");
      setParamPath("");
      refetch();
    } catch (e: unknown) {
      showToast(e instanceof Error ? e.message : "Failed to create job", false);
    } finally {
      setSubmitting(false);
    }
  };

  const readyJobs = (jobs ?? []).filter((j) => j.status === "ready").length;
  const activeJobs = (jobs ?? []).filter((j) => j.status === "pending" || j.status === "collecting").length;

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-orange-500/15 flex items-center justify-center">
            <Archive size={20} className="text-orange-400" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-[var(--color-text-primary)]">Forensic Acquisition</h1>
            <p className="text-sm text-[var(--color-text-muted)]">
              Remote artifact collection from live agents — bundles delivered as tar.gz
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={refetch}
            className="text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)] transition-colors"
          >
            <RefreshCw size={15} />
          </button>
          <button
            onClick={() => setShowForm(true)}
            className="flex items-center gap-1.5 px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <Plus size={14} /> New Collection
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "Total jobs", value: (jobs ?? []).length },
          { label: "Active",     value: activeJobs },
          { label: "Ready",      value: readyJobs },
        ].map(({ label, value }) => (
          <div key={label} className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl px-4 py-3">
            <p className="text-[11px] text-[var(--color-text-muted)] uppercase tracking-wide">{label}</p>
            <p className="text-2xl font-semibold text-[var(--color-text-primary)] mt-0.5">{value}</p>
          </div>
        ))}
      </div>

      {/* New Collection Form */}
      {showForm && (
        <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium text-[var(--color-text-primary)]">New Collection Job</p>
            <button onClick={() => setShowForm(false)} className="text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]">
              <X size={16} />
            </button>
          </div>

          {/* Agent selector */}
          <div className="space-y-1">
            <label className="text-xs text-[var(--color-text-muted)]">Target Agent</label>
            <select
              value={selectedAgent}
              onChange={(e) => setSelectedAgent(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-orange-500"
            >
              <option value="">— Select agent —</option>
              {(agents ?? []).map((a) => (
                <option key={a.id} value={a.id}>
                  {a.hostname} ({a.id.slice(0, 8)}…)
                </option>
              ))}
            </select>
          </div>

          {/* Collection type grid */}
          <div className="space-y-1">
            <label className="text-xs text-[var(--color-text-muted)]">Collection Type</label>
            <div className="grid grid-cols-2 gap-2">
              {(Object.keys(TYPE_META) as ForensicsJob["job_type"][]).map((t) => {
                const meta = TYPE_META[t];
                const Icon = meta.icon;
                return (
                  <button
                    key={t}
                    onClick={() => setJobType(t)}
                    className={cn(
                      "flex items-start gap-2.5 px-3 py-2.5 rounded-lg border text-left transition-colors",
                      jobType === t
                        ? "border-orange-500/50 bg-orange-500/10"
                        : "border-[var(--color-border)] bg-[var(--color-bg-tertiary)] hover:border-[var(--color-border-hover)]"
                    )}
                  >
                    <Icon size={16} className={cn("shrink-0 mt-0.5", meta.color)} />
                    <div>
                      <p className="text-xs font-medium text-[var(--color-text-primary)]">{meta.label}</p>
                      <p className="text-[10px] text-[var(--color-text-muted)] mt-0.5 leading-tight">{meta.desc}</p>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Type-specific params */}
          {jobType === "process_memory" && (
            <div className="space-y-1">
              <label className="text-xs text-[var(--color-text-muted)]">PID</label>
              <input
                type="number"
                value={paramPID}
                onChange={(e) => setParamPID(e.target.value)}
                placeholder="e.g. 1234"
                className="w-full px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:border-orange-500"
              />
            </div>
          )}
          {jobType === "file" && (
            <div className="space-y-1">
              <label className="text-xs text-[var(--color-text-muted)]">File Path</label>
              <input
                value={paramPath}
                onChange={(e) => setParamPath(e.target.value)}
                placeholder="/etc/passwd"
                className="w-full px-3 py-2 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:border-orange-500 font-mono"
              />
            </div>
          )}

          <button
            onClick={handleSubmit}
            disabled={submitting || !selectedAgent}
            className="flex items-center gap-1.5 px-4 py-2 bg-orange-600 hover:bg-orange-700 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
          >
            {submitting ? <Loader2 size={13} className="animate-spin" /> : <Archive size={13} />}
            Start Collection
          </button>
        </div>
      )}

      {/* Jobs table */}
      <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-[var(--color-border)]">
          <HardDrive size={14} className="text-orange-400" />
          <p className="text-sm font-medium text-[var(--color-text-primary)]">Collection Jobs</p>
          <span className="ml-auto text-xs text-[var(--color-text-muted)] bg-[var(--color-bg-tertiary)] px-2 py-0.5 rounded-full">
            {(jobs ?? []).length}
          </span>
        </div>

        {loading ? (
          <div className="flex justify-center py-12">
            <Loader2 size={20} className="animate-spin text-[var(--color-text-muted)]" />
          </div>
        ) : (jobs ?? []).length === 0 ? (
          <div className="text-center py-12 space-y-2">
            <Archive size={28} className="mx-auto text-[var(--color-text-muted)] opacity-40" />
            <p className="text-sm text-[var(--color-text-muted)]">No collection jobs yet</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[10px] uppercase tracking-widest text-[var(--color-text-muted)] border-b border-[var(--color-border)]">
                  <th className="text-left px-4 py-2 font-medium">Created</th>
                  <th className="text-left px-4 py-2 font-medium">Agent</th>
                  <th className="text-left px-4 py-2 font-medium">Type</th>
                  <th className="text-left px-4 py-2 font-medium">Status</th>
                  <th className="text-right px-4 py-2 font-medium">Size</th>
                  <th className="text-left px-4 py-2 font-medium">Created By</th>
                  <th className="px-4 py-2"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border)]">
                {(jobs ?? []).map((job) => {
                  const typeMeta = TYPE_META[job.job_type] ?? TYPE_META.artifacts;
                  const statusMeta = STATUS_META[job.status] ?? STATUS_META.pending;
                  const TypeIcon = typeMeta.icon;
                  const StatusIcon = statusMeta.icon;
                  return (
                    <tr key={job.id} className="hover:bg-[var(--color-bg-tertiary)] transition-colors">
                      <td className="px-4 py-2.5 whitespace-nowrap text-[var(--color-text-muted)] text-xs">
                        {formatDate(job.created_at)}
                      </td>
                      <td className="px-4 py-2.5 whitespace-nowrap text-[var(--color-text-secondary)]">
                        {job.hostname || job.agent_id.slice(0, 8)}
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="flex items-center gap-1.5">
                          <TypeIcon size={13} className={typeMeta.color} />
                          <span className="text-xs text-[var(--color-text-secondary)]">{typeMeta.label}</span>
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className={cn("flex items-center gap-1.5 text-xs font-medium", statusMeta.color)}>
                          <StatusIcon size={12} className={job.status === "collecting" ? "animate-spin" : ""} />
                          {statusMeta.label}
                        </span>
                        {job.error_msg && (
                          <p className="text-[10px] text-red-400 mt-0.5 truncate max-w-[200px]">{job.error_msg}</p>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-right text-[var(--color-text-muted)] text-xs font-mono">
                        {formatBytes(job.bundle_size)}
                      </td>
                      <td className="px-4 py-2.5 text-xs text-[var(--color-text-muted)]">
                        {job.created_by || "—"}
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        {job.status === "ready" && (
                          <a
                            href={`/api/v1/forensics/jobs/${job.id}/download`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-green-500/15 text-green-400 hover:bg-green-500/25 text-xs font-medium transition-colors"
                          >
                            <Download size={11} /> Download
                          </a>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Toast */}
      {toast && (
        <div className={cn(
          "fixed bottom-5 right-5 flex items-center gap-2 px-4 py-2.5 rounded-lg shadow-lg text-sm font-medium text-white z-50",
          toast.ok ? "bg-green-600" : "bg-red-600"
        )}>
          {toast.ok ? <CheckCircle2 size={15} /> : <AlertCircle size={15} />}
          {toast.msg}
        </div>
      )}
    </div>
  );
}
