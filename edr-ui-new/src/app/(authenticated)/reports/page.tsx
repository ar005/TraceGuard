"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";

interface Report {
  id: string;
  title: string;
  type: string;
  format: string;
  status: string;
  row_count: number;
  created_by: string;
  created_at: string;
  completed_at: string | null;
}

type ReportType = "alerts" | "incidents";

const TYPE_LABELS: Record<ReportType, string> = {
  alerts: "Alerts",
  incidents: "Incidents",
};

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    READY:
      "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
    GENERATING:
      "text-blue-400 bg-blue-500/10 border-blue-500/20",
    FAILED: "text-red-400 bg-red-500/10 border-red-500/20",
  };
  return (
    <span
      className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${styles[status] ?? "text-white/40 bg-white/5 border-white/10"}`}
    >
      {status}
    </span>
  );
}

export default function ReportsPage() {
  const [generating, setGenerating] = useState(false);
  const [genError, setGenError] = useState<string | null>(null);

  const [form, setForm] = useState<{
    type: ReportType;
    title: string;
    limit: number;
  }>({
    type: "alerts",
    title: "",
    limit: 1000,
  });

  const { data: reports, loading, refetch } = useApi<Report[]>(
    () => api.get("/reports"),
  );

  const rows = reports ?? [];

  async function handleGenerate(e: React.FormEvent) {
    e.preventDefault();
    setGenError(null);
    setGenerating(true);
    try {
      const title =
        form.title.trim() ||
        `${TYPE_LABELS[form.type]} Report — ${new Date().toLocaleDateString()}`;
      await api.post("/reports", {
        type: form.type,
        title,
        limit: form.limit,
      });
      refetch();
    } catch (err: unknown) {
      setGenError(err instanceof Error ? err.message : "Generation failed");
    } finally {
      setGenerating(false);
    }
  }

  function downloadUrl(id: string) {
    const base =
      process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8080";
    return `${base}/api/v1/reports/${id}/download`;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-white">Reports</h1>
        <p className="text-sm text-white/50 mt-0.5">
          Generate and download CSV exports of alerts and incidents
        </p>
      </div>

      {/* Generate form */}
      <form
        onSubmit={handleGenerate}
        className="rounded-xl border border-white/10 bg-white/[0.02] p-5 space-y-4"
      >
        <p className="text-sm font-medium text-white">Generate New Report</p>
        <div className="grid grid-cols-3 gap-4">
          <div className="space-y-1">
            <label className="text-xs text-white/50">Type</label>
            <select
              value={form.type}
              onChange={(e) =>
                setForm((f) => ({ ...f, type: e.target.value as ReportType }))
              }
              className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50"
            >
              <option value="alerts">Alerts</option>
              <option value="incidents">Incidents</option>
            </select>
          </div>
          <div className="space-y-1">
            <label className="text-xs text-white/50">
              Title{" "}
              <span className="text-white/30">(optional)</span>
            </label>
            <input
              type="text"
              value={form.title}
              onChange={(e) =>
                setForm((f) => ({ ...f, title: e.target.value }))
              }
              placeholder="My weekly alerts report"
              className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder:text-white/20 focus:outline-none focus:border-blue-500/50"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-white/50">Max rows</label>
            <select
              value={form.limit}
              onChange={(e) =>
                setForm((f) => ({ ...f, limit: Number(e.target.value) }))
              }
              className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50"
            >
              {[100, 500, 1000, 5000, 10000].map((n) => (
                <option key={n} value={n}>
                  {n.toLocaleString()}
                </option>
              ))}
            </select>
          </div>
        </div>

        {genError && (
          <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
            {genError}
          </p>
        )}

        <button
          type="submit"
          disabled={generating}
          className="px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white transition-colors"
        >
          {generating ? "Generating…" : "Generate Report"}
        </button>
      </form>

      {/* Reports list */}
      <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 flex items-center justify-between">
          <p className="text-sm font-medium text-white">Past Reports</p>
          <button
            onClick={() => refetch()}
            className="text-xs text-white/40 hover:text-white/70 transition-colors"
          >
            Refresh
          </button>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/10">
              {[
                "Title",
                "Type",
                "Status",
                "Rows",
                "Created by",
                "Created at",
                "",
              ].map((h) => (
                <th
                  key={h}
                  className="text-left px-4 py-3 text-xs font-medium text-white/40 uppercase tracking-wider"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {loading && (
              <tr>
                <td
                  colSpan={7}
                  className="px-4 py-10 text-center text-white/30 text-sm"
                >
                  Loading…
                </td>
              </tr>
            )}
            {!loading && rows.length === 0 && (
              <tr>
                <td
                  colSpan={7}
                  className="px-4 py-10 text-center text-white/30 text-sm"
                >
                  No reports yet — generate your first one above.
                </td>
              </tr>
            )}
            {rows.map((r) => (
              <tr
                key={r.id}
                className="hover:bg-white/[0.02] transition-colors"
              >
                <td className="px-4 py-3 text-white font-medium max-w-xs truncate">
                  {r.title}
                </td>
                <td className="px-4 py-3 text-white/50 text-xs capitalize">
                  {r.type}
                </td>
                <td className="px-4 py-3">
                  <StatusBadge status={r.status} />
                </td>
                <td className="px-4 py-3 text-white/50 font-mono text-xs">
                  {r.row_count > 0 ? r.row_count.toLocaleString() : "—"}
                </td>
                <td className="px-4 py-3 text-white/40 text-xs">
                  {r.created_by}
                </td>
                <td className="px-4 py-3 text-white/30 text-xs font-mono">
                  {new Date(r.created_at).toLocaleString()}
                </td>
                <td className="px-4 py-3">
                  {r.status === "READY" && (
                    <a
                      href={downloadUrl(r.id)}
                      download
                      className="text-xs px-3 py-1.5 rounded-lg bg-blue-600/20 border border-blue-500/30 text-blue-400 hover:bg-blue-600/30 transition-colors"
                    >
                      Download CSV
                    </a>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
