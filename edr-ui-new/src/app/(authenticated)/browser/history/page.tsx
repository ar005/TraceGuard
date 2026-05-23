"use client";

import { useCallback, useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn, formatDate } from "@/lib/utils";
import { Clock, Globe, RefreshCw, Loader2, Search, Download, BookOpen } from "lucide-react";
import type { Event, Agent } from "@/types";
import { exportToCSV } from "@/lib/export";

const BROWSER_EMOJI: Record<string, string> = {
  Chrome: "🌐",
  Chromium: "🌐",
  Brave: "🦁",
  Edge: "🔵",
  Firefox: "🦊",
};

interface HistoryPayload {
  url: string;
  domain: string;
  title?: string;
  visit_count?: number;
  last_visit_at?: string;
  browser_name?: string;
  profile_path?: string;
}

export default function BrowserHistoryPage() {
  const [selectedAgent, setSelectedAgent] = useState("");
  const [search, setSearch] = useState("");

  const fetchAgents = useCallback(
    (s: AbortSignal) =>
      api
        .get<{ agents?: Agent[] } | Agent[]>("/api/v1/agents", undefined, s)
        .then((r) => (Array.isArray(r) ? r : (r as { agents?: Agent[] }).agents ?? [])),
    []
  );
  const { data: agents } = useApi(fetchAgents);

  const fetchEvents = useCallback(
    (s: AbortSignal) =>
      api
        .get<{ events?: Event[] } | Event[]>(
          "/api/v1/events",
          { event_type: "BROWSER_HISTORY", agent_id: selectedAgent || undefined, limit: 500 },
          s
        )
        .then((r) => (Array.isArray(r) ? r : (r as { events?: Event[] }).events ?? [])),
    [selectedAgent]
  );
  const { data: rawEvents, loading, refetch } = useApi(fetchEvents);

  const events = (rawEvents ?? []) as Event[];

  const filtered = events.filter((e) => {
    if (!search) return true;
    const p = e.payload as unknown as HistoryPayload;
    const q = search.toLowerCase();
    return (
      p.url?.toLowerCase().includes(q) ||
      p.domain?.toLowerCase().includes(q) ||
      p.title?.toLowerCase().includes(q) ||
      p.browser_name?.toLowerCase().includes(q)
    );
  });

  const handleExport = () => {
    exportToCSV(filtered, "browser-history");
  };

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-sky-500/15 flex items-center justify-center">
            <BookOpen size={20} className="text-sky-400" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-[var(--color-text-primary)]">Browser History</h1>
            <p className="text-sm text-[var(--color-text-muted)]">
              URL visits polled from agent Chrome/Firefox SQLite history databases
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleExport}
            disabled={filtered.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] text-sm text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] disabled:opacity-40 transition-colors"
          >
            <Download size={13} /> Export
          </button>
          <button
            onClick={refetch}
            className="text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)] transition-colors"
          >
            <RefreshCw size={15} />
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <select
          value={selectedAgent}
          onChange={(e) => setSelectedAgent(e.target.value)}
          className="px-3 py-1.5 rounded-lg bg-[var(--color-bg-secondary)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] focus:outline-none focus:border-sky-500"
        >
          <option value="">All agents</option>
          {(agents ?? []).map((a) => (
            <option key={a.id} value={a.id}>
              {a.hostname}
            </option>
          ))}
        </select>

        <div className="flex items-center gap-1.5 flex-1 min-w-[200px] px-3 py-1.5 rounded-lg bg-[var(--color-bg-secondary)] border border-[var(--color-border)]">
          <Search size={13} className="text-[var(--color-text-muted)] shrink-0" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by URL, domain, or title…"
            className="flex-1 bg-transparent text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)] focus:outline-none"
          />
        </div>
      </div>

      {/* Stats strip */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "Total visits", value: events.length },
          {
            label: "Unique domains",
            value: new Set(events.map((e) => (e.payload as unknown as HistoryPayload).domain)).size,
          },
          {
            label: "Browsers seen",
            value: new Set(events.map((e) => (e.payload as unknown as HistoryPayload).browser_name).filter(Boolean)).size,
          },
        ].map(({ label, value }) => (
          <div
            key={label}
            className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl px-4 py-3"
          >
            <p className="text-[11px] text-[var(--color-text-muted)] uppercase tracking-wide">{label}</p>
            <p className="text-2xl font-semibold text-[var(--color-text-primary)] mt-0.5">{value}</p>
          </div>
        ))}
      </div>

      {/* Table */}
      <div className="bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-xl overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-[var(--color-border)]">
          <Globe size={14} className="text-sky-400" />
          <p className="text-sm font-medium text-[var(--color-text-primary)]">
            Visits
          </p>
          <span className="ml-auto text-xs text-[var(--color-text-muted)] bg-[var(--color-bg-tertiary)] px-2 py-0.5 rounded-full">
            {filtered.length}
          </span>
        </div>

        {loading ? (
          <div className="flex justify-center py-12">
            <Loader2 size={20} className="animate-spin text-[var(--color-text-muted)]" />
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-12 space-y-2">
            <Clock size={28} className="mx-auto text-[var(--color-text-muted)] opacity-40" />
            <p className="text-sm text-[var(--color-text-muted)]">
              {events.length === 0
                ? "No history events yet — enable browser_history in the agent config"
                : "No results match the filter"}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[10px] uppercase tracking-widest text-[var(--color-text-muted)] border-b border-[var(--color-border)]">
                  <th className="text-left px-4 py-2 font-medium">When</th>
                  <th className="text-left px-4 py-2 font-medium">Agent</th>
                  <th className="text-left px-4 py-2 font-medium">Browser</th>
                  <th className="text-left px-4 py-2 font-medium">URL / Title</th>
                  <th className="text-right px-4 py-2 font-medium">Visits</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border)]">
                {filtered.map((event) => {
                  const p = event.payload as unknown as HistoryPayload;
                  const emoji = BROWSER_EMOJI[p.browser_name ?? ""] ?? "🌐";
                  return (
                    <tr
                      key={event.id}
                      className="hover:bg-[var(--color-bg-tertiary)] transition-colors"
                    >
                      <td className="px-4 py-2.5 whitespace-nowrap text-[var(--color-text-muted)]">
                        {formatDate(event.timestamp)}
                      </td>
                      <td className="px-4 py-2.5 whitespace-nowrap text-[var(--color-text-secondary)]">
                        {event.hostname}
                      </td>
                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <span className="flex items-center gap-1.5">
                          <span>{emoji}</span>
                          <span className={cn("text-xs", p.browser_name ? "text-[var(--color-text-secondary)]" : "text-[var(--color-text-muted)]")}>
                            {p.browser_name ?? "Unknown"}
                          </span>
                        </span>
                      </td>
                      <td className="px-4 py-2.5 max-w-sm">
                        <a
                          href={p.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sky-400 hover:underline truncate block max-w-xs font-mono text-xs"
                          title={p.url}
                        >
                          {p.url}
                        </a>
                        {p.title && (
                          <p className="text-[var(--color-text-muted)] text-xs truncate mt-0.5">{p.title}</p>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-right text-[var(--color-text-muted)]">
                        {p.visit_count ?? 1}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
