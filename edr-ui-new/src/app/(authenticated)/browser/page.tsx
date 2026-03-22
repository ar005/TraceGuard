"use client";

import { useCallback, useMemo, useState } from "react";
import { Globe, Chrome, ExternalLink, ArrowRight, AlertTriangle, Filter, X } from "lucide-react";
import { api } from "@/lib/api-client";
import { useApi } from "@/hooks/use-api";
import { cn, formatDate, timeAgo } from "@/lib/utils";
import type { Agent, Event } from "@/types";

/* ── Constants ───────────────────────────────────────────────── */

const PAGE_SIZE = 100;

const STATUS_COLORS: Record<string, string> = {
  "2xx": "text-emerald-400",
  "3xx": "text-sky-400",
  "4xx": "text-amber-400",
  "5xx": "text-red-400",
  err: "text-red-500",
};

function statusGroup(code: number): string {
  if (code === 0) return "err";
  if (code < 300) return "2xx";
  if (code < 400) return "3xx";
  if (code < 500) return "4xx";
  return "5xx";
}

const BROWSER_ICONS: Record<string, string> = {
  Chrome: "🌐",
  Firefox: "🦊",
  Edge: "🔵",
  Safari: "🧭",
};

/* ── URL Detail Panel ────────────────────────────────────────── */

function s(v: unknown): string { return String(v ?? ""); }

interface BrowserPayload {
  url?: string; domain?: string; path?: string; method?: string;
  status_code?: number; content_type?: string; referrer?: string;
  tab_url?: string; resource_type?: string; server_ip?: string;
  from_cache?: boolean; error?: string; is_form_submit?: boolean;
  redirect_chain?: string[]; browser_name?: string;
}

function URLDetail({ event, onClose }: { event: Event; onClose: () => void }) {
  const p = (event.payload ?? {}) as BrowserPayload;
  const statusCode = p.status_code ?? 0;
  const redirectChain = p.redirect_chain ?? [];

  return (
    <div
      className="fixed inset-y-0 right-0 z-50 w-full max-w-md border-l shadow-xl overflow-y-auto animate-fade-in"
      style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
    >
      <div className="flex items-center justify-between p-4 border-b" style={{ borderColor: "var(--border)" }}>
        <h3 className="text-sm font-semibold font-heading">Request Detail</h3>
        <button
          onClick={onClose}
          className="text-xs rounded px-2 py-1 hover:bg-[var(--surface-2)] transition-colors"
          style={{ color: "var(--muted)" }}
        >
          <X size={14} />
        </button>
      </div>
      <div className="p-4 space-y-4">
        {/* URL */}
        <div>
          <div className="text-[10px] uppercase tracking-wider mb-1" style={{ color: "var(--muted)" }}>URL</div>
          <div className="font-mono text-xs break-all" style={{ color: "var(--fg)" }}>
            {p.url ?? ""}
          </div>
        </div>

        {/* Key fields grid */}
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div>
            <div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: "var(--muted)" }}>Method</div>
            <div className="font-semibold" style={{ color: "var(--fg)" }}>{p.method ?? "GET"}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: "var(--muted)" }}>Status</div>
            <div className={cn("font-mono font-bold", STATUS_COLORS[statusGroup(statusCode)])}>
              {statusCode === 0 ? "ERR" : String(statusCode)}
            </div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: "var(--muted)" }}>Domain</div>
            <div style={{ color: "var(--fg)" }}>{p.domain ?? ""}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: "var(--muted)" }}>Browser</div>
            <div style={{ color: "var(--fg)" }}>{p.browser_name ?? "Unknown"}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: "var(--muted)" }}>Server IP</div>
            <div className="font-mono" style={{ color: "var(--fg)" }}>{p.server_ip ?? "—"}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: "var(--muted)" }}>Content Type</div>
            <div style={{ color: "var(--fg)" }}>{p.content_type ?? "—"}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: "var(--muted)" }}>Type</div>
            <div style={{ color: "var(--fg)" }}>{p.resource_type ?? "—"}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: "var(--muted)" }}>Form Submit</div>
            <div style={{ color: p.is_form_submit ? "var(--destructive)" : "var(--fg)" }}>
              {p.is_form_submit ? "Yes" : "No"}
            </div>
          </div>
        </div>

        {/* Referrer */}
        {p.referrer && (
          <div>
            <div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: "var(--muted)" }}>Referrer</div>
            <div className="font-mono text-xs break-all" style={{ color: "var(--fg)" }}>{p.referrer ?? ""}</div>
          </div>
        )}

        {/* Tab URL */}
        {p.tab_url && (
          <div>
            <div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: "var(--muted)" }}>Tab URL</div>
            <div className="font-mono text-xs break-all" style={{ color: "var(--fg)" }}>{p.tab_url ?? ""}</div>
          </div>
        )}

        {/* Redirect Chain */}
        {redirectChain.length > 0 && (
          <div>
            <div className="text-[10px] uppercase tracking-wider mb-1" style={{ color: "var(--muted)" }}>
              Redirect Chain ({redirectChain.length} hops)
            </div>
            <div
              className="rounded border p-2 space-y-1"
              style={{ background: "var(--surface-1)", borderColor: "var(--border)" }}
            >
              {redirectChain.map((url, i) => (
                <div key={i} className="flex items-start gap-1.5 text-xs">
                  <ArrowRight size={10} className="shrink-0 mt-1" style={{ color: "var(--muted)" }} />
                  <span className="font-mono break-all" style={{ color: "var(--fg)" }}>{url}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Error */}
        {p.error && (
          <div
            className="rounded border p-2 text-xs"
            style={{ background: "oklch(0.45 0.15 25 / 0.1)", borderColor: "oklch(0.45 0.15 25 / 0.3)", color: "var(--destructive)" }}
          >
            {p.error ?? ""}
          </div>
        )}

        {/* Metadata */}
        <div className="pt-2 border-t space-y-1 text-xs" style={{ borderColor: "var(--border)" }}>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Event ID</span>
            <span className="font-mono" style={{ color: "var(--fg)" }}>{event.id}</span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Agent</span>
            <span style={{ color: "var(--fg)" }}>{event.hostname}</span>
          </div>
          <div className="flex justify-between">
            <span style={{ color: "var(--muted)" }}>Timestamp</span>
            <span className="font-mono" style={{ color: "var(--fg)" }}>{formatDate(event.timestamp)}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── Main Page ───────────────────────────────────────────────── */

export default function BrowserActivityPage() {
  const [selectedAgent, setSelectedAgent] = useState<string>("");
  const [selectedBrowser, setSelectedBrowser] = useState<string>("");
  const [domainFilter, setDomainFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);

  /* Fetch agents */
  const fetchAgents = useCallback(
    () =>
      api
        .get<{ agents?: Agent[] } | Agent[]>("/api/v1/agents")
        .then((r) => (Array.isArray(r) ? r : r.agents ?? [])),
    []
  );
  const { data: agents, loading: agentsLoading } = useApi(fetchAgents);

  /* Fetch browser events for selected agent */
  const fetchEvents = useCallback(
    () =>
      api
        .get<{ events?: Event[] } | Event[]>("/api/v1/events", {
          event_type: "BROWSER_REQUEST",
          agent_id: selectedAgent || undefined,
          limit: PAGE_SIZE,
        })
        .then((r) => (Array.isArray(r) ? r : r.events ?? [])),
    [selectedAgent]
  );
  const { data: rawEvents, loading: eventsLoading } = useApi(fetchEvents);

  /* Derive available browsers from events */
  const availableBrowsers = useMemo(() => {
    if (!rawEvents) return [];
    const set = new Set<string>();
    for (const ev of rawEvents) {
      const p = (ev.payload ?? {}) as BrowserPayload;
      if (p.browser_name) set.add(p.browser_name);
    }
    return Array.from(set).sort();
  }, [rawEvents]);

  /* Apply client-side filters */
  const filteredEvents = useMemo(() => {
    if (!rawEvents) return [];
    return rawEvents.filter((ev) => {
      const p = (ev.payload ?? {}) as BrowserPayload;
      if (selectedBrowser && p.browser_name !== selectedBrowser) return false;
      if (domainFilter) {
        const domain = (p.domain ?? "").toLowerCase();
        if (!domain.includes(domainFilter.toLowerCase())) return false;
      }
      if (statusFilter) {
        const code = p.status_code ?? 0;
        if (statusFilter !== statusGroup(code)) return false;
      }
      return true;
    });
  }, [rawEvents, selectedBrowser, domainFilter, statusFilter]);

  /* Stats */
  const stats = useMemo(() => {
    const events = filteredEvents;
    const domains = new Set(events.map((e) => ((e.payload ?? {}) as BrowserPayload).domain ?? ""));
    const formSubmits = events.filter((e) => ((e.payload ?? {}) as BrowserPayload).is_form_submit).length;
    const errors = events.filter((e) => {
      const code = ((e.payload ?? {}) as BrowserPayload).status_code ?? 0;
      return code === 0 || code >= 400;
    }).length;
    return { total: events.length, domains: domains.size, formSubmits, errors };
  }, [filteredEvents]);

  const onlineAgents = (agents ?? []).filter((a) => a.is_online);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-heading text-xl font-bold flex items-center gap-2">
            <Globe size={20} style={{ color: "var(--primary)" }} />
            Browser Activity
          </h1>
          <p className="text-sm" style={{ color: "var(--muted)" }}>
            URLs visited by browsers on monitored endpoints
          </p>
        </div>
      </div>

      {/* Filters row */}
      <div
        className="flex flex-wrap items-center gap-3 p-3 rounded border"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
      >
        {/* Agent selector */}
        <div className="flex items-center gap-2">
          <label className="text-[10px] uppercase tracking-wider font-medium" style={{ color: "var(--muted)" }}>Agent</label>
          <select
            value={selectedAgent}
            onChange={(e) => { setSelectedAgent(e.target.value); setSelectedBrowser(""); }}
            className="rounded border px-2 py-1.5 text-xs font-mono"
            style={{ background: "var(--surface-1)", borderColor: "var(--border)", color: "var(--fg)" }}
          >
            <option value="">All agents</option>
            {(agents ?? []).map((a) => (
              <option key={a.id} value={a.id}>
                {a.hostname} {a.is_online ? "" : "(offline)"}
              </option>
            ))}
          </select>
        </div>

        {/* Browser selector */}
        <div className="flex items-center gap-2">
          <label className="text-[10px] uppercase tracking-wider font-medium" style={{ color: "var(--muted)" }}>Browser</label>
          <select
            value={selectedBrowser}
            onChange={(e) => setSelectedBrowser(e.target.value)}
            className="rounded border px-2 py-1.5 text-xs"
            style={{ background: "var(--surface-1)", borderColor: "var(--border)", color: "var(--fg)" }}
          >
            <option value="">All browsers</option>
            {availableBrowsers.map((b) => (
              <option key={b} value={b}>
                {BROWSER_ICONS[b] ?? "🌐"} {b}
              </option>
            ))}
          </select>
        </div>

        {/* Domain filter */}
        <div className="flex items-center gap-2">
          <label className="text-[10px] uppercase tracking-wider font-medium" style={{ color: "var(--muted)" }}>Domain</label>
          <input
            value={domainFilter}
            onChange={(e) => setDomainFilter(e.target.value)}
            placeholder="Filter domain..."
            className="rounded border px-2 py-1.5 text-xs w-40"
            style={{ background: "var(--surface-1)", borderColor: "var(--border)", color: "var(--fg)" }}
          />
        </div>

        {/* Status filter */}
        <div className="flex items-center gap-1.5">
          <label className="text-[10px] uppercase tracking-wider font-medium" style={{ color: "var(--muted)" }}>Status</label>
          {["", "2xx", "3xx", "4xx", "5xx", "err"].map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={cn(
                "rounded px-2 py-1 text-[10px] font-bold uppercase border transition-colors",
                statusFilter === s
                  ? "border-[var(--primary)] text-[var(--primary)] bg-[var(--primary)]/10"
                  : "border-transparent hover:bg-[var(--surface-2)]"
              )}
              style={{ color: statusFilter === s ? undefined : "var(--muted)" }}
            >
              {s || "All"}
            </button>
          ))}
        </div>

        {/* Clear all */}
        {(selectedAgent || selectedBrowser || domainFilter || statusFilter) && (
          <button
            onClick={() => { setSelectedAgent(""); setSelectedBrowser(""); setDomainFilter(""); setStatusFilter(""); }}
            className="flex items-center gap-1 rounded px-2 py-1 text-[10px] transition-colors hover:bg-[var(--surface-2)]"
            style={{ color: "var(--muted)" }}
          >
            <X size={10} /> Clear
          </button>
        )}
      </div>

      {/* Stats bar */}
      <div className="flex items-center gap-6 text-xs" style={{ color: "var(--muted)" }}>
        <span><strong className="font-mono" style={{ color: "var(--fg)" }}>{stats.total}</strong> requests</span>
        <span><strong className="font-mono" style={{ color: "var(--fg)" }}>{stats.domains}</strong> domains</span>
        <span className={stats.formSubmits > 0 ? "text-amber-400" : ""}>
          <strong className="font-mono">{stats.formSubmits}</strong> form submissions
        </span>
        <span className={stats.errors > 0 ? "text-red-400" : ""}>
          <strong className="font-mono">{stats.errors}</strong> errors
        </span>
      </div>

      {/* Loading */}
      {eventsLoading && (
        <div className="space-y-2">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="animate-shimmer h-10 rounded" />
          ))}
        </div>
      )}

      {/* Timeline table */}
      {!eventsLoading && (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr
                className="text-left text-[10px] uppercase tracking-wider border-b"
                style={{ color: "var(--muted)", borderColor: "var(--border)" }}
              >
                <th className="pb-2 pr-3 w-28">Time</th>
                <th className="pb-2 pr-3 w-12">Status</th>
                <th className="pb-2 pr-3 w-14">Method</th>
                <th className="pb-2 pr-3">URL</th>
                <th className="pb-2 pr-3 w-24">Domain</th>
                <th className="pb-2 pr-3 w-20">Browser</th>
                <th className="pb-2 pr-3 w-16">Host</th>
                <th className="pb-2 w-8"></th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.map((ev) => {
                const p = (ev.payload ?? {}) as BrowserPayload;
                const code = p.status_code ?? 0;
                const url = p.url ?? "";
                const isForm = !!p.is_form_submit;
                const hasRedirects = (p.redirect_chain ?? []).length > 0;
                const isSelected = selectedEvent?.id === ev.id;

                return (
                  <tr
                    key={ev.id}
                    onClick={() => setSelectedEvent(isSelected ? null : ev)}
                    className={cn(
                      "border-b cursor-pointer transition-colors",
                      isSelected ? "bg-[var(--primary)]/5" : "hover:bg-[var(--surface-1)]"
                    )}
                    style={{ borderColor: "var(--border-subtle, var(--border))" }}
                  >
                    <td className="py-2 pr-3 font-mono whitespace-nowrap" style={{ color: "var(--muted)" }}>
                      {timeAgo(ev.timestamp)}
                    </td>
                    <td className="py-2 pr-3">
                      <span className={cn("font-mono font-bold", STATUS_COLORS[statusGroup(code)])}>
                        {code === 0 ? "ERR" : code}
                      </span>
                    </td>
                    <td className="py-2 pr-3 font-mono" style={{ color: "var(--fg)" }}>
                      {p.method ?? "GET"}
                    </td>
                    <td className="py-2 pr-3 max-w-md">
                      <div className="flex items-center gap-1.5">
                        {isForm && (
                          <span
                            className="shrink-0 rounded px-1 py-0.5 text-[9px] font-bold uppercase"
                            style={{ background: "oklch(0.70 0.15 25 / 0.15)", color: "var(--destructive)" }}
                          >
                            POST
                          </span>
                        )}
                        {hasRedirects && (
                          <span
                            className="shrink-0 rounded px-1 py-0.5 text-[9px] font-bold uppercase"
                            style={{ background: "oklch(0.60 0.12 250 / 0.15)", color: "var(--info, #60a5fa)" }}
                          >
                            REDIR
                          </span>
                        )}
                        <span className="truncate font-mono" style={{ color: "var(--fg)" }} title={url}>
                          {url.length > 80 ? url.substring(0, 80) + "..." : url}
                        </span>
                      </div>
                    </td>
                    <td className="py-2 pr-3 truncate" style={{ color: "var(--fg)" }}>
                      {p.domain ?? ""}
                    </td>
                    <td className="py-2 pr-3 whitespace-nowrap" style={{ color: "var(--muted)" }}>
                      {BROWSER_ICONS[p.browser_name ?? ""] ?? ""} {p.browser_name ?? ""}
                    </td>
                    <td className="py-2 pr-3 font-mono truncate" style={{ color: "var(--muted)" }}>
                      {ev.hostname}
                    </td>
                    <td className="py-2">
                      <ExternalLink size={10} style={{ color: "var(--muted)" }} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {filteredEvents.length === 0 && (
            <div className="py-16 text-center">
              <Globe size={32} className="mx-auto mb-3" style={{ color: "var(--muted)" }} />
              <p className="text-sm" style={{ color: "var(--muted)" }}>
                {rawEvents && rawEvents.length > 0
                  ? "No requests match your filters"
                  : "No browser activity recorded yet"}
              </p>
              <p className="text-xs mt-1" style={{ color: "var(--muted)" }}>
                Install the TraceGuard browser extension to start capturing URLs
              </p>
            </div>
          )}
        </div>
      )}

      {/* Detail panel */}
      {selectedEvent && (
        <URLDetail event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      )}
    </div>
  );
}
