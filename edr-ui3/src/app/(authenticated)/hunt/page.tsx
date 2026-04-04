"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Download, ChevronDown, ChevronRight } from "lucide-react";
import { api } from "@/lib/api-client";
import { cn, timeAgo, eventTypeColor } from "@/lib/utils";
import { exportToCSV, exportToJSON } from "@/lib/export";
import type { Event } from "@/types";

/* ---------- Query Templates ---------- */

interface QueryTemplate {
  label: string;
  query: string;
  category: string;
}

const QUERY_TEMPLATES: QueryTemplate[] = [
  // Process
  { category: "Process", label: "All process executions", query: `SELECT * FROM events WHERE event_type = 'PROCESS_EXEC' ORDER BY timestamp DESC LIMIT 100` },
  { category: "Process", label: "curl/wget executions", query: `SELECT * FROM events WHERE event_type = 'PROCESS_EXEC' AND (payload->>'comm' = 'curl' OR payload->>'comm' = 'wget') LIMIT 50` },
  { category: "Process", label: "Shell spawned by web server", query: `SELECT * FROM events WHERE event_type = 'PROCESS_EXEC' AND payload->'parent_process'->>'comm' IN ('nginx','apache2','httpd','php') LIMIT 50` },
  { category: "Process", label: "Fileless execution (memfd)", query: `SELECT * FROM events WHERE event_type = 'PROCESS_EXEC' AND payload->>'is_memfd' = 'true' LIMIT 50` },
  { category: "Process", label: "Processes running as root", query: `SELECT * FROM events WHERE event_type = 'PROCESS_EXEC' AND payload->'process'->>'uid' = '0' ORDER BY timestamp DESC LIMIT 100` },

  // Network
  { category: "Network", label: "External connections (non-private)", query: `SELECT * FROM events WHERE event_type = 'NET_CONNECT' AND payload->>'is_private' = 'false' LIMIT 50` },
  { category: "Network", label: "Connections on high ports (>49151)", query: `SELECT * FROM events WHERE event_type = 'NET_CONNECT' AND (payload->>'dst_port')::int > 49151 LIMIT 50` },
  { category: "Network", label: "SSH connections (port 22)", query: `SELECT * FROM events WHERE event_type = 'NET_CONNECT' AND payload->>'dst_port' = '22' LIMIT 50` },
  { category: "Network", label: "DNS queries for rare TLDs", query: `SELECT * FROM events WHERE event_type = 'NET_DNS' AND payload->>'dns_query' ~ '\\.(tk|xyz|top|pw|cc|click)$' LIMIT 50` },

  // File
  { category: "File", label: "Files written to /tmp", query: `SELECT * FROM events WHERE event_type = 'FILE_WRITE' AND payload->>'path' LIKE '/tmp/%' ORDER BY timestamp DESC LIMIT 50` },
  { category: "File", label: "Executable files created", query: `SELECT * FROM events WHERE event_type = 'FILE_CREATE' AND payload->>'path' LIKE '/usr/bin/%' LIMIT 50` },
  { category: "File", label: "sudoers modifications", query: `SELECT * FROM events WHERE event_type IN ('FILE_WRITE','FILE_CREATE') AND payload->>'path' LIKE '/etc/sudoers%' LIMIT 50` },

  // Browser
  { category: "Browser", label: "All form submissions", query: `SELECT * FROM events WHERE event_type = 'BROWSER_REQUEST' AND payload->>'is_form_submit' = 'true' ORDER BY timestamp DESC LIMIT 50` },
  { category: "Browser", label: "Requests with redirect chains", query: `SELECT * FROM events WHERE event_type = 'BROWSER_REQUEST' AND jsonb_array_length(payload->'redirect_chain') > 2 LIMIT 50` },
  { category: "Browser", label: "HTTP errors (4xx/5xx)", query: `SELECT * FROM events WHERE event_type = 'BROWSER_REQUEST' AND (payload->>'status_code')::int >= 400 LIMIT 50` },
  { category: "Browser", label: "Visits to .tk/.xyz domains", query: `SELECT * FROM events WHERE event_type = 'BROWSER_REQUEST' AND payload->>'domain' ~ '\\.(tk|xyz|top|pw|click)$' LIMIT 50` },

  // Auth
  { category: "Auth", label: "Failed logins", query: `SELECT * FROM events WHERE event_type = 'LOGIN_FAILED' ORDER BY timestamp DESC LIMIT 100` },
  { category: "Auth", label: "Sudo to root", query: `SELECT * FROM events WHERE event_type = 'SUDO_EXEC' AND payload->>'target_user' = 'root' LIMIT 50` },
  { category: "Auth", label: "SSH logins from external IPs", query: `SELECT * FROM events WHERE event_type = 'LOGIN_SUCCESS' AND payload->>'service' = 'sshd' AND payload->>'source_ip' != '' LIMIT 50` },

  // USB & Kernel
  { category: "Hardware", label: "USB mass storage devices", query: `SELECT * FROM events WHERE event_type = 'USB_CONNECT' AND payload->>'dev_type' = 'mass_storage' LIMIT 50` },
  { category: "Hardware", label: "All USB events", query: `SELECT * FROM events WHERE event_type IN ('USB_CONNECT','USB_DISCONNECT') ORDER BY timestamp DESC LIMIT 50` },
  { category: "Hardware", label: "Kernel module loads", query: `SELECT * FROM events WHERE event_type = 'KERNEL_MODULE_LOAD' ORDER BY timestamp DESC LIMIT 50` },
  { category: "Hardware", label: "Unsigned kernel modules", query: `SELECT * FROM events WHERE event_type = 'KERNEL_MODULE_LOAD' AND payload->>'signed' = 'false' LIMIT 50` },

  // Security
  { category: "Security", label: "Memory injection detected", query: `SELECT * FROM events WHERE event_type = 'MEMORY_INJECT' ORDER BY timestamp DESC LIMIT 50` },
  { category: "Security", label: "Named pipes in /tmp or /dev/shm", query: `SELECT * FROM events WHERE event_type = 'PIPE_CREATE' AND payload->>'location' IN ('tmp','dev_shm') LIMIT 50` },
  { category: "Security", label: "Network shares mounted", query: `SELECT * FROM events WHERE event_type = 'SHARE_MOUNT' ORDER BY timestamp DESC LIMIT 50` },
  { category: "Security", label: "Suspicious cron jobs", query: `SELECT * FROM events WHERE event_type = 'CRON_MODIFY' AND payload->>'suspicious' = 'true' LIMIT 50` },
  { category: "Security", label: "Reverse shell cron entries", query: `SELECT * FROM events WHERE event_type = 'CRON_MODIFY' AND payload->>'cron_tags' LIKE '%reverse-shell%' LIMIT 50` },

  // File Integrity Monitoring
  { category: "FIM", label: "All FIM violations", query: `SELECT * FROM events WHERE event_type = 'FIM_VIOLATION' ORDER BY timestamp DESC LIMIT 100` },
  { category: "FIM", label: "Modified files", query: `SELECT * FROM events WHERE event_type = 'FIM_VIOLATION' AND payload->>'action' = 'modified' LIMIT 50` },
  { category: "FIM", label: "Deleted monitored files", query: `SELECT * FROM events WHERE event_type = 'FIM_VIOLATION' AND payload->>'action' = 'deleted' LIMIT 50` },
  { category: "FIM", label: "Password/shadow file changes", query: `SELECT * FROM events WHERE event_type = 'FIM_VIOLATION' AND payload->>'file_path' ~ '(passwd|shadow|gshadow)' LIMIT 50` },
  { category: "FIM", label: "SSH config changes", query: `SELECT * FROM events WHERE event_type = 'FIM_VIOLATION' AND payload->>'file_path' LIKE '%ssh%' LIMIT 50` },

  // TLS SNI
  { category: "TLS/HTTPS", label: "All TLS SNI connections", query: `SELECT * FROM events WHERE event_type = 'NET_TLS_SNI' ORDER BY timestamp DESC LIMIT 100` },
  { category: "TLS/HTTPS", label: "TLS connections to rare TLDs", query: `SELECT * FROM events WHERE event_type = 'NET_TLS_SNI' AND payload->>'domain' ~ '\\.(tk|xyz|top|pw|cc|click)$' LIMIT 50` },
  { category: "TLS/HTTPS", label: "TLS connections by specific process", query: `SELECT * FROM events WHERE event_type = 'NET_TLS_SNI' AND payload->>'process_comm' = 'curl' LIMIT 50` },
  { category: "TLS/HTTPS", label: "TLS 1.0/1.1 connections (deprecated)", query: `SELECT * FROM events WHERE event_type = 'NET_TLS_SNI' AND payload->>'tls_version' IN ('TLS 1.0','TLS 1.1') LIMIT 50` },

  // Commands
  { category: "Commands", label: "Reverse shell commands", query: `SELECT * FROM events WHERE event_type IN ('CMD_EXEC','CMD_HISTORY') AND payload->>'tags' LIKE '%revshell%' LIMIT 50` },
  { category: "Commands", label: "History evasion attempts", query: `SELECT * FROM events WHERE event_type IN ('CMD_EXEC','CMD_HISTORY') AND payload->>'tags' LIKE '%history-evasion%' LIMIT 50` },

  // Cross-cutting
  { category: "Cross-cutting", label: "All CRITICAL severity events", query: `SELECT * FROM events WHERE severity = 4 ORDER BY timestamp DESC LIMIT 100` },
  { category: "Cross-cutting", label: "Events in last hour", query: `SELECT * FROM events WHERE timestamp > NOW() - INTERVAL '1 hour' ORDER BY timestamp DESC LIMIT 200` },
  { category: "Cross-cutting", label: "Events from specific agent", query: `SELECT * FROM events WHERE agent_id = 'REPLACE_WITH_AGENT_ID' ORDER BY timestamp DESC LIMIT 100` },
];

const CATEGORIES = [...new Set(QUERY_TEMPLATES.map((q) => q.category))];

/* ---------- Helpers ---------- */

function summarizeEvent(evt: Event): string {
  const p = (evt.payload ?? {}) as Record<string, unknown>;
  switch (evt.event_type?.toUpperCase()) {
    case "PROCESS_EXEC":
    case "PROCESS_EXIT":
      return String(p.cmdline ?? p.comm ?? "—");
    case "CMD_EXEC":
    case "CMD_HISTORY":
      return String(p.command ?? p.cmdline ?? "—");
    case "FILE_WRITE":
    case "FILE_CREATE":
    case "FILE_DELETE":
    case "FILE_RENAME":
    case "FILE_CHMOD":
      return String(p.path ?? p.filename ?? "—");
    case "NET_CONNECT":
    case "NET_ACCEPT":
      return `${p.dst_ip ?? "?"}:${p.dst_port ?? "?"}`;
    case "NET_DNS":
      return String(p.dns_query ?? p.resolved_domain ?? "—");
    case "BROWSER_REQUEST":
      return `${p.method ?? "GET"} ${p.status_code ?? "?"} ${p.url ?? "—"}`;
    case "KERNEL_MODULE_LOAD":
    case "KERNEL_MODULE_UNLOAD":
      return `${p.module_name ?? "?"} ${p.signed === false ? "(unsigned)" : ""}`;
    case "USB_CONNECT":
    case "USB_DISCONNECT":
      return `${p.vendor ?? ""} ${p.product ?? ""} [${p.dev_type ?? ""}]`;
    case "MEMORY_INJECT":
      return `${p.target_comm ?? "?"} ${p.technique ?? ""} @ ${p.address ?? "?"}`;
    case "CRON_MODIFY":
      return `${p.schedule ?? ""} ${p.command ?? "—"}`;
    case "PIPE_CREATE":
      return `${p.creator_comm ?? "?"} -> ${p.pipe_path ?? "?"}`;
    case "SHARE_MOUNT":
    case "SHARE_UNMOUNT":
      return `${p.source ?? "?"} -> ${p.mount_point ?? "?"} (${p.fs_type ?? "?"})`;
    case "NET_TLS_SNI":
      return `${p.process_comm ?? ""} → ${p.domain ?? "?"} (${p.dst_ip ?? "?"}:${p.dst_port ?? "443"}) ${p.tls_version ?? ""}`;
    case "LOGIN_SUCCESS":
    case "LOGIN_FAILED":
    case "SUDO_EXEC":
      return `${p.username ?? "?"} via ${p.service ?? "?"} ${p.source_ip ? "from " + p.source_ip : ""}`;
    case "FIM_VIOLATION":
      return `${String(p.action ?? "?").toUpperCase()}: ${p.file_path ?? "?"}`;
    default:
      return JSON.stringify(p).slice(0, 120);
  }
}

/* ---------- Hunt Page ---------- */
export default function HuntPage() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<Event[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedCategory, setExpandedCategory] = useState<string | null>(null);
  const [showExportMenu, setShowExportMenu] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  async function runQuery() {
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    setResults(null);
    try {
      const r = await api.post<{ events?: Event[] } | Event[]>("/api/v1/hunt", {
        query: query.trim(),
      });
      const events = Array.isArray(r) ? r : r.events ?? [];
      setResults(events);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        runQuery();
      }
    }
    const el = textareaRef.current;
    if (el) {
      el.addEventListener("keydown", handleKeyDown);
      return () => el.removeEventListener("keydown", handleKeyDown);
    }
  });

  return (
    <div className="animate-fade-in space-y-4">
      <h1 className="text-lg font-semibold" style={{ fontFamily: "var(--font-space-grotesk)" }}>
        Threat Hunt
      </h1>

      {/* Query input */}
      <div
        className="rounded-lg border overflow-hidden"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
      >
        <textarea
          ref={textareaRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          rows={5}
          placeholder="Enter SQL-like query... e.g. SELECT * FROM events WHERE event_type = 'PROCESS_EXEC' LIMIT 50"
          className="w-full px-4 py-3 text-sm font-mono outline-none resize-y"
          style={{
            background: "hsl(220 20% 8%)",
            color: "var(--fg)",
            caretColor: "var(--primary)",
          }}
        />
        <div
          className="flex items-center justify-between px-4 py-2 border-t"
          style={{ borderColor: "var(--border)", background: "var(--surface-1)" }}
        >
          <span className="text-[10px]" style={{ color: "var(--muted)" }}>
            Ctrl+Enter to run
          </span>
          <button
            onClick={runQuery}
            disabled={loading || !query.trim()}
            className="rounded-md px-4 py-1.5 text-xs font-medium transition-colors disabled:opacity-50"
            style={{ background: "var(--primary)", color: "var(--primary-fg)" }}
          >
            {loading ? "Running..." : "Run Query"}
          </button>
        </div>
      </div>

      {/* Query templates — grouped by category */}
      <div>
        <div
          className="text-[10px] font-semibold uppercase tracking-wider mb-2"
          style={{ color: "var(--muted)" }}
        >
          Query Templates ({QUERY_TEMPLATES.length})
        </div>
        <div className="space-y-1">
          {CATEGORIES.map((cat) => {
            const templates = QUERY_TEMPLATES.filter((q) => q.category === cat);
            const isExpanded = expandedCategory === cat;
            return (
              <div key={cat}>
                <button
                  onClick={() => setExpandedCategory(isExpanded ? null : cat)}
                  className="w-full flex items-center justify-between rounded-md border px-3 py-2 text-xs font-medium transition-colors hover:bg-[var(--surface-1)]"
                  style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
                >
                  <div className="flex items-center gap-2">
                    {isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                    <span style={{ color: "var(--fg)" }}>{cat}</span>
                  </div>
                  <span className="rounded-full px-1.5 py-0.5 text-[9px] font-mono" style={{ background: "var(--surface-2)", color: "var(--muted)" }}>
                    {templates.length}
                  </span>
                </button>
                {isExpanded && (
                  <div className="ml-5 mt-1 space-y-1 animate-fade-in">
                    {templates.map((tpl, i) => (
                      <button
                        key={i}
                        onClick={() => {
                          setQuery(tpl.query);
                          textareaRef.current?.focus();
                        }}
                        className="w-full text-left rounded border px-3 py-1.5 text-xs transition-colors hover:bg-[var(--surface-1)]"
                        style={{ borderColor: "var(--border)", background: "var(--surface-0)" }}
                      >
                        <div style={{ color: "var(--fg)" }}>{tpl.label}</div>
                        <div className="font-mono text-[10px] truncate mt-0.5" style={{ color: "var(--muted)" }}>
                          {tpl.query}
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div
          className="rounded-lg border p-4 text-center text-sm text-red-400"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
        >
          {error}
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="rounded-lg border overflow-hidden" style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}>
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3 px-3 py-2">
              <div className="animate-shimmer h-4 w-20 rounded" />
              <div className="animate-shimmer h-5 w-24 rounded" />
              <div className="animate-shimmer h-4 w-28 rounded" />
              <div className="animate-shimmer h-4 w-64 rounded" />
            </div>
          ))}
        </div>
      )}

      {/* Results */}
      {results !== null && !loading && (
        <div>
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold" style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}>
                Results
              </span>
              <span
                className="rounded-full px-2 py-0.5 text-[10px] font-mono font-semibold"
                style={{ background: "var(--primary)", color: "var(--primary-fg)" }}
              >
                {results.length}
              </span>
            </div>

            {/* Export dropdown */}
            {results.length > 0 && (
              <div className="relative">
                <button
                  onClick={() => setShowExportMenu(!showExportMenu)}
                  className="flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-2)]"
                  style={{ borderColor: "var(--border)", color: "var(--muted)" }}
                >
                  <Download size={12} />
                  Export
                </button>
                {showExportMenu && (
                  <div
                    className="absolute right-0 top-full mt-1 rounded border shadow-lg z-10 py-1 min-w-[120px]"
                    style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
                  >
                    <button
                      onClick={() => { exportToCSV(results, "hunt-results.csv"); setShowExportMenu(false); }}
                      className="w-full text-left px-3 py-1.5 text-xs hover:bg-[var(--surface-1)] transition-colors"
                      style={{ color: "var(--fg)" }}
                    >
                      Export as CSV
                    </button>
                    <button
                      onClick={() => { exportToJSON(results, "hunt-results.json"); setShowExportMenu(false); }}
                      className="w-full text-left px-3 py-1.5 text-xs hover:bg-[var(--surface-1)] transition-colors"
                      style={{ color: "var(--fg)" }}
                    >
                      Export as JSON
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

          {results.length > 0 ? (
            <div
              className="rounded-lg border overflow-hidden"
              style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
            >
              <div
                className="grid grid-cols-[120px_120px_120px_1fr] gap-2 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider border-b"
                style={{ color: "var(--muted-fg)", borderColor: "var(--border)", background: "var(--surface-1)" }}
              >
                <span>Time</span>
                <span>Type</span>
                <span>Host</span>
                <span>Summary</span>
              </div>
              {results.map((evt, i) => (
                <div
                  key={evt.id || i}
                  className="grid grid-cols-[120px_120px_120px_1fr] gap-2 px-3 py-2 text-xs border-b last:border-b-0 hover:bg-[var(--surface-1)] transition-colors"
                  style={{ borderColor: "var(--border-subtle)" }}
                >
                  <span className="font-mono truncate" style={{ color: "var(--muted)" }}>{timeAgo(evt.timestamp)}</span>
                  <span className="flex items-center">
                    <span
                      className={cn("rounded px-1.5 py-0.5 text-[10px] font-mono font-semibold uppercase truncate", eventTypeColor(evt.event_type))}
                      style={{ background: "var(--surface-2)" }}
                    >
                      {evt.event_type}
                    </span>
                  </span>
                  <span className="truncate" style={{ color: "var(--fg)" }}>{evt.hostname || "—"}</span>
                  <span className="truncate font-mono" style={{ color: "var(--fg)" }}>{summarizeEvent(evt)}</span>
                </div>
              ))}
            </div>
          ) : (
            <div
              className="rounded-lg border py-12 text-center text-xs"
              style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--muted)" }}
            >
              No results found
            </div>
          )}
        </div>
      )}
    </div>
  );
}
