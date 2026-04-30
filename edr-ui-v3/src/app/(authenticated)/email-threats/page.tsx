"use client";

import { useCallback, useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn, severityLabel, severityBgClass, timeAgo } from "@/lib/utils";
import type { Alert } from "@/types";

/* ── Constants ─────────────────────────────────────────────────────────────── */

// Rule name prefixes that belong to the email threat category.
const EMAIL_RULE_PREFIXES = [
  "rule-email-",
  "rule-office-macro",
];

const THREAT_META: Record<string, { label: string; icon: string; desc: string }> = {
  "rule-email-client-suspicious-child": {
    label: "Suspicious Child Process",
    icon: "🪲",
    desc: "Email client spawned a shell or script interpreter — spear-phishing attachment likely executed.",
  },
  "rule-email-attachment-temp-exec": {
    label: "Attachment Temp Exec",
    icon: "📎",
    desc: "Process launched from an email attachment staging path (Outlook temp, Thunderbird cache, Downloads).",
  },
  "rule-email-browser-phishing-download": {
    label: "Phishing Download",
    icon: "⬇️",
    desc: "Executable file dropped to Downloads or /tmp — likely delivered via webmail phishing link.",
  },
  "rule-email-client-network-c2": {
    label: "C2 via Email Client",
    icon: "📡",
    desc: "Email client connected to an unexpected port — possible C2 channel from a malicious attachment.",
  },
  "rule-office-macro-exec": {
    label: "Office Macro Execution",
    icon: "📄",
    desc: "Office application spawned a script interpreter — malicious macro in a document attachment.",
  },
};

function isEmailAlert(alert: Alert): boolean {
  const name = (alert.rule_name ?? "").toLowerCase();
  return EMAIL_RULE_PREFIXES.some((p) => name.startsWith(p));
}

function threatMeta(ruleName: string) {
  return (
    THREAT_META[ruleName] ?? {
      label: ruleName,
      icon: "⚠️",
      desc: "",
    }
  );
}

/* ── Status badge ──────────────────────────────────────────────────────────── */
function statusBadge(status: string) {
  const map: Record<string, string> = {
    open: "bg-red-900/40 text-red-300 border-red-800",
    "in-progress": "bg-amber-900/40 text-amber-300 border-amber-800",
    resolved: "bg-green-900/40 text-green-300 border-green-800",
    suppressed: "bg-neutral-800 text-neutral-400 border-neutral-700",
  };
  return map[status] ?? "bg-neutral-800 text-neutral-400 border-neutral-700";
}

/* ── Summary strip ─────────────────────────────────────────────────────────── */
function SummaryStrip({ alerts }: { alerts: Alert[] }) {
  const open = alerts.filter((a) => a.status === "open").length;
  const critical = alerts.filter((a) => a.severity >= 4).length;
  const hosts = new Set(alerts.map((a) => a.hostname).filter(Boolean)).size;
  const rules = new Set(alerts.map((a) => a.rule_name).filter(Boolean)).size;

  return (
    <div className="grid grid-cols-4 gap-3">
      {[
        { label: "Total alerts", value: alerts.length },
        { label: "Open", value: open, highlight: open > 0 },
        { label: "Critical / High", value: critical, highlight: critical > 0 },
        { label: "Affected hosts", value: hosts },
      ].map((s) => (
        <div
          key={s.label}
          className="rounded-lg border p-3"
          style={{ background: "var(--surface-1)", borderColor: "var(--border)" }}
        >
          <div
            className={cn(
              "text-2xl font-bold",
              s.highlight ? "text-red-400" : ""
            )}
            style={!s.highlight ? { color: "var(--fg)" } : undefined}
          >
            {s.value}
          </div>
          <div className="text-xs mt-0.5" style={{ color: "var(--muted)" }}>
            {s.label}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ── Alert row ─────────────────────────────────────────────────────────────── */
function AlertRow({
  alert,
  onStatusChange,
}: {
  alert: Alert;
  onStatusChange: (id: string, status: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const meta = threatMeta(alert.rule_name);

  return (
    <div
      className="border rounded-lg overflow-hidden"
      style={{ borderColor: "var(--border)", background: "var(--surface-1)" }}
    >
      {/* Header row */}
      <div
        className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-[var(--surface-2)] transition-colors"
        onClick={() => setOpen((v) => !v)}
      >
        <span className="text-base leading-none select-none">{meta.icon}</span>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span
              className="font-medium text-sm truncate"
              style={{ color: "var(--fg)" }}
            >
              {meta.label}
            </span>
            <span
              className={cn(
                "text-xs px-1.5 py-0.5 rounded border font-medium",
                statusBadge(alert.status)
              )}
            >
              {alert.status}
            </span>
            <span
              className={cn(
                "text-xs px-1.5 py-0.5 rounded font-medium",
                severityBgClass(alert.severity)
              )}
            >
              {severityLabel(alert.severity)}
            </span>
          </div>
          <div className="flex items-center gap-3 mt-0.5 text-xs" style={{ color: "var(--muted)" }}>
            <span className="font-mono">{alert.hostname || "unknown host"}</span>
            {alert.mitre_ids?.length > 0 && (
              <span>{alert.mitre_ids.join(" · ")}</span>
            )}
            <span className="ml-auto">{timeAgo(alert.last_seen)}</span>
          </div>
        </div>

        <span
          className="text-xs select-none"
          style={{ color: "var(--muted)" }}
        >
          {open ? "▲" : "▼"}
        </span>
      </div>

      {/* Expanded detail */}
      {open && (
        <div
          className="border-t px-4 py-3 space-y-3"
          style={{ borderColor: "var(--border)" }}
        >
          {meta.desc && (
            <p className="text-xs leading-relaxed" style={{ color: "var(--muted)" }}>
              {meta.desc}
            </p>
          )}

          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
            <div>
              <span style={{ color: "var(--muted)" }}>Rule: </span>
              <span className="font-mono" style={{ color: "var(--fg)" }}>
                {alert.rule_name}
              </span>
            </div>
            <div>
              <span style={{ color: "var(--muted)" }}>Agent: </span>
              <span className="font-mono" style={{ color: "var(--fg)" }}>
                {alert.agent_id}
              </span>
            </div>
            <div>
              <span style={{ color: "var(--muted)" }}>First seen: </span>
              <span style={{ color: "var(--fg)" }}>{timeAgo(alert.first_seen)}</span>
            </div>
            <div>
              <span style={{ color: "var(--muted)" }}>Hits: </span>
              <span style={{ color: "var(--fg)" }}>{alert.hit_count}</span>
            </div>
          </div>

          {/* Triage actions */}
          <div className="flex items-center gap-2 pt-1">
            <span className="text-xs" style={{ color: "var(--muted)" }}>Triage:</span>
            {["open", "in-progress", "resolved", "suppressed"].map((s) => (
              <button
                key={s}
                onClick={() => onStatusChange(alert.id, s)}
                disabled={alert.status === s}
                className={cn(
                  "text-xs px-2 py-0.5 rounded border transition-colors",
                  alert.status === s
                    ? "opacity-40 cursor-default border-neutral-600"
                    : "border-neutral-600 hover:bg-[var(--surface-2)]"
                )}
                style={{ color: "var(--muted)" }}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Page ──────────────────────────────────────────────────────────────────── */
export default function EmailThreatsPage() {
  const [statusFilter, setStatusFilter] = useState("");

  // Fetch alerts matching email rule names — backend searches rule_name ILIKE
  const fetchEmail = useCallback(
    () =>
      api
        .get<{ alerts?: Alert[] } | Alert[]>("/api/v1/alerts", {
          search: "email",
          limit: 200,
        })
        .then((r) => (Array.isArray(r) ? r : r.alerts ?? [])),
    []
  );

  const fetchMacro = useCallback(
    () =>
      api
        .get<{ alerts?: Alert[] } | Alert[]>("/api/v1/alerts", {
          search: "office-macro",
          limit: 200,
        })
        .then((r) => (Array.isArray(r) ? r : r.alerts ?? [])),
    []
  );

  const { data: emailAlerts, loading: l1, refetch: r1 } = useApi(fetchEmail);
  const { data: macroAlerts, loading: l2, refetch: r2 } = useApi(fetchMacro);

  function refetch() { r1(); r2(); }

  const allAlerts = [
    ...(emailAlerts ?? []),
    ...(macroAlerts ?? []),
  ].filter(isEmailAlert);

  // Deduplicate by id
  const seen = new Set<string>();
  const alerts = allAlerts.filter((a) => {
    if (seen.has(a.id)) return false;
    seen.add(a.id);
    return true;
  });

  const filtered = statusFilter
    ? alerts.filter((a) => a.status === statusFilter)
    : alerts;

  const loading = l1 || l2;

  async function handleStatusChange(id: string, status: string) {
    await api.patch(`/api/v1/alerts/${id}`, { status });
    refetch();
  }

  // Group by rule for the breakdown
  const byRule = filtered.reduce<Record<string, Alert[]>>((acc, a) => {
    const k = a.rule_name || "unknown";
    (acc[k] ??= []).push(a);
    return acc;
  }, {});

  const STATUS_FILTERS = [
    { label: "All", value: "" },
    { label: "Open", value: "open" },
    { label: "In progress", value: "in-progress" },
    { label: "Resolved", value: "resolved" },
  ];

  return (
    <div className="p-6 space-y-5">
      {/* Page header */}
      <div>
        <h1 className="text-lg font-semibold" style={{ fontFamily: "var(--font-space-grotesk)" }}>
          Email Threats
        </h1>
        <p className="text-xs mt-0.5" style={{ color: "var(--muted)" }}>
          Endpoint-observable email attack signals — phishing attachments, macro execution, suspicious child processes, and C2 over email clients.
        </p>
      </div>

      {loading && (
        <div className="text-sm" style={{ color: "var(--muted)" }}>Loading…</div>
      )}

      {!loading && alerts.length > 0 && <SummaryStrip alerts={alerts} />}

      {/* Detection coverage */}
      {!loading && (
        <div
          className="rounded-lg border p-4 space-y-2"
          style={{ background: "var(--surface-1)", borderColor: "var(--border)" }}
        >
          <div className="text-xs font-semibold mb-3" style={{ color: "var(--fg)" }}>
            Detection Coverage
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            {Object.entries(THREAT_META).map(([rule, meta]) => {
              const count = (byRule[rule] ?? []).length;
              return (
                <div
                  key={rule}
                  className={cn(
                    "flex items-start gap-3 rounded-lg border p-3 transition-colors",
                    count > 0
                      ? "border-orange-800/60 bg-orange-900/10"
                      : "border-neutral-800"
                  )}
                >
                  <span className="text-lg leading-none mt-0.5">{meta.icon}</span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-medium" style={{ color: "var(--fg)" }}>
                        {meta.label}
                      </span>
                      {count > 0 ? (
                        <span className="text-xs font-bold text-orange-400">{count} alert{count !== 1 ? "s" : ""}</span>
                      ) : (
                        <span className="text-xs text-green-500">clean</span>
                      )}
                    </div>
                    <p className="text-[11px] leading-relaxed mt-0.5" style={{ color: "var(--muted)" }}>
                      {meta.desc}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Status filter pills */}
      {!loading && alerts.length > 0 && (
        <div className="flex gap-2 flex-wrap">
          {STATUS_FILTERS.map((f) => (
            <button
              key={f.value}
              onClick={() => setStatusFilter(f.value)}
              className="text-xs px-3 py-1 rounded-full border transition-colors"
              style={{
                background: statusFilter === f.value ? "var(--primary)" : "var(--surface-1)",
                color: statusFilter === f.value ? "var(--primary-fg)" : "var(--muted)",
                borderColor: statusFilter === f.value ? "var(--primary)" : "var(--border)",
              }}
            >
              {f.label}
              {f.value === "" && ` (${alerts.length})`}
              {f.value !== "" &&
                ` (${alerts.filter((a) => a.status === f.value).length})`}
            </button>
          ))}
        </div>
      )}

      {/* Alert list */}
      {!loading && filtered.length === 0 && (
        <div
          className="rounded-lg border p-8 text-center"
          style={{ borderColor: "var(--border)", background: "var(--surface-1)" }}
        >
          <div className="text-3xl mb-2">✅</div>
          <div className="text-sm font-medium" style={{ color: "var(--fg)" }}>
            No email threat alerts
          </div>
          <div className="text-xs mt-1" style={{ color: "var(--muted)" }}>
            {statusFilter
              ? `No alerts with status "${statusFilter}".`
              : "All 5 email threat rules are active. Alerts will appear here when triggered."}
          </div>
        </div>
      )}

      <div className="space-y-2">
        {filtered
          .sort((a, b) => {
            // Sort: open first, then by severity desc, then by last_seen desc
            if (a.status === "open" && b.status !== "open") return -1;
            if (b.status === "open" && a.status !== "open") return 1;
            if (b.severity !== a.severity) return b.severity - a.severity;
            return new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime();
          })
          .map((alert) => (
            <AlertRow
              key={alert.id}
              alert={alert}
              onStatusChange={handleStatusChange}
            />
          ))}
      </div>
    </div>
  );
}
