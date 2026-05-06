"use client";

import { useCallback, useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn, timeAgo, severityLabel, severityBgClass } from "@/lib/utils";
import type { IOC, IOCStats, IOCEnrichment } from "@/types";

/* ---------- Constants ---------- */
const TYPE_FILTERS = [
  { label: "All", value: "" },
  { label: "IP", value: "ip" },
  { label: "Domain", value: "domain" },
  { label: "Hash", value: "hash_sha256" },
] as const;

const IOC_TYPES = ["ip", "domain", "hash_sha256", "hash_md5"] as const;

const TYPE_BADGE: Record<string, string> = {
  ip: "bg-blue-500/15 text-blue-400",
  domain: "bg-emerald-500/15 text-emerald-400",
  hash_sha256: "bg-purple-500/15 text-purple-400",
  hash_md5: "bg-purple-500/15 text-purple-300",
};

function typeBadgeClass(type: string): string {
  return TYPE_BADGE[type?.toLowerCase()] ?? "bg-neutral-500/15 text-neutral-400";
}

function severityDot(sev: number): string {
  switch (sev) {
    case 4: return "bg-red-500";
    case 3: return "bg-orange-500";
    case 2: return "bg-amber-500";
    case 1: return "bg-blue-500";
    default: return "bg-neutral-500";
  }
}

function isExpired(ioc: IOC): boolean {
  return !!ioc.expires_at && new Date(ioc.expires_at) < new Date();
}

function isStale(ioc: IOC): boolean {
  if (!ioc.enabled) return false;
  if (ioc.hit_count > 0 && ioc.last_hit_at) {
    const daysSinceHit = (Date.now() - new Date(ioc.last_hit_at).getTime()) / 86_400_000;
    return daysSinceHit > 30;
  }
  return false;
}

function confidenceColor(c: number): string {
  if (c >= 70) return "bg-emerald-500";
  if (c >= 40) return "bg-amber-500";
  return "bg-red-500";
}

const TLP_BADGE: Record<string, string> = {
  WHITE: "bg-white/10 text-white/60",
  GREEN: "bg-emerald-500/15 text-emerald-400",
  AMBER: "bg-amber-500/15 text-amber-400",
  RED:   "bg-red-500/15 text-red-400",
};

/* ---------- Skeleton ---------- */
function SkeletonRow() {
  return (
    <div className="flex items-center gap-3 px-3 py-2">
      <div className="animate-shimmer h-4 w-16 rounded" />
      <div className="animate-shimmer h-4 w-40 rounded" />
      <div className="animate-shimmer h-4 w-20 rounded" />
      <div className="animate-shimmer h-3 w-3 rounded-full" />
      <div className="animate-shimmer h-4 w-12 rounded" />
      <div className="animate-shimmer h-4 w-16 rounded" />
      <div className="animate-shimmer h-4 w-20 rounded" />
    </div>
  );
}

/* ---------- Add IOC Form ---------- */
function AddIOCForm({ onSubmit, onCancel }: { onSubmit: (ioc: Record<string, unknown>) => void; onCancel: () => void }) {
  const [type, setType] = useState<string>("ip");
  const [value, setValue] = useState("");
  const [source, setSource] = useState("");
  const [severity, setSeverity] = useState(1);
  const [description, setDescription] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async () => {
    if (!value.trim()) return;
    setSubmitting(true);
    try {
      await onSubmit({ type, value: value.trim(), source: source.trim(), severity, description: description.trim() });
      setValue("");
      setSource("");
      setDescription("");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="rounded-lg border p-4 space-y-3 animate-fade-in"
      style={{ background: "var(--surface-1)", borderColor: "var(--border)" }}
    >
      <div className="flex items-center gap-3 flex-wrap">
        <select
          value={type}
          onChange={(e) => setType(e.target.value)}
          className="rounded-md border px-2 py-1.5 text-xs outline-none"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
        >
          {IOC_TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <input
          type="text"
          placeholder="Value (IP, domain, hash...)"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          className="rounded-md border px-3 py-1.5 text-xs flex-1 min-w-[200px] outline-none font-mono focus-ring"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
        />
        <input
          type="text"
          placeholder="Source"
          value={source}
          onChange={(e) => setSource(e.target.value)}
          className="rounded-md border px-3 py-1.5 text-xs w-32 outline-none focus-ring"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
        />
        <select
          value={severity}
          onChange={(e) => setSeverity(Number(e.target.value))}
          className="rounded-md border px-2 py-1.5 text-xs outline-none"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
        >
          {[0, 1, 2, 3, 4].map((s) => (
            <option key={s} value={s}>{severityLabel(s)} ({s})</option>
          ))}
        </select>
      </div>
      <textarea
        placeholder="Description (optional)"
        value={description}
        onChange={(e) => setDescription(e.target.value)}
        rows={2}
        className="w-full rounded-md border px-3 py-1.5 text-xs outline-none resize-none focus-ring"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
      />
      <div className="flex gap-2">
        <button
          onClick={handleSubmit}
          disabled={submitting || !value.trim()}
          className="rounded-md px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50"
          style={{ background: "var(--primary)", color: "var(--primary-fg)" }}
        >
          {submitting ? "Adding..." : "Add IOC"}
        </button>
        <button
          onClick={onCancel}
          className="rounded-md border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-2)]"
          style={{ borderColor: "var(--border)", color: "var(--muted)" }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

/* ---------- Bulk Import Form ---------- */
function BulkImportForm({ onSubmit, onCancel }: { onSubmit: (iocs: Record<string, unknown>[]) => void; onCancel: () => void }) {
  const [text, setText] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async () => {
    if (!text.trim()) return;
    setSubmitting(true);
    const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
    const iocs = lines.map((line) => {
      const parts = line.split(",").map((p) => p.trim());
      return {
        type: parts[0] || "ip",
        value: parts[1] || parts[0] || "",
        source: parts[2] || "bulk_import",
        severity: parts[3] ? Number(parts[3]) : 1,
      };
    });
    try {
      await onSubmit(iocs);
      setText("");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="rounded-lg border p-4 space-y-3 animate-fade-in"
      style={{ background: "var(--surface-1)", borderColor: "var(--border)" }}
    >
      <div className="text-xs" style={{ color: "var(--muted)" }}>
        One IOC per line. Format: <span className="font-mono">type,value,source,severity</span> or just a value per line.
      </div>
      <textarea
        placeholder={"ip,192.168.1.1,threat_feed,3\ndomain,malware.example.com,osint,2\n10.0.0.1"}
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={6}
        className="w-full rounded-md border px-3 py-2 text-xs font-mono outline-none resize-none focus-ring"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
      />
      <div className="flex gap-2">
        <button
          onClick={handleSubmit}
          disabled={submitting || !text.trim()}
          className="rounded-md px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50"
          style={{ background: "var(--primary)", color: "var(--primary-fg)" }}
        >
          {submitting ? "Importing..." : "Import"}
        </button>
        <button
          onClick={onCancel}
          className="rounded-md border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-2)]"
          style={{ borderColor: "var(--border)", color: "var(--muted)" }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

/* ---------- Enrichment Drawer ---------- */
const VT_VERDICT_STYLE: Record<string, string> = {
  malicious:  "text-red-400 bg-red-500/10 border-red-500/20",
  suspicious: "text-amber-400 bg-amber-500/10 border-amber-500/20",
  clean:      "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
  unknown:    "text-white/40 bg-white/5 border-white/10",
};

function EnrichmentDrawer({ ioc, onClose, onReenrich }: {
  ioc: IOC;
  onClose: () => void;
  onReenrich: () => void;
}) {
  const [enriching, setEnriching] = useState(false);
  const e: IOCEnrichment | undefined = ioc.enrichment && Object.keys(ioc.enrichment).length > 0
    ? ioc.enrichment
    : undefined;

  async function handleReenrich() {
    setEnriching(true);
    try {
      await api.post(`/api/v1/iocs/${ioc.id}/enrich`);
      onReenrich();
    } finally {
      setEnriching(false);
    }
  }

  const vtPct = e?.vt_total_engines ? Math.round((e.vt_detections ?? 0) / e.vt_total_engines * 100) : 0;

  return (
    <div className="fixed inset-0 z-50 flex" onClick={onClose}>
      <div className="flex-1" />
      <div
        className="w-96 h-full overflow-y-auto border-l shadow-2xl"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="sticky top-0 z-10 flex items-center justify-between gap-2 px-4 py-3 border-b"
          style={{ background: "var(--surface-1)", borderColor: "var(--border)" }}>
          <div className="min-w-0">
            <p className="text-xs font-mono truncate" style={{ color: "var(--fg)" }}>{ioc.value}</p>
            <p className="text-[10px] uppercase tracking-wider mt-0.5" style={{ color: "var(--muted)" }}>{ioc.type} · {ioc.source}</p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={handleReenrich}
              disabled={enriching}
              className="rounded-md border px-2.5 py-1 text-[10px] font-medium transition-colors disabled:opacity-50"
              style={{ borderColor: "var(--border)", color: "var(--muted)" }}
            >
              {enriching ? "Enriching…" : "Re-enrich"}
            </button>
            <button onClick={onClose} className="rounded p-1 hover:bg-[var(--surface-2)] transition-colors" style={{ color: "var(--muted)" }}>
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          </div>
        </div>

        <div className="p-4 space-y-4">
          {/* Enrichment section */}
          {!e ? (
            <div className="rounded-lg border p-4 text-center" style={{ borderColor: "var(--border)" }}>
              <p className="text-xs" style={{ color: "var(--muted)" }}>
                {ioc.enrichment_ver === 0 ? "Not yet enriched — click Re-enrich above." : "No enrichment data available."}
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {/* VirusTotal */}
              {e.vt_verdict && (
                <div className="rounded-lg border p-3 space-y-2" style={{ borderColor: "var(--border)" }}>
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--muted)" }}>VirusTotal</span>
                    <span className={cn("rounded border px-1.5 py-0.5 text-[10px] font-medium", VT_VERDICT_STYLE[e.vt_verdict] ?? VT_VERDICT_STYLE.unknown)}>
                      {e.vt_verdict}
                    </span>
                  </div>
                  {(e.vt_total_engines ?? 0) > 0 && (
                    <div className="space-y-1">
                      <div className="flex justify-between text-[10px]" style={{ color: "var(--muted)" }}>
                        <span>{e.vt_detections ?? 0} / {e.vt_total_engines} engines</span>
                        <span>{vtPct}%</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-white/5">
                        <div className="h-full rounded-full bg-red-500 transition-all" style={{ width: `${vtPct}%` }} />
                      </div>
                    </div>
                  )}
                  {e.vt_malware_family && (
                    <p className="text-[10px]" style={{ color: "var(--muted)" }}>Family: <span className="font-medium text-amber-400">{e.vt_malware_family}</span></p>
                  )}
                </div>
              )}

              {/* Network / Geo */}
              {(e.asn || e.country || e.geo_city || e.rdns) && (
                <div className="rounded-lg border p-3 space-y-1.5" style={{ borderColor: "var(--border)" }}>
                  <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--muted)" }}>Network</span>
                  {e.asn && <EnrichRow label="ASN" value={e.asn} />}
                  {e.country && <EnrichRow label="Country" value={e.country} />}
                  {e.geo_city && <EnrichRow label="City" value={e.geo_city} />}
                  {e.rdns && <EnrichRow label="rDNS" value={e.rdns} mono />}
                </div>
              )}

              {/* WHOIS / Domain */}
              {(e.whois_registrar || e.domain_age_days) && (
                <div className="rounded-lg border p-3 space-y-1.5" style={{ borderColor: "var(--border)" }}>
                  <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--muted)" }}>WHOIS</span>
                  {e.whois_registrar && <EnrichRow label="Registrar" value={e.whois_registrar} />}
                  {e.domain_age_days != null && <EnrichRow label="Domain Age" value={`${e.domain_age_days} days`} />}
                </div>
              )}

              {e.enriched_at && (
                <p className="text-[10px] text-right" style={{ color: "var(--muted)" }}>
                  Enriched {timeAgo(e.enriched_at)}
                </p>
              )}
            </div>
          )}

          {/* IOC metadata */}
          <div className="rounded-lg border p-3 space-y-1.5" style={{ borderColor: "var(--border)" }}>
            <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: "var(--muted)" }}>Details</span>
            <EnrichRow label="Severity" value={severityLabel(ioc.severity)} />
            <EnrichRow label="Hits" value={String(ioc.hit_count)} />
            <EnrichRow label="Created" value={timeAgo(ioc.created_at)} />
            {ioc.last_hit_at && <EnrichRow label="Last Hit" value={timeAgo(ioc.last_hit_at)} />}
            {ioc.description && <EnrichRow label="Description" value={ioc.description} />}
            {ioc.tags?.length > 0 && (
              <div className="flex items-start gap-2 text-[10px]">
                <span className="w-20 shrink-0" style={{ color: "var(--muted)" }}>Tags</span>
                <div className="flex flex-wrap gap-1">
                  {ioc.tags.map((t) => (
                    <span key={t} className="rounded px-1.5 py-0.5 text-[10px] font-medium bg-white/5 text-white/50">{t}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function EnrichRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start gap-2 text-[10px]">
      <span className="w-20 shrink-0" style={{ color: "var(--muted)" }}>{label}</span>
      <span className={cn("break-all", mono && "font-mono")} style={{ color: "var(--fg)" }}>{value}</span>
    </div>
  );
}

/* ---------- IOCs Page ---------- */
export default function IOCsPage() {
  const [typeFilter, setTypeFilter] = useState("");
  const [staleFilter, setStaleFilter] = useState(false);
  const [search, setSearch] = useState("");
  const [showAddForm, setShowAddForm] = useState(false);
  const [showBulkForm, setShowBulkForm] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [selectedIOC, setSelectedIOC] = useState<IOC | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [retiring, setRetiring] = useState(false);

  /* Fetch IOC stats */
  const fetchStats = useCallback(
    (signal: AbortSignal) => api.get<IOCStats | { stats?: IOCStats }>("/api/v1/iocs/stats", undefined, signal).then((r) => {
      if (r && typeof r === "object" && "stats" in r && r.stats) return r.stats as IOCStats;
      return r as IOCStats;
    }),
    []
  );
  const { data: stats } = useApi(fetchStats);

  /* Fetch IOCs */
  const fetchIOCs = useCallback(
    (signal: AbortSignal) =>
      api
        .get<{ iocs?: IOC[] } | IOC[]>("/api/v1/iocs", {
          type: typeFilter || undefined,
          search: search || undefined,
        }, signal)
        .then((r) => (Array.isArray(r) ? r : r.iocs ?? [])),
    [typeFilter, search]
  );
  const { data: iocs, loading, error, refetch } = useApi(fetchIOCs);

  /* Actions */
  const handleAddIOC = async (body: Record<string, unknown>) => {
    await api.post("/api/v1/iocs", body);
    setShowAddForm(false);
    refetch();
  };

  const handleBulkImport = async (iocList: Record<string, unknown>[]) => {
    await api.post("/api/v1/iocs/bulk", { iocs: iocList });
    setShowBulkForm(false);
    refetch();
  };

  const handleSyncFeeds = async () => {
    setSyncing(true);
    try {
      await api.post("/api/v1/iocs/feeds/sync");
      refetch();
    } catch {
      // ignore
    } finally {
      setSyncing(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm("Delete this IOC?")) return;
    await api.del(`/api/v1/iocs/${id}`);
    refetch();
  };

  const handleToggleEnabled = async (ioc: IOC) => {
    await api.put(`/api/v1/iocs/${ioc.id}`, { ...ioc, enabled: !ioc.enabled });
    refetch();
  };

  const toggleSelect = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const handleBulkRetire = async () => {
    if (selected.size === 0) return;
    if (!window.confirm(`Retire ${selected.size} selected IOC(s)? They will be disabled.`)) return;
    setRetiring(true);
    try {
      await api.post("/api/v1/iocs/bulk-retire", { ids: Array.from(selected) });
      setSelected(new Set());
      refetch();
    } finally {
      setRetiring(false);
    }
  };

  const allDisplayIds = (iocs ?? []).map((i) => i.id);
  const allSelected = allDisplayIds.length > 0 && allDisplayIds.every((id) => selected.has(id));
  const toggleSelectAll = () => {
    if (allSelected) {
      setSelected(new Set());
    } else {
      setSelected(new Set(allDisplayIds));
    }
  };

  const rawIOCs = iocs ?? [];
  const displayIOCs = staleFilter
    ? rawIOCs.filter((ioc) => isStale(ioc) || isExpired(ioc))
    : rawIOCs;

  return (
    <div className="animate-fade-in space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <h1
          className="text-lg font-semibold"
          style={{ fontFamily: "var(--font-space-grotesk)" }}
        >
          IOC Management
        </h1>
        <div className="flex items-center gap-2">
          {selected.size > 0 && (
            <button
              onClick={handleBulkRetire}
              disabled={retiring}
              className="rounded-md px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50"
              style={{ background: "var(--destructive, #ef4444)", color: "#fff" }}
            >
              {retiring ? "Retiring…" : `Retire ${selected.size} Selected`}
            </button>
          )}
          <button
            onClick={handleSyncFeeds}
            disabled={syncing}
            className="flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-2)] disabled:opacity-50"
            style={{ borderColor: "var(--border)", color: "var(--muted)" }}
          >
            {syncing && (
              <svg className="h-3 w-3 animate-spin" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
            )}
            {syncing ? "Syncing..." : "Sync Feeds"}
          </button>
          <button
            onClick={() => { setShowBulkForm(!showBulkForm); setShowAddForm(false); }}
            className="rounded-md border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-2)]"
            style={{ borderColor: "var(--border)", color: "var(--muted)" }}
          >
            Bulk Import
          </button>
          <button
            onClick={() => { setShowAddForm(!showAddForm); setShowBulkForm(false); }}
            className="rounded-md px-3 py-1.5 text-xs font-medium transition-colors"
            style={{ background: "var(--primary)", color: "var(--primary-fg)" }}
          >
            Add IOC
          </button>
        </div>
      </div>

      {/* Stats bar */}
      {stats && (
        <div
          className="grid grid-cols-8 gap-3 rounded-lg border p-3"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
        >
          {[
            { label: "Total IOCs",    value: stats.total_iocs,           warn: false },
            { label: "IPs",           value: stats.ip_count,             warn: false },
            { label: "Domains",       value: stats.domain_count,         warn: false },
            { label: "Hashes",        value: stats.hash_count,           warn: false },
            { label: "Enabled",       value: stats.enabled_count,        warn: false },
            { label: "Total Hits",    value: stats.total_hits,           warn: false },
            { label: "Stale",         value: stats.stale_count ?? 0,     warn: (stats.stale_count ?? 0) > 0 },
            { label: "Expiring Soon", value: stats.expiring_soon_count ?? 0, warn: (stats.expiring_soon_count ?? 0) > 0 },
          ].map((s) => (
            <div key={s.label} className="text-center">
              <div className={cn("text-lg font-semibold font-mono", s.warn && s.value > 0 ? "text-amber-400" : "")} style={!s.warn || s.value === 0 ? { color: "var(--fg)" } : {}}>
                {s.value?.toLocaleString() ?? 0}
              </div>
              <div className="text-[10px] uppercase tracking-wider" style={{ color: "var(--muted)" }}>
                {s.label}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Search */}
      <input
        type="text"
        placeholder="Search IOCs by value or source..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="rounded-md border px-3 py-1.5 text-xs w-full max-w-md outline-none focus-ring"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
      />

      {/* Filter pills */}
      <div className="flex flex-wrap items-center gap-2">
        {TYPE_FILTERS.map((f) => (
          <button
            key={f.value}
            onClick={() => { setTypeFilter(f.value); setStaleFilter(false); }}
            className={cn(
              "rounded-full px-3 py-1 text-xs font-medium transition-colors",
              typeFilter === f.value && !staleFilter
                ? "text-[var(--primary-fg)]"
                : "hover:bg-[var(--surface-2)]"
            )}
            style={{
              background: typeFilter === f.value && !staleFilter ? "var(--primary)" : "var(--surface-1)",
              color: typeFilter === f.value && !staleFilter ? "var(--primary-fg)" : "var(--muted)",
            }}
          >
            {f.label}
          </button>
        ))}
        <button
          onClick={() => { setStaleFilter((v) => !v); setTypeFilter(""); }}
          className={cn(
            "rounded-full px-3 py-1 text-xs font-medium transition-colors",
            staleFilter ? "text-amber-900" : "hover:bg-[var(--surface-2)]"
          )}
          style={{
            background: staleFilter ? "rgb(245 158 11)" : "var(--surface-1)",
            color: staleFilter ? "#1c1400" : "rgb(245 158 11)",
          }}
        >
          Stale / Expired
        </button>
      </div>

      {/* Add IOC form */}
      {showAddForm && (
        <AddIOCForm
          onSubmit={handleAddIOC}
          onCancel={() => setShowAddForm(false)}
        />
      )}

      {/* Bulk import form */}
      {showBulkForm && (
        <BulkImportForm
          onSubmit={handleBulkImport}
          onCancel={() => setShowBulkForm(false)}
        />
      )}

      {/* Error state */}
      {error && (
        <div
          className="rounded-lg border p-4 text-center text-sm text-red-400"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
        >
          {error}
        </div>
      )}

      {/* IOC table */}
      <div
        className="rounded-lg border overflow-hidden"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
      >
        {/* Table header */}
        <div
          className="grid grid-cols-[32px_80px_1fr_100px_50px_60px_70px_80px_80px_50px] gap-2 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider border-b"
          style={{ color: "var(--muted-fg)", borderColor: "var(--border)", background: "var(--surface-1)" }}
        >
          <span className="flex items-center justify-center">
            <input
              type="checkbox"
              checked={allSelected}
              onChange={toggleSelectAll}
              className="rounded"
              onClick={(e) => e.stopPropagation()}
            />
          </span>
          <span>Type</span>
          <span>Value</span>
          <span>Source</span>
          <span>Sev</span>
          <span>Enabled</span>
          <span>Hits</span>
          <span>Confidence</span>
          <span>Created</span>
          <span></span>
        </div>

        {/* Loading skeleton */}
        {loading && displayIOCs.length === 0 && (
          <div>
            {Array.from({ length: 8 }).map((_, i) => (
              <SkeletonRow key={i} />
            ))}
          </div>
        )}

        {/* Rows */}
        {displayIOCs.map((ioc) => {
          const expired = isExpired(ioc);
          const stale   = isStale(ioc);
          const conf    = ioc.confidence ?? 50;
          return (
            <div
              key={ioc.id}
              onClick={() => setSelectedIOC(ioc)}
              className={cn(
                "grid grid-cols-[32px_80px_1fr_100px_50px_60px_70px_80px_80px_50px] gap-2 px-3 py-2 text-xs items-center transition-colors border-b last:border-b-0 hover:bg-[var(--surface-1)] cursor-pointer",
                selected.has(ioc.id) && "bg-[var(--surface-1)]"
              )}
              style={{ borderColor: "var(--border-subtle)" }}
            >
              {/* Checkbox */}
              <span className="flex items-center justify-center" onClick={(e) => e.stopPropagation()}>
                <input
                  type="checkbox"
                  checked={selected.has(ioc.id)}
                  onChange={() => toggleSelect(ioc.id)}
                  className="rounded"
                />
              </span>
              {/* Type + staleness badge */}
              <span className="flex flex-col gap-0.5">
                <span className={cn("inline-flex rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase", typeBadgeClass(ioc.type))}>
                  {ioc.type}
                </span>
                {expired && (
                  <span className="text-[9px] px-1 rounded bg-red-500/15 text-red-400 font-medium">expired</span>
                )}
                {!expired && stale && (
                  <span className="text-[9px] px-1 rounded bg-amber-500/15 text-amber-400 font-medium">stale</span>
                )}
              </span>
              {/* Value */}
              <span className="truncate font-mono" style={{ color: "var(--fg)" }} title={ioc.value}>
                {ioc.value}
              </span>
              <span className="truncate" style={{ color: "var(--muted)" }}>
                {ioc.source || "—"}
              </span>
              <span className="flex justify-center">
                <span className={cn("inline-block h-2.5 w-2.5 rounded-full", severityDot(ioc.severity))} />
              </span>
              <span className="flex justify-center">
                <button
                  onClick={(e) => { e.stopPropagation(); handleToggleEnabled(ioc); }}
                  className={cn(
                    "relative inline-flex h-5 w-9 items-center rounded-full transition-colors",
                    ioc.enabled ? "bg-emerald-500" : "bg-neutral-600"
                  )}
                >
                  <span
                    className={cn(
                      "inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform",
                      ioc.enabled ? "translate-x-4" : "translate-x-0.5"
                    )}
                  />
                </button>
              </span>
              <span className="font-mono text-center" style={{ color: "var(--fg)" }}>
                {ioc.hit_count ?? 0}
              </span>
              {/* Confidence bar */}
              <span className="flex items-center gap-1.5">
                <div className="flex-1 h-1.5 rounded-full bg-white/8 overflow-hidden">
                  <div
                    className={cn("h-full rounded-full transition-all", confidenceColor(conf))}
                    style={{ width: `${conf}%` }}
                  />
                </div>
                <span className="text-[10px] font-mono w-6 text-right shrink-0" style={{ color: "var(--muted)" }}>
                  {conf}
                </span>
              </span>
              <span className="font-mono truncate" style={{ color: "var(--muted)" }}>
                {timeAgo(ioc.created_at)}
              </span>
              <span className="flex justify-center">
                <button
                  onClick={(e) => { e.stopPropagation(); handleDelete(ioc.id); }}
                  className="rounded p-1 text-red-400/60 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                  title="Delete IOC"
                >
                  <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                </button>
              </span>
            </div>
          );
        })}

        {/* Empty state */}
        {!loading && displayIOCs.length === 0 && (
          <div className="py-12 text-center text-xs" style={{ color: "var(--muted)" }}>
            No IOCs found
          </div>
        )}
      </div>

      {/* Enrichment detail drawer */}
      {selectedIOC && (
        <EnrichmentDrawer
          ioc={selectedIOC}
          onClose={() => setSelectedIOC(null)}
          onReenrich={() => {
            refetch();
            setSelectedIOC(null);
          }}
        />
      )}
    </div>
  );
}
