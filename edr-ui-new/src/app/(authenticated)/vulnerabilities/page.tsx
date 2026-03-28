"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn, timeAgo } from "@/lib/utils";
import { exportToCSV, exportToJSON } from "@/lib/export";
import { Bug, Download, ExternalLink, Package, Shield, Search, Loader2 } from "lucide-react";
import type { Agent, Vulnerability } from "@/types";

/* ── Types ─────────────────────────────────────────────────── */

interface AgentPackage {
  id: number;
  agent_id: string;
  name: string;
  version: string;
  arch: string;
  collected_at: string;
}

interface CVEDetail {
  cve_id: string;
  description: string;
  severity: string;
  published_date: string | null;
  references: string[];
  exploit_available: boolean;
  cisa_kev: boolean;
  source: string;
  fetched_at: string;
}

/* ── Constants ─────────────────────────────────────────────── */

const SEVERITY_FILTERS = [
  { label: "All", value: "" },
  { label: "Critical", value: "CRITICAL" },
  { label: "High", value: "HIGH" },
  { label: "Medium", value: "MEDIUM" },
  { label: "Low", value: "LOW" },
  { label: "Unknown", value: "UNKNOWN" },
] as const;

const SEV_BADGE: Record<string, string> = {
  CRITICAL: "bg-red-600/15 text-red-400",
  HIGH: "bg-orange-500/15 text-orange-400",
  MEDIUM: "bg-amber-500/15 text-amber-400",
  LOW: "bg-blue-500/15 text-blue-400",
  UNKNOWN: "bg-neutral-500/15 text-neutral-400",
};

/* ── CVE Lookup (via backend cache) ────────────────────────── */

async function lookupCVE(cveId: string): Promise<CVEDetail | null> {
  try {
    const detail = await api.get<CVEDetail>(`/api/v1/cve/${cveId}`);
    return detail;
  } catch {
    return null;
  }
}

/* ── CVE Detail Panel ──────────────────────────────────────── */

function CVEDetailPanel({ cveId, onClose }: { cveId: string; onClose: () => void }) {
  const [detail, setDetail] = useState<CVEDetail | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    setDetail(null);
    lookupCVE(cveId).then((d) => {
      setDetail(d);
      setLoading(false);
    });
  }, [cveId]);

  return (
    <div
      className="fixed inset-y-0 right-0 z-50 w-full max-w-lg border-l shadow-xl overflow-y-auto animate-fade-in"
      style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
    >
      <div className="flex items-center justify-between p-4 border-b" style={{ borderColor: "var(--border)" }}>
        <h3 className="text-sm font-semibold font-heading font-mono">{cveId}</h3>
        <button onClick={onClose} className="text-xs rounded px-2 py-1 hover:bg-[var(--surface-2)]" style={{ color: "var(--muted)" }}>
          Close
        </button>
      </div>
      <div className="p-4 space-y-4">
        {loading && (
          <div className="flex items-center gap-2 text-xs" style={{ color: "var(--muted)" }}>
            <Loader2 size={14} className="animate-spin" /> Fetching from NVD...
          </div>
        )}
        {!loading && !detail && (
          <p className="text-xs" style={{ color: "var(--muted)" }}>
            Could not fetch CVE details from NVD. The API may be rate-limited.
          </p>
        )}
        {!loading && detail && (
          <>
            {/* Severity + flags */}
            <div className="flex items-center gap-2">
              <span className={cn("rounded px-2 py-0.5 text-[10px] font-bold uppercase", SEV_BADGE[detail.severity?.toUpperCase()] ?? SEV_BADGE.UNKNOWN)}>
                {detail.severity}
              </span>
              {detail.exploit_available && (
                <span className="rounded px-2 py-0.5 text-[10px] font-bold uppercase bg-red-600/20 text-red-400">
                  Exploit Available
                </span>
              )}
              {detail.cisa_kev && (
                <span className="rounded px-2 py-0.5 text-[10px] font-bold uppercase bg-orange-600/20 text-orange-400">
                  CISA KEV
                </span>
              )}
            </div>

            {/* Description */}
            <div>
              <div className="text-[10px] uppercase tracking-wider mb-1 font-medium" style={{ color: "var(--muted)" }}>Description</div>
              <p className="text-xs leading-relaxed" style={{ color: "var(--fg)" }}>{detail.description}</p>
            </div>

            {/* Published */}
            {detail.published_date && (
              <div className="text-xs">
                <span style={{ color: "var(--muted)" }}>Published: </span>
                <span className="font-mono" style={{ color: "var(--fg)" }}>{new Date(detail.published_date).toLocaleDateString()}</span>
              </div>
            )}

            {/* Source + cache info */}
            <div className="text-[10px]" style={{ color: "var(--muted)" }}>
              Source: {detail.source?.toUpperCase()} | Cached: {detail.fetched_at ? new Date(detail.fetched_at).toLocaleString() : "—"}
            </div>

            {/* References */}
            {detail.references.length > 0 && (
              <div>
                <div className="text-[10px] uppercase tracking-wider mb-1 font-medium" style={{ color: "var(--muted)" }}>References</div>
                <div className="space-y-1">
                  {detail.references.map((ref, i) => (
                    <a
                      key={i}
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1 text-xs truncate hover:underline"
                      style={{ color: "var(--primary)" }}
                    >
                      <ExternalLink size={10} className="shrink-0" />
                      {ref.replace(/^https?:\/\//, "").slice(0, 70)}
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* External links */}
            <div className="flex flex-wrap gap-2 pt-2 border-t" style={{ borderColor: "var(--border)" }}>
              <a
                href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded border px-2 py-1 text-[10px] font-medium hover:bg-[var(--surface-2)] transition-colors"
                style={{ borderColor: "var(--border)", color: "var(--primary)" }}
              >
                NVD
              </a>
              <a
                href={`https://www.exploit-db.com/search?cve=${cveId.replace("CVE-", "")}`}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded border px-2 py-1 text-[10px] font-medium hover:bg-[var(--surface-2)] transition-colors"
                style={{ borderColor: "var(--border)", color: "var(--primary)" }}
              >
                Exploit-DB
              </a>
              <a
                href={`https://www.cisa.gov/known-exploited-vulnerabilities-catalog`}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded border px-2 py-1 text-[10px] font-medium hover:bg-[var(--surface-2)] transition-colors"
                style={{ borderColor: "var(--border)", color: "var(--primary)" }}
              >
                CISA KEV
              </a>
              <a
                href={`https://github.com/advisories?query=${cveId}`}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded border px-2 py-1 text-[10px] font-medium hover:bg-[var(--surface-2)] transition-colors"
                style={{ borderColor: "var(--border)", color: "var(--primary)" }}
              >
                GitHub Advisory
              </a>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/* ── Main Page ─────────────────────────────────────────────── */

export default function VulnerabilitiesPage() {
  const [selectedAgent, setSelectedAgent] = useState<string>("");
  const [activeTab, setActiveTab] = useState<"vulns" | "packages">("vulns");
  const [sevFilter, setSevFilter] = useState("");
  const [search, setSearch] = useState("");
  const [selectedCVE, setSelectedCVE] = useState<string | null>(null);
  const [showExport, setShowExport] = useState(false);

  /* Fetch agents */
  const fetchAgents = useCallback(
    () => api.get<{ agents?: Agent[] } | Agent[]>("/api/v1/agents").then((r) => (Array.isArray(r) ? r : r.agents ?? [])),
    []
  );
  const { data: agents } = useApi(fetchAgents);

  /* Fetch vulnerabilities — all or per-agent */
  const fetchVulns = useCallback(
    () => {
      const url = selectedAgent
        ? `/api/v1/agents/${selectedAgent}/vulnerabilities`
        : "/api/v1/vulnerabilities";
      return api.get<{ vulnerabilities?: Vulnerability[]; stats?: Record<string, number> } | Vulnerability[]>(url)
        .then((r) => {
          if (Array.isArray(r)) return r;
          return r.vulnerabilities ?? [];
        });
    },
    [selectedAgent]
  );
  const { data: vulns, loading: vulnsLoading, refetch: refetchVulns } = useApi(fetchVulns);
  const [scanning, setScanning] = useState(false);
  const [scanMsg, setScanMsg] = useState("");

  async function triggerScan() {
    if (!selectedAgent) return;
    setScanning(true);
    setScanMsg("Scanning packages on agent...");
    try {
      const res = await api.post<{ status?: string; packages?: number }>(
        `/api/v1/agents/${selectedAgent}/scan-packages`
      );
      const count = res.packages ?? 0;
      setScanMsg(`Scan complete — ${count} packages found`);
      // Refresh data immediately
      refetchVulns();
      refetchPkgs();
      setTimeout(() => setScanMsg(""), 5000);
    } catch (err) {
      setScanMsg(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setScanning(false);
    }
  }

  /* Fetch packages (only when agent selected + packages tab) */
  const fetchPackages = useCallback(
    () => {
      if (!selectedAgent) return Promise.resolve([] as AgentPackage[]);
      return api.get<{ packages?: AgentPackage[] } | AgentPackage[]>(`/api/v1/agents/${selectedAgent}/packages`)
        .then((r) => (Array.isArray(r) ? r : r.packages ?? []));
    },
    [selectedAgent]
  );
  const { data: packages, loading: pkgLoading, refetch: refetchPkgs } = useApi(fetchPackages);

  /* Filtered vulns */
  const displayVulns = useMemo(() => {
    let list = vulns ?? [];
    if (sevFilter) list = list.filter((v) => v.severity?.toUpperCase() === sevFilter);
    if (search) {
      const q = search.toLowerCase();
      list = list.filter((v) => v.cve_id?.toLowerCase().includes(q) || v.package_name?.toLowerCase().includes(q));
    }
    return list;
  }, [vulns, sevFilter, search]);

  /* Filtered packages */
  const displayPackages = useMemo(() => {
    let list = packages ?? [];
    if (search) {
      const q = search.toLowerCase();
      list = list.filter((p) => p.name?.toLowerCase().includes(q) || p.version?.toLowerCase().includes(q));
    }
    return list;
  }, [packages, search]);

  /* Stats */
  const stats = useMemo(() => {
    const all = vulns ?? [];
    return {
      total: all.length,
      critical: all.filter((v) => v.severity?.toUpperCase() === "CRITICAL").length,
      high: all.filter((v) => v.severity?.toUpperCase() === "HIGH").length,
      medium: all.filter((v) => v.severity?.toUpperCase() === "MEDIUM").length,
      low: all.filter((v) => v.severity?.toUpperCase() === "LOW").length,
    };
  }, [vulns]);

  const selectedAgentObj = (agents ?? []).find((a) => a.id === selectedAgent);

  return (
    <div className="animate-fade-in space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-lg font-semibold flex items-center gap-2" style={{ fontFamily: "var(--font-space-grotesk)" }}>
          <Bug size={20} style={{ color: "var(--primary)" }} />
          Vulnerabilities & Packages
        </h1>
      </div>

      {/* Agent selector + tabs */}
      <div
        className="flex flex-wrap items-center gap-3 p-3 rounded border"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
      >
        <div className="flex items-center gap-2">
          <label className="text-[10px] uppercase tracking-wider font-medium" style={{ color: "var(--muted)" }}>Agent</label>
          <select
            value={selectedAgent}
            onChange={(e) => { setSelectedAgent(e.target.value); setSearch(""); }}
            className="rounded border px-2 py-1.5 text-xs font-mono"
            style={{ background: "var(--surface-1)", borderColor: "var(--border)", color: "var(--fg)" }}
          >
            <option value="">All agents (vulnerable packages only)</option>
            {(agents ?? []).map((a) => (
              <option key={a.id} value={a.id}>{a.hostname} ({a.ip})</option>
            ))}
          </select>
          {/* Scan button */}
          {selectedAgent && (
            <button
              onClick={triggerScan}
              disabled={scanning}
              className="flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-2)] disabled:opacity-50"
              style={{ borderColor: "var(--border)", color: "var(--primary)" }}
            >
              {scanning ? <Loader2 size={12} className="animate-spin" /> : <Search size={12} />}
              {scanning ? "Scanning..." : "Scan Now"}
            </button>
          )}
          {scanMsg && (
            <span className="text-[10px]" style={{ color: "var(--muted)" }}>{scanMsg}</span>
          )}
        </div>

        {/* Tabs — show Packages tab only when agent selected */}
        <div className="flex gap-1 ml-auto">
          <button
            onClick={() => setActiveTab("vulns")}
            className={cn("rounded px-3 py-1 text-xs font-medium transition-colors", activeTab === "vulns" ? "" : "hover:bg-[var(--surface-2)]")}
            style={{
              background: activeTab === "vulns" ? "var(--primary)" : "var(--surface-1)",
              color: activeTab === "vulns" ? "var(--primary-fg)" : "var(--muted)",
            }}
          >
            <Shield size={12} className="inline mr-1" />
            Vulnerabilities
          </button>
          {selectedAgent && (
            <button
              onClick={() => setActiveTab("packages")}
              className={cn("rounded px-3 py-1 text-xs font-medium transition-colors", activeTab === "packages" ? "" : "hover:bg-[var(--surface-2)]")}
              style={{
                background: activeTab === "packages" ? "var(--primary)" : "var(--surface-1)",
                color: activeTab === "packages" ? "var(--primary-fg)" : "var(--muted)",
              }}
            >
              <Package size={12} className="inline mr-1" />
              Packages ({(packages ?? []).length})
            </button>
          )}
        </div>
      </div>

      {/* Stats bar (vulns tab) */}
      {activeTab === "vulns" && (
        <div className="flex items-center gap-6 text-xs" style={{ color: "var(--muted)" }}>
          <span><strong className="font-mono text-red-400">{stats.critical}</strong> Critical</span>
          <span><strong className="font-mono text-orange-400">{stats.high}</strong> High</span>
          <span><strong className="font-mono text-amber-400">{stats.medium}</strong> Medium</span>
          <span><strong className="font-mono text-blue-400">{stats.low}</strong> Low</span>
          <span><strong className="font-mono" style={{ color: "var(--fg)" }}>{stats.total}</strong> Total</span>
          {!selectedAgent && (
            <span className="text-[10px]" style={{ color: "var(--muted)" }}>
              Showing vulnerable packages across all endpoints
            </span>
          )}
          {selectedAgent && selectedAgentObj && (
            <span className="text-[10px]" style={{ color: "var(--muted)" }}>
              Agent: {selectedAgentObj.hostname}
            </span>
          )}
        </div>
      )}

      {/* Filter row */}
      <div className="flex flex-wrap items-center gap-2">
        {activeTab === "vulns" && SEVERITY_FILTERS.map((f) => (
          <button
            key={f.value}
            onClick={() => setSevFilter(f.value)}
            className={cn("rounded-full px-3 py-1 text-xs font-medium transition-colors")}
            style={{
              background: sevFilter === f.value ? "var(--primary)" : "var(--surface-1)",
              color: sevFilter === f.value ? "var(--primary-fg)" : "var(--muted)",
            }}
          >
            {f.label}
          </button>
        ))}
        <div className="flex-1" />
        <input
          type="text"
          placeholder={activeTab === "vulns" ? "Search CVE or package..." : "Search package name..."}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="rounded-md border px-3 py-1.5 text-xs w-56 outline-none"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
        />
        {/* Export */}
        {((activeTab === "vulns" && displayVulns.length > 0) || (activeTab === "packages" && displayPackages.length > 0)) && (
          <div className="relative">
            <button
              onClick={() => setShowExport(!showExport)}
              className="flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-2)]"
              style={{ borderColor: "var(--border)", color: "var(--muted)" }}
            >
              <Download size={12} /> Export
            </button>
            {showExport && (
              <div
                className="absolute right-0 top-full mt-1 rounded border shadow-lg z-10 py-1 min-w-[120px]"
                style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
              >
                <button
                  onClick={() => {
                    if (activeTab === "vulns") {
                      const csv = displayVulns.map(v => [v.cve_id, v.package_name, v.package_version, v.severity, v.fixed_version, v.agent_id, v.detected_at].join(","));
                      const blob = new Blob(["cve_id,package,version,severity,fixed_version,agent_id,detected_at\n" + csv.join("\n")], { type: "text/csv" });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a"); a.href = url; a.download = "vulnerabilities.csv"; a.click(); URL.revokeObjectURL(url);
                    } else {
                      const csv = displayPackages.map(p => [p.name, p.version, p.arch].join(","));
                      const blob = new Blob(["name,version,arch\n" + csv.join("\n")], { type: "text/csv" });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a"); a.href = url; a.download = "packages.csv"; a.click(); URL.revokeObjectURL(url);
                    }
                    setShowExport(false);
                  }}
                  className="w-full text-left px-3 py-1.5 text-xs hover:bg-[var(--surface-1)] transition-colors"
                  style={{ color: "var(--fg)" }}
                >
                  Export as CSV
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ═══ Vulnerabilities Tab ═══ */}
      {activeTab === "vulns" && (
        <div
          className="rounded-lg border overflow-hidden"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
        >
          <div
            className="grid grid-cols-[130px_1fr_90px_80px_110px_90px_80px] gap-2 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider border-b"
            style={{ color: "var(--muted-fg)", borderColor: "var(--border)", background: "var(--surface-1)" }}
          >
            <span>CVE ID</span>
            <span>Package</span>
            <span>Version</span>
            <span>Severity</span>
            <span>Hostname</span>
            <span>Fixed In</span>
            <span>Detected</span>
          </div>

          {vulnsLoading && (
            <div className="space-y-0">
              {Array.from({ length: 8 }).map((_, i) => (
                <div key={i} className="flex gap-3 px-3 py-2">
                  <div className="animate-shimmer h-4 w-28 rounded" />
                  <div className="animate-shimmer h-4 flex-1 rounded" />
                  <div className="animate-shimmer h-4 w-16 rounded" />
                </div>
              ))}
            </div>
          )}

          {displayVulns.map((vuln) => (
            <button
              key={vuln.id}
              onClick={() => setSelectedCVE(selectedCVE === vuln.cve_id ? null : vuln.cve_id)}
              className="w-full grid grid-cols-[130px_1fr_90px_80px_110px_90px_80px] gap-2 px-3 py-2 text-xs items-center transition-colors border-b last:border-b-0 hover:bg-[var(--surface-1)] text-left"
              style={{ borderColor: "var(--border-subtle)" }}
            >
              <span className="font-mono truncate" style={{ color: "var(--primary)" }}>{vuln.cve_id}</span>
              <span className="truncate" style={{ color: "var(--fg)" }}>{vuln.package_name}</span>
              <span className="font-mono truncate" style={{ color: "var(--muted)" }}>{vuln.package_version}</span>
              <span>
                <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase", SEV_BADGE[vuln.severity?.toUpperCase()] ?? SEV_BADGE.UNKNOWN)}>
                  {vuln.severity}
                </span>
              </span>
              <span className="truncate" style={{ color: "var(--fg)" }}>
                {selectedAgent ? (selectedAgentObj?.hostname ?? "—") : (vuln.agent_id?.slice(0, 8) ?? "—")}
              </span>
              <span className="font-mono truncate" style={{ color: vuln.fixed_version ? "var(--fg)" : "var(--muted)" }}>
                {vuln.fixed_version || "—"}
              </span>
              <span className="font-mono truncate" style={{ color: "var(--muted)" }}>{timeAgo(vuln.detected_at)}</span>
            </button>
          ))}

          {!vulnsLoading && displayVulns.length === 0 && (
            <div className="py-12 text-center text-xs" style={{ color: "var(--muted)" }}>
              {selectedAgent ? "No vulnerabilities detected on this agent" : "No vulnerable packages found across endpoints"}
            </div>
          )}
        </div>
      )}

      {/* ═══ Packages Tab ═══ */}
      {activeTab === "packages" && selectedAgent && (
        <div
          className="rounded-lg border overflow-hidden"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
        >
          <div
            className="grid grid-cols-[1fr_150px_100px_120px] gap-2 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider border-b"
            style={{ color: "var(--muted-fg)", borderColor: "var(--border)", background: "var(--surface-1)" }}
          >
            <span>Package Name</span>
            <span>Version</span>
            <span>Architecture</span>
            <span>Collected</span>
          </div>

          {pkgLoading && (
            <div className="space-y-0">
              {Array.from({ length: 10 }).map((_, i) => (
                <div key={i} className="flex gap-3 px-3 py-2">
                  <div className="animate-shimmer h-4 flex-1 rounded" />
                  <div className="animate-shimmer h-4 w-24 rounded" />
                  <div className="animate-shimmer h-4 w-16 rounded" />
                </div>
              ))}
            </div>
          )}

          {displayPackages.map((pkg) => (
            <div
              key={pkg.id}
              className="grid grid-cols-[1fr_150px_100px_120px] gap-2 px-3 py-2 text-xs items-center border-b last:border-b-0 hover:bg-[var(--surface-1)] transition-colors"
              style={{ borderColor: "var(--border-subtle)" }}
            >
              <span style={{ color: "var(--fg)" }}>{pkg.name}</span>
              <span className="font-mono" style={{ color: "var(--fg)" }}>{pkg.version}</span>
              <span style={{ color: "var(--muted)" }}>{pkg.arch}</span>
              <span className="font-mono" style={{ color: "var(--muted)" }}>{timeAgo(pkg.collected_at)}</span>
            </div>
          ))}

          {!pkgLoading && displayPackages.length === 0 && (
            <div className="py-12 text-center text-xs" style={{ color: "var(--muted)" }}>
              No packages found for this agent
            </div>
          )}

          {!pkgLoading && displayPackages.length > 0 && (
            <div className="px-3 py-2 text-[10px] border-t" style={{ borderColor: "var(--border)", color: "var(--muted)" }}>
              {displayPackages.length} packages installed on {selectedAgentObj?.hostname}
            </div>
          )}
        </div>
      )}

      {activeTab === "packages" && !selectedAgent && (
        <div
          className="rounded-lg border py-12 text-center text-xs"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--muted)" }}
        >
          Select an agent to view installed packages
        </div>
      )}

      {/* CVE Detail Panel */}
      {selectedCVE && (
        <CVEDetailPanel cveId={selectedCVE} onClose={() => setSelectedCVE(null)} />
      )}
    </div>
  );
}
