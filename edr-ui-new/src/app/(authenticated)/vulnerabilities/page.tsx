"use client";

import { useCallback, useMemo, useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { cn, timeAgo } from "@/lib/utils";
import type { Vulnerability } from "@/types";

/* ---------- Constants ---------- */
const SEVERITY_FILTERS = [
  { label: "All", value: "" },
  { label: "Critical", value: "CRITICAL" },
  { label: "High", value: "HIGH" },
  { label: "Medium", value: "MEDIUM" },
  { label: "Low", value: "LOW" },
  { label: "Unknown", value: "UNKNOWN" },
] as const;

const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: "bg-red-600/15 text-red-400",
  HIGH: "bg-orange-500/15 text-orange-400",
  MEDIUM: "bg-amber-500/15 text-amber-400",
  LOW: "bg-blue-500/15 text-blue-400",
  UNKNOWN: "bg-neutral-500/15 text-neutral-400",
};

function sevBadgeClass(sev: string): string {
  return SEVERITY_BADGE[sev?.toUpperCase()] ?? "bg-neutral-500/15 text-neutral-400";
}

/* ---------- Skeleton ---------- */
function SkeletonRow() {
  return (
    <div className="flex items-center gap-3 px-3 py-2">
      <div className="animate-shimmer h-4 w-28 rounded" />
      <div className="animate-shimmer h-4 w-24 rounded" />
      <div className="animate-shimmer h-4 w-16 rounded" />
      <div className="animate-shimmer h-5 w-16 rounded" />
      <div className="animate-shimmer h-4 w-24 rounded" />
      <div className="animate-shimmer h-4 w-20 rounded" />
      <div className="animate-shimmer h-4 w-16 rounded" />
    </div>
  );
}

/* ---------- Vulnerabilities Page ---------- */
export default function VulnerabilitiesPage() {
  const [sevFilter, setSevFilter] = useState("");
  const [search, setSearch] = useState("");

  /* Fetch vulnerabilities */
  const fetchVulns = useCallback(
    () =>
      api
        .get<{ vulnerabilities?: Vulnerability[] } | Vulnerability[]>("/api/v1/vulnerabilities")
        .then((r) => (Array.isArray(r) ? r : r.vulnerabilities ?? [])),
    []
  );
  const { data: vulns, loading, error } = useApi(fetchVulns);

  /* Client-side filtering */
  const displayVulns = useMemo(() => {
    let list = vulns ?? [];
    if (sevFilter) {
      list = list.filter((v) => v.severity?.toUpperCase() === sevFilter.toUpperCase());
    }
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(
        (v) =>
          v.cve_id?.toLowerCase().includes(q) ||
          v.package_name?.toLowerCase().includes(q)
      );
    }
    return list;
  }, [vulns, sevFilter, search]);

  return (
    <div className="animate-fade-in space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <h1
          className="text-lg font-semibold"
          style={{ fontFamily: "var(--font-space-grotesk)" }}
        >
          Vulnerabilities
        </h1>
      </div>

      {/* Filter pills + search */}
      <div className="flex flex-wrap items-center gap-2">
        {SEVERITY_FILTERS.map((f) => (
          <button
            key={f.value}
            onClick={() => setSevFilter(f.value)}
            className={cn(
              "rounded-full px-3 py-1 text-xs font-medium transition-colors",
              sevFilter === f.value
                ? "text-[var(--primary-fg)]"
                : "hover:bg-[var(--surface-2)]"
            )}
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
          placeholder="Search CVE or package..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="rounded-md border px-3 py-1.5 text-xs w-56 outline-none focus-ring"
          style={{
            background: "var(--surface-0)",
            borderColor: "var(--border)",
            color: "var(--fg)",
          }}
        />
      </div>

      {/* Error state */}
      {error && (
        <div
          className="rounded-lg border p-4 text-center text-sm text-red-400"
          style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
        >
          {error}
        </div>
      )}

      {/* Table */}
      <div
        className="rounded-lg border overflow-hidden"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
      >
        {/* Table header */}
        <div
          className="grid grid-cols-[140px_1fr_100px_90px_120px_100px_100px] gap-2 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider border-b"
          style={{ color: "var(--muted-fg)", borderColor: "var(--border)", background: "var(--surface-1)" }}
        >
          <span>CVE ID</span>
          <span>Package</span>
          <span>Version</span>
          <span>Severity</span>
          <span>Hostname</span>
          <span>Fixed Version</span>
          <span>Detected</span>
        </div>

        {/* Loading skeleton */}
        {loading && displayVulns.length === 0 && (
          <div>
            {Array.from({ length: 10 }).map((_, i) => (
              <SkeletonRow key={i} />
            ))}
          </div>
        )}

        {/* Rows */}
        {displayVulns.map((vuln) => (
          <div
            key={vuln.id}
            className="grid grid-cols-[140px_1fr_100px_90px_120px_100px_100px] gap-2 px-3 py-2 text-xs items-center transition-colors border-b last:border-b-0 hover:bg-[var(--surface-1)]"
            style={{ borderColor: "var(--border-subtle)" }}
          >
            <span className="font-mono truncate" style={{ color: "var(--primary)" }}>
              <a
                href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="hover:underline"
              >
                {vuln.cve_id}
              </a>
            </span>
            <span className="truncate" style={{ color: "var(--fg)" }}>
              {vuln.package_name}
            </span>
            <span className="font-mono truncate" style={{ color: "var(--muted)" }}>
              {vuln.package_version}
            </span>
            <span>
              <span className={cn("inline-flex rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase", sevBadgeClass(vuln.severity))}>
                {vuln.severity}
              </span>
            </span>
            <span className="truncate" style={{ color: "var(--fg)" }}>
              {vuln.agent_id ? vuln.agent_id.slice(0, 8) : "—"}
            </span>
            <span className="font-mono truncate" style={{ color: vuln.fixed_version ? "var(--fg)" : "var(--muted)" }}>
              {vuln.fixed_version || "—"}
            </span>
            <span className="font-mono truncate" style={{ color: "var(--muted)" }}>
              {timeAgo(vuln.detected_at)}
            </span>
          </div>
        ))}

        {/* Empty state */}
        {!loading && displayVulns.length === 0 && (
          <div className="py-12 text-center text-xs" style={{ color: "var(--muted)" }}>
            No vulnerabilities detected
          </div>
        )}
      </div>
    </div>
  );
}
