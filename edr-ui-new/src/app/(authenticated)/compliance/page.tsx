"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";

type Framework = "nist-csf" | "iso-27001" | "pci-dss";

interface CoverageItem {
  id: string;
  name: string;
  category: string;
  description: string;
  covered: boolean;
  rule_ids?: string[];
  mitre_ids?: string[];
}

interface ComplianceReport {
  framework: Framework;
  total: number;
  covered: number;
  percentage: number;
  controls: CoverageItem[];
}

const FRAMEWORKS: { id: Framework; label: string; short: string }[] = [
  { id: "nist-csf",  label: "NIST CSF 2.0",       short: "NIST" },
  { id: "iso-27001", label: "ISO 27001:2022",       short: "ISO" },
  { id: "pci-dss",   label: "PCI-DSS 4.0",         short: "PCI" },
];

const CATEGORY_COLORS: Record<string, string> = {
  Govern:           "text-violet-400 bg-violet-500/10 border-violet-500/20",
  Identify:         "text-blue-400 bg-blue-500/10 border-blue-500/20",
  Protect:          "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
  Detect:           "text-amber-400 bg-amber-500/10 border-amber-500/20",
  Respond:          "text-orange-400 bg-orange-500/10 border-orange-500/20",
  Recover:          "text-red-400 bg-red-500/10 border-red-500/20",
  Organizational:   "text-blue-400 bg-blue-500/10 border-blue-500/20",
  People:           "text-purple-400 bg-purple-500/10 border-purple-500/20",
  Technological:    "text-cyan-400 bg-cyan-500/10 border-cyan-500/20",
  "Network Security":        "text-red-400 bg-red-500/10 border-red-500/20",
  "Vulnerability Management":"text-orange-400 bg-orange-500/10 border-orange-500/20",
  "Software Development":    "text-blue-400 bg-blue-500/10 border-blue-500/20",
  "Logging & Monitoring":    "text-amber-400 bg-amber-500/10 border-amber-500/20",
  "Testing":                 "text-purple-400 bg-purple-500/10 border-purple-500/20",
  "Incident Response":       "text-red-400 bg-red-500/10 border-red-500/20",
};

function GaugArc({ pct }: { pct: number }) {
  const r = 52;
  const circ = 2 * Math.PI * r;
  const dash = (pct / 100) * circ;
  const color = pct >= 70 ? "#10b981" : pct >= 40 ? "#f59e0b" : "#ef4444";
  return (
    <svg width="130" height="80" viewBox="0 0 130 80">
      <path d="M15,70 A52,52,0,0,1,115,70" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="10" strokeLinecap="round" />
      <path
        d="M15,70 A52,52,0,0,1,115,70"
        fill="none"
        stroke={color}
        strokeWidth="10"
        strokeLinecap="round"
        strokeDasharray={`${dash * 0.5} ${circ}`}
        style={{ transition: "stroke-dasharray 0.6s ease" }}
      />
      <text x="65" y="66" textAnchor="middle" fontSize="22" fontWeight="700" fill="white" fontFamily="monospace">
        {pct}%
      </text>
    </svg>
  );
}

export default function CompliancePage() {
  const [framework, setFramework] = useState<Framework>("nist-csf");
  const [filterCovered, setFilterCovered] = useState<"all" | "covered" | "gap">("all");
  const [filterCategory, setFilterCategory] = useState("");

  const { data, loading, error } = useApi<ComplianceReport>(
    (signal) => api.get(`/compliance/coverage`, { framework }, signal),
  );

  const controls = data?.controls ?? [];
  const categories = Array.from(new Set(controls.map((c) => c.category)));

  const filtered = controls.filter((c) => {
    if (filterCovered === "covered" && !c.covered) return false;
    if (filterCovered === "gap" && c.covered) return false;
    if (filterCategory && c.category !== filterCategory) return false;
    return true;
  });

  const gaps = controls.filter((c) => !c.covered).length;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Compliance Coverage</h1>
          <p className="text-sm text-white/50 mt-0.5">
            Map active detection rules to regulatory framework controls
          </p>
        </div>
        {/* Framework selector */}
        <div className="flex gap-2">
          {FRAMEWORKS.map((fw) => (
            <button
              key={fw.id}
              onClick={() => setFramework(fw.id)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-lg border transition-colors ${
                framework === fw.id
                  ? "border-blue-500 bg-blue-500/10 text-blue-400"
                  : "border-white/10 text-white/50 hover:text-white hover:border-white/20"
              }`}
            >
              {fw.label}
            </button>
          ))}
        </div>
      </div>

      {loading && (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center text-white/30 text-sm">
          Loading…
        </div>
      )}
      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">{error}</div>
      )}

      {data && (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4 col-span-2 flex items-center gap-6">
              <GaugArc pct={data.percentage} />
              <div>
                <p className="text-xs text-white/40 uppercase tracking-wider mb-1">Overall Coverage</p>
                <p className="text-3xl font-bold text-white">{data.covered}<span className="text-white/30 text-xl">/{data.total}</span></p>
                <p className="text-xs text-white/40 mt-1">controls covered</p>
              </div>
            </div>
            <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4 flex flex-col justify-between">
              <p className="text-xs text-emerald-400/70 uppercase tracking-wider">Covered</p>
              <p className="text-3xl font-bold text-emerald-400 mt-2">{data.covered}</p>
              <p className="text-xs text-white/30">detection rules mapped</p>
            </div>
            <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 flex flex-col justify-between">
              <p className="text-xs text-red-400/70 uppercase tracking-wider">Gaps</p>
              <p className="text-3xl font-bold text-red-400 mt-2">{gaps}</p>
              <p className="text-xs text-white/30">controls without coverage</p>
            </div>
          </div>

          {/* Category breakdown */}
          <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
            <p className="text-xs font-medium text-white/40 uppercase tracking-wider mb-3">Coverage by Category</p>
            <div className="flex flex-wrap gap-2">
              {categories.map((cat) => {
                const total = controls.filter((c) => c.category === cat).length;
                const covered = controls.filter((c) => c.category === cat && c.covered).length;
                const pct = total > 0 ? Math.round(covered * 100 / total) : 0;
                const cls = CATEGORY_COLORS[cat] ?? "text-white/50 bg-white/5 border-white/10";
                return (
                  <button
                    key={cat}
                    onClick={() => setFilterCategory(filterCategory === cat ? "" : cat)}
                    className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs transition-colors ${cls} ${
                      filterCategory === cat ? "ring-1 ring-white/20" : "opacity-80 hover:opacity-100"
                    }`}
                  >
                    <span className="font-semibold">{cat}</span>
                    <span className="font-mono opacity-70">{covered}/{total} ({pct}%)</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Controls table */}
          <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
            {/* Filter bar */}
            <div className="flex items-center gap-3 px-4 py-3 border-b border-white/10">
              <p className="text-xs text-white/40 mr-auto">{filtered.length} control{filtered.length !== 1 ? "s" : ""}</p>
              {[
                { v: "all", label: "All" },
                { v: "covered", label: "Covered" },
                { v: "gap", label: "Gaps" },
              ].map(({ v, label }) => (
                <button
                  key={v}
                  onClick={() => setFilterCovered(v as typeof filterCovered)}
                  className={`text-xs px-2.5 py-1 rounded-md transition-colors ${
                    filterCovered === v
                      ? "bg-white/10 text-white"
                      : "text-white/40 hover:text-white"
                  }`}
                >
                  {label}
                </button>
              ))}
              {filterCategory && (
                <button
                  onClick={() => setFilterCategory("")}
                  className="text-xs text-white/30 hover:text-white transition-colors"
                >
                  Clear category
                </button>
              )}
            </div>

            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/10">
                  {["", "Control", "Category", "Description", "Mapped Rules"].map((h) => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-medium text-white/40 uppercase tracking-wider">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filtered.map((ctrl) => (
                  <tr key={ctrl.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="px-4 py-3 w-8">
                      <div className={`w-2 h-2 rounded-full ${ctrl.covered ? "bg-emerald-500" : "bg-red-500/50"}`} />
                    </td>
                    <td className="px-4 py-3">
                      <p className="text-white font-mono text-xs font-semibold">{ctrl.id}</p>
                      <p className="text-white/70 text-xs mt-0.5">{ctrl.name}</p>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${CATEGORY_COLORS[ctrl.category] ?? "text-white/40 bg-white/5 border-white/10"}`}>
                        {ctrl.category}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-white/40 text-xs max-w-xs">{ctrl.description}</td>
                    <td className="px-4 py-3">
                      {ctrl.covered ? (
                        <div className="space-y-1">
                          {ctrl.rule_ids?.slice(0, 2).map((r) => (
                            <span key={r} className="block text-xs font-mono text-blue-400/70">{r}</span>
                          ))}
                          {(ctrl.rule_ids?.length ?? 0) > 2 && (
                            <span className="text-xs text-white/30">+{(ctrl.rule_ids?.length ?? 0) - 2} more</span>
                          )}
                          {ctrl.mitre_ids?.slice(0, 3).map((m) => (
                            <span key={m} className="block text-[10px] font-mono text-amber-400/60">{m}</span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-xs text-red-400/50">No coverage</span>
                      )}
                    </td>
                  </tr>
                ))}
                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-10 text-center text-white/30 text-sm">
                      No controls match the current filter.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
