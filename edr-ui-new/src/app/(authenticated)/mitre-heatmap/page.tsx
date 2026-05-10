"use client";

import { useState } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";

interface Rule {
  id: string;
  name: string;
  mitre_ids?: string[];
}

const TACTICS = [
  {
    id: "TA0001",
    name: "Initial Access",
    techniques: ["T1078", "T1190", "T1133", "T1200", "T1566", "T1091", "T1195"],
  },
  {
    id: "TA0002",
    name: "Execution",
    techniques: ["T1059", "T1106", "T1204", "T1047", "T1053", "T1129"],
  },
  {
    id: "TA0003",
    name: "Persistence",
    techniques: ["T1543", "T1547", "T1053", "T1505", "T1546", "T1136"],
  },
  {
    id: "TA0004",
    name: "Privilege Escalation",
    techniques: ["T1055", "T1134", "T1548", "T1068", "T1611"],
  },
  {
    id: "TA0005",
    name: "Defense Evasion",
    techniques: ["T1027", "T1036", "T1055", "T1112", "T1562", "T1070"],
  },
  {
    id: "TA0006",
    name: "Credential Access",
    techniques: ["T1003", "T1110", "T1555", "T1558", "T1078"],
  },
  {
    id: "TA0007",
    name: "Discovery",
    techniques: ["T1046", "T1018", "T1082", "T1083", "T1087", "T1057"],
  },
  {
    id: "TA0008",
    name: "Lateral Movement",
    techniques: ["T1021", "T1550", "T1076", "T1570", "T1534"],
  },
  {
    id: "TA0009",
    name: "Collection",
    techniques: ["T1005", "T1039", "T1056", "T1113", "T1185"],
  },
  {
    id: "TA0010",
    name: "Exfiltration",
    techniques: ["T1041", "T1048", "T1020", "T1030", "T1071"],
  },
  {
    id: "TA0011",
    name: "Command and Control",
    techniques: ["T1071", "T1095", "T1105", "T1571", "T1572"],
  },
  {
    id: "TA0040",
    name: "Impact",
    techniques: ["T1486", "T1490", "T1561", "T1499", "T1495"],
  },
];

// All unique techniques across the grid
const ALL_TECHNIQUES = Array.from(new Set(TACTICS.flatMap((t) => t.techniques)));

interface SelectedTechnique {
  techniqueId: string;
  rules: Rule[];
}

export default function MitreHeatmapPage() {
  const { data: rules, loading } = useApi<Rule[]>((signal) => api.get("/rules", undefined, signal));

  const [selected, setSelected] = useState<SelectedTechnique | null>(null);

  // Build set of covered techniques and map technique → rules
  const coveredTechniqueMap = new Map<string, Rule[]>();
  for (const rule of rules ?? []) {
    for (const tid of rule.mitre_ids ?? []) {
      const existing = coveredTechniqueMap.get(tid) ?? [];
      existing.push(rule);
      coveredTechniqueMap.set(tid, existing);
    }
  }

  const coveredCount = ALL_TECHNIQUES.filter((t) => coveredTechniqueMap.has(t)).length;
  const totalCount = ALL_TECHNIQUES.length;
  const coveragePct =
    totalCount > 0 ? Math.round((coveredCount / totalCount) * 100) : 0;

  function handleCellClick(techniqueId: string) {
    const coveringRules = coveredTechniqueMap.get(techniqueId) ?? [];
    setSelected({ techniqueId, rules: coveringRules });
  }

  // Max technique count across any tactic column (for grid alignment)
  const maxTechCount = Math.max(...TACTICS.map((t) => t.techniques.length));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">MITRE ATT&amp;CK Coverage</h1>
          <p className="text-sm text-white/50 mt-0.5">
            Heatmap of MITRE techniques covered by active detection rules
          </p>
        </div>

        {/* Summary stats */}
        {!loading && (
          <div className="flex items-center gap-6 text-right">
            <div>
              <div className="text-2xl font-bold text-white font-mono">
                {coveredCount}
                <span className="text-white/30 text-base font-normal"> / {totalCount}</span>
              </div>
              <div className="text-xs text-white/40 mt-0.5">techniques covered</div>
            </div>
            <div
              className="w-14 h-14 rounded-full flex items-center justify-center text-sm font-bold border-2"
              style={{
                borderColor:
                  coveragePct >= 70
                    ? "#22c55e"
                    : coveragePct >= 40
                    ? "#f59e0b"
                    : "#ef4444",
                color:
                  coveragePct >= 70
                    ? "#22c55e"
                    : coveragePct >= 40
                    ? "#f59e0b"
                    : "#ef4444",
              }}
            >
              {coveragePct}%
            </div>
          </div>
        )}
      </div>

      {loading && (
        <div className="flex items-center justify-center py-20 text-white/30 text-sm">
          Loading rules…
        </div>
      )}

      {!loading && (
        <div className="flex gap-4">
          {/* Heatmap grid */}
          <div className="flex-1 overflow-x-auto">
            <div
              className="inline-grid gap-3 min-w-full"
              style={{
                gridTemplateColumns: `repeat(${TACTICS.length}, minmax(100px, 1fr))`,
              }}
            >
              {TACTICS.map((tactic) => (
                <div key={tactic.id} className="space-y-1.5">
                  {/* Tactic header */}
                  <div className="rounded-lg bg-white/[0.04] border border-white/10 px-2 py-1.5 text-center">
                    <div className="text-[9px] font-mono text-white/30">{tactic.id}</div>
                    <div className="text-[10px] font-semibold text-white leading-tight mt-0.5">
                      {tactic.name}
                    </div>
                  </div>

                  {/* Technique cells */}
                  <div className="space-y-1">
                    {tactic.techniques.map((tid) => {
                      const covered = coveredTechniqueMap.has(tid);
                      const isSelected = selected?.techniqueId === tid;
                      return (
                        <button
                          key={tid}
                          onClick={() => handleCellClick(tid)}
                          title={tid}
                          className={[
                            "w-full rounded px-2 py-1.5 text-[10px] font-mono font-medium border transition-all text-left",
                            covered
                              ? "bg-blue-500/20 border-blue-500/30 text-blue-400 hover:bg-blue-500/30"
                              : "bg-white/[0.02] border-white/10 text-white/20 hover:bg-white/[0.04] hover:text-white/40",
                            isSelected ? "ring-1 ring-blue-400/50 ring-offset-1 ring-offset-[#0f1117]" : "",
                          ]
                            .filter(Boolean)
                            .join(" ")}
                        >
                          {tid}
                        </button>
                      );
                    })}

                    {/* Spacer cells to align columns to equal height */}
                    {Array.from({
                      length: maxTechCount - tactic.techniques.length,
                    }).map((_, i) => (
                      <div key={i} className="w-full h-[30px]" />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Side panel — rules for selected technique */}
          {selected && (
            <div className="w-64 shrink-0 rounded-xl border border-white/10 bg-white/[0.02] p-4 space-y-3 self-start sticky top-4">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="text-xs font-mono font-semibold text-blue-400">
                    {selected.techniqueId}
                  </div>
                  <div className="text-[10px] text-white/40 mt-0.5">
                    {selected.rules.length === 0
                      ? "Not covered"
                      : `${selected.rules.length} rule${selected.rules.length !== 1 ? "s" : ""}`}
                  </div>
                </div>
                <button
                  onClick={() => setSelected(null)}
                  className="text-white/30 hover:text-white text-xs transition-colors"
                >
                  ✕
                </button>
              </div>

              <a
                href={`https://attack.mitre.org/techniques/${selected.techniqueId.replace(".", "/")}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-[10px] text-blue-400/60 hover:text-blue-400 transition-colors"
              >
                View on MITRE ATT&amp;CK ↗
              </a>

              {selected.rules.length === 0 ? (
                <div className="rounded-lg border border-white/5 bg-white/[0.02] px-3 py-3 text-xs text-white/30">
                  No detection rules cover this technique. Consider adding a rule targeting{" "}
                  <span className="font-mono text-white/50">{selected.techniqueId}</span>.
                </div>
              ) : (
                <div className="space-y-1.5">
                  {selected.rules.map((r) => (
                    <div
                      key={r.id}
                      className="rounded-lg border border-white/5 bg-white/[0.02] px-3 py-2 space-y-0.5"
                    >
                      <div className="text-xs text-white font-medium truncate">{r.name}</div>
                      <div className="text-[10px] font-mono text-white/30 truncate">{r.id}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Legend */}
      {!loading && (
        <div className="flex items-center gap-6 pt-2">
          <div className="flex items-center gap-2">
            <div className="w-8 h-4 rounded bg-blue-500/20 border border-blue-500/30" />
            <span className="text-xs text-white/40">Covered by ≥1 rule</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-4 rounded bg-white/[0.02] border border-white/10" />
            <span className="text-xs text-white/40">No coverage</span>
          </div>
          <div className="text-xs text-white/20 ml-auto">
            Click a technique cell to see which rules cover it
          </div>
        </div>
      )}
    </div>
  );
}
