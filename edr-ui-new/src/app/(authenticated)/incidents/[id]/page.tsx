"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { ForensicTimeline } from "@/components/forensic-timeline";

interface AttackGraphNode {
  id: string;
  tactic: string;
  technique: string;
  event_type: string;
  hostname: string;
  agent_id: string;
  time: string;
  summary: string;
}

interface AttackGraphEdge {
  source: string;
  target: string;
  label: string;
}

interface AttackGraph {
  incident_id: string;
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
}

const TACTIC_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  "Initial Access":        { bg: "bg-pink-500/10",    border: "border-pink-500/30",    text: "text-pink-400" },
  "Execution":             { bg: "bg-orange-500/10",  border: "border-orange-500/30",  text: "text-orange-400" },
  "Persistence":           { bg: "bg-yellow-500/10",  border: "border-yellow-500/30",  text: "text-yellow-400" },
  "Privilege Escalation":  { bg: "bg-amber-500/10",   border: "border-amber-500/30",   text: "text-amber-400" },
  "Defense Evasion":       { bg: "bg-lime-500/10",    border: "border-lime-500/30",    text: "text-lime-400" },
  "Credential Access":     { bg: "bg-emerald-500/10", border: "border-emerald-500/30", text: "text-emerald-400" },
  "Discovery":             { bg: "bg-teal-500/10",    border: "border-teal-500/30",    text: "text-teal-400" },
  "Lateral Movement":      { bg: "bg-cyan-500/10",    border: "border-cyan-500/30",    text: "text-cyan-400" },
  "Exfiltration":          { bg: "bg-blue-500/10",    border: "border-blue-500/30",    text: "text-blue-400" },
  "Impact":                { bg: "bg-red-500/10",      border: "border-red-500/30",     text: "text-red-400" },
  "Other":                 { bg: "bg-white/5",        border: "border-white/10",       text: "text-white/50" },
};

function NodeCard({ node, index }: { node: AttackGraphNode; index: number }) {
  const c = TACTIC_COLORS[node.tactic] ?? TACTIC_COLORS["Other"];
  return (
    <div className={`rounded-xl border p-4 ${c.bg} ${c.border} relative`}>
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${c.bg} ${c.border} ${c.text}`}>
              {node.tactic}
            </span>
            {node.technique && (
              <span className="text-xs font-mono text-white/40">{node.technique}</span>
            )}
          </div>
          <p className="text-sm font-medium text-white truncate">{node.summary}</p>
          {node.hostname && (
            <p className="text-xs text-white/40 font-mono mt-1">{node.hostname}</p>
          )}
          <p className="text-xs text-white/25 font-mono mt-0.5">
            {new Date(node.time).toLocaleString()}
          </p>
        </div>
        <div className="shrink-0 w-7 h-7 rounded-full bg-white/10 flex items-center justify-center text-xs font-bold text-white/40">
          {index + 1}
        </div>
      </div>
    </div>
  );
}

function Arrow() {
  return (
    <div className="flex items-center justify-center py-1">
      <div className="flex flex-col items-center gap-0.5">
        <div className="w-px h-3 bg-white/20" />
        <svg width="8" height="5" viewBox="0 0 8 5" fill="none">
          <path d="M4 5L0 0H8L4 5Z" fill="rgba(255,255,255,0.2)" />
        </svg>
      </div>
    </div>
  );
}

// Group nodes by tactic for the heatmap summary
function TacticSummary({ nodes }: { nodes: AttackGraphNode[] }) {
  const counts: Record<string, number> = {};
  for (const n of nodes) {
    counts[n.tactic] = (counts[n.tactic] ?? 0) + 1;
  }
  const tactics = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  return (
    <div className="flex flex-wrap gap-2">
      {tactics.map(([tactic, count]) => {
        const c = TACTIC_COLORS[tactic] ?? TACTIC_COLORS["Other"];
        return (
          <div key={tactic} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border ${c.bg} ${c.border}`}>
            <span className={`text-xs font-semibold ${c.text}`}>{tactic}</span>
            <span className="text-xs text-white/30 font-mono">{count}</span>
          </div>
        );
      })}
    </div>
  );
}

export default function IncidentAttackGraphPage() {
  const params = useParams();
  const id = typeof params?.id === "string" ? params.id : "";
  const [activeTab, setActiveTab] = useState<"graph" | "timeline">("graph");

  const { data: graph, loading, error } = useApi<AttackGraph>(
    (signal) => api.get(`/incidents/${id}/attack-graph`, {}, signal),
  );

  const nodes = graph?.nodes ?? [];
  const edges = graph?.edges ?? [];

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm">
        <Link href="/incidents" className="text-white/40 hover:text-white transition-colors">
          Incidents
        </Link>
        <span className="text-white/20">/</span>
        <span className="text-white/60 font-mono text-xs truncate max-w-48">{id}</span>
      </div>

      <div>
        <h1 className="text-xl font-semibold text-white">Incident Detail</h1>
        <p className="text-sm text-white/50 mt-0.5">Attack graph and forensic event timeline</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-white/8 pb-0">
        {(["graph", "timeline"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
              activeTab === tab
                ? "border-white/60 text-white"
                : "border-transparent text-white/40 hover:text-white/70"
            }`}
          >
            {tab === "graph" ? "Attack Graph" : "Forensic Timeline"}
          </button>
        ))}
      </div>

      {activeTab === "graph" && (
        <div className="space-y-6">
          {loading && (
            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center text-white/30 text-sm">
              Loading…
            </div>
          )}
          {error && (
            <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">
              {error}
            </div>
          )}
          {!loading && nodes.length === 0 && !error && (
            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center">
              <p className="text-white/30 text-sm">No correlated alerts for this incident yet.</p>
              <p className="text-white/20 text-xs mt-1">The attack graph populates as alerts are linked to this incident.</p>
            </div>
          )}
          {nodes.length > 0 && (
            <>
              <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4 space-y-2">
                <p className="text-xs font-medium text-white/40 uppercase tracking-wider">Kill-chain coverage</p>
                <TacticSummary nodes={nodes} />
              </div>
              <div className="rounded-xl border border-white/10 bg-white/[0.02] p-5">
                <p className="text-xs font-medium text-white/40 uppercase tracking-wider mb-4">
                  Attack sequence — {nodes.length} alert{nodes.length !== 1 ? "s" : ""}, {edges.length} transition{edges.length !== 1 ? "s" : ""}
                </p>
                <div className="space-y-0">
                  {nodes.map((node, i) => (
                    <div key={node.id}>
                      <NodeCard node={node} index={i} />
                      {i < nodes.length - 1 && <Arrow />}
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {activeTab === "timeline" && (
        <ForensicTimeline incidentId={id} />
      )}
    </div>
  );
}
