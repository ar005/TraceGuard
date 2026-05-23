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

/* ── tactic style maps ─────────────────────────────────────────────────────── */

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
  "Impact":                { bg: "bg-red-500/10",     border: "border-red-500/30",     text: "text-red-400" },
  "Other":                 { bg: "bg-white/5",        border: "border-white/10",       text: "text-white/50" },
};

// SVG fill colors (Tailwind can't be used as SVG attributes)
const TACTIC_FILL: Record<string, string> = {
  "Initial Access":       "#ec4899",
  "Execution":            "#f97316",
  "Persistence":          "#eab308",
  "Privilege Escalation": "#f59e0b",
  "Defense Evasion":      "#a3e635",
  "Credential Access":    "#10b981",
  "Discovery":            "#14b8a6",
  "Lateral Movement":     "#06b6d4",
  "Collection":           "#818cf8",
  "Exfiltration":         "#3b82f6",
  "Impact":               "#ef4444",
  "Unknown":              "#6b7280",
  "Other":                "#4b5563",
};

const KILL_CHAIN_ORDER = [
  "Initial Access", "Execution", "Persistence", "Privilege Escalation",
  "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Exfiltration", "Impact", "Unknown", "Other",
];

function tacticFill(tactic: string): string {
  return TACTIC_FILL[tactic] ?? TACTIC_FILL["Other"];
}

/* ── NodeCard (used in detail panel) ──────────────────────────────────────── */

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

/* ── TacticSummary heatmap ─────────────────────────────────────────────────── */

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
          <span
            key={tactic}
            className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs border ${c.bg} ${c.border} ${c.text}`}
          >
            {tactic}
            <span className="rounded-full px-1.5 py-0.5 bg-white/10 text-white/60 text-[10px] font-bold">
              {count}
            </span>
          </span>
        );
      })}
    </div>
  );
}

/* ── KillChainCanvas ───────────────────────────────────────────────────────── */

const NODE_R = 18;
const COL_W  = 148;
const ROW_H  = 96;
const LEFT_PAD = 108;
const TOP_PAD  = 44;

function KillChainCanvas({
  nodes,
  edges,
}: {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
}) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [hoveredId, setHoveredId]   = useState<string | null>(null);

  // Tactic columns: only stages that appear, in kill-chain order
  const usedTactics = KILL_CHAIN_ORDER.filter((t) =>
    nodes.some((n) => n.tactic === t)
  );
  // Add any tactic not in KILL_CHAIN_ORDER at the end
  for (const n of nodes) {
    if (!usedTactics.includes(n.tactic)) usedTactics.push(n.tactic);
  }

  // Host rows: in order of first appearance
  const seen = new Set<string>();
  const usedHosts: string[] = [];
  for (const n of nodes) {
    const h = n.hostname || "unknown";
    if (!seen.has(h)) { seen.add(h); usedHosts.push(h); }
  }

  // Group nodes into cells (tactic × host), preserving chronological order
  const cellMap = new Map<string, AttackGraphNode[]>();
  for (const n of nodes) {
    const key = `${n.tactic}||${n.hostname || "unknown"}`;
    const arr = cellMap.get(key) ?? [];
    arr.push(n);
    cellMap.set(key, arr);
  }

  // Assign final (x, y) per node
  const pos = new Map<string, { x: number; y: number }>();
  for (const [key, cellNodes] of cellMap) {
    const [tactic, host] = key.split("||");
    const ci = usedTactics.indexOf(tactic);
    const ri = usedHosts.indexOf(host);
    const baseX = LEFT_PAD + ci * COL_W + COL_W / 2;
    const baseY = TOP_PAD + ri * ROW_H + ROW_H / 2;
    for (let i = 0; i < cellNodes.length; i++) {
      const offset =
        cellNodes.length === 1
          ? 0
          : (i - (cellNodes.length - 1) / 2) * (NODE_R * 2 + 6);
      pos.set(cellNodes[i].id, { x: baseX + offset, y: baseY });
    }
  }

  const W = LEFT_PAD + usedTactics.length * COL_W + 24;
  const H = TOP_PAD + usedHosts.length * ROW_H + 24;

  const selectedNode = nodes.find((n) => n.id === selectedId) ?? null;

  return (
    <div className="space-y-4">
      {/* Scrollable canvas */}
      <div className="overflow-x-auto rounded-xl border border-white/10 bg-[#0a0a0b]">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          width={W}
          height={H}
          className="block"
          style={{ minWidth: W }}
        >
          <defs>
            <marker
              id="atk-arrow"
              markerWidth="6"
              markerHeight="6"
              refX="5"
              refY="3"
              orient="auto"
            >
              <path d="M0,0 L6,3 L0,6 Z" fill="rgba(255,255,255,0.25)" />
            </marker>
          </defs>

          {/* Column header backgrounds */}
          {usedTactics.map((t, i) => (
            <rect
              key={t}
              x={LEFT_PAD + i * COL_W}
              y={0}
              width={COL_W}
              height={H}
              fill={i % 2 === 0 ? "rgba(255,255,255,0.012)" : "transparent"}
            />
          ))}

          {/* Row dividers */}
          {usedHosts.map((_, i) => (
            <line
              key={i}
              x1={LEFT_PAD}
              y1={TOP_PAD + i * ROW_H}
              x2={W - 12}
              y2={TOP_PAD + i * ROW_H}
              stroke="rgba(255,255,255,0.05)"
              strokeWidth={1}
            />
          ))}

          {/* Tactic column headers */}
          {usedTactics.map((t, i) => {
            const x = LEFT_PAD + i * COL_W + COL_W / 2;
            const fill = tacticFill(t);
            const label = t.length > 16 ? t.replace(" ", "\n") : t;
            return (
              <g key={t}>
                <rect
                  x={LEFT_PAD + i * COL_W + 6}
                  y={6}
                  width={COL_W - 12}
                  height={24}
                  rx={4}
                  fill={fill}
                  opacity={0.12}
                />
                <text
                  x={x}
                  y={22}
                  textAnchor="middle"
                  fontSize={9}
                  fontWeight={700}
                  fill={fill}
                  opacity={0.9}
                  style={{ letterSpacing: "0.06em", textTransform: "uppercase" }}
                >
                  {label.length > 14 ? label.slice(0, 13) + "…" : label}
                </text>
              </g>
            );
          })}

          {/* Host row labels */}
          {usedHosts.map((host, i) => (
            <text
              key={host}
              x={LEFT_PAD - 8}
              y={TOP_PAD + i * ROW_H + ROW_H / 2 + 4}
              textAnchor="end"
              fontSize={10}
              fill="rgba(255,255,255,0.28)"
              style={{ fontFamily: "monospace" }}
            >
              {host.length > 13 ? host.slice(0, 12) + "…" : host}
            </text>
          ))}

          {/* Edges */}
          {edges.map((e) => {
            const a = pos.get(e.source);
            const b = pos.get(e.target);
            if (!a || !b) return null;
            const mx = (a.x + b.x) / 2;
            const isActive =
              hoveredId === e.source ||
              hoveredId === e.target ||
              selectedId === e.source ||
              selectedId === e.target;
            return (
              <path
                key={`${e.source}-${e.target}`}
                d={`M ${a.x} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x} ${b.y}`}
                fill="none"
                stroke={isActive ? "rgba(255,255,255,0.45)" : "rgba(255,255,255,0.12)"}
                strokeWidth={isActive ? 2 : 1.5}
                strokeDasharray={a.y === b.y ? undefined : "4 3"}
                markerEnd="url(#atk-arrow)"
              />
            );
          })}

          {/* Nodes */}
          {nodes.map((n, idx) => {
            const p = pos.get(n.id);
            if (!p) return null;
            const fill   = tacticFill(n.tactic);
            const isSel  = selectedId === n.id;
            const isHov  = hoveredId  === n.id;
            return (
              <g
                key={n.id}
                transform={`translate(${p.x},${p.y})`}
                style={{ cursor: "pointer" }}
                onClick={() => setSelectedId(isSel ? null : n.id)}
                onMouseEnter={() => setHoveredId(n.id)}
                onMouseLeave={() => setHoveredId(null)}
              >
                {/* Glow ring */}
                {(isSel || isHov) && (
                  <circle r={NODE_R + 8} fill={fill} opacity={0.18} />
                )}
                {/* Body */}
                <circle
                  r={NODE_R}
                  fill={fill}
                  opacity={isSel ? 1 : 0.8}
                  stroke={isSel ? "white" : "transparent"}
                  strokeWidth={2}
                />
                {/* Step number */}
                <text
                  textAnchor="middle"
                  y={5}
                  fontSize={11}
                  fontWeight={700}
                  fill="white"
                  style={{ pointerEvents: "none", userSelect: "none" }}
                >
                  {idx + 1}
                </text>
                {/* MITRE technique below */}
                {n.technique && (
                  <text
                    textAnchor="middle"
                    y={NODE_R + 13}
                    fontSize={8}
                    fill="rgba(255,255,255,0.38)"
                    style={{
                      pointerEvents: "none",
                      userSelect: "none",
                      fontFamily: "monospace",
                    }}
                  >
                    {n.technique}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 flex-wrap text-[10px] text-white/30 px-1">
        <span className="flex items-center gap-1.5">
          <svg width="20" height="8">
            <line x1="0" y1="4" x2="14" y2="4" stroke="rgba(255,255,255,0.25)" strokeWidth="1.5" markerEnd="url(#atk-arrow)" />
          </svg>
          Same host
        </span>
        <span className="flex items-center gap-1.5">
          <svg width="20" height="8">
            <line x1="0" y1="4" x2="14" y2="4" stroke="rgba(255,255,255,0.25)" strokeWidth="1.5" strokeDasharray="3 2" />
          </svg>
          Cross-host
        </span>
        <span>Click a node to inspect</span>
      </div>

      {/* Selected node detail */}
      {selectedNode && (
        <div className="pt-1">
          <NodeCard node={selectedNode} index={nodes.indexOf(selectedNode)} />
        </div>
      )}
    </div>
  );
}

/* ── Page ─────────────────────────────────────────────────────────────────── */

export default function IncidentAttackGraphPage() {
  const params = useParams();
  const id = typeof params?.id === "string" ? params.id : "";
  const [activeTab, setActiveTab] = useState<"graph" | "timeline" | "ai">("graph");

  const { data: graph, loading, error } = useApi<AttackGraph>(
    (signal) => api.get(`/api/v1/incidents/${id}/attack-graph`, {}, signal),
  );

  const nodes = graph?.nodes ?? [];
  const edges = graph?.edges ?? [];

  // AI chat state
  const [chatMessages, setChatMessages] = useState<{role: "user" | "assistant"; content: string}[]>([]);
  const [chatInput, setChatInput]         = useState("");
  const [chatLoading, setChatLoading]     = useState(false);

  async function sendMessage(text: string) {
    const msg = text.trim();
    if (!msg || chatLoading) return;
    setChatInput("");
    const next = [...chatMessages, { role: "user" as const, content: msg }];
    setChatMessages(next);
    setChatLoading(true);
    try {
      const res = await api.post<{ reply: string }>(
        `/api/v1/incidents/${id}/chat`,
        { messages: next }
      );
      setChatMessages([...next, { role: "assistant" as const, content: res.reply ?? "No response." }]);
    } catch (err) {
      setChatMessages([...next, { role: "assistant" as const, content: err instanceof Error ? err.message : "Request failed." }]);
    } finally {
      setChatLoading(false);
    }
  }

  return (
    <div className="space-y-6 max-w-5xl">
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
        <p className="text-sm text-white/50 mt-0.5">
          Kill-chain attack path, forensic timeline, and AI investigation assistant
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-white/8 pb-0">
        {(["graph", "timeline", "ai"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
              activeTab === tab
                ? "border-white/60 text-white"
                : "border-transparent text-white/40 hover:text-white/70"
            }`}
          >
            {tab === "graph" ? "Attack Path" : tab === "timeline" ? "Forensic Timeline" : "AI Assistant"}
          </button>
        ))}
      </div>

      {/* Attack Path tab */}
      {activeTab === "graph" && (
        <div className="space-y-5">
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
              <p className="text-white/20 text-xs mt-1">
                The attack path populates as alerts are linked to this incident.
              </p>
            </div>
          )}
          {nodes.length > 0 && (
            <>
              {/* Kill-chain coverage heatmap */}
              <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4 space-y-2">
                <p className="text-xs font-medium text-white/40 uppercase tracking-wider">
                  Kill-chain coverage
                </p>
                <TacticSummary nodes={nodes} />
              </div>

              {/* Swimlane canvas */}
              <div>
                <p className="text-xs font-medium text-white/40 uppercase tracking-wider mb-3">
                  Attack path — {nodes.length} alert{nodes.length !== 1 ? "s" : ""} across{" "}
                  {new Set(nodes.map((n) => n.hostname).filter(Boolean)).size || 1} host
                  {new Set(nodes.map((n) => n.hostname).filter(Boolean)).size !== 1 ? "s" : ""}
                </p>
                <KillChainCanvas nodes={nodes} edges={edges} />
              </div>
            </>
          )}
        </div>
      )}

      {/* Forensic Timeline tab */}
      {activeTab === "timeline" && (
        <ForensicTimeline incidentId={id} />
      )}

      {/* AI Assistant tab */}
      {activeTab === "ai" && (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-white/8">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-cyan-400">
              <path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/>
            </svg>
            <span className="text-sm font-semibold text-white">AI Investigation Assistant</span>
            {chatLoading && (
              <span className="ml-auto flex items-center gap-1.5 text-xs text-white/40">
                <svg className="h-3 w-3 animate-spin" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Thinking…
              </span>
            )}
          </div>

          {chatMessages.length > 0 && (
            <div className="max-h-96 overflow-y-auto p-4 space-y-3">
              {chatMessages.map((m, i) => (
                <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
                  <div className={`rounded-xl px-4 py-2.5 text-sm max-w-[88%] leading-relaxed whitespace-pre-wrap ${
                    m.role === "user"
                      ? "bg-cyan-500/20 text-cyan-100 border border-cyan-500/20"
                      : "bg-white/5 text-white/80 border border-white/10"
                  }`}>
                    {m.content}
                  </div>
                </div>
              ))}
            </div>
          )}

          {chatMessages.length === 0 && (
            <div className="p-4 space-y-2">
              <p className="text-xs text-white/30 mb-3">Ask the AI about this incident:</p>
              {[
                "Summarise what happened in this incident",
                "What MITRE ATT&CK techniques are present?",
                "What is the likely attacker goal?",
                "What containment steps should I take?",
                "Are there any lateral movement indicators?",
              ].map((q) => (
                <button
                  key={q}
                  onClick={() => sendMessage(q)}
                  className="block w-full text-left text-xs px-3 py-2 rounded-lg border border-white/8 text-white/40 hover:text-white/70 hover:bg-white/5 transition-colors"
                >
                  {q}
                </button>
              ))}
            </div>
          )}

          <div className="flex gap-2 p-3 border-t border-white/8">
            <input
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(chatInput); } }}
              placeholder="Ask about this incident…"
              disabled={chatLoading}
              className="flex-1 rounded-lg px-3 py-2 text-sm bg-white/5 border border-white/10 text-white placeholder:text-white/20 focus:outline-none focus:border-white/20"
            />
            <button
              onClick={() => sendMessage(chatInput)}
              disabled={chatLoading || !chatInput.trim()}
              className="rounded-lg px-3 py-2 text-sm bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 transition-colors text-white"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
              </svg>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
