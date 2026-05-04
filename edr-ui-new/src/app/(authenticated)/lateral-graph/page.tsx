"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import Link from "next/link";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { AlertTriangle, RefreshCw, X } from "lucide-react";

interface LateralNode {
  id: string;
  hostname: string;
  ip: string;
  risk_score: number;
  agent_id: string;
  alert_count: number;
}

interface LateralEdge {
  src: string;
  dst: string;
  count: number;
  protocols: string[];
  last_seen: string;
}

interface LateralGraph {
  nodes: LateralNode[];
  edges: LateralEdge[];
}

interface SimNode extends LateralNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
}

const HOURS_OPTIONS = [1, 6, 24, 168] as const;
const HOURS_LABELS: Record<number, string> = { 1: "1 h", 6: "6 h", 24: "24 h", 168: "7 d" };

function riskColor(score: number) {
  if (score >= 70) return "#ef4444";
  if (score >= 31) return "#f59e0b";
  return "#22c55e";
}

function riskRing(score: number) {
  if (score >= 70) return "#ef444480";
  if (score >= 31) return "#f59e0b80";
  return "#22c55e40";
}

function nodeRadius(score: number) {
  return 10 + (score / 100) * 14;
}

// Very lightweight force simulation — no D3 dependency.
function runForce(nodes: SimNode[], edges: LateralEdge[], width: number, height: number, ticks = 120) {
  const cx = width / 2;
  const cy = height / 2;

  for (let t = 0; t < ticks; t++) {
    // Repulsion between all nodes
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[j].x - nodes[i].x;
        const dy = nodes[j].y - nodes[i].y;
        const dist2 = dx * dx + dy * dy + 1;
        const force = 8000 / dist2;
        const fx = dx * force;
        const fy = dy * force;
        nodes[i].vx -= fx;
        nodes[i].vy -= fy;
        nodes[j].vx += fx;
        nodes[j].vy += fy;
      }
    }
    // Attraction along edges
    for (const e of edges) {
      const a = nodes.find((n) => n.id === e.src);
      const b = nodes.find((n) => n.id === e.dst);
      if (!a || !b) continue;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) + 1;
      const strength = 0.03 * Math.log(e.count + 1);
      const fx = dx * strength;
      const fy = dy * strength;
      a.vx += fx;
      a.vy += fy;
      b.vx -= fx;
      b.vy -= fy;
    }
    // Centre gravity
    for (const n of nodes) {
      n.vx += (cx - n.x) * 0.005;
      n.vy += (cy - n.y) * 0.005;
    }
    // Apply + dampen
    const dampen = 0.85 - t / ticks * 0.3;
    for (const n of nodes) {
      n.x += n.vx;
      n.y += n.vy;
      n.vx *= dampen;
      n.vy *= dampen;
      n.x = Math.max(30, Math.min(width - 30, n.x));
      n.y = Math.max(30, Math.min(height - 30, n.y));
    }
  }
}

export default function LateralGraphPage() {
  const [hours, setHours] = useState(24);
  const [minConn, setMinConn] = useState(1);
  const [selected, setSelected] = useState<LateralNode | null>(null);
  const [simNodes, setSimNodes] = useState<SimNode[]>([]);
  const svgRef = useRef<SVGSVGElement>(null);
  const W = 900;
  const H = 560;

  const { data, loading, error, refetch } = useApi<LateralGraph>(
    (signal) => api.get(`/xdr/lateral-graph?hours=${hours}&min_connections=${minConn}`, {}, signal),
  );

  useEffect(() => {
    if (!data) return;
    const nodes: SimNode[] = data.nodes.map((n, i) => ({
      ...n,
      x: W / 2 + Math.cos((i / data.nodes.length) * Math.PI * 2) * 200,
      y: H / 2 + Math.sin((i / data.nodes.length) * Math.PI * 2) * 160,
      vx: 0,
      vy: 0,
    }));
    runForce(nodes, data.edges, W, H);
    setSimNodes(nodes);
  }, [data]);

  const edgeWidth = useCallback(
    (count: number) => Math.max(1, Math.min(6, 1 + Math.log(count + 1))),
    [],
  );

  const edges = data?.edges ?? [];
  const nodeMap = new Map(simNodes.map((n) => [n.id, n]));

  return (
    <div className="space-y-5 max-w-5xl">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Lateral Movement Graph</h1>
          <p className="text-sm text-white/50 mt-0.5">
            Host-to-host connections derived from shared login sessions
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-1.5 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-white/60 hover:text-white hover:border-white/20 transition-colors"
        >
          <RefreshCw size={13} />
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex items-center gap-1 rounded-lg border border-white/10 bg-white/[0.03] p-1">
          {HOURS_OPTIONS.map((h) => (
            <button
              key={h}
              onClick={() => setHours(h)}
              className={`rounded-md px-3 py-1 text-xs transition-colors ${
                hours === h
                  ? "bg-white/15 text-white"
                  : "text-white/40 hover:text-white/70"
              }`}
            >
              {HOURS_LABELS[h]}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2 text-xs text-white/50">
          <span>Min connections</span>
          <input
            type="number"
            min={1}
            max={50}
            value={minConn}
            onChange={(e) => setMinConn(Math.max(1, parseInt(e.target.value) || 1))}
            className="w-14 rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 text-white text-center focus:outline-none focus:border-white/20"
          />
        </div>
        {data && (
          <span className="text-xs text-white/30">
            {data.nodes.length} nodes · {data.edges.length} edges
          </span>
        )}
      </div>

      {/* Legend */}
      <div className="flex items-center gap-5 text-xs text-white/40">
        {[
          { color: "#22c55e", label: "Low risk (0–30)" },
          { color: "#f59e0b", label: "Medium (31–69)" },
          { color: "#ef4444", label: "High risk (70+)" },
        ].map(({ color, label }) => (
          <span key={label} className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: color }} />
            {label}
          </span>
        ))}
        <span className="ml-2">Edge thickness = connection count</span>
      </div>

      {/* Graph canvas */}
      <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
        {loading && (
          <div className="h-[560px] flex items-center justify-center text-white/30 text-sm">
            Loading graph…
          </div>
        )}
        {error && (
          <div className="h-[560px] flex items-center justify-center">
            <div className="text-sm text-red-400">{error}</div>
          </div>
        )}
        {!loading && !error && simNodes.length === 0 && (
          <div className="h-[560px] flex flex-col items-center justify-center gap-2">
            <p className="text-white/30 text-sm">No lateral movement detected in this window.</p>
            <p className="text-white/20 text-xs">Try a longer time range or lower the minimum connections threshold.</p>
          </div>
        )}
        {!loading && simNodes.length > 0 && (
          <svg ref={svgRef} width="100%" viewBox={`0 0 ${W} ${H}`} className="block">
            <defs>
              <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                <path d="M0,0 L6,3 L0,6 Z" fill="#ffffff30" />
              </marker>
            </defs>
            {/* Edges */}
            {edges.map((e) => {
              const a = nodeMap.get(e.src);
              const b = nodeMap.get(e.dst);
              if (!a || !b) return null;
              const ra = nodeRadius(a.risk_score);
              const rb = nodeRadius(b.risk_score);
              const dx = b.x - a.x;
              const dy = b.y - a.y;
              const len = Math.sqrt(dx * dx + dy * dy) || 1;
              const x1 = a.x + (dx / len) * ra;
              const y1 = a.y + (dy / len) * ra;
              const x2 = b.x - (dx / len) * (rb + 4);
              const y2 = b.y - (dy / len) * (rb + 4);
              return (
                <line
                  key={`${e.src}-${e.dst}`}
                  x1={x1} y1={y1} x2={x2} y2={y2}
                  stroke="#ffffff20"
                  strokeWidth={edgeWidth(e.count)}
                  markerEnd="url(#arrow)"
                />
              );
            })}
            {/* Nodes */}
            {simNodes.map((n) => {
              const r = nodeRadius(n.risk_score);
              const isSelected = selected?.id === n.id;
              return (
                <g
                  key={n.id}
                  transform={`translate(${n.x},${n.y})`}
                  className="cursor-pointer"
                  onClick={() => setSelected(isSelected ? null : n)}
                >
                  {/* glow ring */}
                  <circle r={r + 5} fill={riskRing(n.risk_score)} opacity={isSelected ? 1 : 0.5} />
                  {/* body */}
                  <circle r={r} fill={riskColor(n.risk_score)} opacity={0.9} />
                  {/* alert badge */}
                  {n.alert_count > 0 && (
                    <circle cx={r - 2} cy={-(r - 2)} r={5} fill="#ef4444" />
                  )}
                  {/* hostname label */}
                  <text
                    y={r + 12}
                    textAnchor="middle"
                    fontSize={10}
                    fill="#ffffff99"
                    className="select-none pointer-events-none"
                  >
                    {n.hostname.length > 16 ? n.hostname.slice(0, 15) + "…" : n.hostname}
                  </text>
                </g>
              );
            })}
          </svg>
        )}
      </div>

      {/* Detail panel */}
      {selected && (
        <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">{selected.hostname}</h3>
            <button onClick={() => setSelected(null)} className="text-white/30 hover:text-white transition-colors">
              <X size={15} />
            </button>
          </div>
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div>
              <span className="text-white/40">Agent ID</span>
              <p className="text-white/80 font-mono mt-0.5">{selected.agent_id}</p>
            </div>
            <div>
              <span className="text-white/40">IP Address</span>
              <p className="text-white/80 font-mono mt-0.5">{selected.ip || "—"}</p>
            </div>
            <div>
              <span className="text-white/40">Risk Score</span>
              <p className="mt-0.5 font-semibold" style={{ color: riskColor(selected.risk_score) }}>
                {selected.risk_score}
              </p>
            </div>
            <div>
              <span className="text-white/40">Open Alerts</span>
              <p className={`mt-0.5 font-semibold ${selected.alert_count > 0 ? "text-red-400" : "text-white/60"}`}>
                {selected.alert_count}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3 pt-1">
            <Link
              href={`/agents/${selected.agent_id}`}
              className="text-xs rounded-lg border border-white/10 px-3 py-1.5 text-white/60 hover:text-white hover:border-white/20 transition-colors"
            >
              View agent
            </Link>
            {selected.alert_count > 0 && (
              <Link
                href={`/alerts?agent_id=${selected.agent_id}`}
                className="flex items-center gap-1 text-xs rounded-lg border border-red-500/30 px-3 py-1.5 text-red-400 hover:border-red-500/50 transition-colors"
              >
                <AlertTriangle size={12} />
                View alerts
              </Link>
            )}
          </div>
          {/* Edges for this node */}
          {edges.filter((e) => e.src === selected.id || e.dst === selected.id).length > 0 && (
            <div className="pt-1">
              <p className="text-xs text-white/40 mb-2">Connected to</p>
              <div className="space-y-1.5">
                {edges
                  .filter((e) => e.src === selected.id || e.dst === selected.id)
                  .map((e) => {
                    const peerId = e.src === selected.id ? e.dst : e.src;
                    const peer = nodeMap.get(peerId);
                    return (
                      <div
                        key={`${e.src}-${e.dst}`}
                        className="flex items-center justify-between rounded-lg bg-white/[0.03] px-3 py-2 text-xs"
                      >
                        <span className="text-white/70">{peer?.hostname ?? peerId}</span>
                        <span className="text-white/40">
                          {e.count} session{e.count !== 1 ? "s" : ""} · {e.protocols.join(", ")}
                        </span>
                      </div>
                    );
                  })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
