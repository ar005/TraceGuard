"use client";

import { useState } from "react";
import Link from "next/link";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { RefreshCw, Globe, ShieldOff, X, ChevronRight, AlertTriangle } from "lucide-react";

interface AgentSurface {
  agent_id: string;
  hostname: string;
  ip: string;
  risk_score: number;
  open_port_count: number;
  exposed_vuln_count: number;
  snapshot_at: string;
}

interface OrgSurfaceResponse {
  agents: AgentSurface[];
  total: number;
}

interface OpenPort {
  port: number;
  protocol: string;
  process: string;
  pid: number;
  internet_reachable: boolean;
}

interface ExposedVuln {
  cve_id: string;
  severity: string;
  port: number;
  service: string;
  package_name: string;
}

interface AgentSurfaceDetail {
  agent_id: string;
  open_ports: OpenPort[];
  exposed_vulns: ExposedVuln[];
  risk_score: number;
  recommendations: string[];
  snapshot_at: string | null;
}

function severityColor(s: string) {
  switch (s) {
    case "CRITICAL": return "text-red-400 border-red-500/30 bg-red-500/10";
    case "HIGH":     return "text-orange-400 border-orange-500/30 bg-orange-500/10";
    case "MEDIUM":   return "text-amber-400 border-amber-500/30 bg-amber-500/10";
    case "LOW":      return "text-blue-400 border-blue-500/30 bg-blue-500/10";
    default:         return "text-white/40 border-white/10 bg-white/5";
  }
}

function cardBg(vulnCount: number, riskScore: number) {
  if (vulnCount > 5 || riskScore >= 70) return "border-red-500/30 bg-red-500/5";
  if (vulnCount > 2 || riskScore >= 31) return "border-amber-500/30 bg-amber-500/5";
  return "border-white/10 bg-white/[0.02]";
}

function AgentDetailPanel({ agentId, onClose }: { agentId: string; onClose: () => void }) {
  const { data, loading, error } = useApi<AgentSurfaceDetail>(
    (signal) => api.get(`/agents/${agentId}/attack-surface`, {}, signal),
  );

  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.03] p-5 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-white">Attack Surface Detail</h3>
        <div className="flex items-center gap-2">
          <Link
            href={`/agents/${agentId}`}
            className="text-xs rounded-lg border border-white/10 px-2.5 py-1 text-white/50 hover:text-white transition-colors"
          >
            Open agent <ChevronRight size={11} className="inline" />
          </Link>
          <button onClick={onClose} className="text-white/30 hover:text-white transition-colors">
            <X size={15} />
          </button>
        </div>
      </div>

      {loading && <p className="text-white/30 text-sm">Loading…</p>}
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {data && (
        <>
          {/* Recommendations */}
          {data.recommendations.length > 0 && (
            <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 space-y-1.5">
              <p className="text-xs font-medium text-amber-400 uppercase tracking-wider mb-2">Fix First</p>
              {data.recommendations.map((r, i) => (
                <div key={i} className="flex items-start gap-2 text-xs text-amber-300/80">
                  <AlertTriangle size={11} className="mt-0.5 shrink-0 text-amber-500" />
                  {r}
                </div>
              ))}
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Open ports */}
            <div className="space-y-2">
              <p className="text-xs font-medium text-white/40 uppercase tracking-wider">
                Open Ports ({data.open_ports.length})
              </p>
              {data.open_ports.length === 0 ? (
                <p className="text-white/20 text-xs">No recent NET_ACCEPT events.</p>
              ) : (
                <div className="rounded-lg border border-white/8 overflow-hidden">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-white/5 text-white/30">
                        <th className="px-3 py-1.5 text-left font-normal">Port</th>
                        <th className="px-3 py-1.5 text-left font-normal">Proto</th>
                        <th className="px-3 py-1.5 text-left font-normal">Process</th>
                        <th className="px-3 py-1.5 text-left font-normal">Internet</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.open_ports.map((p) => (
                        <tr key={p.port} className="border-b border-white/5 hover:bg-white/[0.02]">
                          <td className="px-3 py-1.5 font-mono text-white/80">{p.port}</td>
                          <td className="px-3 py-1.5 text-white/50">{p.protocol}</td>
                          <td className="px-3 py-1.5 text-white/60 font-mono">{p.process || "—"}</td>
                          <td className="px-3 py-1.5">
                            {p.internet_reachable ? (
                              <span className="flex items-center gap-1 text-red-400">
                                <Globe size={10} /> Yes
                              </span>
                            ) : (
                              <span className="text-white/25">Local</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Exposed vulns */}
            <div className="space-y-2">
              <p className="text-xs font-medium text-white/40 uppercase tracking-wider">
                Exposed Vulnerabilities ({data.exposed_vulns.length})
              </p>
              {data.exposed_vulns.length === 0 ? (
                <p className="text-white/20 text-xs">No vulnerabilities linked to open ports.</p>
              ) : (
                <div className="rounded-lg border border-white/8 overflow-hidden">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-white/5 text-white/30">
                        <th className="px-3 py-1.5 text-left font-normal">CVE</th>
                        <th className="px-3 py-1.5 text-left font-normal">Sev</th>
                        <th className="px-3 py-1.5 text-left font-normal">Port</th>
                        <th className="px-3 py-1.5 text-left font-normal">Package</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.exposed_vulns.map((v, i) => (
                        <tr key={i} className="border-b border-white/5 hover:bg-white/[0.02]">
                          <td className="px-3 py-1.5 font-mono text-white/70 text-[10px]">{v.cve_id}</td>
                          <td className="px-3 py-1.5">
                            <span className={`rounded border px-1.5 py-0.5 text-[9px] font-medium ${severityColor(v.severity)}`}>
                              {v.severity}
                            </span>
                          </td>
                          <td className="px-3 py-1.5 font-mono text-white/50">{v.port || "—"}</td>
                          <td className="px-3 py-1.5 text-white/50 truncate max-w-[100px]">{v.package_name}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

export default function AttackSurfacePage() {
  const [internetOnly, setInternetOnly] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);

  const { data, loading, error, refetch } = useApi<OrgSurfaceResponse>(
    (signal) => api.get(`/xdr/attack-surface?internet_only=${internetOnly}`, {}, signal),
  );

  const agents = data?.agents ?? [];

  return (
    <div className="space-y-5 max-w-5xl">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Attack Surface Map</h1>
          <p className="text-sm text-white/50 mt-0.5">
            Open listening ports and software with known CVEs across all agents
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setInternetOnly(!internetOnly)}
            className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs transition-colors ${
              internetOnly
                ? "border-red-500/40 bg-red-500/10 text-red-400"
                : "border-white/10 text-white/50 hover:text-white"
            }`}
          >
            <Globe size={13} />
            Internet-reachable only
          </button>
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-white/60 hover:text-white hover:border-white/20 transition-colors"
          >
            <RefreshCw size={13} />
            Refresh
          </button>
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

      {!loading && !error && agents.length === 0 && (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center space-y-2">
          <ShieldOff size={28} className="mx-auto text-white/20" />
          <p className="text-white/30 text-sm">No attack surface data yet.</p>
          <p className="text-white/20 text-xs">
            The scanner runs every 15 minutes on online agents. Make sure agents are connected and generating network events.
          </p>
        </div>
      )}

      {agents.length > 0 && (
        <>
          {/* Summary stats */}
          <div className="grid grid-cols-3 gap-3">
            {[
              { label: "Agents scanned", value: agents.length },
              { label: "Total open ports", value: agents.reduce((s, a) => s + a.open_port_count, 0) },
              { label: "Exposed CVEs", value: agents.reduce((s, a) => s + a.exposed_vuln_count, 0) },
            ].map(({ label, value }) => (
              <div key={label} className="rounded-xl border border-white/10 bg-white/[0.02] p-4 text-center">
                <p className="text-2xl font-bold text-white tabular-nums">{value}</p>
                <p className="text-xs text-white/40 mt-0.5">{label}</p>
              </div>
            ))}
          </div>

          {/* Agent grid */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {agents.map((a) => (
              <button
                key={a.agent_id}
                onClick={() => setSelectedAgent(selectedAgent === a.agent_id ? null : a.agent_id)}
                className={`rounded-xl border p-4 text-left transition-all hover:border-white/20 ${cardBg(a.exposed_vuln_count, a.risk_score)} ${
                  selectedAgent === a.agent_id ? "ring-1 ring-white/20" : ""
                }`}
              >
                <p className="text-sm font-medium text-white/80 truncate">{a.hostname}</p>
                <p className="text-[10px] font-mono text-white/30 mt-0.5 truncate">{a.ip}</p>
                <div className="mt-3 flex items-center gap-3 text-xs">
                  <span className="text-white/50">
                    <span className="font-semibold text-white/70">{a.open_port_count}</span> ports
                  </span>
                  <span className={a.exposed_vuln_count > 0 ? "text-red-400" : "text-white/30"}>
                    <span className="font-semibold">{a.exposed_vuln_count}</span> CVEs
                  </span>
                </div>
                {a.exposed_vuln_count > 0 && (
                  <div className="mt-2 flex items-center gap-1 text-[10px] text-red-400">
                    <AlertTriangle size={9} />
                    Exposed vulns
                  </div>
                )}
              </button>
            ))}
          </div>

          {/* Detail panel */}
          {selectedAgent && (
            <AgentDetailPanel
              agentId={selectedAgent}
              onClose={() => setSelectedAgent(null)}
            />
          )}
        </>
      )}
    </div>
  );
}
