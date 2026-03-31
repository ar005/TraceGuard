"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Circle, Shield, ShieldOff, Plus, Trash2, X, Loader2, Server } from "lucide-react";
import { api } from "@/lib/api-client";
import { useApi } from "@/hooks/use-api";
import { cn, timeAgo } from "@/lib/utils";
import type { Agent } from "@/types";

/* ── Agent Detail Panel ──────────────────────────────────────── */

function AgentDetail({
  agent,
  onClose,
}: {
  agent: Agent;
  onClose: () => void;
}) {
  const [activeTab, setActiveTab] = useState<"info" | "block">("info");

  return (
    <div
      className="fixed inset-y-0 right-0 z-50 w-full max-w-lg border-l shadow-xl overflow-y-auto animate-fade-in"
      style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between p-4 border-b"
        style={{ borderColor: "var(--border)" }}
      >
        <div className="flex items-center gap-2">
          <Circle
            className={cn(
              "h-2.5 w-2.5 fill-current",
              agent.is_online ? "text-emerald-400" : "text-red-400"
            )}
          />
          <h3 className="text-sm font-semibold font-heading">{agent.hostname}</h3>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded hover:bg-[var(--surface-2)] transition-colors"
          style={{ color: "var(--muted)" }}
        >
          <X size={16} />
        </button>
      </div>

      {/* Tabs */}
      <div className="flex border-b" style={{ borderColor: "var(--border)" }}>
        {(["info", "block"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={cn(
              "px-4 py-2 text-xs font-medium transition-colors border-b-2",
              activeTab === tab
                ? "border-[var(--primary)] text-[var(--primary)]"
                : "border-transparent hover:bg-[var(--surface-1)]"
            )}
            style={activeTab !== tab ? { color: "var(--muted)" } : {}}
          >
            {tab === "info" ? "Agent Info" : "Block / Unblock"}
          </button>
        ))}
      </div>

      <div className="p-4">
        {activeTab === "info" && <AgentInfoTab agent={agent} />}
        {activeTab === "block" && <BlockTab agent={agent} />}
      </div>
    </div>
  );
}

/* ── Agent Info Tab ───────────────────────────────────────────── */

function AgentInfoTab({ agent }: { agent: Agent }) {
  const fields = [
    { label: "Agent ID", value: agent.id, mono: true },
    { label: "Hostname", value: agent.hostname },
    { label: "IP Address", value: agent.ip, mono: true },
    { label: "OS", value: `${agent.os} ${agent.os_version}` },
    { label: "Agent Version", value: agent.agent_ver, mono: true },
    { label: "Status", value: agent.is_online ? "Online" : "Offline" },
    { label: "First Seen", value: new Date(agent.first_seen).toLocaleString() },
    { label: "Last Seen", value: timeAgo(agent.last_seen) },
    { label: "Environment", value: agent.env || "—" },
    { label: "Tags", value: agent.tags?.length ? agent.tags.join(", ") : "—" },
    { label: "Notes", value: agent.notes || "—" },
  ];

  return (
    <div className="space-y-2">
      {fields.map((f) => (
        <div key={f.label} className="flex justify-between text-xs py-1">
          <span style={{ color: "var(--muted)" }}>{f.label}</span>
          <span
            className={f.mono ? "font-mono" : ""}
            style={{ color: "var(--fg)" }}
          >
            {f.value}
          </span>
        </div>
      ))}
    </div>
  );
}

/* ── Block / Unblock Tab ──────────────────────────────────────── */

function BlockTab({ agent }: { agent: Agent }) {
  const [ipInput, setIpInput] = useState("");
  const [blocking, setBlocking] = useState(false);
  const [unblocking, setUnblocking] = useState<string | null>(null);
  const [blockedIPs, setBlockedIPs] = useState<string[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [loadingList, setLoadingList] = useState(false);
  const [message, setMessage] = useState<{ text: string; error: boolean } | null>(null);

  // Load blocked IPs list
  async function loadBlockedIPs() {
    if (!agent.is_online) {
      setMessage({ text: "Agent is offline — cannot query blocked IPs.", error: true });
      setLoaded(true);
      return;
    }
    setLoadingList(true);
    setMessage(null);
    try {
      const res = await api.post<{ stdout?: string; output?: string; error?: string }>(
        "/api/v1/liveresponse/command",
        { agent_id: agent.id, action: "list_blocked", args: [], timeout: 10 }
      );
      if (res.error) {
        setMessage({ text: `Agent error: ${res.error}`, error: true });
      } else {
        const output = res.stdout ?? res.output ?? "";
        const ips = output
          .split("\n")
          .map((l) => l.trim())
          .filter(Boolean);
        setBlockedIPs(ips);
      }
      setLoaded(true);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Request failed";
      if (msg.includes("not connected")) {
        setMessage({ text: "Agent is not connected for live response. Ensure the agent is running and connected to the backend.", error: true });
      } else {
        setMessage({ text: `Failed to load: ${msg}`, error: true });
      }
      setLoaded(true);
    } finally {
      setLoadingList(false);
    }
  }

  // Load once on mount — not on every render
  useEffect(() => {
    loadBlockedIPs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agent.id]);

  async function handleBlock() {
    const target = ipInput.trim();
    if (!target) return;

    setBlocking(true);
    setMessage(null);

    try {
      const res = await api.post<{ stdout?: string; output?: string; error?: string }>(
        "/api/v1/liveresponse/command",
        { agent_id: agent.id, action: "block_ip", args: [target], timeout: 15 }
      );

      if (res.error) {
        setMessage({ text: res.error, error: true });
      } else {
        setMessage({ text: `Blocked ${target}`, error: false });
        setIpInput("");
        // Refresh list
        loadBlockedIPs();
      }
    } catch (err) {
      setMessage({
        text: err instanceof Error ? err.message : "Block failed",
        error: true,
      });
    } finally {
      setBlocking(false);
    }
  }

  async function handleUnblock(ip: string) {
    setUnblocking(ip);
    setMessage(null);

    try {
      const res = await api.post<{ stdout?: string; output?: string; error?: string }>(
        "/api/v1/liveresponse/command",
        { agent_id: agent.id, action: "unblock_ip", args: [ip], timeout: 15 }
      );

      if (res.error) {
        setMessage({ text: res.error, error: true });
      } else {
        setMessage({ text: `Unblocked ${ip}`, error: false });
        loadBlockedIPs();
      }
    } catch (err) {
      setMessage({
        text: err instanceof Error ? err.message : "Unblock failed",
        error: true,
      });
    } finally {
      setUnblocking(null);
    }
  }

  return (
    <div className="space-y-4">
      {/* Block new IP/domain */}
      <div>
        <div
          className="text-xs font-semibold mb-2 font-heading"
          style={{ color: "var(--fg)" }}
        >
          Block IP or Domain
        </div>
        <div className="flex gap-2">
          <input
            value={ipInput}
            onChange={(e) => setIpInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleBlock()}
            placeholder="e.g. 1.2.3.4 or malicious-site.com"
            className="flex-1 rounded border px-3 py-1.5 text-xs font-mono outline-none transition-colors"
            style={{
              background: "var(--surface-1)",
              borderColor: "var(--border)",
              color: "var(--fg)",
            }}
            disabled={blocking || !agent.is_online}
          />
          <button
            onClick={handleBlock}
            disabled={blocking || !ipInput.trim() || !agent.is_online}
            className="flex items-center gap-1.5 rounded border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-red-500/10 disabled:opacity-50"
            style={{ borderColor: "var(--border)", color: "#ef4444" }}
          >
            {blocking ? (
              <Loader2 size={12} className="animate-spin" />
            ) : (
              <Shield size={12} />
            )}
            {blocking ? "Blocking..." : "Block"}
          </button>
        </div>
        {!agent.is_online && (
          <p className="text-[10px] mt-1" style={{ color: "var(--destructive)" }}>
            Agent is offline — cannot send commands.
          </p>
        )}
      </div>

      {/* Status message */}
      {message && (
        <div
          className="rounded border px-3 py-2 text-xs"
          style={{
            background: message.error
              ? "oklch(0.45 0.15 25 / 0.1)"
              : "oklch(0.55 0.15 145 / 0.1)",
            borderColor: message.error
              ? "oklch(0.45 0.15 25 / 0.3)"
              : "oklch(0.55 0.15 145 / 0.3)",
            color: message.error ? "var(--destructive)" : "#22c55e",
          }}
        >
          {message.text}
        </div>
      )}

      {/* Currently blocked list */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <div
            className="text-xs font-semibold font-heading"
            style={{ color: "var(--fg)" }}
          >
            Currently Blocked
          </div>
          <button
            onClick={loadBlockedIPs}
            disabled={loadingList}
            className="text-[10px] rounded px-2 py-0.5 transition-colors hover:bg-[var(--surface-2)]"
            style={{ color: "var(--muted)" }}
          >
            {loadingList ? "Loading..." : "Refresh"}
          </button>
        </div>

        {loadingList && !loaded && (
          <div className="space-y-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="animate-shimmer h-8 rounded" />
            ))}
          </div>
        )}

        {loaded && blockedIPs.length === 0 && (
          <div
            className="rounded border px-3 py-6 text-center text-xs"
            style={{
              borderColor: "var(--border)",
              background: "var(--surface-1)",
              color: "var(--muted)",
            }}
          >
            No IPs or domains are currently blocked on this agent.
          </div>
        )}

        {loaded && blockedIPs.length > 0 && (
          <div
            className="rounded border divide-y"
            style={{
              borderColor: "var(--border)",
              background: "var(--surface-1)",
            }}
          >
            {blockedIPs.map((ip) => (
              <div
                key={ip}
                className="flex items-center justify-between px-3 py-2"
                style={{ borderColor: "var(--border)" }}
              >
                <div className="flex items-center gap-2">
                  <ShieldOff size={12} className="text-red-400" />
                  <span className="font-mono text-xs" style={{ color: "var(--fg)" }}>
                    {ip}
                  </span>
                </div>
                <button
                  onClick={() => handleUnblock(ip)}
                  disabled={unblocking === ip || !agent.is_online}
                  className="flex items-center gap-1 rounded px-2 py-1 text-[10px] font-medium transition-colors hover:bg-emerald-500/10 disabled:opacity-50"
                  style={{ color: "#22c55e" }}
                >
                  {unblocking === ip ? (
                    <Loader2 size={10} className="animate-spin" />
                  ) : (
                    <Trash2 size={10} />
                  )}
                  Unblock
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Info */}
      <div
        className="rounded border px-3 py-2 text-[10px] leading-relaxed"
        style={{
          borderColor: "var(--border)",
          background: "var(--surface-1)",
          color: "var(--muted)",
        }}
      >
        Blocked IPs are enforced via <span className="font-mono">iptables</span> on the
        agent endpoint. Both inbound and outbound traffic to/from the IP is dropped.
        Blocks persist until manually unblocked or the agent restarts.
      </div>
    </div>
  );
}

/* ── Main Page ───────────────────────────────────────────────── */

export default function AgentsPage() {
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);

  const fetchAgents = useCallback(
    () =>
      api
        .get<{ agents?: Agent[] } | Agent[]>("/api/v1/agents")
        .then((r) => (Array.isArray(r) ? r : r.agents ?? [])),
    []
  );
  const { data: agents, loading } = useApi(fetchAgents);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="font-heading text-xl font-bold flex items-center gap-2">
          <Server size={20} style={{ color: "var(--primary)" }} />
          Agents
        </h1>
        <span className="text-xs font-mono" style={{ color: "var(--muted)" }}>
          {(agents ?? []).filter((a) => a.is_online).length} online / {(agents ?? []).length} total
        </span>
      </div>

      {loading && (
        <div className="space-y-2">
          {[1, 2, 3].map((i) => (
            <div key={i} className="animate-shimmer h-10 rounded" />
          ))}
        </div>
      )}

      {!loading && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr
                className="text-left text-[10px] uppercase tracking-wider border-b"
                style={{ color: "var(--muted)", borderColor: "var(--border)" }}
              >
                <th className="pb-2 pr-4 w-8">Status</th>
                <th className="pb-2 pr-4">Hostname</th>
                <th className="pb-2 pr-4">IP</th>
                <th className="pb-2 pr-4">OS</th>
                <th className="pb-2 pr-4">Version</th>
                <th className="pb-2 pr-4">Last Seen</th>
                <th className="pb-2 w-8"></th>
              </tr>
            </thead>
            <tbody>
              {(agents ?? []).map((a) => {
                const isSelected = selectedAgent?.id === a.id;
                return (
                  <tr
                    key={a.id}
                    onClick={() => setSelectedAgent(isSelected ? null : a)}
                    className={cn(
                      "border-b cursor-pointer transition-colors",
                      isSelected
                        ? "bg-[var(--primary)]/5"
                        : "hover:bg-[var(--surface-1)]"
                    )}
                    style={{ borderColor: "var(--border)" }}
                  >
                    <td className="py-2 pr-4">
                      <Circle
                        className={cn(
                          "h-2.5 w-2.5 fill-current",
                          a.is_online ? "text-emerald-400" : "text-red-400"
                        )}
                      />
                    </td>
                    <td className="py-2 pr-4 font-medium" style={{ color: "var(--fg)" }}>
                      <Link
                        href={`/agents/${a.id}`}
                        className="hover:underline transition-colors"
                        style={{ color: "var(--primary)" }}
                        onClick={(e) => e.stopPropagation()}
                      >
                        {a.hostname}
                      </Link>
                    </td>
                    <td className="py-2 pr-4 font-mono text-xs" style={{ color: "var(--fg)" }}>
                      {a.ip}
                    </td>
                    <td className="py-2 pr-4" style={{ color: "var(--muted)" }}>
                      {a.os} {a.os_version}
                    </td>
                    <td className="py-2 pr-4 font-mono text-xs" style={{ color: "var(--muted)" }}>
                      {a.agent_ver}
                    </td>
                    <td className="py-2 pr-4" style={{ color: "var(--muted)" }}>
                      {timeAgo(a.last_seen)}
                    </td>
                    <td className="py-2">
                      <Shield size={12} style={{ color: "var(--muted)" }} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {(agents ?? []).length === 0 && (
            <div className="py-12 text-center text-sm" style={{ color: "var(--muted)" }}>
              No agents registered
            </div>
          )}
        </div>
      )}

      {/* Detail panel */}
      {selectedAgent && (
        <AgentDetail agent={selectedAgent} onClose={() => setSelectedAgent(null)} />
      )}
    </div>
  );
}
