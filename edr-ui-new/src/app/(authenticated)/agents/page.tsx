"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Circle, Shield, ShieldOff, Plus, Trash2, X, Loader2, Server, Lock, Unlock, Globe, AlertTriangle } from "lucide-react";
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
            {tab === "info" ? "Agent Info" : "Containment"}
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

/* ── Containment Tab ─────────────────────────────────────────── */

/** Returns true when the value looks like an IP address (v4 or v6). */
function looksLikeIP(value: string): boolean {
  // IPv4: digits and dots only (e.g. 192.168.1.1)
  if (/^[\d.]+$/.test(value)) return true;
  // IPv6: hex digits and colons (e.g. ::1, fe80::1)
  if (/^[0-9a-fA-F:]+$/.test(value) && value.includes(":")) return true;
  return false;
}

function BlockTab({ agent }: { agent: Agent }) {
  const [ipInput, setIpInput] = useState("");
  const [persistent, setPersistent] = useState(false);
  const [blocking, setBlocking] = useState(false);
  const [unblocking, setUnblocking] = useState<string | null>(null);
  const [blockedIPs, setBlockedIPs] = useState<string[]>([]);
  const [blockedDomains, setBlockedDomains] = useState<string[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [loadingList, setLoadingList] = useState(false);
  const [message, setMessage] = useState<{ text: string; error: boolean } | null>(null);

  // Isolation state
  const [isolated, setIsolated] = useState(false);
  const [isolating, setIsolating] = useState(false);
  const [releasing, setReleasing] = useState(false);
  const [showIsolateConfirm, setShowIsolateConfirm] = useState(false);

  // Helper to send a live-response command
  async function sendCommand(action: string, args: string[] = [], timeout = 15) {
    return api.post<{ stdout?: string; output?: string; error?: string }>(
      "/api/v1/liveresponse/command",
      { agent_id: agent.id, action, args, timeout }
    );
  }

  // Load blocked IPs list
  async function loadBlockedIPs() {
    if (!agent.is_online) {
      setMessage({ text: "Agent is offline — cannot query blocked list.", error: true });
      setLoaded(true);
      return;
    }
    setLoadingList(true);
    setMessage(null);
    try {
      // Fetch IPs and domains in parallel
      const [ipRes, domainRes] = await Promise.all([
        sendCommand("list_blocked", [], 10),
        sendCommand("list_blocked_domains", [], 10).catch(() => null),
      ]);

      if (ipRes.error) {
        setMessage({ text: `Agent error: ${ipRes.error}`, error: true });
      } else {
        const ipOutput = ipRes.stdout ?? ipRes.output ?? "";
        setBlockedIPs(
          ipOutput
            .split("\n")
            .map((l) => l.trim())
            .filter(Boolean)
        );
      }

      if (domainRes && !domainRes.error) {
        const domainOutput = domainRes.stdout ?? domainRes.output ?? "";
        setBlockedDomains(
          domainOutput
            .split("\n")
            .map((l) => l.trim())
            .filter(Boolean)
        );
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

  // ── Isolation handlers ──

  async function handleIsolate() {
    setShowIsolateConfirm(false);
    setIsolating(true);
    setMessage(null);
    try {
      const res = await sendCommand("isolate");
      if (res.error) {
        setMessage({ text: res.error, error: true });
      } else {
        setIsolated(true);
        setMessage({ text: "Host isolated — all traffic blocked except backend communication.", error: false });
      }
    } catch (err) {
      setMessage({ text: err instanceof Error ? err.message : "Isolate failed", error: true });
    } finally {
      setIsolating(false);
    }
  }

  async function handleRelease() {
    setReleasing(true);
    setMessage(null);
    try {
      const res = await sendCommand("release");
      if (res.error) {
        setMessage({ text: res.error, error: true });
      } else {
        setIsolated(false);
        setMessage({ text: "Host released — normal network access restored.", error: false });
        loadBlockedIPs();
      }
    } catch (err) {
      setMessage({ text: err instanceof Error ? err.message : "Release failed", error: true });
    } finally {
      setReleasing(false);
    }
  }

  // ── Block / Unblock handlers ──

  async function handleBlock() {
    const target = ipInput.trim();
    if (!target) return;

    const isIP = looksLikeIP(target);
    const action = isIP ? "block_ip" : "block_domain";
    const args = persistent ? [target, "persistent"] : [target];

    setBlocking(true);
    setMessage(null);

    try {
      const res = await sendCommand(action, args);

      if (res.error) {
        setMessage({ text: res.error, error: true });
      } else {
        const label = isIP ? "IP" : "domain";
        const extra = persistent ? " (persistent)" : "";
        setMessage({ text: `Blocked ${label} ${target}${extra}`, error: false });
        setIpInput("");
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

  async function handleUnblock(entry: string, type: "ip" | "domain") {
    setUnblocking(entry);
    setMessage(null);

    const action = type === "ip" ? "unblock_ip" : "unblock_domain";

    try {
      const res = await sendCommand(action, [entry]);

      if (res.error) {
        setMessage({ text: res.error, error: true });
      } else {
        setMessage({ text: `Unblocked ${type === "ip" ? "IP" : "domain"} ${entry}`, error: false });
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

  // Auto-detect type for display in input
  const detectedType = ipInput.trim()
    ? looksLikeIP(ipInput.trim())
      ? "IP"
      : "Domain"
    : null;

  return (
    <div className="space-y-4">
      {/* ── Host Isolation ── */}
      <div
        className="rounded border p-3 space-y-3"
        style={{ borderColor: "var(--border)", background: "var(--surface-1)" }}
      >
        <div className="flex items-center justify-between">
          <div
            className="text-xs font-semibold font-heading flex items-center gap-1.5"
            style={{ color: "var(--fg)" }}
          >
            <Lock size={12} />
            Host Isolation
          </div>
          <span
            className="text-[10px] font-medium rounded-full px-2 py-0.5"
            style={{
              background: isolated ? "oklch(0.45 0.15 25 / 0.15)" : "oklch(0.55 0.15 145 / 0.15)",
              color: isolated ? "#ef4444" : "#22c55e",
            }}
          >
            {isolated ? "Isolated" : "Normal"}
          </span>
        </div>

        <p className="text-[10px] leading-relaxed" style={{ color: "var(--muted)" }}>
          Isolating a host blocks <strong>all</strong> network traffic except communication
          with the TraceGuard backend.
        </p>

        <div className="flex gap-2">
          <button
            onClick={() => setShowIsolateConfirm(true)}
            disabled={isolating || releasing || isolated || !agent.is_online}
            className="flex items-center gap-1.5 rounded border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-red-500/10 disabled:opacity-50"
            style={{ borderColor: "var(--border)", color: "#ef4444" }}
          >
            {isolating ? (
              <Loader2 size={12} className="animate-spin" />
            ) : (
              <Lock size={12} />
            )}
            {isolating ? "Isolating..." : "Isolate Host"}
          </button>
          <button
            onClick={handleRelease}
            disabled={releasing || isolating || !isolated || !agent.is_online}
            className="flex items-center gap-1.5 rounded border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-emerald-500/10 disabled:opacity-50"
            style={{ borderColor: "var(--border)", color: "#22c55e" }}
          >
            {releasing ? (
              <Loader2 size={12} className="animate-spin" />
            ) : (
              <Unlock size={12} />
            )}
            {releasing ? "Releasing..." : "Release Host"}
          </button>
        </div>

        {!agent.is_online && (
          <p className="text-[10px]" style={{ color: "var(--destructive)" }}>
            Agent is offline — cannot send commands.
          </p>
        )}
      </div>

      {/* Isolation confirmation dialog */}
      {showIsolateConfirm && (
        <div
          className="rounded border p-3 space-y-3"
          style={{
            borderColor: "oklch(0.45 0.15 25 / 0.4)",
            background: "oklch(0.45 0.15 25 / 0.08)",
          }}
        >
          <div className="flex items-center gap-2 text-xs font-semibold" style={{ color: "#ef4444" }}>
            <AlertTriangle size={14} />
            Confirm Host Isolation
          </div>
          <p className="text-[11px] leading-relaxed" style={{ color: "var(--fg)" }}>
            This will block <strong>ALL</strong> network traffic except backend communication. Continue?
          </p>
          <div className="flex gap-2">
            <button
              onClick={handleIsolate}
              className="flex items-center gap-1.5 rounded border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-red-500/10"
              style={{ borderColor: "oklch(0.45 0.15 25 / 0.4)", color: "#ef4444" }}
            >
              <Lock size={12} />
              Yes, Isolate
            </button>
            <button
              onClick={() => setShowIsolateConfirm(false)}
              className="rounded border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--surface-2)]"
              style={{ borderColor: "var(--border)", color: "var(--muted)" }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* ── Block IP / Domain ── */}
      <div>
        <div
          className="text-xs font-semibold mb-2 font-heading"
          style={{ color: "var(--fg)" }}
        >
          Block IP or Domain
        </div>
        <div className="flex gap-2">
          <div className="relative flex-1">
            <input
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleBlock()}
              placeholder="e.g. 1.2.3.4 or malicious-site.com"
              className="w-full rounded border px-3 py-1.5 text-xs font-mono outline-none transition-colors"
              style={{
                background: "var(--surface-1)",
                borderColor: "var(--border)",
                color: "var(--fg)",
              }}
              disabled={blocking || !agent.is_online}
            />
            {detectedType && (
              <span
                className="absolute right-2 top-1/2 -translate-y-1/2 text-[9px] font-medium rounded px-1.5 py-0.5"
                style={{ background: "var(--surface-2)", color: "var(--muted)" }}
              >
                {detectedType}
              </span>
            )}
          </div>
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

        {/* Persistent toggle */}
        <div className="flex items-center gap-2 mt-2">
          <label className="relative inline-flex cursor-pointer items-center">
            <input
              type="checkbox"
              checked={persistent}
              onChange={(e) => setPersistent(e.target.checked)}
              className="peer sr-only"
              disabled={!agent.is_online}
            />
            <div
              className="h-5 w-9 rounded-full transition-colors"
              style={{
                background: persistent ? "var(--primary)" : "var(--surface-2)",
              }}
            >
              <div
                className="absolute top-[2px] left-[2px] h-4 w-4 rounded-full transition-transform"
                style={{
                  background: "var(--fg)",
                  transform: persistent ? "translateX(16px)" : "translateX(0)",
                }}
              />
            </div>
          </label>
          <span className="text-[11px]" style={{ color: "var(--muted)" }}>
            Persistent
          </span>
          <span
            className="text-[9px] rounded border px-1.5 py-0.5"
            style={{ borderColor: "var(--border)", color: "var(--muted)" }}
            title="Block persists even after agent restart"
          >
            ?
          </span>
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

      {/* ── Currently Blocked ── */}
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

        {loaded && blockedIPs.length === 0 && blockedDomains.length === 0 && (
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

        {/* Blocked IPs */}
        {loaded && blockedIPs.length > 0 && (
          <div className="mb-3">
            <div
              className="text-[10px] font-medium mb-1 flex items-center gap-1"
              style={{ color: "var(--muted)" }}
            >
              <Shield size={10} />
              Blocked IPs
            </div>
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
                    onClick={() => handleUnblock(ip, "ip")}
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
          </div>
        )}

        {/* Blocked Domains */}
        {loaded && blockedDomains.length > 0 && (
          <div>
            <div
              className="text-[10px] font-medium mb-1 flex items-center gap-1"
              style={{ color: "var(--muted)" }}
            >
              <Globe size={10} />
              Blocked Domains
            </div>
            <div
              className="rounded border divide-y"
              style={{
                borderColor: "var(--border)",
                background: "var(--surface-1)",
              }}
            >
              {blockedDomains.map((domain) => (
                <div
                  key={domain}
                  className="flex items-center justify-between px-3 py-2"
                  style={{ borderColor: "var(--border)" }}
                >
                  <div className="flex items-center gap-2">
                    <Globe size={12} className="text-red-400" />
                    <span className="font-mono text-xs" style={{ color: "var(--fg)" }}>
                      {domain}
                    </span>
                  </div>
                  <button
                    onClick={() => handleUnblock(domain, "domain")}
                    disabled={unblocking === domain || !agent.is_online}
                    className="flex items-center gap-1 rounded px-2 py-1 text-[10px] font-medium transition-colors hover:bg-emerald-500/10 disabled:opacity-50"
                    style={{ color: "#22c55e" }}
                  >
                    {unblocking === domain ? (
                      <Loader2 size={10} className="animate-spin" />
                    ) : (
                      <Trash2 size={10} />
                    )}
                    Unblock
                  </button>
                </div>
              ))}
            </div>
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
        Blocks are enforced at the firewall level (<span className="font-mono">iptables</span> on
        Linux, Windows Firewall on Windows). Both inbound and outbound traffic is dropped.
        Persistent blocks survive agent restarts. Host isolation blocks all traffic except
        backend communication.
      </div>
    </div>
  );
}

/* ── Main Page ───────────────────────────────────────────────── */

export default function AgentsPage() {
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
  const [search, setSearch] = useState("");

  const fetchAgents = useCallback(
    () =>
      api
        .get<{ agents?: Agent[] } | Agent[]>("/api/v1/agents")
        .then((r) => (Array.isArray(r) ? r : r.agents ?? [])),
    []
  );
  const { data: agents, loading } = useApi(fetchAgents);

  const displayAgents = (agents ?? []).filter((a) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      a.hostname?.toLowerCase().includes(q) ||
      a.ip?.toLowerCase().includes(q) ||
      a.os?.toLowerCase().includes(q) ||
      a.os_version?.toLowerCase().includes(q) ||
      a.agent_ver?.toLowerCase().includes(q) ||
      a.env?.toLowerCase().includes(q) ||
      a.tags?.some((t) => t.toLowerCase().includes(q))
    );
  });

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

      {/* Search */}
      <input
        type="text"
        placeholder="Search agents by hostname, IP, OS, or tags..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="rounded-md border px-3 py-1.5 text-xs w-full max-w-md outline-none focus-ring"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)", color: "var(--fg)" }}
      />

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
              {displayAgents.map((a) => {
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
          {displayAgents.length === 0 && (
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
