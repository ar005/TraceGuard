"use client";

import { useCallback, useEffect, useRef, useState, type KeyboardEvent } from "react";
import { Terminal, ChevronRight, Shield, AlertTriangle } from "lucide-react";
import { api } from "@/lib/api-client";
import { useApi } from "@/hooks/use-api";
import type { Agent } from "@/types";

interface OutputBlock {
  id: number;
  command: string;
  response: string;
  timestamp: string;
  isError: boolean;
}

export default function LiveResponsePage() {
  const fetchAgents = useCallback(
    (signal: AbortSignal) =>
      api
        .get<{ agents?: Agent[] } | Agent[]>("/api/v1/agents", undefined, signal)
        .then((r) => (Array.isArray(r) ? r : r.agents ?? [])),
    []
  );
  const { data: allAgents, loading: agentsLoading } = useApi(fetchAgents);
  const onlineAgents = (allAgents ?? []).filter((a) => a.is_online);

  const [selectedAgentId, setSelectedAgentId] = useState<string>("");
  const [commandInput, setCommandInput] = useState("");
  const [outputs, setOutputs] = useState<OutputBlock[]>([]);
  const [sending, setSending] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [historyIdx, setHistoryIdx] = useState(-1);

  const terminalEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const selectedAgent = onlineAgents.find((a) => a.id === selectedAgentId);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [outputs]);

  async function submitCommand() {
    const cmd = commandInput.trim();
    if (!cmd || !selectedAgentId || sending) return;

    setHistory((prev) => [cmd, ...prev]);
    setHistoryIdx(-1);
    setCommandInput("");
    setSending(true);

    const blockId = Date.now();
    try {
      // Backend expects: { agent_id, action, args[], timeout }
      // Split command into action (first word) + args (rest)
      const parts = cmd.split(/\s+/);
      const action = parts[0];
      const args = parts.slice(1);

      const res = await api.post<{ output?: string; result?: string; error?: string; stdout?: string; stderr?: string }>(
        "/api/v1/liveresponse/command",
        { agent_id: selectedAgentId, action, args, timeout: 30 }
      );
      const output = res?.output ?? res?.stdout ?? res?.result ?? "";
      const stderr = res?.stderr ?? "";
      const errMsg = res?.error ?? "";
      const fullResponse = [output, stderr, errMsg].filter(Boolean).join("\n") || "Command sent (no output returned)";

      setOutputs((prev) => [
        ...prev,
        {
          id: blockId,
          command: cmd,
          response: fullResponse,
          timestamp: new Date().toISOString(),
          isError: !!errMsg,
        },
      ]);
    } catch (err) {
      setOutputs((prev) => [
        ...prev,
        {
          id: blockId,
          command: cmd,
          response: err instanceof Error ? err.message : String(err),
          timestamp: new Date().toISOString(),
          isError: true,
        },
      ]);
    } finally {
      setSending(false);
      inputRef.current?.focus();
    }
  }

  function handleKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") {
      e.preventDefault();
      submitCommand();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (history.length === 0) return;
      const nextIdx = historyIdx + 1;
      if (nextIdx < history.length) {
        setHistoryIdx(nextIdx);
        setCommandInput(history[nextIdx]);
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIdx <= 0) {
        setHistoryIdx(-1);
        setCommandInput("");
      } else {
        const nextIdx = historyIdx - 1;
        setHistoryIdx(nextIdx);
        setCommandInput(history[nextIdx]);
      }
    }
  }

  const disabled = !selectedAgentId;

  return (
    <div className="flex flex-col gap-4 h-full">
      {/* Header */}
      <div>
        <h1 className="font-heading text-xl font-bold flex items-center gap-2">
          <Terminal size={20} style={{ color: "var(--primary)" }} />
          Live Response
        </h1>
        <p className="text-sm" style={{ color: "var(--muted)" }}>
          Execute commands on remote agents in real time
        </p>
      </div>

      {/* Agent selector */}
      <div
        className="flex items-center gap-3 p-3 rounded border"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
      >
        <label className="text-xs font-medium whitespace-nowrap" style={{ color: "var(--muted)" }}>
          Target Agent
        </label>
        <select
          value={selectedAgentId}
          onChange={(e) => {
            setSelectedAgentId(e.target.value);
            setOutputs([]);
          }}
          className="flex-1 rounded border px-3 py-1.5 text-sm font-mono focus-ring"
          style={{
            background: "var(--surface-1)",
            borderColor: "var(--border)",
            color: "var(--fg)",
          }}
        >
          <option value="">
            {agentsLoading
              ? "Loading agents..."
              : onlineAgents.length === 0
                ? "No online agents available"
                : "Select an agent..."}
          </option>
          {onlineAgents.map((a) => (
            <option key={a.id} value={a.id}>
              {a.hostname} ({a.ip}) — v{a.agent_ver}
            </option>
          ))}
        </select>
        {selectedAgent && (
          <span className="flex items-center gap-1.5 text-xs text-emerald-400">
            <span className="inline-block h-2 w-2 rounded-full bg-emerald-400 animate-pulse-ring" />
            Connected
          </span>
        )}
      </div>

      {/* Safety notice */}
      <div
        className="flex items-center gap-2 px-3 py-2 rounded border text-xs"
        style={{
          background: "oklch(0.70 0.15 75 / 0.08)",
          borderColor: "oklch(0.70 0.15 75 / 0.25)",
          color: "var(--warning)",
        }}
      >
        <AlertTriangle size={14} />
        <span>Commands execute on the remote agent with root privileges. Use with caution.</span>
      </div>

      {/* Terminal area */}
      <div
        className="flex-1 flex flex-col rounded border overflow-hidden min-h-[400px]"
        style={{ borderColor: "var(--border)" }}
      >
        {/* Terminal output */}
        <div
          className="flex-1 overflow-y-auto p-4 font-mono text-sm"
          style={{ background: "var(--bg)" }}
          onClick={() => inputRef.current?.focus()}
        >
          {outputs.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full gap-2" style={{ color: "var(--muted)" }}>
              <Shield size={32} />
              <span className="text-xs">
                {disabled
                  ? "Select an online agent to begin a live response session"
                  : `Ready — type a command for ${selectedAgent?.hostname}`}
              </span>
            </div>
          )}

          {outputs.map((block) => (
            <div key={block.id} className="mb-4 animate-fade-in">
              {/* Command line */}
              <div className="flex items-center gap-1.5">
                <ChevronRight size={12} className="text-emerald-400 shrink-0" />
                <span className="text-emerald-400 font-medium">{selectedAgent?.hostname ?? "agent"}</span>
                <span style={{ color: "var(--muted)" }}>$</span>
                <span style={{ color: "var(--fg)" }}>{block.command}</span>
              </div>
              {/* Response */}
              <pre
                className="mt-1 ml-5 whitespace-pre-wrap text-xs leading-relaxed"
                style={{ color: block.isError ? "var(--destructive)" : "var(--muted)" }}
              >
                {block.response}
              </pre>
            </div>
          ))}
          <div ref={terminalEndRef} />
        </div>

        {/* Command input */}
        <div
          className="flex items-center gap-2 px-4 py-2.5 border-t"
          style={{
            background: "var(--surface-0)",
            borderColor: "var(--border)",
          }}
        >
          <span className="text-emerald-400 font-mono text-sm font-bold select-none">$</span>
          <input
            ref={inputRef}
            type="text"
            value={commandInput}
            onChange={(e) => {
              setCommandInput(e.target.value);
              setHistoryIdx(-1);
            }}
            onKeyDown={handleKeyDown}
            disabled={disabled || sending}
            placeholder={
              disabled
                ? "Select an agent first..."
                : sending
                  ? "Waiting for response..."
                  : "Type a command and press Enter..."
            }
            className="flex-1 bg-transparent font-mono text-sm outline-none placeholder:text-[var(--muted-fg)]"
            style={{ color: "var(--fg)" }}
            autoFocus
          />
          {sending && (
            <div
              className="h-4 w-4 rounded-full border-2 border-t-transparent animate-spin"
              style={{ borderColor: "var(--primary)", borderTopColor: "transparent" }}
            />
          )}
        </div>
      </div>
    </div>
  );
}
