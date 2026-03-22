"use client";
import { useCallback } from "react";
import { Monitor, Circle } from "lucide-react";
import { api } from "@/lib/api-client";
import { useApi } from "@/hooks/use-api";
import { timeAgo } from "@/lib/utils";
import type { Agent } from "@/types";

export default function AgentsPage() {
  const fetch = useCallback(
    () => api.get<{agents?:Agent[]}|Agent[]>("/api/v1/agents").then(r => Array.isArray(r) ? r : r.agents ?? []),
    []
  );
  const { data: agents, loading } = useApi(fetch);
  return (
    <div className="space-y-4">
      <h1 className="font-heading text-xl font-bold">Agents</h1>
      {loading && <div className="text-sm text-[hsl(var(--muted-foreground))]">Loading...</div>}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead><tr className="border-b border-[hsl(var(--border))] text-left text-xs text-[hsl(var(--muted-foreground))]">
            <th className="pb-2 pr-4">Status</th><th className="pb-2 pr-4">Hostname</th><th className="pb-2 pr-4">IP</th>
            <th className="pb-2 pr-4">OS</th><th className="pb-2 pr-4">Version</th><th className="pb-2 pr-4">Last Seen</th>
          </tr></thead>
          <tbody>
            {(agents ?? []).map(a => (
              <tr key={a.id} className="border-b border-[hsl(var(--border)/.5)] hover:bg-[hsl(var(--accent))] transition-colors">
                <td className="py-2 pr-4"><Circle className={`h-2.5 w-2.5 fill-current ${a.is_online ? "text-emerald-400" : "text-red-400"}`} /></td>
                <td className="py-2 pr-4 font-medium">{a.hostname}</td>
                <td className="py-2 pr-4 font-mono text-xs">{a.ip}</td>
                <td className="py-2 pr-4">{a.os} {a.os_version}</td>
                <td className="py-2 pr-4 font-mono text-xs">{a.agent_ver}</td>
                <td className="py-2 pr-4 text-[hsl(var(--muted-foreground))]">{timeAgo(a.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!loading && (agents ?? []).length === 0 && (
          <div className="py-12 text-center text-sm text-[hsl(var(--muted-foreground))]">No agents registered</div>
        )}
      </div>
    </div>
  );
}
