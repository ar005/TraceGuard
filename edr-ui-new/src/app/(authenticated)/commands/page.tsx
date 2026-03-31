"use client";
import { useState, useCallback } from "react";
import { Terminal } from "lucide-react";
import { api } from "@/lib/api-client";
import { useApi } from "@/hooks/use-api";
import { cn, formatDate, eventTypeColor } from "@/lib/utils";
import type { Event } from "@/types";

export default function CommandsPage() {
  const [filter, setFilter] = useState("");
  const fetch = useCallback(
    () => api.get<{events?:Event[]}|Event[]>("/api/v1/events", {
      event_type: "CMD_EXEC",
      search: filter || undefined, limit: 100,
    }).then(r => Array.isArray(r) ? r : r.events ?? []),
    [filter]
  );
  const { data: events, loading } = useApi(fetch);
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="font-heading text-xl font-bold">Commands</h1>
        <input
          className="rounded border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-[hsl(var(--ring))]"
          placeholder="Filter commands..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
        />
      </div>
      {loading && <div className="text-sm text-[hsl(var(--muted-foreground))]">Loading...</div>}
      <div className="space-y-1">
        {(events ?? []).map(ev => (
          <div key={ev.id} className="flex items-center gap-3 rounded px-3 py-2 text-sm hover:bg-[hsl(var(--accent))] transition-colors">
            <Terminal className="h-3.5 w-3.5 text-purple-400 shrink-0" />
            <span className="font-mono text-xs text-[hsl(var(--muted-foreground))] w-32 shrink-0">{formatDate(ev.timestamp)}</span>
            <span className="text-xs text-[hsl(var(--muted-foreground))] w-24 shrink-0">{ev.hostname}</span>
            <span className="font-mono text-xs truncate">{String(ev.payload?.command || ev.payload?.cmdline || ev.payload?.comm || "--")}</span>
          </div>
        ))}
        {!loading && (events ?? []).length === 0 && (
          <div className="py-12 text-center text-sm text-[hsl(var(--muted-foreground))]">No command events found</div>
        )}
      </div>
    </div>
  );
}
