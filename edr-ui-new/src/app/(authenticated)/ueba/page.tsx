"use client";

import { useState, useEffect } from "react";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";

interface UEBAEvent {
  time: string;
  category: string;
  summary: string;
  agent_id: string;
  hostname: string;
  severity?: number;
  alert_id?: string;
}

interface TimelineResponse {
  uid: string;
  hours: number;
  events: UEBAEvent[];
}

const CATEGORY_STYLES: Record<string, { dot: string; label: string; bg: string }> = {
  login:   { dot: "bg-blue-500",    label: "Login",   bg: "bg-blue-500/10 border-blue-500/20 text-blue-400" },
  alert:   { dot: "bg-red-500",     label: "Alert",   bg: "bg-red-500/10 border-red-500/20 text-red-400" },
  process: { dot: "bg-orange-500",  label: "Process", bg: "bg-orange-500/10 border-orange-500/20 text-orange-400" },
  network: { dot: "bg-purple-500",  label: "Network", bg: "bg-purple-500/10 border-purple-500/20 text-purple-400" },
  file:    { dot: "bg-yellow-500",  label: "File",    bg: "bg-yellow-500/10 border-yellow-500/20 text-yellow-400" },
};

const SEV_COLORS = ["", "text-blue-400", "text-yellow-400", "text-orange-400", "text-red-400", "text-red-500"];

function TimelineItem({ ev }: { ev: UEBAEvent }) {
  const style = CATEGORY_STYLES[ev.category] ?? { dot: "bg-white/30", label: ev.category, bg: "bg-white/5 border-white/10 text-white/50" };
  return (
    <div className="flex gap-4 group">
      {/* Timeline spine */}
      <div className="flex flex-col items-center">
        <div className={`w-2.5 h-2.5 rounded-full mt-1 shrink-0 ${style.dot}`} />
        <div className="w-px flex-1 bg-white/10 mt-1" />
      </div>
      {/* Content */}
      <div className="pb-4 flex-1 min-w-0">
        <div className="flex items-start gap-2 flex-wrap">
          <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${style.bg}`}>
            {style.label}
          </span>
          {ev.severity != null && ev.severity > 0 && (
            <span className={`text-xs font-mono ${SEV_COLORS[ev.severity] ?? "text-white/40"}`}>
              SEV {ev.severity}
            </span>
          )}
          {ev.hostname && (
            <span className="text-xs text-white/30 font-mono">{ev.hostname}</span>
          )}
        </div>
        <p className="text-sm text-white/80 mt-1 truncate">{ev.summary}</p>
        <p className="text-xs text-white/30 font-mono mt-0.5">
          {new Date(ev.time).toLocaleString()}
        </p>
      </div>
    </div>
  );
}

export default function UEBAPage() {
  const [uid, setUid] = useState("");
  const [submittedUid, setSubmittedUid] = useState("");
  const [hours, setHours] = useState(24);
  const [filterCat, setFilterCat] = useState("");

  const { data, loading, error, refetch } = useApi<TimelineResponse | null>(
    () =>
      submittedUid
        ? api.get(`/identity/${encodeURIComponent(submittedUid)}/timeline?hours=${hours}`)
        : Promise.resolve(null),
  );

  useEffect(() => {
    if (submittedUid) refetch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [submittedUid, hours]);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (uid.trim()) setSubmittedUid(uid.trim());
  }

  const events = data?.events ?? [];
  const filtered = filterCat ? events.filter((e) => e.category === filterCat) : events;

  const cats = Array.from(new Set(events.map((e) => e.category)));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-white">UEBA Timeline</h1>
        <p className="text-sm text-white/50 mt-0.5">
          Unified user activity timeline — logins, alerts, and events in one view
        </p>
      </div>

      {/* Search bar */}
      <form onSubmit={submit} className="flex gap-3">
        <input
          className="flex-1 bg-white/5 border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-blue-500/50"
          value={uid}
          onChange={(e) => setUid(e.target.value)}
          placeholder="Enter user UID (e.g. alice, DOMAIN\alice)"
        />
        <div className="flex gap-2">
          {[6, 24, 48, 168].map((h) => (
            <button
              type="button"
              key={h}
              onClick={() => setHours(h)}
              className={`px-3 py-2 text-xs rounded-lg border transition-colors ${
                hours === h
                  ? "border-blue-500 bg-blue-500/10 text-blue-400"
                  : "border-white/10 text-white/50 hover:text-white hover:border-white/20"
              }`}
            >
              {h < 24 ? `${h}h` : `${h / 24}d`}
            </button>
          ))}
        </div>
        <button
          type="submit"
          disabled={!uid.trim()}
          className="px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white transition-colors"
        >
          Search
        </button>
      </form>

      {submittedUid && (
        <div className="grid grid-cols-3 gap-4">
          <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4 col-span-3 lg:col-span-1">
            <p className="text-xs text-white/40 uppercase tracking-wider mb-3">User</p>
            <p className="text-lg font-semibold text-white font-mono">{submittedUid}</p>
            <p className="text-xs text-white/40 mt-1">Last {hours < 24 ? `${hours} hours` : `${hours / 24} days`}</p>
            <div className="mt-4 space-y-2">
              {cats.map((cat) => {
                const count = events.filter((e) => e.category === cat).length;
                const style = CATEGORY_STYLES[cat];
                return (
                  <button
                    key={cat}
                    onClick={() => setFilterCat(filterCat === cat ? "" : cat)}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-lg border text-sm transition-colors ${
                      filterCat === cat
                        ? "border-white/20 bg-white/10"
                        : "border-white/5 hover:border-white/10 hover:bg-white/5"
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${style?.dot ?? "bg-white/30"}`} />
                      <span className="text-white/70 capitalize">{cat}</span>
                    </div>
                    <span className="text-white/40 font-mono text-xs">{count}</span>
                  </button>
                );
              })}
              {cats.length === 0 && !loading && (
                <p className="text-white/30 text-xs">No events found</p>
              )}
            </div>
          </div>

          {/* Timeline */}
          <div className="rounded-xl border border-white/10 bg-white/[0.02] p-5 col-span-3 lg:col-span-2">
            <div className="flex items-center justify-between mb-4">
              <p className="text-sm font-medium text-white">
                {filtered.length} event{filtered.length !== 1 ? "s" : ""}
                {filterCat && ` (${filterCat})`}
              </p>
              {filterCat && (
                <button onClick={() => setFilterCat("")} className="text-xs text-white/40 hover:text-white transition-colors">
                  Clear filter
                </button>
              )}
            </div>

            {loading && (
              <p className="text-white/30 text-sm py-8 text-center">Loading…</p>
            )}
            {error && (
              <p className="text-red-400 text-sm py-4">{error}</p>
            )}
            {!loading && filtered.length === 0 && !error && (
              <p className="text-white/30 text-sm py-8 text-center">
                No events for this user in the selected timeframe.
              </p>
            )}

            <div className="overflow-y-auto max-h-[60vh] pr-1">
              {filtered.map((ev, i) => (
                <TimelineItem key={i} ev={ev} />
              ))}
            </div>
          </div>
        </div>
      )}

      {!submittedUid && (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-12 text-center">
          <p className="text-white/30 text-sm">Enter a user UID above to view their activity timeline</p>
          <p className="text-white/20 text-xs mt-1">Combines login sessions, triggered alerts, and endpoint events</p>
        </div>
      )}
    </div>
  );
}
