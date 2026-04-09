"use client";

import { Fragment, useCallback, useMemo, useState } from "react";
import { Usb, ChevronDown, ChevronRight, X } from "lucide-react";
import { api } from "@/lib/api-client";
import { useApi } from "@/hooks/use-api";
import { cn, formatDate, timeAgo } from "@/lib/utils";
import type { Agent, Event } from "@/types";

/* -- Constants ----------------------------------------------------------- */

const PAGE_SIZE = 100;

const DEVICE_TYPE_FILTERS = [
  { label: "All", value: "" },
  { label: "Mass Storage", value: "mass_storage" },
  { label: "HID", value: "hid" },
  { label: "Audio", value: "audio" },
  { label: "Other", value: "other" },
] as const;

const KNOWN_DEVICE_TYPES: Record<string, string[]> = {
  mass_storage: ["mass_storage", "storage", "disk", "usb_storage"],
  hid: ["hid", "keyboard", "mouse", "input"],
  audio: ["audio", "sound"],
};

function classifyDeviceType(devType: string): string {
  const lower = (devType ?? "").toLowerCase();
  for (const [category, keywords] of Object.entries(KNOWN_DEVICE_TYPES)) {
    if (keywords.some((kw) => lower.includes(kw))) return category;
  }
  return "other";
}

/* -- USB Payload --------------------------------------------------------- */

interface USBPayload {
  vendor?: string;
  product?: string;
  serial?: string;
  dev_type?: string;
  vendor_id?: string;
  product_id?: string;
  bus_num?: number;
  dev_num?: number;
  mount_point?: string;
}

/* -- Detail Row ---------------------------------------------------------- */

function USBDetail({ event }: { event: Event }) {
  const p = (event.payload ?? {}) as USBPayload;
  const fields = [
    { label: "Vendor", value: p.vendor },
    { label: "Product", value: p.product },
    { label: "Serial", value: p.serial },
    { label: "Device Type", value: p.dev_type },
    { label: "Vendor ID", value: p.vendor_id },
    { label: "Product ID", value: p.product_id },
    { label: "Bus Number", value: p.bus_num },
    { label: "Device Number", value: p.dev_num },
    { label: "Mount Point", value: p.mount_point },
    { label: "Event ID", value: event.id },
    { label: "Agent ID", value: event.agent_id },
    { label: "Hostname", value: event.hostname },
    { label: "Timestamp", value: formatDate(event.timestamp) },
  ];

  return (
    <tr>
      <td colSpan={7}>
        <div
          className="px-6 py-3 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3 text-xs animate-fade-in"
          style={{ background: "var(--surface-1)" }}
        >
          {fields.map((f) => (
            <div key={f.label}>
              <div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: "var(--muted)" }}>
                {f.label}
              </div>
              <div className="font-mono" style={{ color: "var(--fg)" }}>
                {f.value != null ? String(f.value) : "\u2014"}
              </div>
            </div>
          ))}
        </div>
      </td>
    </tr>
  );
}

/* -- Main Page ----------------------------------------------------------- */

export default function USBDevicesPage() {
  const [selectedAgent, setSelectedAgent] = useState<string>("");
  const [deviceTypeFilter, setDeviceTypeFilter] = useState<string>("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  /* Fetch agents */
  const fetchAgents = useCallback(
    () =>
      api
        .get<{ agents?: Agent[] } | Agent[]>("/api/v1/agents")
        .then((r) => (Array.isArray(r) ? r : r.agents ?? [])),
    []
  );
  const { data: agents } = useApi(fetchAgents);

  /* Fetch USB connect events */
  const fetchConnects = useCallback(
    () =>
      api
        .get<{ events?: Event[] } | Event[]>("/api/v1/events", {
          event_type: "USB_CONNECT",
          agent_id: selectedAgent || undefined,
          limit: PAGE_SIZE,
        })
        .then((r) => (Array.isArray(r) ? r : r.events ?? [])),
    [selectedAgent]
  );
  const { data: connectEvents, loading: loadingConnects } = useApi(fetchConnects);

  /* Fetch USB disconnect events */
  const fetchDisconnects = useCallback(
    () =>
      api
        .get<{ events?: Event[] } | Event[]>("/api/v1/events", {
          event_type: "USB_DISCONNECT",
          agent_id: selectedAgent || undefined,
          limit: PAGE_SIZE,
        })
        .then((r) => (Array.isArray(r) ? r : r.events ?? [])),
    [selectedAgent]
  );
  const { data: disconnectEvents, loading: loadingDisconnects } = useApi(fetchDisconnects);

  const loading = loadingConnects || loadingDisconnects;

  /* Merge and sort */
  const allEvents = useMemo(() => {
    const merged = [...(connectEvents ?? []), ...(disconnectEvents ?? [])];
    merged.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    return merged;
  }, [connectEvents, disconnectEvents]);

  /* Apply device type filter */
  const filteredEvents = useMemo(() => {
    if (!deviceTypeFilter) return allEvents;
    return allEvents.filter((ev) => {
      const p = (ev.payload ?? {}) as USBPayload;
      return classifyDeviceType(p.dev_type ?? "") === deviceTypeFilter;
    });
  }, [allEvents, deviceTypeFilter]);

  /* Stats */
  const stats = useMemo(() => {
    const total = filteredEvents.length;
    const serials = new Set(
      filteredEvents
        .map((e) => ((e.payload ?? {}) as USBPayload).serial)
        .filter(Boolean)
    );
    const massStorage = filteredEvents.filter((e) => {
      const p = (e.payload ?? {}) as USBPayload;
      return classifyDeviceType(p.dev_type ?? "") === "mass_storage" && e.event_type === "USB_CONNECT";
    }).length;
    return { total, uniqueDevices: serials.size, massStorageConnections: massStorage };
  }, [filteredEvents]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div>
        <h1 className="font-heading text-xl font-bold flex items-center gap-2">
          <Usb size={20} style={{ color: "var(--primary)" }} />
          USB Devices
        </h1>
        <p className="text-sm" style={{ color: "var(--muted)" }}>
          USB device connect and disconnect activity across monitored endpoints
        </p>
      </div>

      {/* Filters row */}
      <div
        className="flex flex-wrap items-center gap-3 p-3 rounded border"
        style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}
      >
        {/* Agent selector */}
        <div className="flex items-center gap-2">
          <label className="text-[10px] uppercase tracking-wider font-medium" style={{ color: "var(--muted)" }}>
            Agent
          </label>
          <select
            value={selectedAgent}
            onChange={(e) => setSelectedAgent(e.target.value)}
            className="rounded border px-2 py-1.5 text-xs font-mono"
            style={{ background: "var(--surface-1)", borderColor: "var(--border)", color: "var(--fg)" }}
          >
            <option value="">All agents</option>
            {(agents ?? []).map((a) => (
              <option key={a.id} value={a.id}>
                {a.hostname} {a.is_online ? "" : "(offline)"}
              </option>
            ))}
          </select>
        </div>

        {/* Device type filter */}
        <div className="flex items-center gap-1.5">
          <label className="text-[10px] uppercase tracking-wider font-medium" style={{ color: "var(--muted)" }}>
            Device Type
          </label>
          {DEVICE_TYPE_FILTERS.map((f) => (
            <button
              key={f.value}
              onClick={() => setDeviceTypeFilter(f.value)}
              className={cn(
                "rounded px-2 py-1 text-[10px] font-bold uppercase border transition-colors",
                deviceTypeFilter === f.value
                  ? "border-[var(--primary)] text-[var(--primary)] bg-[var(--primary)]/10"
                  : "border-transparent hover:bg-[var(--surface-2)]"
              )}
              style={{ color: deviceTypeFilter === f.value ? undefined : "var(--muted)" }}
            >
              {f.label}
            </button>
          ))}
        </div>

        {/* Clear all */}
        {(selectedAgent || deviceTypeFilter) && (
          <button
            onClick={() => {
              setSelectedAgent("");
              setDeviceTypeFilter("");
            }}
            className="flex items-center gap-1 rounded px-2 py-1 text-[10px] transition-colors hover:bg-[var(--surface-2)]"
            style={{ color: "var(--muted)" }}
          >
            <X size={10} /> Clear
          </button>
        )}
      </div>

      {/* Stats bar */}
      <div className="flex items-center gap-6 text-xs" style={{ color: "var(--muted)" }}>
        <span>
          <strong className="font-mono" style={{ color: "var(--fg)" }}>{stats.total}</strong> events
        </span>
        <span>
          <strong className="font-mono" style={{ color: "var(--fg)" }}>{stats.uniqueDevices}</strong> unique devices
        </span>
        <span className={stats.massStorageConnections > 0 ? "text-orange-400" : ""}>
          <strong className="font-mono">{stats.massStorageConnections}</strong> mass storage connections
        </span>
      </div>

      {/* Loading */}
      {loading && (
        <div className="space-y-2">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="animate-shimmer h-10 rounded" />
          ))}
        </div>
      )}

      {/* Events table */}
      {!loading && (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr
                className="text-left text-[10px] uppercase tracking-wider border-b"
                style={{ color: "var(--muted)", borderColor: "var(--border)" }}
              >
                <th className="pb-2 pr-3 w-6"></th>
                <th className="pb-2 pr-3 w-28">Time</th>
                <th className="pb-2 pr-3 w-24">Action</th>
                <th className="pb-2 pr-3">Vendor</th>
                <th className="pb-2 pr-3">Product</th>
                <th className="pb-2 pr-3 w-28">Serial</th>
                <th className="pb-2 pr-3 w-24">Device Type</th>
                <th className="pb-2 w-20">Agent</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.map((ev) => {
                const p = (ev.payload ?? {}) as USBPayload;
                const isConnect = ev.event_type === "USB_CONNECT";
                const isExpanded = expandedId === ev.id;

                return (
                  <Fragment key={ev.id}>
                    <tr
                      onClick={() => setExpandedId(isExpanded ? null : ev.id)}
                      className={cn(
                        "border-b cursor-pointer transition-colors",
                        isExpanded ? "bg-[var(--primary)]/5" : "hover:bg-[var(--surface-1)]"
                      )}
                      style={{ borderColor: "var(--border-subtle, var(--border))" }}
                    >
                      <td className="py-2 pr-1" style={{ color: "var(--muted)" }}>
                        {isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                      </td>
                      <td className="py-2 pr-3 font-mono whitespace-nowrap" style={{ color: "var(--muted)" }}>
                        {timeAgo(ev.timestamp)}
                      </td>
                      <td className="py-2 pr-3">
                        <span
                          className={cn(
                            "inline-flex rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                            isConnect
                              ? "bg-emerald-500/15 text-emerald-400"
                              : "bg-red-500/15 text-red-400"
                          )}
                        >
                          {isConnect ? "Connect" : "Disconnect"}
                        </span>
                      </td>
                      <td className="py-2 pr-3" style={{ color: "var(--fg)" }}>
                        {p.vendor ?? "\u2014"}
                      </td>
                      <td className="py-2 pr-3" style={{ color: "var(--fg)" }}>
                        {p.product ?? "\u2014"}
                      </td>
                      <td className="py-2 pr-3 font-mono truncate" style={{ color: "var(--muted)" }}>
                        {p.serial ?? "\u2014"}
                      </td>
                      <td className="py-2 pr-3" style={{ color: "var(--fg)" }}>
                        {p.dev_type ?? "\u2014"}
                      </td>
                      <td className="py-2 font-mono truncate" style={{ color: "var(--muted)" }}>
                        {ev.hostname}
                      </td>
                    </tr>
                    {isExpanded && <USBDetail event={ev} />}
                  </Fragment>
                );
              })}
            </tbody>
          </table>

          {filteredEvents.length === 0 && (
            <div className="py-16 text-center">
              <Usb size={32} className="mx-auto mb-3" style={{ color: "var(--muted)" }} />
              <p className="text-sm" style={{ color: "var(--muted)" }}>
                No USB device activity recorded
              </p>
              <p className="text-xs mt-1" style={{ color: "var(--muted)" }}>
                USB events will appear here when devices are connected or disconnected on monitored endpoints
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
