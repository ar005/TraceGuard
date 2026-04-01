import type { Event } from "@/types";

/**
 * Export events to CSV and trigger browser download.
 */
export function exportToCSV(events: Event[], filename: string = "events.csv") {
  if (events.length === 0) return;

  const headers = ["id", "timestamp", "event_type", "hostname", "agent_id", "severity", "payload"];
  const rows = events.map((e) => [
    e.id,
    e.timestamp,
    e.event_type,
    e.hostname,
    e.agent_id,
    String(e.severity),
    JSON.stringify(e.payload).replace(/"/g, '""'),
  ]);

  const csv = [
    headers.join(","),
    ...rows.map((r) => r.map((cell) => `"${cell}"`).join(",")),
  ].join("\n");

  downloadBlob(csv, filename, "text/csv;charset=utf-8;");
}

/**
 * Export events to JSON and trigger browser download.
 */
export function exportToJSON(events: Event[], filename: string = "events.json") {
  if (events.length === 0) return;
  const json = JSON.stringify(events, null, 2);
  downloadBlob(json, filename, "application/json");
}

function downloadBlob(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
