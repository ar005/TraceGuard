import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** Merge Tailwind classes with clsx */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Format ISO date to locale string */
export function formatDate(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

/** Relative time (e.g. "3m ago", "2h ago") */
export function timeAgo(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  const seconds = Math.floor((Date.now() - d.getTime()) / 1000);
  if (seconds < 0) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  return `${months}mo ago`;
}

/** Map severity number to label */
export function severityLabel(n: number): string {
  switch (n) {
    case 4:
      return "Critical";
    case 3:
      return "High";
    case 2:
      return "Medium";
    case 1:
      return "Low";
    default:
      return "Info";
  }
}

/** Map severity number to CSS color variable value */
export function severityColor(n: number): string {
  switch (n) {
    case 4:
      return "var(--severity-critical)";
    case 3:
      return "var(--severity-high)";
    case 2:
      return "var(--severity-medium)";
    case 1:
      return "var(--severity-low)";
    default:
      return "var(--severity-info)";
  }
}

/** Map severity number to Tailwind-compatible background class */
export function severityBgClass(n: number): string {
  switch (n) {
    case 4:
      return "bg-red-600/15 text-red-400";
    case 3:
      return "bg-orange-500/15 text-orange-400";
    case 2:
      return "bg-amber-500/15 text-amber-400";
    case 1:
      return "bg-blue-500/15 text-blue-400";
    default:
      return "bg-neutral-500/15 text-neutral-400";
  }
}

/** Map alert status to Tailwind color class */
export function statusColor(status: string): string {
  switch (status?.toLowerCase()) {
    case "open":
      return "text-red-400";
    case "investigating":
    case "in_progress":
      return "text-amber-400";
    case "closed":
    case "resolved":
      return "text-emerald-400";
    case "suppressed":
      return "text-neutral-400";
    default:
      return "text-neutral-400";
  }
}

/** Map event type string to Tailwind color class */
export function eventTypeColor(type: string): string {
  switch (type?.toUpperCase()) {
    case "PROCESS_EXEC":
      return "text-emerald-400";
    case "PROCESS_EXIT":
      return "text-emerald-300";
    case "FILE_OPEN":
      return "text-sky-400";
    case "FILE_CREATE":
    case "FILE_DELETE":
    case "FILE_RENAME":
      return "text-sky-300";
    case "NET_CONNECT":
      return "text-violet-400";
    case "NET_ACCEPT":
      return "text-violet-300";
    case "DNS_QUERY":
      return "text-indigo-400";
    case "BROWSER_REQUEST":
      return "text-pink-400";
    case "KERNEL_MODULE_LOAD":
    case "KERNEL_MODULE_UNLOAD":
      return "text-red-400";
    case "USB_CONNECT":
    case "USB_DISCONNECT":
      return "text-orange-400";
    case "MEMORY_INJECT":
      return "text-red-500";
    case "CRON_MODIFY":
      return "text-yellow-400";
    case "PIPE_CREATE":
      return "text-cyan-400";
    case "NET_TLS_SNI":
      return "text-indigo-400";
    case "SHARE_MOUNT":
    case "SHARE_UNMOUNT":
      return "text-teal-400";
    case "USER_LOGIN":
    case "USER_LOGOUT":
      return "text-amber-400";
    default:
      return "text-neutral-400";
  }
}
