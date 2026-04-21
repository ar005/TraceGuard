import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api-client";
import type { Alert } from "@/types";

const POLL_MS = 30_000;

export interface Notification {
  id: string;
  type: "alert" | "agent_offline";
  title: string;
  subtitle: string;
  severity?: number;
  ts: string;
  read: boolean;
}

interface DashboardPayload {
  online_agents?: number;
  total_agents?: number;
  open_alerts?: number;
  critical_alerts?: number;
  recent_alerts?: Alert[];
}

export function useNotifications() {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [unread, setUnread] = useState(0);
  const prevOnline  = useRef<number | null>(null);
  const prevAlertIds = useRef<Set<string>>(new Set());
  const initialized = useRef(false);

  const poll = useCallback(async () => {
    try {
      const data = await api.get<DashboardPayload>("/api/v1/dashboard");
      const alerts  = data.recent_alerts ?? [];
      const online  = data.online_agents ?? 0;

      const next: Notification[] = [];

      if (initialized.current) {
        // Detect new alerts by ID
        for (const a of alerts) {
          if (!prevAlertIds.current.has(a.id)) {
            next.push({
              id: `alert-${a.id}`,
              type: "alert",
              title: a.rule_name ?? a.title ?? "New Alert",
              subtitle: a.hostname ?? a.agent_id ?? "",
              severity: a.severity,
              ts: a.first_seen,
              read: false,
            });
          }
        }

        // Detect agent count drop
        if (prevOnline.current !== null && online < prevOnline.current) {
          const dropped = prevOnline.current - online;
          next.push({
            id: `offline-${Date.now()}`,
            type: "agent_offline",
            title: `${dropped} agent${dropped > 1 ? "s" : ""} went offline`,
            subtitle: new Date().toLocaleTimeString(),
            ts: new Date().toISOString(),
            read: false,
          });
        }

        if (next.length > 0) {
          setNotifications((prev) => [...next, ...prev].slice(0, 50));
          setUnread((n) => n + next.length);
        }
      }

      // Update baseline
      prevAlertIds.current = new Set(alerts.map((a) => a.id));
      prevOnline.current   = online;
      initialized.current  = true;
    } catch {
      // ignore network errors
    }
  }, []);

  useEffect(() => {
    void poll();
    const id = setInterval(() => void poll(), POLL_MS);
    return () => clearInterval(id);
  }, [poll]);

  const markAllRead = useCallback(() => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
    setUnread(0);
  }, []);

  const clear = useCallback(() => {
    setNotifications([]);
    setUnread(0);
  }, []);

  return { notifications, unread, markAllRead, clear };
}
