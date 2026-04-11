"use client";

import { useEffect, useRef, useState } from "react";
import { BASE, api } from "@/lib/api-client";
import type { Event } from "@/types";

interface UseSSEResult {
  events: Event[];
  connected: boolean;
}

export function useSSE(path: string, maxEvents = 200): UseSSEResult {
  const [events, setEvents] = useState<Event[]>([]);
  const [connected, setConnected] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function connect() {
      // Exchange the session JWT for a short-lived SSE ticket (30s) so the
      // long-lived token never appears in a URL (logs, Referer, browser history).
      let ticket = "";
      try {
        const res = await api.post<{ ticket?: string }>("/api/v1/auth/sse-ticket", {});
        ticket = res.ticket ?? "";
      } catch {
        // Fallback: if the ticket endpoint isn't available, skip auth.
        // The SSE handler will reject the connection if auth is required.
      }

      if (cancelled) return;

      const separator = path.includes("?") ? "&" : "?";
      const url = `${BASE}${path}${ticket ? `${separator}token=${ticket}` : ""}`;

      const es = new EventSource(url);
      esRef.current = es;

      es.onopen = () => {
        if (!cancelled) setConnected(true);
      };

      es.onmessage = (msg) => {
        try {
          const evt = JSON.parse(msg.data) as Event;
          setEvents((prev) => {
            const next = [evt, ...prev];
            return next.length > maxEvents ? next.slice(0, maxEvents) : next;
          });
        } catch {
          // Ignore non-JSON messages (e.g. heartbeat)
        }
      };

      es.onerror = () => {
        if (!cancelled) setConnected(false);
      };
    }

    connect();

    return () => {
      cancelled = true;
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
      setConnected(false);
    };
  }, [path, maxEvents]);

  return { events, connected };
}
