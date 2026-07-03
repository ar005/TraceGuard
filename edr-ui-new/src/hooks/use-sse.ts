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
    let retryDelay = 2000; // ms, doubles on each failure up to 30 s
    let retryTimer: ReturnType<typeof setTimeout> | null = null;

    async function connect() {
      if (cancelled) return;

      // Close any existing connection before reconnecting.
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }

      // Exchange the session JWT for a short-lived SSE ticket (15s) so the
      // long-lived token never appears in a URL (logs, Referer, browser history).
      let ticket = "";
      try {
        const res = await api.post<{ ticket?: string }>("/api/v1/auth/sse-ticket", {});
        ticket = res.ticket ?? "";
      } catch {
        // Fallback: if the ticket endpoint isn't available, skip auth.
      }

      if (cancelled) return;

      const separator = path.includes("?") ? "&" : "?";
      const url = `${BASE}${path}${ticket ? `${separator}token=${ticket}` : ""}`;

      const es = new EventSource(url);
      esRef.current = es;

      es.onopen = () => {
        if (!cancelled) {
          setConnected(true);
          retryDelay = 2000; // reset backoff on successful connection
        }
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
        if (cancelled) return;
        setConnected(false);
        // Close the dead connection and schedule a reconnect with backoff.
        es.close();
        esRef.current = null;
        retryTimer = setTimeout(() => {
          retryDelay = Math.min(retryDelay * 2, 30000);
          connect();
        }, retryDelay);
      };
    }

    connect();

    return () => {
      cancelled = true;
      if (retryTimer !== null) clearTimeout(retryTimer);
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
      setConnected(false);
    };
  }, [path, maxEvents]);

  return { events, connected };
}
