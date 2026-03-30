"use client";

import { useEffect, useRef, useState } from "react";
import { BASE } from "@/lib/api-client";
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
    const token = localStorage.getItem("edr_token");
    const separator = path.includes("?") ? "&" : "?";
    const url = `${BASE}${path}${token ? `${separator}token=${token}` : ""}`;

    const es = new EventSource(url);
    esRef.current = es;

    es.onopen = () => {
      setConnected(true);
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
      setConnected(false);
    };

    return () => {
      es.close();
      esRef.current = null;
      setConnected(false);
    };
  }, [path, maxEvents]);

  return { events, connected };
}
