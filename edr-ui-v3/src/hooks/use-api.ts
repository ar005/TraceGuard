"use client";

import { useCallback, useEffect, useRef, useState } from "react";

interface UseApiResult<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

export function useApi<T>(fetchFn: (signal: AbortSignal) => Promise<T>): UseApiResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const mountedRef = useRef(true);
  const inflightRef = useRef(false);
  // Keep a stable ref to the latest fetchFn so the effect doesn't re-run
  // every render when callers pass inline arrow functions.
  const fetchFnRef = useRef(fetchFn);
  fetchFnRef.current = fetchFn;

  const refetch = useCallback(() => {
    setTick((t) => t + 1);
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    const controller = new AbortController();

    if (inflightRef.current) return () => { mountedRef.current = false; controller.abort(); };
    inflightRef.current = true;

    setLoading(true);
    setError(null);

    fetchFnRef.current(controller.signal)
      .then((result) => {
        if (mountedRef.current) {
          setData(result);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (mountedRef.current && err?.name !== "AbortError") {
          setError(err instanceof Error ? err.message : String(err));
          setLoading(false);
        }
      })
      .finally(() => {
        inflightRef.current = false;
      });

    return () => {
      mountedRef.current = false;
      controller.abort();
    };
  }, [tick]); // fetchFn intentionally excluded — latest version is always in fetchFnRef

  return { data, loading, error, refetch };
}
