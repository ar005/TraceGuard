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
  // Latest-ref pattern: always call the most recent fetchFn without adding it
  // to the effect dependency array (avoids infinite loops from inline lambdas).
  const fetchFnRef = useRef(fetchFn);
  fetchFnRef.current = fetchFn;

  const refetch = useCallback(() => {
    setTick((t) => t + 1);
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    const controller = new AbortController();

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
      });

    return () => {
      mountedRef.current = false;
      controller.abort();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick]); // fetchFn intentionally excluded — use fetchFnRef.current instead

  return { data, loading, error, refetch };
}
