"use client";

import { useCallback, useEffect, useRef, useState } from "react";

interface UseApiOptions {
  /**
   * Values that, when changed, automatically trigger a refetch — similar to
   * useEffect's dependency array. Use this when your fetch function depends on
   * state (e.g. a selected agent ID, search term, or date range).
   *
   * You do NOT need to wrap fetchFn in useCallback — the hook stores it in a
   * ref and always calls the latest version without adding it to the effect
   * dependency array. This means inline arrow functions are safe to pass.
   *
   * Example:
   *   useApi((s) => api.get("/events", { agent_id: selectedId }, s), {
   *     deps: [selectedId],
   *   });
   */
  deps?: readonly unknown[];

  /**
   * Auto-refresh interval in ms. Minimum enforced: 5 000 ms.
   * Omit to disable polling.
   */
  pollInterval?: number;
}

interface UseApiResult<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

const MIN_POLL_MS = 5_000;

export function useApi<T>(
  fetchFn: (signal: AbortSignal) => Promise<T>,
  options?: UseApiOptions
): UseApiResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  // Always hold the latest fetchFn without it being a dep.
  // This makes inline arrow functions (no useCallback) safe to pass — a new
  // function reference on every parent render will NOT trigger a refetch.
  const fetchFnRef = useRef(fetchFn);
  fetchFnRef.current = fetchFn;

  const refetch = useCallback(() => setTick((t) => t + 1), []);

  // Bump tick when explicit deps change (filter state, selected IDs, etc.).
  // Skip the mount run so we don't double-fetch: the [tick] effect below
  // already fires once on mount with tick=0; without this guard, the deps
  // effect would also fire on mount, bump tick to 1, and trigger a second
  // fetch that aborts the first.
  const skipFirstDepsRun = useRef(true);
  useEffect(() => {
    if (skipFirstDepsRun.current) {
      skipFirstDepsRun.current = false;
      return;
    }
    setTick((t) => t + 1);
  }, options?.deps ?? []);

  // Run the fetch on mount and whenever tick changes.
  useEffect(() => {
    let alive = true;
    const controller = new AbortController();

    setLoading(true);
    setError(null);

    fetchFnRef.current(controller.signal)
      .then((result) => {
        if (alive) {
          setData(result);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (alive && err?.name !== "AbortError") {
          setError(err instanceof Error ? err.message : String(err));
          setLoading(false);
        }
      });

    return () => {
      alive = false;
      controller.abort();
    };
    // fetchFn intentionally excluded — fetchFnRef always holds the latest
    // version. Adding fetchFn here would cause a refetch on every parent
    // re-render for any caller that passes an inline arrow function.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick]);

  // Optional polling with a hard minimum of 5 s.
  useEffect(() => {
    if (!options?.pollInterval) return;
    const interval = Math.max(options.pollInterval, MIN_POLL_MS);
    const id = setInterval(() => setTick((t) => t + 1), interval);
    return () => clearInterval(id);
  }, [options?.pollInterval]);

  return { data, loading, error, refetch };
}
