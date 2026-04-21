import { useCallback, useEffect, useRef, useState } from "react";

const TIMEOUT_MS = 5 * 60 * 1000;  // 5 minutes total
const WARN_BEFORE_MS = 60 * 1000;  // show warning 60s before logout

const ACTIVITY_EVENTS = [
  "mousemove", "mousedown", "keydown",
  "scroll", "touchstart", "click",
] as const;

export interface InactivityState {
  warningVisible: boolean;
  secondsLeft: number;
  dismiss: () => void;
}

export function useInactivityTimeout(onTimeout: () => void): InactivityState {
  const [warningVisible, setWarningVisible] = useState(false);
  const [secondsLeft, setSecondsLeft] = useState(60);

  const logoutTimer  = useRef<ReturnType<typeof setTimeout> | null>(null);
  const warnTimer    = useRef<ReturnType<typeof setTimeout> | null>(null);
  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const clearAll = useCallback(() => {
    if (logoutTimer.current)  clearTimeout(logoutTimer.current);
    if (warnTimer.current)    clearTimeout(warnTimer.current);
    if (countdownRef.current) clearInterval(countdownRef.current);
  }, []);

  const reset = useCallback(() => {
    clearAll();
    setWarningVisible(false);

    warnTimer.current = setTimeout(() => {
      setWarningVisible(true);
      setSecondsLeft(Math.round(WARN_BEFORE_MS / 1000));
      countdownRef.current = setInterval(() => {
        setSecondsLeft((s) => Math.max(0, s - 1));
      }, 1_000);
    }, TIMEOUT_MS - WARN_BEFORE_MS);

    logoutTimer.current = setTimeout(() => {
      clearAll();
      onTimeout();
    }, TIMEOUT_MS);
  }, [clearAll, onTimeout]);

  useEffect(() => {
    reset();
    const handler = () => reset();
    ACTIVITY_EVENTS.forEach((ev) =>
      window.addEventListener(ev, handler, { passive: true })
    );
    return () => {
      clearAll();
      ACTIVITY_EVENTS.forEach((ev) =>
        window.removeEventListener(ev, handler)
      );
    };
  }, [reset, clearAll]);

  return { warningVisible, secondsLeft, dismiss: reset };
}
