"use client";

import { useEffect } from "react";

export default function AuthenticatedError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("Unhandled error:", error);
  }, [error]);

  return (
    <div
      className="flex flex-col items-center justify-center gap-4 min-h-[60vh] px-4"
      style={{ color: "var(--fg)" }}
    >
      <div
        className="rounded-lg border p-6 max-w-md w-full text-center"
        style={{
          background: "var(--surface-0)",
          borderColor: "var(--border)",
        }}
      >
        <h2 className="text-lg font-semibold mb-2">Something went wrong</h2>
        <p className="text-sm mb-4" style={{ color: "var(--muted)" }}>
          {error.message || "An unexpected error occurred."}
        </p>
        <button
          onClick={reset}
          className="px-4 py-2 rounded text-sm font-medium transition-colors"
          style={{
            background: "var(--primary)",
            color: "var(--primary-fg)",
          }}
        >
          Try again
        </button>
      </div>
    </div>
  );
}
