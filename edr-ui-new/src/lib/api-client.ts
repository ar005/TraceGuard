// Deployment modes:
//   Proxy mode (recommended): leave NEXT_PUBLIC_BACKEND_URL unset.
//     All /api/* requests go through the Next.js rewrites proxy (next.config.ts).
//     httpOnly cookies and CSP connect-src work correctly.
//   Direct mode: set NEXT_PUBLIC_BACKEND_URL=https://your-backend-host.
//     Requests bypass the proxy and go directly to the backend (cross-origin).
//     Requires CORS configured on the backend and breaks httpOnly cookie delivery
//     in some browsers. Only use when the Next.js proxy is not viable.
export const BASE = process.env.NEXT_PUBLIC_BACKEND_URL ?? "";
// NEXT_PUBLIC_ENVIRONMENT is the operator-controlled signal in .env / .env.local:
//   NEXT_PUBLIC_ENVIRONMENT=prod  → real production deploy; warn if BASE missing
//   anything else / unset         → dev / staging; warn is silenced
// We don't key off NODE_ENV because `npm run build && npm start` always sets
// NODE_ENV=production, even on a developer's laptop — that signal can't tell
// "real prod" from "I just like running the optimized build locally."
const IS_PROD = process.env.NEXT_PUBLIC_ENVIRONMENT === "prod";
if (!BASE && IS_PROD && typeof window !== "undefined") {
  console.error(
    "[TraceGuard] NEXT_PUBLIC_BACKEND_URL is not set. " +
    "API calls will fail unless Next.js rewrites are configured. " +
    "Set it in .env.local or your deployment config."
  );
}

function buildHeaders(): HeadersInit {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  return headers;
}

function buildUrl(path: string, params?: Record<string, string | number | boolean | undefined>): string {
  const qs = new URLSearchParams();
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && value !== "") {
        qs.set(key, String(value));
      }
    }
  }
  const query = qs.toString();
  return BASE + path + (query ? `?${query}` : "");
}

// Module-level flag so a burst of concurrent 401s (parallel useApi calls during
// a session-expired render) only triggers one redirect. Without this, every
// inflight fetch would race to set window.location, polluting history and
// occasionally fighting AuthGuard's router.replace.
let redirecting = false;

async function request<T>(method: string, path: string, body?: unknown, params?: Record<string, string | number | boolean | undefined>, signal?: AbortSignal): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 90_000);
  const combinedSignal = signal
    ? AbortSignal.any([controller.signal, signal])
    : controller.signal;

  try {
    const res = await fetch(buildUrl(path, params), {
      method,
      headers: buildHeaders(),
      body: body ? JSON.stringify(body) : undefined,
      signal: combinedSignal,
      credentials: "include", // send httpOnly cookie
    });

    if (res.status === 401) {
      // /api/v1/me is the auth probe used by AuthProvider on mount. A 401 here
      // is expected when the user isn't logged in — AuthProvider catches it
      // and AuthGuard handles the redirect via router.replace. If we also
      // hard-navigated here we'd race AuthGuard and double-trigger navigation.
      const isAuthProbe = path === "/api/v1/me";
      if (!isAuthProbe && !redirecting && typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
        redirecting = true;
        // replace() instead of href= so the failed page isn't on the back stack.
        window.location.replace("/login");
      }
      throw new Error("Unauthorized");
    }

    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      throw new Error(`API ${method} ${path} failed (${res.status}): ${text}`);
    }

    // Handle 204 No Content
    if (res.status === 204) {
      return undefined as T;
    }

    return (await res.json()) as T;
  } finally {
    clearTimeout(timeout);
  }
}

export const api = {
  get<T>(path: string, params?: Record<string, string | number | boolean | undefined>, signal?: AbortSignal): Promise<T> {
    return request<T>("GET", path, undefined, params, signal);
  },
  post<T>(path: string, body?: unknown): Promise<T> {
    return request<T>("POST", path, body);
  },
  patch<T>(path: string, body?: unknown): Promise<T> {
    return request<T>("PATCH", path, body);
  },
  put<T>(path: string, body?: unknown): Promise<T> {
    return request<T>("PUT", path, body);
  },
  del<T>(path: string): Promise<T> {
    return request<T>("DELETE", path);
  },
};

