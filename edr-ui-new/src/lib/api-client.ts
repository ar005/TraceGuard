const BASE = process.env.NEXT_PUBLIC_BACKEND_URL ?? "";
if (!BASE && typeof window !== "undefined") {
  console.error(
    "[TraceGuard] NEXT_PUBLIC_BACKEND_URL is not set. " +
    "API calls will fail. Set it in .env.local or your deployment config."
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
      if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
        window.location.href = "/login";
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

export { BASE };
