const BASE =
  typeof window !== "undefined"
    ? (process.env.NEXT_PUBLIC_BACKEND_URL ?? "http://localhost:8080")
    : "http://localhost:8080";

function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("edr_token");
}

function buildHeaders(): HeadersInit {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  const token = getToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

function buildUrl(path: string, params?: Record<string, string | number | boolean | undefined>): string {
  const url = new URL(path, BASE);
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    }
  }
  return url.toString();
}

async function request<T>(method: string, path: string, body?: unknown, params?: Record<string, string | number | boolean | undefined>): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30_000);

  try {
    const res = await fetch(buildUrl(path, params), {
      method,
      headers: buildHeaders(),
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    if (res.status === 401) {
      if (typeof window !== "undefined") {
        localStorage.removeItem("edr_token");
        localStorage.removeItem("edr_user");
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
  get<T>(path: string, params?: Record<string, string | number | boolean | undefined>): Promise<T> {
    return request<T>("GET", path, undefined, params);
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
