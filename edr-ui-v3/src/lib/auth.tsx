"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api } from "@/lib/api-client";
import type { User } from "@/types";

interface LoginResponse {
  token?: string;
  user?: User;
  expires_at?: string;
  mfa_required?: boolean;
  mfa_token?: string;
}

interface AuthState {
  user: User | null;
  token: string | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<LoginResponse>;
  verifyTOTP: (mfaToken: string, code: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Hydrate session on mount by calling /me with the httpOnly cookie.
  // The JWT is never stored client-side — the browser sends it
  // automatically via the httpOnly cookie set by the backend.
  useEffect(() => {
    let cancelled = false;
    async function hydrate() {
      try {
        const res = await api.get<{ user?: User } & Partial<User>>("/api/v1/me");
        if (!cancelled) {
          const u = res.user ?? (res as unknown as User);
          if (u && u.id) {
            setUser(u);
            setToken("cookie"); // sentinel — actual JWT is in httpOnly cookie
          }
        }
      } catch {
        // No valid session — stay logged out.
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    hydrate();
    return () => { cancelled = true; };
  }, []);

  const login = useCallback(async (username: string, password: string): Promise<LoginResponse> => {
    const res = await api.post<LoginResponse>(
      "/api/v1/auth/login",
      { username, password }
    );

    // If MFA is required, return the response without storing a token.
    if (res.mfa_required) {
      return res;
    }

    // Normal login — backend has set the httpOnly cookie.
    // Store user profile in memory only (not localStorage).
    if (res.user) {
      setToken("cookie");
      setUser(res.user);
    }
    return res;
  }, []);

  const verifyTOTP = useCallback(async (mfaToken: string, code: string) => {
    const res = await api.post<LoginResponse>(
      "/api/v1/auth/totp/verify-login",
      { mfa_token: mfaToken, code }
    );
    if (!res.user) {
      throw new Error("TOTP verification failed");
    }
    // Backend has set the httpOnly cookie.
    setToken("cookie");
    setUser(res.user);
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.post("/api/v1/auth/logout");
    } catch {
      // Best-effort — clear local state anyway.
    }
    setToken(null);
    setUser(null);
    window.location.href = "/login";
  }, []);

  const value = useMemo(
    () => ({ user, token, loading, login, verifyTOTP, logout }),
    [user, token, loading, login, verifyTOTP, logout]
  );

  return <AuthContext value={value}>{children}</AuthContext>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}
