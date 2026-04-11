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

  // Hydrate from localStorage on mount
  useEffect(() => {
    try {
      const savedToken = localStorage.getItem("edr_token");
      const savedUser = localStorage.getItem("edr_user");
      if (savedToken && savedUser) {
        setToken(savedToken);
        setUser(JSON.parse(savedUser));
      }
    } catch {
      // Corrupt storage — ignore
    } finally {
      setLoading(false);
    }
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

    // Normal login — store token and user.
    if (res.token && res.user) {
      localStorage.setItem("edr_token", res.token);
      localStorage.setItem("edr_user", JSON.stringify(res.user));
      setToken(res.token);
      setUser(res.user);
    }
    return res;
  }, []);

  const verifyTOTP = useCallback(async (mfaToken: string, code: string) => {
    const res = await api.post<LoginResponse>(
      "/api/v1/auth/totp/verify-login",
      { mfa_token: mfaToken, code }
    );
    if (!res.token || !res.user) {
      throw new Error("TOTP verification failed");
    }
    localStorage.setItem("edr_token", res.token);
    localStorage.setItem("edr_user", JSON.stringify(res.user));
    setToken(res.token);
    setUser(res.user);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem("edr_token");
    localStorage.removeItem("edr_user");
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
