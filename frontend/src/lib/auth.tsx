/**
 * Client-side authentication state.
 *
 * The bearer token lives in localStorage (see `lib/api-client.ts`), so it
 * survives reloads; this provider mirrors it into React state, hydrates the
 * current user from `/auth/me` on mount, and registers a global 401 handler
 * that logs the user out. Per-account provider keys are stored server-side
 * against the account, so they simply reappear on the next login and are no
 * longer visible once the token is cleared on logout.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { useQueryClient } from "@tanstack/react-query";

import { authApi } from "@/api/auth";
import type { AuthUser } from "@/api/types";
import {
  getAuthToken,
  setAuthToken,
  setUnauthorizedHandler,
} from "@/lib/api-client";

interface AuthContextValue {
  user: AuthUser | null;
  status: "loading" | "authenticated" | "anonymous";
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, displayName?: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [user, setUser] = useState<AuthUser | null>(null);
  const [status, setStatus] = useState<AuthContextValue["status"]>("loading");

  const logout = useCallback(() => {
    setAuthToken(null);
    setUser(null);
    setStatus("anonymous");
    // Drop every cached query so one account's data can't flash for the next.
    queryClient.clear();
  }, [queryClient]);

  // Hydrate from a persisted token on first client render.
  useEffect(() => {
    let cancelled = false;
    const token = getAuthToken();
    if (!token) {
      setStatus("anonymous");
      return;
    }
    authApi
      .me()
      .then((me) => {
        if (cancelled) return;
        setUser(me);
        setStatus("authenticated");
      })
      .catch(() => {
        if (cancelled) return;
        setAuthToken(null);
        setStatus("anonymous");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // A 401 from anywhere clears the session.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setAuthToken(null);
      setUser(null);
      setStatus("anonymous");
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  const login = useCallback(
    async (email: string, password: string) => {
      const res = await authApi.login(email, password);
      setAuthToken(res.access_token);
      setUser(res.user);
      setStatus("authenticated");
    },
    [],
  );

  const register = useCallback(
    async (email: string, password: string, displayName?: string) => {
      const res = await authApi.register(email, password, displayName);
      setAuthToken(res.access_token);
      setUser(res.user);
      setStatus("authenticated");
    },
    [],
  );

  const value = useMemo<AuthContextValue>(
    () => ({ user, status, login, register, logout }),
    [user, status, login, register, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}
