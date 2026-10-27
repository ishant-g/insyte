import { apiFetch } from "@/lib/api-client";
import type { AuthUser, TokenResponse } from "./types";

export const authApi = {
  register: (email: string, password: string, display_name?: string) =>
    apiFetch<TokenResponse>("/api/auth/register", {
      method: "POST",
      body: { email, password, display_name: display_name || null },
    }),
  login: (email: string, password: string) =>
    apiFetch<TokenResponse>("/api/auth/login", {
      method: "POST",
      body: { email, password },
    }),
  me: () => apiFetch<AuthUser>("/api/auth/me"),
};
