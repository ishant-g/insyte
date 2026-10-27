import { apiFetch } from "@/lib/api-client";
import type { CredentialsListResponse } from "./types";

export const credentialsApi = {
  list: () => apiFetch<CredentialsListResponse>("/api/credentials"),
  set: (providerId: string, fields: Record<string, string>) =>
    apiFetch<CredentialsListResponse>(`/api/credentials/${providerId}`, {
      method: "PUT",
      body: { fields },
    }),
  remove: (providerId: string) =>
    apiFetch<CredentialsListResponse>(`/api/credentials/${providerId}`, {
      method: "DELETE",
    }),
};
