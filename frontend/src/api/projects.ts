import { apiFetch } from "@/lib/api-client";
import type { ProjectRead, ScanListItem } from "./types";

export const projectsApi = {
  list: () => apiFetch<ProjectRead[]>("/api/projects"),
  get: (id: string) => apiFetch<ProjectRead>(`/api/projects/${id}`),
  create: (payload: { name: string; description?: string | null }) =>
    apiFetch<ProjectRead>("/api/projects", { method: "POST", body: payload }),
  update: (id: string, payload: { name?: string; description?: string | null }) =>
    apiFetch<ProjectRead>(`/api/projects/${id}`, { method: "PUT", body: payload }),
  delete: (id: string) => apiFetch<void>(`/api/projects/${id}`, { method: "DELETE" }),
  scans: (id: string) => apiFetch<ScanListItem[]>(`/api/projects/${id}/scans`),
};
