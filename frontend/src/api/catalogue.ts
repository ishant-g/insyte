import { apiFetch } from "@/lib/api-client";
import type {
  EffectiveSettings,
  HealthResponse,
  ModuleDescriptor,
  ProviderDescriptor,
  SecurityPolicy,
} from "./types";

export const catalogueApi = {
  modules: () => apiFetch<ModuleDescriptor[]>("/api/modules"),
  providers: () => apiFetch<ProviderDescriptor[]>("/api/providers"),
  securityPolicy: () => apiFetch<SecurityPolicy>("/api/security-policy"),
  settings: () => apiFetch<EffectiveSettings>("/api/settings"),
  health: () => apiFetch<HealthResponse>("/health"),
};
