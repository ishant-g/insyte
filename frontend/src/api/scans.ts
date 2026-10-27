import { apiDownload, apiFetch } from "@/lib/api-client";
import type {
  ApiEndpointRead,
  AssetDetailRead,
  AssetRead,
  CertificateRead,
  CveRead,
  DnsRecordRead,
  ExposureSummary,
  FindingDetailRead,
  FindingRead,
  GraphRead,
  HistoricalEventRead,
  IndexedExposureRead,
  JavaScriptRead,
  Page,
  ScanCreatePayload,
  ScanDetailRead,
  ScanDiff,
  ScanListItem,
  ScanLogRead,
  ScanProgressRead,
  ScanRead,
  TechnologyRead,
  UrlRead,
} from "./types";

export const scansApi = {
  create: (payload: ScanCreatePayload) =>
    apiFetch<ScanRead>("/api/scans", { method: "POST", body: payload }),

  list: (params?: { limit?: number; offset?: number; status?: string; target?: string }) =>
    apiFetch<Page<ScanListItem>>("/api/scans", { params }),

  get: (scanId: string) => apiFetch<ScanDetailRead>(`/api/scans/${scanId}`),

  cancel: (scanId: string) => apiFetch<ScanRead>(`/api/scans/${scanId}/cancel`, { method: "POST" }),

  delete: (scanId: string) => apiFetch<void>(`/api/scans/${scanId}`, { method: "DELETE" }),

  progress: (scanId: string) => apiFetch<ScanProgressRead>(`/api/scans/${scanId}/progress`),

  logs: (scanId: string, params?: { limit?: number; offset?: number; since_sequence?: number }) =>
    apiFetch<Page<ScanLogRead>>(`/api/scans/${scanId}/logs`, { params }),

  assets: (
    scanId: string,
    params?: {
      asset_type?: string;
      in_scope?: boolean;
      min_confidence?: number;
      search?: string;
      limit?: number;
      offset?: number;
    },
  ) => apiFetch<Page<AssetRead>>(`/api/scans/${scanId}/assets`, { params }),

  asset: (scanId: string, assetId: string) =>
    apiFetch<AssetDetailRead>(`/api/scans/${scanId}/assets/${assetId}`),

  graph: (
    scanId: string,
    maxNodes?: number,
    opts?: { in_scope?: boolean; min_confidence?: number },
  ) =>
    apiFetch<GraphRead>(`/api/scans/${scanId}/graph`, {
      params: { max_nodes: maxNodes, in_scope: opts?.in_scope, min_confidence: opts?.min_confidence },
    }),

  findings: (
    scanId: string,
    params?: { severity?: string; category?: string; min_confidence?: number; limit?: number; offset?: number },
  ) => apiFetch<Page<FindingRead>>(`/api/scans/${scanId}/findings`, { params }),

  finding: (scanId: string, findingId: string) =>
    apiFetch<FindingDetailRead>(`/api/scans/${scanId}/findings/${findingId}`),

  exposure: (scanId: string) => apiFetch<ExposureSummary>(`/api/scans/${scanId}/exposure`),

  technologies: (scanId: string, params?: { category?: string; limit?: number; offset?: number }) =>
    apiFetch<Page<TechnologyRead>>(`/api/scans/${scanId}/technologies`, { params }),

  cves: (scanId: string, params?: { definitive_only?: boolean; limit?: number; offset?: number }) =>
    apiFetch<Page<CveRead>>(`/api/scans/${scanId}/cves`, { params }),

  urls: (
    scanId: string,
    params?: { classification?: string; in_scope?: boolean; retrieved?: boolean; limit?: number; offset?: number },
  ) => apiFetch<Page<UrlRead>>(`/api/scans/${scanId}/urls`, { params }),

  apis: (scanId: string, params?: { api_type?: string; limit?: number; offset?: number }) =>
    apiFetch<Page<ApiEndpointRead>>(`/api/scans/${scanId}/apis`, { params }),

  javascript: (scanId: string, params?: { has_secrets?: boolean; limit?: number; offset?: number }) =>
    apiFetch<Page<JavaScriptRead>>(`/api/scans/${scanId}/javascript`, { params }),

  historical: (scanId: string, params?: { year?: number; limit?: number; offset?: number }) =>
    apiFetch<Page<HistoricalEventRead>>(`/api/scans/${scanId}/historical`, { params }),

  indexedExposures: (scanId: string, params?: { limit?: number; offset?: number }) =>
    apiFetch<Page<IndexedExposureRead>>(`/api/scans/${scanId}/indexed-exposures`, { params }),

  certificates: (scanId: string) => apiFetch<CertificateRead[]>(`/api/scans/${scanId}/certificates`),

  dnsRecords: (scanId: string) => apiFetch<DnsRecordRead[]>(`/api/scans/${scanId}/dns-records`),

  changes: (scanId: string, compareTo: string) =>
    apiFetch<ScanDiff>(`/api/scans/${scanId}/changes`, { params: { compare_to: compareTo } }),

  downloadReport: (scanId: string, format: "pdf" | "md" | "json") =>
    apiDownload(`/api/scans/${scanId}/report/${format}`),
};
