/**
 * TypeScript types mirroring the Insyte API's Pydantic schemas exactly
 * (see backend/app/schemas/*.py). Kept hand-written and in lockstep with
 * the backend rather than generated, because the backend is the only
 * writer of this contract and a generation step would just be one more
 * thing that can silently drift.
 */

export type ScanMode = "passive" | "web_surface";
export type ScanStatus = "queued" | "running" | "partial" | "completed" | "failed" | "cancelled";
export type ModuleStatus = "queued" | "running" | "completed" | "failed" | "skipped";
export type TargetType = "domain" | "ipv4" | "ipv6";
export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type ConfidenceBand = "very_high" | "high" | "medium" | "low" | "very_low";
export type ExposureLevel = "direct" | "indexed" | "historical" | "inferred";
export type ExposureBand = "critical" | "high" | "medium" | "low" | "minimal";

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface ScanModuleRead {
  module_id: string;
  display_name: string;
  category: string;
  sequence: number;
  status: ModuleStatus;
  started_at: string | null;
  completed_at: string | null;
  duration: number | null;
  result_count: number;
  finding_count: number;
  skip_reason: string | null;
  error: string | null;
  /** The module's own structured summary (social profiles, robots.txt
   * structure, corporate candidates, dork hits, ...). */
  data: Record<string, unknown>;
}

export interface ScanRead {
  id: string;
  target_value: string;
  target_type: TargetType;
  mode: ScanMode;
  status: ScanStatus;
  progress: number;
  project_id: string | null;
  queued_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  duration: number | null;
  exposure_score: number | null;
  exposure_band: ExposureBand | null;
  summary: ScanSummary;
  provider_status: Record<string, ProviderStatus>;
  limits: Record<string, unknown>;
  error: string | null;
  created_at: string;
  warnings?: string[];
}

export interface ScanSummary {
  assets_total?: number;
  relationships_total?: number;
  asset_counts?: Record<string, number>;
  domains?: number;
  subdomains?: number;
  ips?: number;
  urls?: number;
  apis?: number;
  javascript_files?: number;
  certificates?: number;
  technologies?: number;
  findings_total?: number;
  findings_by_severity?: Record<string, number>;
  exposure_score?: number;
  exposure_band?: ExposureBand;
}

export interface ProviderStatus {
  provider: string;
  name: string;
  available: boolean;
  configured: boolean;
  requires_api_key: boolean;
  reason: string | null;
  calls: number;
  cache_hits: number;
  errors: string[];
  result_count: number;
  rate_limited: boolean;
  duration: number;
}

export interface ScanDetailRead extends ScanRead {
  modules: ScanModuleRead[];
}

export interface ScanListItem {
  id: string;
  target_value: string;
  target_type: TargetType;
  mode: ScanMode;
  status: ScanStatus;
  progress: number;
  exposure_score: number | null;
  exposure_band: ExposureBand | null;
  created_at: string;
  completed_at: string | null;
}

export interface ScanLogRead {
  sequence: number;
  timestamp: string;
  level: string;
  module_id: string | null;
  event: string;
  message: string;
  context: Record<string, unknown>;
}

export interface ScanProgressRead {
  status: ScanStatus;
  progress: number;
  modules: ScanModuleRead[];
  exposure_score: number | null;
  exposure_band: ExposureBand | null;
}

export interface ScanCreatePayload {
  target: string;
  mode: ScanMode;
  modules?: string[];
  project_id?: string | null;
}

export interface AssetRead {
  id: string;
  asset_type: string;
  value: string;
  label: string | null;
  status: string;
  confidence: number;
  sources: string[];
  source_count: number;
  observation_count: number;
  is_target: boolean;
  in_scope: boolean;
  attributes: Record<string, unknown>;
  first_seen: string | null;
  last_seen: string | null;
  created_at: string;
}

export interface RelationshipRead {
  id: string;
  source_asset_id: string;
  target_asset_id: string;
  relation: string;
  confidence: number;
  sources: string[];
}

export interface AssetDetailRead extends AssetRead {
  evidence: Record<string, unknown>;
  outgoing: RelationshipRead[];
  incoming: RelationshipRead[];
}

export interface GraphNode {
  id: string;
  asset_type: string;
  value: string;
  confidence: number;
  is_target: boolean;
  in_scope: boolean;
  sources: string[];
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
  confidence: number;
}

export interface GraphRead {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface FindingRead {
  id: string;
  asset_id: string | null;
  module_id: string;
  category: string;
  severity: Severity;
  risk_score: number;
  priority: string | null;
  confidence: number;
  confidence_band: ConfidenceBand;
  exposure: ExposureLevel;
  title: string;
  description: string | null;
  recommendation: string | null;
  location: string | null;
  sources: string[];
  reference_links: string[];
  cve_ids: string[];
  status: string;
  created_at: string;
}

export interface FindingDetailRead extends FindingRead {
  evidence: Record<string, unknown>;
}

export interface TechnologyRead {
  id: string;
  name: string;
  version: string | null;
  version_confidence: number;
  category: string | null;
  vendor: string | null;
  host: string | null;
  confidence: number;
  sources: string[];
}

export interface CveRead {
  id: string;
  cve_id: string;
  technology_name: string;
  detected_version: string | null;
  cvss_score: number | null;
  cvss_severity: string | null;
  cvss_vector: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
  known_exploited: boolean;
  match_confidence: number;
  definitive: boolean;
  description: string | null;
  reference_links: string[];
}

export interface ExposureSummary {
  score: number;
  band: ExposureBand;
  severity_counts: Record<string, number>;
  finding_count: number;
}

export interface UrlRead {
  id: string;
  url: string;
  normalized_url: string;
  host: string;
  classification: string;
  extension: string | null;
  status_code: number | null;
  content_type: string | null;
  retrieved: boolean;
  in_scope: boolean;
  confidence: number;
  sources: string[];
}

export interface ApiEndpointRead {
  id: string;
  url: string;
  host: string;
  path: string;
  method: string | null;
  api_type: string;
  api_version: string | null;
  auth_hint: string | null;
  source_artifact: string | null;
  validated: boolean;
  confidence: number;
  sources: string[];
}

export interface JavaScriptRead {
  id: string;
  url: string;
  content_sha256: string | null;
  size: number | null;
  is_third_party: boolean;
  libraries: { name: string; version: string | null }[];
  endpoints: string[];
  domains: string[];
  integrations: { name: string; category: string }[];
  secret_indicators: SecretIndicator[];
  has_source_map: boolean;
  source_map_url: string | null;
}

export interface SecretIndicator {
  type: string;
  severity: string;
  confidence: number;
  masked: string;
}

export interface HistoricalEventRead {
  id: string;
  asset_type: string;
  value: string;
  source_id: string;
  status: string;
  observed_at: string | null;
  first_seen: string | null;
  last_seen: string | null;
  year: number | null;
}

export interface IndexedExposureRead {
  id: string;
  exposure_type: string;
  url: string;
  host: string | null;
  observation_class: string;
  retrievable: boolean;
  severity: Severity;
  confidence: number;
}

export interface CertificateRead {
  id: string;
  fingerprint_sha256: string;
  subject_cn: string | null;
  issuer_cn: string | null;
  issuer_org: string | null;
  sans: string[];
  not_before: string | null;
  not_after: string | null;
  is_expired: boolean;
  days_until_expiry: number | null;
  signature_algorithm: string | null;
  public_key_algorithm: string | null;
  tls_version: string | null;
}

export interface DnsRecordRead {
  id: string;
  name: string;
  record_type: string;
  value: string;
  ttl: number | null;
  parsed: Record<string, unknown>;
}

export interface ChangeEntry {
  asset_type: string;
  value: string;
  detail: Record<string, unknown> | null;
}

export interface ScanDiff {
  scan_a: string;
  scan_b: string;
  added: ChangeEntry[];
  removed: ChangeEntry[];
  changed: ChangeEntry[];
  summary: { added: number; removed: number; changed: number };
}

export interface ModuleDescriptor {
  id: string;
  name: string;
  description: string;
  category: string;
  category_label: string;
  version: string;
  mode_support: ScanMode[];
  input_types: TargetType[];
  dependencies: string[];
  providers: string[];
  requires_api_key: boolean;
  timeout: number;
  recommended: boolean;
}

export interface ProviderDescriptor {
  id: string;
  name: string;
  kind: string;
  description: string;
  homepage: string;
  requires_api_key: boolean;
  configured: boolean;
  reliability: number;
  intents: string[];
}

export interface ProjectRead {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
  updated_at: string;
}

export interface SecurityPolicy {
  allowed_schemes: string[];
  allowed_ports: number[];
  allowed_methods: string[];
  blocked_ipv4_ranges: string[];
  blocked_ipv6_ranges: string[];
  blocked_hostnames: string[];
  blocked_suffixes: string[];
  dns_rebinding_protection: string;
  redirects_revalidated: boolean;
  max_redirects: number;
  max_response_bytes: number;
  private_targets_allowed: boolean;
}

export interface EffectiveSettings {
  app_name: string;
  app_version: string;
  tagline: string;
  environment: string;
  http_total_timeout: number;
  http_max_redirects: number;
  http_max_response_bytes: number;
  http_max_concurrency: number;
  max_urls_per_scan: number;
  max_js_files_per_scan: number;
  max_pages_per_scan: number;
  max_subdomains_per_scan: number;
  scan_time_limit: number;
  cache_enabled: boolean;
  report_retention_days: number;
  providers: { id: string; name: string; requires_api_key: boolean; configured: boolean }[];
}

export interface HealthResponse {
  status: string;
  app: string;
  version: string;
  database: boolean;
  redis: boolean;
  worker_alive: boolean;
  worker_count: number;
}

// ---- Accounts & credentials ---------------------------------------------

export interface AuthUser {
  id: string;
  email: string;
  display_name: string | null;
  is_admin: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: AuthUser;
}

export interface CredentialField {
  key: string;
  label: string;
  secret: boolean;
  configured: boolean;
  hint: string;
  from_environment: boolean;
}

export interface ProviderCredential {
  provider_id: string;
  name: string;
  optional: boolean;
  signup_url: string;
  free_tier: string;
  requires_api_key: boolean;
  configured: boolean;
  user_configured: boolean;
  fields: CredentialField[];
}

export interface CredentialsListResponse {
  providers: ProviderCredential[];
}
