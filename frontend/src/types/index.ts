// frontend/src/types/index.ts
// Shared TypeScript types — mirrors backend Pydantic schemas

export type OSType = 'windows' | 'linux' | 'macos' | 'unknown';
export type CaseStatus =
  | 'pending' | 'queued' | 'detecting' | 'building_symbols' | 'triage_complete' | 'analyzing'
  | 'enriching' | 'ai_analysis' | 'complete' | 'failed' | 'cancelled';
export type PluginStatus = 'pending' | 'running' | 'complete' | 'failed' | 'skipped' | 'timeout';
export type Verdict = 'clean' | 'suspicious' | 'compromised' | 'inconclusive';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type IOCType =
  | 'ip' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256'
  | 'file_path' | 'registry_key' | 'mutex' | 'process_name' | 'email';

export interface Case {
  id: string;
  short_id: string;
  name: string;
  description: string | null;
  priority: number;
  original_filename: string;
  file_size_bytes: number;
  sha256: string;
  detected_os: OSType;
  detected_os_detail: string | null;
  status: CaseStatus;
  verdict: Verdict | null;
  error_message: string | null;
  created_at: string;
  queued_at: string | null;
  vt_enriched_at: string | null;
  completed_at: string | null;
  dump_purged_at: string | null;
  submitted_by: string;
}

export interface CaseListResponse {
  items: Case[];
  total: number;
  page: number;
  page_size: number;
}

export interface PluginRun {
  id: string;
  case_id: string;
  plugin_name: string;
  plugin_domain: string;
  status: PluginStatus;
  exit_code: number | null;
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  row_count: number | null;
  // Output fields are only present when fetched via the single-plugin detail
  // endpoint — they are omitted from the plugin list response.
  parsed_output?: Record<string, unknown> | unknown[] | null;
  raw_output?: string | null;
  error_message: string | null;
  ai_flagged: boolean;
  ai_summary: string | null;
}

export interface MitreTTP {
  tactic: string;
  tactic_name: string;
  technique: string;
  technique_name: string;
  evidence: string;
  severity: Severity;
}

export interface IOCEntry {
  id: string;
  ioc_type: IOCType;
  value: string;
  severity: Severity;
  description: string;
  source_plugin: string | null;
  source_pid: number | null;
  vt_positives: number | null;
  vt_total: number | null;
  vt_permalink: string | null;
  threat_names: string[];
}

export interface TimelineEvent {
  timestamp_estimate: string;
  event: string;
  evidence_plugin: string;
}

export interface Recommendation {
  priority: number;
  action: string;
  rationale: string;
}

export interface Report {
  id: string;
  case_id: string;
  verdict: Verdict;
  confidence: number;
  verdict_reasoning: string;
  executive_summary: string;
  technical_narrative: string;
  mitre_ttps: MitreTTP[];
  timeline: TimelineEvent[];
  recommendations: Recommendation[];
  model_used: string;
  agent_version: string;
  token_usage: Record<string, { input_tokens: number; output_tokens: number }> | null;
  generated_at: string;
  superseded_at: string | null;
}

export interface KBArticle {
  id: string;
  title: string;
  content: string;
  tags: string[];
  created_by: string;
  created_at: string;
  updated_at: string;
}

export type UserRole = 'analyst' | 'admin' | 'viewer';

export interface AdminUser {
  id: string;
  email: string;
  display_name: string;
  role: UserRole;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface SystemHealth {
  api: string;
  database: string;
  worker_count: number;
  platform: string;
  python_version: string;
  total_cases: number;
  total_reports: number;
  disk_total_bytes: number;
  disk_used_bytes: number;
  disk_free_bytes: number;
  disk_device: string;
  disk_type: 'lvm' | 'zfs' | 'btrfs' | 'mdraid' | 'raw' | 'unknown';
}

export interface StorageInfo {
  dumps_bytes: number;
  dumps_objects: number;
  reports_bytes: number;
  reports_objects: number;
}

export interface AdminSettings {
  // App
  env: string;
  api_prefix: string;
  secret_key: string;
  // Database
  database_url: string;
  // Redis
  redis_url: string;
  // Storage
  s3_endpoint: string;
  s3_bucket_dumps: string;
  s3_bucket_reports: string;
  s3_access_key: string;
  s3_secret_key: string;
  // Volatility
  volatility_path: string;
  symbol_cache_path: string;
  dwarf2json_path: string;
  worker_tmp_dir: string;
  plugin_timeout_seconds: number;
  max_dump_size_bytes: number;
  max_cases_per_hour_per_user: number;
  // AI
  primary_model: string;
  fast_model: string;
  ai_max_context_tokens: number;
  summarise_threshold_chars: number;
  anthropic_api_key: string;
  fallback_api_url: string;
  fallback_api_key: string;
  fallback_model: string;
  // Enrichment
  vt_rate_limit_per_min: number;
  virustotal_api_key: string;
  // Auth
  jwt_algorithm: string;
  jwt_access_expire_minutes: number;
  jwt_refresh_expire_days: number;
  // Celery
  celery_concurrency: number;
  strings_max_workers: number;
  // Retention
  dump_retention_days: number;
  report_retention_days: number;
  // Watch Folder
  watch_dir_enabled: boolean;
  watch_dir: string;
  watch_dir_poll_interval: number;
  watch_dir_stable_age: number;
  // OIDC / SSO
  oidc_client_id: string;
  oidc_client_secret: string;
  oidc_discovery_url: string;
  oidc_redirect_uri: string;
  oidc_frontend_callback_url: string;
  oidc_provider_name: string;
  oidc_role_claim: string;
  oidc_admin_group: string;
  oidc_viewer_group: string;
  oidc_jit_provisioning: boolean;
  // LDAP / LDAPS
  ldap_enabled: boolean;
  ldap_url: string;
  ldap_use_starttls: boolean;
  ldap_tls_verify: boolean;
  ldap_bind_dn: string;
  ldap_bind_password: string;
  ldap_base_dn: string;
  ldap_user_filter: string;
  ldap_attr_email: string;
  ldap_attr_display_name: string;
  ldap_group_base_dn: string;
  ldap_admin_group: string;
  ldap_analyst_group: string;
  ldap_viewer_group: string;
  ldap_jit_provisioning: boolean;
}

// WebSocket event payloads
export type WSEvent =
  | { event: 'initial_state'; data: InitialStatePayload }
  | { event: 'status_change'; data: { status: CaseStatus } }
  | { event: 'triage_complete'; data: { os: OSType; detail: string | null } }
  | { event: 'os_detected'; data: { os: OSType; detail: string | null } }
  | { event: 'plugin_started'; data: { plugin: string } }
  | { event: 'plugin_complete'; data: { plugin: string; status: PluginStatus; rows: number; duration_ms: number } }
  | { event: 'enrichment_started'; data: Record<string, never> }
  | { event: 'enrichment_complete'; data: { ioc_count: number } }
  | { event: 'report_ready'; data: { verdict: Verdict; confidence: number } }
  | { event: 'error'; data: { message: string; stage: string } }
  | { event: 'strings_started'; data: Record<string, never> }
  | { event: 'strings_complete'; data: { line_count: number; compressed_size: number } }
  | { event: 'strings_failed'; data: { error: string } }
  | { event: 'ping'; data: Record<string, never> };

export interface InitialStatePayload {
  status: CaseStatus;
  detected_os: OSType;
  plugins: Array<{
    name: string;
    domain: string;
    status: PluginStatus;
    row_count: number | null;
    ai_flagged: boolean;
  }>;
}

