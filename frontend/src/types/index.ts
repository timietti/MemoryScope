// frontend/src/types/index.ts
// Shared TypeScript types — mirrors backend Pydantic schemas

export type OSType = 'windows' | 'linux' | 'macos' | 'unknown';
export type CaseStatus =
  | 'pending' | 'queued' | 'detecting' | 'analyzing'
  | 'ai_analysis' | 'complete' | 'failed' | 'cancelled';
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
  error_message: string | null;
  created_at: string;
  queued_at: string | null;
  completed_at: string | null;
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
  parsed_output: Record<string, unknown> | unknown[] | null;
  raw_output: string | null;
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
}

// WebSocket event payloads
export type WSEvent =
  | { event: 'initial_state'; data: InitialStatePayload }
  | { event: 'status_change'; data: { status: CaseStatus } }
  | { event: 'os_detected'; data: { os: OSType; detail: string | null } }
  | { event: 'plugin_started'; data: { plugin: string } }
  | { event: 'plugin_complete'; data: { plugin: string; status: PluginStatus; rows: number; duration_ms: number } }
  | { event: 'enrichment_started'; data: Record<string, never> }
  | { event: 'enrichment_complete'; data: { ioc_count: number } }
  | { event: 'report_ready'; data: { verdict: Verdict; confidence: number } }
  | { event: 'error'; data: { message: string; stage: string } }
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

// ─────────────────────────────────────────────────────────────────────────────
// frontend/src/api/client.ts

import axios from 'axios';
import { queryClient } from './queryClient';

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '';

export const apiClient = axios.create({
  baseURL: `${BASE_URL}/api/v1`,
  timeout: 30_000,
});

// Attach JWT from localStorage
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Handle 401 → redirect to login
apiClient.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('access_token');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

// ── API helpers ───────────────────────────────────────────────────────────────

export const casesApi = {
  list: (params: { page?: number; page_size?: number; status?: string; search?: string }) =>
    apiClient.get('/cases', { params }).then(r => r.data),

  get: (id: string) =>
    apiClient.get(`/cases/${id}`).then(r => r.data),

  submit: (formData: FormData, onProgress?: (pct: number) => void) =>
    apiClient.post('/cases', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress: (e) => {
        if (onProgress && e.total) onProgress(Math.round((e.loaded / e.total) * 100));
      },
      timeout: 7_200_000,   // 2 hours for large uploads
    }).then(r => r.data),

  delete: (id: string) =>
    apiClient.delete(`/cases/${id}`),

  plugins: {
    list: (caseId: string, domain?: string) =>
      apiClient.get(`/cases/${caseId}/plugins`, { params: { domain } }).then(r => r.data),
    get: (caseId: string, pluginName: string) =>
      apiClient.get(`/cases/${caseId}/plugins/${encodeURIComponent(pluginName)}`).then(r => r.data),
  },

  report: {
    get: (caseId: string) =>
      apiClient.get(`/cases/${caseId}/report`).then(r => r.data),
    downloadPdf: (caseId: string) =>
      apiClient.get(`/cases/${caseId}/report/pdf`, { responseType: 'blob' }).then(r => r.data),
  },

  iocs: {
    list: (caseId: string, params?: { severity?: string; ioc_type?: string }) =>
      apiClient.get(`/cases/${caseId}/iocs`, { params }).then(r => r.data),
  },
};

export const authApi = {
  login: (email: string, password: string) =>
    apiClient.post('/auth/login', { email, password }).then(r => r.data),
  refresh: (refreshToken: string) =>
    apiClient.post('/auth/refresh', { refresh_token: refreshToken }).then(r => r.data),
  me: () =>
    apiClient.get('/auth/me').then(r => r.data),
};
