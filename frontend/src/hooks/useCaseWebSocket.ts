// frontend/src/hooks/useCaseWebSocket.ts
/**
 * WebSocket hook that subscribes to real-time events for a single case.
 * - Auto-reconnects on disconnect (exponential backoff)
 * - Invalidates React Query cache on relevant events
 * - Returns current plugin progress map
 */
import { useEffect, useRef, useCallback, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { WSEvent, PluginStatus, CaseStatus } from '../types';

interface PluginProgress {
  status: PluginStatus;
  rows: number | null;
  ai_flagged: boolean;
  duration_ms: number | null;
}

interface CaseProgress {
  status: CaseStatus | null;
  plugins: Record<string, PluginProgress>;
  lastEvent: WSEvent | null;
  connected: boolean;
}

const MAX_RECONNECT_DELAY_MS = 30_000;

// Terminal states — WS does not reconnect after reaching these
const TERMINAL_STATUSES = new Set(['complete', 'failed', 'cancelled']);

export function useCaseWebSocket(caseId: string | undefined): CaseProgress & { reconnect: () => void } {
  const qc = useQueryClient();
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>();
  const reconnectDelay = useRef(1_000);
  // Ref tracks latest status so onclose never reads stale closure state
  const statusRef = useRef<CaseStatus | null>(null);

  const [progress, setProgress] = useState<CaseProgress>({
    status: null,
    plugins: {},
    lastEvent: null,
    connected: false,
  });

  const connect = useCallback(() => {
    if (!caseId) return;
    // Don't open a second connection if one is already live
    if (wsRef.current && wsRef.current.readyState <= WebSocket.OPEN) return;

    const token = localStorage.getItem('access_token');
    if (!token) return;

    const wsBase = window.location.origin
      .replace(/^https/, 'wss')
      .replace(/^http/, 'ws');
    const url = `${wsBase}/ws/cases/${caseId}?token=${encodeURIComponent(token)}`;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      reconnectDelay.current = 1_000;
      setProgress((p: CaseProgress) => ({ ...p, connected: true }));
    };

    ws.onmessage = (ev) => {
      let event: WSEvent;
      try {
        event = JSON.parse(ev.data);
      } catch {
        return;
      }

      setProgress((p: CaseProgress) => {
        const next = { ...p, lastEvent: event };

        switch (event.event) {
          case 'initial_state': {
            const pluginMap: Record<string, PluginProgress> = {};
            for (const pl of event.data.plugins) {
              pluginMap[pl.name] = {
                status: pl.status,
                rows: pl.row_count,
                ai_flagged: pl.ai_flagged,
                duration_ms: null,
              };
            }
            next.status = event.data.status;
            next.plugins = pluginMap;
            statusRef.current = event.data.status;
            break;
          }
          case 'status_change':
            next.status = event.data.status;
            statusRef.current = event.data.status;
            // Always invalidate on status change so REST data stays fresh
            qc.invalidateQueries({ queryKey: ['case', caseId] });
            qc.invalidateQueries({ queryKey: ['cases'] });
            if (['complete', 'failed', 'triage_complete'].includes(event.data.status)) {
              qc.invalidateQueries({ queryKey: ['report', caseId] });
              qc.invalidateQueries({ queryKey: ['plugins', caseId] });
            }
            break;

          case 'plugin_started':
            next.plugins = {
              ...p.plugins,
              [event.data.plugin]: {
                ...(p.plugins[event.data.plugin] ?? {}),
                status: 'running',
                rows: null,
                ai_flagged: false,
                duration_ms: null,
              },
            };
            break;

          case 'plugin_complete':
            next.plugins = {
              ...p.plugins,
              [event.data.plugin]: {
                status: event.data.status,
                rows: event.data.rows,
                ai_flagged: false,
                duration_ms: event.data.duration_ms,
              },
            };
            qc.invalidateQueries({ queryKey: ['plugins', caseId] });
            break;

          case 'enrichment_complete':
            qc.invalidateQueries({ queryKey: ['iocs', caseId] });
            qc.invalidateQueries({ queryKey: ['case', caseId] });
            break;

          case 'report_ready':
            qc.invalidateQueries({ queryKey: ['report', caseId] });
            qc.invalidateQueries({ queryKey: ['iocs', caseId] });
            break;

          case 'strings_started':
          case 'strings_complete':
          case 'strings_failed':
            qc.invalidateQueries({ queryKey: ['strings', caseId] });
            break;

          case 'ping':
            // keepalive — no state change
            break;
        }

        return next;
      });
    };

    ws.onclose = () => {
      wsRef.current = null;
      setProgress((p: CaseProgress) => ({ ...p, connected: false }));

      // Only skip reconnect for truly terminal states; triage_complete is not
      // terminal since the analyst can reanalyze at any time.
      if (TERMINAL_STATUSES.has(statusRef.current ?? '')) return;

      reconnectTimer.current = setTimeout(() => {
        reconnectDelay.current = Math.min(reconnectDelay.current * 2, MAX_RECONNECT_DELAY_MS);
        connect();
      }, reconnectDelay.current);
    };

    ws.onerror = () => ws.close();
  }, [caseId, qc]);

  // Force-reconnect: close existing WS (triggers reconnect via onclose) or open fresh
  const reconnect = useCallback(() => {
    clearTimeout(reconnectTimer.current);
    statusRef.current = null;  // clear terminal status so onclose allows reconnect
    reconnectDelay.current = 1_000;
    if (wsRef.current) {
      wsRef.current.close();
    } else {
      connect();
    }
  }, [connect]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { ...progress, reconnect };
}

// ─────────────────────────────────────────────────────────────────────────────
// frontend/src/hooks/useCase.ts
// React Query hooks for case data fetching

import { useQuery, useMutation } from '@tanstack/react-query';
import { casesApi } from '../api/client';
import type { Case, PluginRun, Report, CaseListResponse, IOCEntry } from '../types';

export const caseKeys = {
  all: ['cases'] as const,
  list: (params: object) => [...caseKeys.all, 'list', params] as const,
  detail: (id: string) => ['case', id] as const,
  plugins: (id: string) => ['plugins', id] as const,
  plugin: (id: string, name: string) => ['plugin', id, name] as const,
  report: (id: string) => ['report', id] as const,
  iocs: (id: string) => ['iocs', id] as const,
};

export function useCases(params: { page?: number; status?: string; search?: string } = {}) {
  return useQuery<CaseListResponse>({
    queryKey: caseKeys.list(params),
    queryFn: () => casesApi.list(params),
    staleTime: 30_000,
    // Poll every 5s when any case is actively processing — covers pages without an open WS
    refetchInterval: (query: { state: { data?: CaseListResponse } }) => {
      const items = query.state.data?.items ?? [];
      return items.some(c => ACTIVE_STATUSES.has(c.status)) ? 5_000 : false;
    },
  });
}

const ACTIVE_STATUSES = new Set(['queued', 'detecting', 'building_symbols', 'analyzing', 'ai_analysis']);

export function useCase(id: string | undefined) {
  return useQuery<Case>({
    queryKey: caseKeys.detail(id!),
    queryFn: () => casesApi.get(id!),
    enabled: !!id,
    staleTime: 10_000,
    // Poll every 4s when case is actively processing — fallback when WS is down
    refetchInterval: (query: { state: { data?: Case } }) => {
      const status = query.state.data?.status;
      return status && ACTIVE_STATUSES.has(status) ? 4_000 : false;
    },
  });
}

export function usePluginRuns(caseId: string | undefined, domain?: string) {
  return useQuery<PluginRun[]>({
    queryKey: [...caseKeys.plugins(caseId!), domain],
    queryFn: () => casesApi.plugins.list(caseId!, domain),
    enabled: !!caseId,
    staleTime: 60_000,
  });
}

export function usePluginOutput(caseId: string | undefined, pluginName: string | undefined) {
  return useQuery<PluginRun>({
    queryKey: caseKeys.plugin(caseId!, pluginName!),
    queryFn: () => casesApi.plugins.get(caseId!, pluginName!),
    enabled: !!caseId && !!pluginName,
    staleTime: 300_000,  // plugin output doesn't change once complete
  });
}

export function useReport(caseId: string | undefined) {
  return useQuery<Report>({
    queryKey: caseKeys.report(caseId!),
    queryFn: () => casesApi.report.get(caseId!),
    enabled: !!caseId,
    staleTime: 300_000,
    retry: (failureCount, err: any) => {
      // Don't retry 404 (report not ready)
      if (err?.response?.status === 404) return false;
      return failureCount < 3;
    },
  });
}

export function useIOCs(caseId: string | undefined) {
  return useQuery<IOCEntry[]>({
    queryKey: caseKeys.iocs(caseId!),
    queryFn: () => casesApi.iocs.list(caseId!),
    enabled: !!caseId,
    staleTime: 300_000,
  });
}

export function useDeleteCase() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (caseId: string) => casesApi.delete(caseId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cases'] });
    },
  });
}

export function useReanalyzeCase(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => casesApi.reanalyze(caseId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['case', caseId] });
      qc.invalidateQueries({ queryKey: ['plugins', caseId] });
      qc.invalidateQueries({ queryKey: ['report', caseId] });
      qc.invalidateQueries({ queryKey: ['iocs', caseId] });
    },
  });
}

export function useSubmitCase() {
  return useMutation({
    mutationFn: ({ formData, onProgress, signal }: { formData: FormData; onProgress: (n: number) => void; signal?: AbortSignal }) =>
      casesApi.submit(formData, onProgress, signal),
  });
}

export function useRunPlugins(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (pluginNames: string[]) => casesApi.runPlugins(caseId, pluginNames),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['case', caseId] });
      qc.invalidateQueries({ queryKey: ['plugins', caseId] });
    },
  });
}

export function useEnrichCase(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => casesApi.enrich(caseId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['case', caseId] });
      qc.invalidateQueries({ queryKey: ['iocs', caseId] });
    },
  });
}

export function useAnalyzeCase(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => casesApi.analyze(caseId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['case', caseId] });
    },
  });
}

export function useCaseKBArticles(caseId: string | undefined) {
  return useQuery({
    queryKey: ['kb', caseId],
    queryFn: () => casesApi.kb.list(caseId!),
    enabled: !!caseId,
    staleTime: 60_000,
  });
}
