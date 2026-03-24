// frontend/src/pages/CaseDetail.tsx
import React, { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  useCase, usePluginRuns, usePluginOutput, useReport, useIOCs,
  useReanalyzeCase, useRunPlugins, useEnrichCase, useAnalyzeCase, useCaseKBArticles,
} from '../hooks/useCaseWebSocket'
import { useCaseWebSocket } from '../hooks/useCaseWebSocket'
import { kbApi } from '../api/client'
import { useQueryClient } from '@tanstack/react-query'
import type { PluginRun, Report, IOCEntry, KBArticle, Verdict, Severity } from '../types'

const TABS = ['overview', 'plugins', 'report', 'iocs'] as const
type Tab = typeof TABS[number]

const VERDICT_CONFIG: Record<Verdict, { label: string; color: string; bg: string }> = {
  clean:        { label: 'CLEAN',        color: '#2ee88a', bg: 'rgba(46,232,138,0.08)'  },
  suspicious:   { label: 'SUSPICIOUS',   color: '#f5c518', bg: 'rgba(245,197,24,0.08)'  },
  compromised:  { label: 'COMPROMISED',  color: '#ff3d57', bg: 'rgba(255,61,87,0.08)'   },
  inconclusive: { label: 'INCONCLUSIVE', color: '#a8c0d8', bg: 'rgba(168,192,216,0.06)' },
}

export default function CaseDetail() {
  const { id, tab } = useParams<{ id: string; tab?: string }>()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState<Tab>((tab as Tab) ?? 'overview')
  const [selectedPlugin, setSelectedPlugin] = useState<string | null>(null)

  const { data: case_ } = useCase(id)
  const { data: plugins } = usePluginRuns(id)
  const { data: report } = useReport(id)
  const { data: iocs } = useIOCs(id)
  const wsProgress = useCaseWebSocket(id)
  const { mutate: reanalyze,   isPending: isReanalyzing   } = useReanalyzeCase(id!)
  const { mutate: runPlugins,  isPending: isRunningPlugins } = useRunPlugins(id!)
  const { mutate: enrichCase,  isPending: isEnriching      } = useEnrichCase(id!)
  const { mutate: analyzeCase, isPending: isAnalyzing      } = useAnalyzeCase(id!)
  const [selectedPlugins, setSelectedPlugins] = useState<Set<string>>(new Set())

  useEffect(() => {
    if (tab) setActiveTab(tab as Tab)
  }, [tab])

  useEffect(() => {
    if (wsProgress.lastEvent?.event === 'report_ready' && activeTab === 'overview') {
      setActiveTab('report')
    }
  }, [wsProgress.lastEvent])

  const handleTabChange = (t: Tab) => {
    setActiveTab(t)
    navigate(`/cases/${id}/${t}`, { replace: true })
  }

  if (!case_) return <LoadingShell />

  const currentStatus = wsProgress.status ?? case_.status
  const isRunning = ['queued','detecting','analyzing','ai_analysis'].includes(currentStatus)
  const isTriageComplete = currentStatus === 'triage_complete'
  const canReanalyze = ['failed','complete','cancelled','triage_complete','queued','detecting','analyzing','ai_analysis'].includes(currentStatus) && !case_.dump_purged_at
  const hasCompletedPlugins =
    Object.values(wsProgress.plugins).some(p => p.status === 'complete') ||
    (plugins ?? []).some(p => p.status === 'complete')

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg)' }}>
      {/* Case Header */}
      <div style={{
        background: 'var(--surface)',
        borderBottom: '1px solid var(--border)',
        padding: '24px 40px',
      }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
              <button onClick={() => navigate('/cases')} style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: '0.08em' }}>← CASES</button>
              <span style={{ color: 'var(--border2)' }}>/</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', letterSpacing: '0.08em' }}>{case_.short_id}</span>
            </div>
            <h1 style={{ fontFamily: 'var(--font-cond)', fontSize: 24, fontWeight: 600, color: 'var(--text-bright)', letterSpacing: '0.02em' }}>
              {case_.name}
            </h1>
            <div style={{ display: 'flex', gap: 16, marginTop: 8, flexWrap: 'wrap' }}>
              <MetaChip label="OS" value={case_.detected_os.toUpperCase()} />
              <MetaChip label="SIZE" value={formatBytes(case_.file_size_bytes)} />
              <MetaChip label="SHA256" value={case_.sha256.slice(0,16) + '...'} mono />
              {case_.detected_os_detail && <MetaChip label="VERSION" value={case_.detected_os_detail.slice(0,40)} />}
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
            {/* Triage-complete action buttons */}
            {isTriageComplete && hasCompletedPlugins && (
              <>
                <ActionButton
                  label="Enrich with VT"
                  loading={isEnriching}
                  loadingLabel="Enriching..."
                  onClick={() => enrichCase()}
                  title="Query VirusTotal for IPs, hashes and domains from plugin output"
                />
                <ActionButton
                  label="Run AI Analysis"
                  loading={isAnalyzing}
                  loadingLabel="Queuing..."
                  onClick={() => analyzeCase()}
                  accent
                  title="Run the AI agent to generate a forensic report"
                />
              </>
            )}
            {canReanalyze && (
              <button
                onClick={() => reanalyze()}
                disabled={isReanalyzing}
                style={{
                  background: 'none',
                  border: '1px solid var(--border2)',
                  color: isReanalyzing ? 'var(--text-dim)' : 'var(--text)',
                  fontFamily: 'var(--font-cond)',
                  fontSize: 12,
                  fontWeight: 500,
                  letterSpacing: '0.08em',
                  padding: '7px 14px',
                  borderRadius: 4,
                  cursor: isReanalyzing ? 'not-allowed' : 'pointer',
                  textTransform: 'uppercase',
                }}
              >
                {isReanalyzing ? 'Queuing...' : '↺ Restart Triage'}
              </button>
            )}
            <StatusBadge status={currentStatus} isLive={isRunning} />
          </div>
        </div>

        {/* Live progress bar */}
        {isRunning && <AnalysisProgress plugins={wsProgress.plugins} status={currentStatus} />}

        {/* Triage complete — guide analyst to next step */}
        {isTriageComplete && (
          <div style={{ marginTop: 14, padding: '10px 16px', background: 'rgba(0,200,255,0.06)', border: '1px solid rgba(0,200,255,0.2)', borderRadius: 6, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', letterSpacing: '0.06em' }}>
            TRIAGE COMPLETE — OS detected as {case_.detected_os.toUpperCase()}.
            {!hasCompletedPlugins
              ? ' Open the Plugins tab, select which modules to run, then click Run.'
              : ' Run AI Analysis when ready, or select additional plugins.'}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div style={{ background: 'var(--surface)', borderBottom: '1px solid var(--border)', padding: '0 40px', display: 'flex', gap: 0 }}>
        {TABS.map(t => (
          <button
            key={t}
            onClick={() => handleTabChange(t)}
            style={{
              background: 'none',
              border: 'none',
              borderBottom: activeTab === t ? '2px solid var(--accent)' : '2px solid transparent',
              color: activeTab === t ? 'var(--accent)' : 'var(--text-dim)',
              fontFamily: 'var(--font-cond)',
              fontSize: 13,
              fontWeight: 500,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              padding: '12px 20px',
              cursor: 'pointer',
              transition: 'color 0.15s',
            }}
          >
            {t}
            {t === 'report' && report && (
              <span style={{ marginLeft: 6, fontSize: 10, fontFamily: 'var(--font-mono)', color: VERDICT_CONFIG[report.verdict].color }}>
                ●
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ padding: '32px 40px' }}>
        {activeTab === 'overview' && <OverviewTab case_={case_} plugins={plugins ?? []} wsProgress={wsProgress} report={report} caseId={id!} />}
        {activeTab === 'plugins' && (
          <PluginsTab
            plugins={plugins ?? []}
            wsProgress={wsProgress}
            selected={selectedPlugin}
            onSelect={setSelectedPlugin}
            caseId={id!}
            isTriageComplete={isTriageComplete}
            selectedPlugins={selectedPlugins}
            setSelectedPlugins={setSelectedPlugins}
            onRunPlugins={(names) => runPlugins(names)}
            isRunningPlugins={isRunningPlugins}
          />
        )}
        {activeTab === 'report' && <ReportTab report={report} />}
        {activeTab === 'iocs' && <IOCsTab iocs={iocs ?? []} vtEnrichedAt={case_?.vt_enriched_at ?? null} />}
      </div>
    </div>
  )
}

// ── Overview Tab ──────────────────────────────────────────────────────────────

function OverviewTab({ case_, plugins, wsProgress, report, caseId }: any) {
  const { data: kbArticles } = useCaseKBArticles(caseId)
  const qc = useQueryClient()

  const domainGroups = plugins.reduce((acc: any, p: PluginRun) => {
    if (!acc[p.plugin_domain]) acc[p.plugin_domain] = []
    acc[p.plugin_domain].push(p)
    return acc
  }, {} as Record<string, PluginRun[]>)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 28 }}>
      <div style={{ display: 'grid', gridTemplateColumns: report ? '1fr 1fr' : '1fr', gap: 24 }}>
        {/* Plugin domain summary */}
        <div>
          <SectionLabel>Plugin Domains</SectionLabel>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {Object.keys(domainGroups).length === 0 ? (
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>
                No plugins yet — select and run plugins in the Plugins tab.
              </div>
            ) : Object.entries(domainGroups).map(([domain, ps]: [string, any]) => {
              const done = ps.filter((p: PluginRun) => p.status === 'complete').length
              const flagged = ps.filter((p: PluginRun) => {
                const ws = wsProgress.plugins[p.plugin_name]
                return (ws?.ai_flagged || p.ai_flagged)
              }).length
              return (
                <DomainCard key={domain} domain={domain} total={ps.length} done={done} flagged={flagged} />
              )
            })}
          </div>
        </div>

        {/* Mini report verdict if available */}
        {report && (
          <div>
            <SectionLabel>Assessment</SectionLabel>
            <VerdictCard report={report} />
          </div>
        )}
      </div>

      {/* KB Articles */}
      <KBArticlesSection caseId={caseId} articles={kbArticles ?? []} onRefresh={() => qc.invalidateQueries({ queryKey: ['kb', caseId] })} />
    </div>
  )
}

function DomainCard({ domain, total, done, flagged }: any) {
  const pct = total > 0 ? (done / total) * 100 : 0
  return (
    <div style={{ background: 'var(--surface)', border: `1px solid ${flagged > 0 ? 'rgba(255,61,87,0.3)' : 'var(--border)'}`, borderRadius: 6, padding: '12px 16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <span style={{ fontFamily: 'var(--font-cond)', fontSize: 13, fontWeight: 600, color: 'var(--text-bright)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          {domain.replace(/_/g, ' ')}
        </span>
        <div style={{ display: 'flex', gap: 8 }}>
          {flagged > 0 && <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--red)', background: 'rgba(255,61,87,0.1)', padding: '2px 7px', borderRadius: 3 }}>⚠ {flagged} flagged</span>}
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>{done}/{total}</span>
        </div>
      </div>
      <div style={{ height: 3, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: flagged > 0 ? 'var(--red)' : 'var(--accent)', transition: 'width 0.3s ease', borderRadius: 2 }} />
      </div>
    </div>
  )
}

function VerdictCard({ report }: { report: Report }) {
  const cfg = VERDICT_CONFIG[report.verdict]
  return (
    <div style={{ background: cfg.bg, border: `1px solid ${cfg.color}30`, borderRadius: 8, padding: 20 }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 24, fontWeight: 'bold', color: cfg.color, letterSpacing: '0.05em', marginBottom: 8 }}>
        {cfg.label}
      </div>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', marginBottom: 12 }}>
        Confidence: <span style={{ color: cfg.color }}>{report.confidence}%</span>
      </div>
      <p style={{ fontSize: 13, color: 'var(--text)', lineHeight: 1.7 }}>{report.executive_summary}</p>
    </div>
  )
}

// ── Plugins Tab ───────────────────────────────────────────────────────────────

function PluginsTab({ plugins, wsProgress, selected, onSelect, caseId, isTriageComplete, selectedPlugins, setSelectedPlugins, onRunPlugins, isRunningPlugins }: any) {
  const { data: pluginDetail } = usePluginOutput(caseId, selected ?? undefined)

  const sortedPlugins = [...plugins].sort((a: PluginRun, b: PluginRun) => {
    const order = { running: 0, failed: 1, timeout: 1, complete: 2, pending: 3, skipped: 4 }
    return (order[a.status] ?? 5) - (order[b.status] ?? 5)
  })

  // Group by domain for the "select all in domain" button
  const domainGroups = plugins.reduce((acc: Record<string, string[]>, p: PluginRun) => {
    if (!acc[p.plugin_domain]) acc[p.plugin_domain] = []
    acc[p.plugin_domain].push(p.plugin_name)
    return acc
  }, {})

  const togglePlugin = (name: string) => {
    setSelectedPlugins((prev: Set<string>) => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name); else next.add(name)
      return next
    })
  }

  const toggleDomain = (domain: string) => {
    const names: string[] = domainGroups[domain] ?? []
    const allSelected = names.every((n: string) => selectedPlugins.has(n))
    setSelectedPlugins((prev: Set<string>) => {
      const next = new Set(prev)
      if (allSelected) names.forEach((n: string) => next.delete(n))
      else names.forEach((n: string) => next.add(n))
      return next
    })
  }

  const selectAll = () => setSelectedPlugins(new Set(plugins.map((p: PluginRun) => p.plugin_name)))
  const selectNone = () => setSelectedPlugins(new Set())

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Selection toolbar — only when triage_complete */}
      {isTriageComplete && (
        <div style={{ background: 'var(--surface)', border: '1px solid rgba(0,200,255,0.2)', borderRadius: 8, padding: '12px 16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', letterSpacing: '0.08em' }}>
              SELECT PLUGINS TO RUN
            </span>
            <button onClick={selectAll} style={smallBtnStyle}>Select All</button>
            <button onClick={selectNone} style={smallBtnStyle}>Select None</button>
            {Object.keys(domainGroups).map(domain => (
              <button key={domain} onClick={() => toggleDomain(domain)} style={{
                ...smallBtnStyle,
                background: domainGroups[domain].every((n: string) => selectedPlugins.has(n)) ? 'rgba(0,200,255,0.12)' : undefined,
                color: domainGroups[domain].every((n: string) => selectedPlugins.has(n)) ? 'var(--accent)' : undefined,
              }}>
                {domain.replace(/_/g, ' ')}
              </button>
            ))}
            <button
              disabled={selectedPlugins.size === 0 || isRunningPlugins}
              onClick={() => onRunPlugins([...selectedPlugins])}
              style={{
                marginLeft: 'auto',
                background: selectedPlugins.size === 0 ? 'none' : 'rgba(0,200,255,0.12)',
                border: '1px solid var(--accent)',
                color: selectedPlugins.size === 0 ? 'var(--text-dim)' : 'var(--accent)',
                fontFamily: 'var(--font-cond)',
                fontSize: 12,
                fontWeight: 600,
                letterSpacing: '0.1em',
                padding: '7px 20px',
                borderRadius: 4,
                cursor: selectedPlugins.size === 0 || isRunningPlugins ? 'not-allowed' : 'pointer',
                textTransform: 'uppercase',
              }}
            >
              {isRunningPlugins ? 'Queuing...' : `Run ${selectedPlugins.size > 0 ? selectedPlugins.size : ''} Selected`}
            </button>
          </div>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 20, height: 'calc(100vh - 320px)' }}>
        {/* Plugin list */}
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'auto' }}>
          {sortedPlugins.map((p: PluginRun) => {
            const ws = wsProgress.plugins[p.plugin_name] ?? {}
            const isFlagged = ws.ai_flagged || p.ai_flagged
            const status = ws.status ?? p.status
            const isChecked = selectedPlugins.has(p.plugin_name)
            return (
              <div
                key={p.plugin_name}
                style={{
                  display: 'flex', alignItems: 'flex-start', gap: 8,
                  background: selected === p.plugin_name ? 'rgba(0,200,255,0.06)' : 'none',
                  borderBottom: '1px solid var(--border)',
                  borderLeft: selected === p.plugin_name ? '2px solid var(--accent)' : '2px solid transparent',
                  padding: '10px 12px',
                }}
              >
                {isTriageComplete && (
                  <input
                    type="checkbox"
                    checked={isChecked}
                    onChange={() => togglePlugin(p.plugin_name)}
                    style={{ marginTop: 2, accentColor: 'var(--accent)', flexShrink: 0 }}
                    onClick={e => e.stopPropagation()}
                  />
                )}
                <button
                  onClick={() => onSelect(selected === p.plugin_name ? null : p.plugin_name)}
                  style={{
                    flex: 1, display: 'flex', flexDirection: 'column', background: 'none',
                    border: 'none', padding: 0, textAlign: 'left', cursor: 'pointer',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: isFlagged ? 'var(--red)' : 'var(--text)', letterSpacing: '0.02em' }}>
                      {isFlagged && '⚠ '}{p.plugin_name}
                    </span>
                    <PluginStatusDot status={status} />
                  </div>
                  {(ws.rows ?? p.row_count) !== null && (
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', marginTop: 3 }}>
                      {ws.rows ?? p.row_count} rows
                    </span>
                  )}
                </button>
              </div>
            )
          })}
        </div>

        {/* Plugin output detail */}
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'auto' }}>
          {!selected ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
              {isTriageComplete ? 'Check plugins above then click Run — or click a plugin name to preview its description' : 'Select a plugin to view output'}
            </div>
          ) : pluginDetail ? (
            <PluginOutputView plugin={pluginDetail} />
          ) : (
            <div style={{ padding: 20, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>Loading...</div>
          )}
        </div>
      </div>
    </div>
  )
}

const smallBtnStyle: React.CSSProperties = {
  background: 'none',
  border: '1px solid var(--border2)',
  color: 'var(--text-dim)',
  fontFamily: 'var(--font-mono)',
  fontSize: 10,
  padding: '4px 10px',
  borderRadius: 3,
  cursor: 'pointer',
  letterSpacing: '0.06em',
  textTransform: 'uppercase',
}

function PluginOutputView({ plugin }: { plugin: PluginRun }) {
  const [viewMode, setViewMode] = useState<'table' | 'raw'>('table')
  const rows = Array.isArray(plugin.parsed_output) ? plugin.parsed_output
    : (plugin.parsed_output as any)?.rows ?? []
  const cols = rows.length > 0 ? Object.keys(rows[0]) : []

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--accent)' }}>{plugin.plugin_name}</span>
          {plugin.ai_flagged && <span style={{ marginLeft: 10, fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--red)', background: 'rgba(255,61,87,0.1)', padding: '2px 7px', borderRadius: 3 }}>AI FLAGGED</span>}
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {(['table','raw'] as const).map(m => (
            <button key={m} onClick={() => setViewMode(m)} style={{
              background: viewMode === m ? 'var(--border2)' : 'none',
              border: '1px solid var(--border2)', color: viewMode === m ? 'var(--text-bright)' : 'var(--text-dim)',
              fontFamily: 'var(--font-mono)', fontSize: 10, padding: '3px 10px', borderRadius: 3, cursor: 'pointer', letterSpacing: '0.08em',
            }}>{m.toUpperCase()}</button>
          ))}
        </div>
      </div>
      {plugin.ai_summary && (
        <div style={{ padding: '10px 16px', background: 'rgba(0,200,255,0.04)', borderBottom: '1px solid var(--border)', fontSize: 12, color: 'var(--text)', fontStyle: 'italic' }}>
          🤖 {plugin.ai_summary}
        </div>
      )}
      <div style={{ flex: 1, overflow: 'auto' }}>
        {viewMode === 'table' && rows.length > 0 ? (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ position: 'sticky', top: 0, background: 'var(--surface2)' }}>
                {cols.map(c => (
                  <th key={c} style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', textAlign: 'left', padding: '8px 12px', borderBottom: '1px solid var(--border)', letterSpacing: '0.08em', whiteSpace: 'nowrap' }}>
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, 500).map((row: any, i: number) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border)', background: row.is_suspicious || row.has_pe_header || row.is_known_bad ? 'rgba(255,61,87,0.04)' : undefined }}>
                  {cols.map(c => (
                    <td key={c} style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: typeof row[c] === 'boolean' ? (row[c] ? 'var(--red)' : 'var(--text-dim)') : 'var(--text)', padding: '7px 12px', whiteSpace: 'nowrap', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {String(row[c] ?? '—')}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <pre style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text)', padding: 16, lineHeight: 1.6, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {plugin.raw_output || JSON.stringify(plugin.parsed_output, null, 2)}
          </pre>
        )}
      </div>
    </div>
  )
}

// ── Report Tab ────────────────────────────────────────────────────────────────

function ReportTab({ report }: { report?: Report }) {
  if (!report) return (
    <div style={{ textAlign: 'center', padding: '80px 40px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 13 }}>
      Report not yet available. Analysis may still be running.
    </div>
  )

  const cfg = VERDICT_CONFIG[report.verdict]

  return (
    <div style={{ maxWidth: 900 }}>
      {/* Verdict banner */}
      <div style={{ background: cfg.bg, border: `1px solid ${cfg.color}40`, borderRadius: 10, padding: '28px 32px', marginBottom: 28, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 32, fontWeight: 700, color: cfg.color, letterSpacing: '0.05em' }}>{cfg.label}</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)', marginTop: 4 }}>
            Confidence: <span style={{ color: cfg.color }}>{report.confidence}%</span> · Model: {report.model_used}
          </div>
        </div>
        <ConfidenceGauge value={report.confidence} color={cfg.color} />
      </div>

      {/* Executive summary */}
      <ReportSection title="Executive Summary">
        <p style={{ color: 'var(--text)', lineHeight: 1.8, fontSize: 14 }}>{report.executive_summary}</p>
      </ReportSection>

      {/* Technical narrative */}
      <ReportSection title="Technical Analysis">
        <p style={{ color: 'var(--text)', lineHeight: 1.8, fontSize: 13, whiteSpace: 'pre-wrap' }}>{report.technical_narrative}</p>
      </ReportSection>

      {/* MITRE ATT&CK */}
      {report.mitre_ttps.length > 0 && (
        <ReportSection title={`MITRE ATT&CK — ${report.mitre_ttps.length} Techniques`}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {report.mitre_ttps.map((t, i) => (
              <div key={i} style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 6, padding: '12px 16px' }}>
                <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 6 }}>
                  <SeverityBadge severity={t.severity} />
                  <a href={`https://attack.mitre.org/techniques/${t.technique.replace('.','/')}`} target="_blank" rel="noreferrer"
                    style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', textDecoration: 'none' }}>{t.technique}</a>
                  <span style={{ fontSize: 13, color: 'var(--text-bright)', fontWeight: 500 }}>{t.technique_name}</span>
                  <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>({t.tactic_name})</span>
                </div>
                <p style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.6 }}>{t.evidence}</p>
              </div>
            ))}
          </div>
        </ReportSection>
      )}

      {/* Timeline */}
      {report.timeline.length > 0 && (
        <ReportSection title="Event Timeline">
          <div style={{ position: 'relative', paddingLeft: 20 }}>
            <div style={{ position: 'absolute', left: 7, top: 0, bottom: 0, width: 1, background: 'var(--border2)' }} />
            {report.timeline.map((e, i) => (
              <div key={i} style={{ position: 'relative', paddingLeft: 20, paddingBottom: 16 }}>
                <div style={{ position: 'absolute', left: -6, top: 4, width: 8, height: 8, borderRadius: '50%', background: 'var(--accent)', border: '2px solid var(--bg)' }} />
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent)', letterSpacing: '0.06em', marginBottom: 3 }}>{e.timestamp_estimate}</div>
                <div style={{ fontSize: 13, color: 'var(--text)' }}>{e.event}</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', marginTop: 2 }}>via {e.evidence_plugin}</div>
              </div>
            ))}
          </div>
        </ReportSection>
      )}

      {/* Recommendations */}
      {report.recommendations.length > 0 && (
        <ReportSection title="Recommendations">
          {report.recommendations
            .sort((a, b) => a.priority - b.priority)
            .map((r, i) => (
              <div key={i} style={{ display: 'flex', gap: 14, marginBottom: 12 }}>
                <div style={{ width: 24, height: 24, borderRadius: '50%', background: 'var(--border2)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', flexShrink: 0 }}>
                  {r.priority}
                </div>
                <div>
                  <div style={{ fontSize: 13, color: 'var(--text-bright)', fontWeight: 500, marginBottom: 3 }}>{r.action}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.6 }}>{r.rationale}</div>
                </div>
              </div>
            ))}
        </ReportSection>
      )}
    </div>
  )
}

// ── IOCs Tab ──────────────────────────────────────────────────────────────────

function IOCsTab({ iocs, vtEnrichedAt }: { iocs: IOCEntry[]; vtEnrichedAt: string | null }) {
  const [typeFilter, setTypeFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const types = [...new Set(iocs.map(i => i.ioc_type))]

  const filtered = iocs.filter(i =>
    (!typeFilter || i.ioc_type === typeFilter) &&
    (!severityFilter || i.severity === severityFilter)
  )

  return (
    <div>
      <div style={{ display: 'flex', gap: 10, marginBottom: 20 }}>
        <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)}
          style={{ background: 'var(--surface)', border: '1px solid var(--border2)', color: 'var(--text)', fontFamily: 'var(--font-mono)', fontSize: 12, padding: '7px 12px', borderRadius: 4, outline: 'none' }}>
          <option value="">All types</option>
          {types.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
          style={{ background: 'var(--surface)', border: '1px solid var(--border2)', color: 'var(--text)', fontFamily: 'var(--font-mono)', fontSize: 12, padding: '7px 12px', borderRadius: 4, outline: 'none' }}>
          <option value="">All severities</option>
          {['critical','high','medium','low','info'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', alignSelf: 'center' }}>{filtered.length} IOCs</span>
      </div>

      {vtEnrichedAt && iocs.length === 0 && (
        <div style={{ marginBottom: 16, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, padding: '10px 16px' }}>
          VirusTotal enrichment ran on {new Date(vtEnrichedAt).toLocaleString()} — no extractable IOCs found in plugin output.
        </div>
      )}

      <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              {['Severity','Type','Value','VT Detections','Source','Description'].map(h => (
                <th key={h} style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', textAlign: 'left', padding: '10px 14px', letterSpacing: '0.1em', textTransform: 'uppercase' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map(ioc => (
              <tr key={ioc.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '10px 14px' }}><SeverityBadge severity={ioc.severity} /></td>
                <td style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', letterSpacing: '0.05em' }}>{ioc.ioc_type}</td>
                <td style={{ padding: '10px 14px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-bright)', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>
                      {ioc.value}
                    </span>
                    <button onClick={() => navigator.clipboard.writeText(ioc.value)}
                      style={{ background: 'none', border: '1px solid var(--border)', color: 'var(--text-dim)', fontSize: 9, padding: '1px 6px', borderRadius: 3, cursor: 'pointer', fontFamily: 'var(--font-mono)', flexShrink: 0 }}>
                      COPY
                    </button>
                    {ioc.vt_permalink && (
                      <a href={ioc.vt_permalink} target="_blank" rel="noreferrer"
                        style={{ color: 'var(--accent)', fontSize: 10, fontFamily: 'var(--font-mono)', textDecoration: 'none', flexShrink: 0 }}>VT →</a>
                    )}
                  </div>
                </td>
                <td style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)', fontSize: 11, color: ioc.vt_positives ? 'var(--red)' : 'var(--text-dim)' }}>
                  {ioc.vt_positives !== null ? `${ioc.vt_positives}/${ioc.vt_total}` : '—'}
                </td>
                <td style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>{ioc.source_plugin || '—'}</td>
                <td style={{ padding: '10px 14px', fontSize: 12, color: 'var(--text)', maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ioc.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── KB Articles Section ────────────────────────────────────────────────────────

function KBArticlesSection({ caseId, articles, onRefresh }: { caseId: string; articles: KBArticle[]; onRefresh: () => void }) {
  const [showNew, setShowNew] = useState(false)
  const [newTitle, setNewTitle] = useState('')
  const [newContent, setNewContent] = useState('')
  const [saving, setSaving] = useState(false)

  const handleCreate = async () => {
    if (!newTitle.trim() || !newContent.trim()) return
    setSaving(true)
    try {
      const article = await kbApi.create({ title: newTitle.trim(), content: newContent.trim() })
      await kbApi.attachToCase(article.id, caseId)
      setNewTitle(''); setNewContent(''); setShowNew(false)
      onRefresh()
    } finally {
      setSaving(false)
    }
  }

  const handleDetach = async (articleId: string) => {
    await kbApi.detachFromCase(articleId, caseId)
    onRefresh()
  }

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        <SectionLabel>Knowledge Base Notes</SectionLabel>
        <button onClick={() => setShowNew(v => !v)} style={{ background: 'none', border: '1px solid var(--border2)', color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: 10, padding: '4px 12px', borderRadius: 3, cursor: 'pointer', letterSpacing: '0.08em' }}>
          {showNew ? 'CANCEL' : '+ NEW NOTE'}
        </button>
      </div>

      {showNew && (
        <div style={{ background: 'var(--surface)', border: '1px solid rgba(0,200,255,0.2)', borderRadius: 8, padding: 16, marginBottom: 14 }}>
          <input
            placeholder="Title"
            value={newTitle}
            onChange={e => setNewTitle(e.target.value)}
            style={{ width: '100%', background: 'var(--bg)', border: '1px solid var(--border2)', color: 'var(--text-bright)', fontFamily: 'var(--font-ui)', fontSize: 13, padding: '8px 12px', borderRadius: 4, marginBottom: 8, outline: 'none', boxSizing: 'border-box' }}
          />
          <textarea
            placeholder="Write your analysis notes, TTP context, or threat intelligence here..."
            value={newContent}
            onChange={e => setNewContent(e.target.value)}
            rows={5}
            style={{ width: '100%', background: 'var(--bg)', border: '1px solid var(--border2)', color: 'var(--text)', fontFamily: 'var(--font-mono)', fontSize: 12, padding: '8px 12px', borderRadius: 4, outline: 'none', resize: 'vertical', lineHeight: 1.7, boxSizing: 'border-box' }}
          />
          <button
            onClick={handleCreate}
            disabled={saving || !newTitle.trim() || !newContent.trim()}
            style={{ marginTop: 8, background: 'rgba(0,200,255,0.1)', border: '1px solid var(--accent)', color: 'var(--accent)', fontFamily: 'var(--font-cond)', fontSize: 12, fontWeight: 600, letterSpacing: '0.1em', padding: '7px 20px', borderRadius: 4, cursor: saving ? 'wait' : 'pointer', textTransform: 'uppercase' }}
          >
            {saving ? 'Saving...' : 'Save Note'}
          </button>
        </div>
      )}

      {articles.length === 0 && !showNew ? (
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)', padding: '14px 0' }}>
          No knowledge base notes attached. Add context notes to aid AI analysis.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {articles.map(a => (
            <div key={a.id} style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: '14px 18px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                <span style={{ fontFamily: 'var(--font-cond)', fontSize: 14, fontWeight: 600, color: 'var(--text-bright)' }}>{a.title}</span>
                <button onClick={() => handleDetach(a.id)} style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 10, padding: '2px 6px' }} title="Detach from case">✕</button>
              </div>
              <p style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text)', lineHeight: 1.7, whiteSpace: 'pre-wrap', margin: 0 }}>{a.content}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Action Button ─────────────────────────────────────────────────────────────

function ActionButton({ label, loading, loadingLabel, onClick, accent, title }: {
  label: string; loading: boolean; loadingLabel: string;
  onClick: () => void; accent?: boolean; title?: string;
}) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      title={title}
      style={{
        background: accent ? 'rgba(0,200,255,0.1)' : 'none',
        border: `1px solid ${accent ? 'var(--accent)' : 'var(--border2)'}`,
        color: loading ? 'var(--text-dim)' : accent ? 'var(--accent)' : 'var(--text)',
        fontFamily: 'var(--font-cond)',
        fontSize: 12,
        fontWeight: accent ? 600 : 500,
        letterSpacing: '0.08em',
        padding: '7px 14px',
        borderRadius: 4,
        cursor: loading ? 'not-allowed' : 'pointer',
        textTransform: 'uppercase',
      }}
    >
      {loading ? loadingLabel : label}
    </button>
  )
}

// ── Shared components ──────────────────────────────────────────────────────────

function AnalysisProgress({ plugins, status }: any) {
  const all = Object.values(plugins) as any[]
  const done = all.filter(p => ['complete','failed','timeout','skipped'].includes(p.status)).length
  const pct = all.length > 0 ? (done / all.length) * 100 : 0
  const stage = { detecting: 'OS Detection', analyzing: 'Plugin Analysis', ai_analysis: 'AI Agent' }[status] ?? 'Processing'

  return (
    <div style={{ marginTop: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)' }}>{stage}</span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }}>{done}/{all.length} plugins</span>
      </div>
      <div style={{ height: 2, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: 'var(--accent)', transition: 'width 0.4s ease', borderRadius: 2 }} />
      </div>
    </div>
  )
}

function StatusBadge({ status, isLive }: { status: string; isLive: boolean }) {
  const colors: Record<string, string> = {
    complete: 'var(--green)', failed: 'var(--red)',
    analyzing: 'var(--accent)', ai_analysis: 'var(--accent2)',
    detecting: 'var(--yellow)', queued: 'var(--text-dim)',
    triage_complete: 'var(--accent2)',
  }
  const color = colors[status] ?? 'var(--text-dim)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      {isLive && <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, animation: 'pulse 1.5s infinite', flexShrink: 0 }} />}
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color, letterSpacing: '0.1em' }}>
        {status.toUpperCase().replace('_', ' ')}
      </span>
    </div>
  )
}

function PluginStatusDot({ status }: { status: string }) {
  const colors: Record<string, string> = {
    complete: 'var(--green)', failed: 'var(--red)', timeout: 'var(--red)',
    running: 'var(--accent)', pending: 'var(--border2)', skipped: 'var(--text-dim)',
  }
  return <span style={{ width: 6, height: 6, borderRadius: '50%', background: colors[status] ?? 'var(--text-dim)', flexShrink: 0, animation: status === 'running' ? 'pulse 1.5s infinite' : undefined }} />
}

function SeverityBadge({ severity }: { severity: string }) {
  const config: Record<string, [string,string]> = {
    critical: ['rgba(255,61,87,0.15)', '#ff3d57'],
    high:     ['rgba(255,107,53,0.15)', '#ff6b35'],
    medium:   ['rgba(245,197,24,0.12)', '#f5c518'],
    low:      ['rgba(46,232,138,0.10)', '#2ee88a'],
    info:     ['rgba(168,192,216,0.08)', '#a8c0d8'],
  }
  const [bg, fg] = config[severity] ?? config.info
  return <span style={{ background: bg, color: fg, fontFamily: 'var(--font-mono)', fontSize: 9, padding: '2px 7px', borderRadius: 3, letterSpacing: '0.1em', textTransform: 'uppercase' }}>{severity}</span>
}

function ConfidenceGauge({ value, color }: { value: number; color: string }) {
  const r = 28, circ = 2 * Math.PI * r
  const dash = (value / 100) * circ
  return (
    <svg width={76} height={76} viewBox="0 0 76 76">
      <circle cx={38} cy={38} r={r} fill="none" stroke="var(--border2)" strokeWidth={5} />
      <circle cx={38} cy={38} r={r} fill="none" stroke={color} strokeWidth={5}
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
        transform="rotate(-90 38 38)" style={{ transition: 'stroke-dasharray 0.5s ease' }} />
      <text x={38} y={43} textAnchor="middle" fontFamily="var(--font-mono)" fontSize={15} fill={color} fontWeight="bold">{value}</text>
    </svg>
  )
}

function ReportSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 24 }}>
      <div style={{ fontFamily: 'var(--font-cond)', fontSize: 13, fontWeight: 600, color: 'var(--text-dim)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 12 }}>{title}</div>
      <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: '20px 24px' }}>
        {children}
      </div>
    </div>
  )
}

function MetaChip({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.12em' }}>{label}</span>
      <span style={{ fontFamily: mono ? 'var(--font-mono)' : 'var(--font-ui)', fontSize: 12, color: 'var(--text)' }}>{value}</span>
    </div>
  )
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return <div style={{ fontFamily: 'var(--font-cond)', fontSize: 12, fontWeight: 600, color: 'var(--text-dim)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 12 }}>{children}</div>
}

function LoadingShell() {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 12, letterSpacing: '0.1em' }}>
      LOADING...
    </div>
  )
}

function formatBytes(n: number) {
  if (n >= 1e9) return `${(n/1e9).toFixed(1)} GB`
  if (n >= 1e6) return `${(n/1e6).toFixed(1)} MB`
  return `${(n/1e3).toFixed(0)} KB`
}
