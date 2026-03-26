// frontend/src/pages/Dashboard.tsx
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useCases, useDeleteCase } from '../hooks/useCaseWebSocket'
import type { Case, CaseStatus, Verdict } from '../types'

const STATUS_COLOR: Record<CaseStatus, string> = {
  pending:          'var(--text-dim)',
  queued:           'var(--text-dim)',
  detecting:        'var(--yellow)',
  building_symbols: 'var(--yellow)',
  analyzing:        'var(--accent)',
  ai_analysis:      'var(--accent2)',
  complete:         'var(--green)',
  failed:           'var(--red)',
  cancelled:        'var(--text-dim)',
  triage_complete:  'var(--text-dim)',
}

const STATUS_PULSE: Record<CaseStatus, boolean> = {
  pending: false, queued: true, detecting: true,
  building_symbols: true,
  analyzing: true, ai_analysis: true,
  complete: false, failed: false, cancelled: false,
  triage_complete: false,
}

export default function Dashboard() {
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [page, setPage] = useState(1)

  const { data, isLoading } = useCases({ page, search, status: statusFilter || undefined })

  return (
    <div style={{ padding: '32px 40px', maxWidth: 1200 }}>
      {/* Page header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 32 }}>
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent)', letterSpacing: '0.15em', marginBottom: 6 }}>
            MEMORY FORENSICS
          </div>
          <h1 style={{ fontFamily: 'var(--font-cond)', fontSize: 28, fontWeight: 600, color: 'var(--text-bright)', letterSpacing: '0.02em' }}>
            Analysis Cases
          </h1>
        </div>
        <button
          onClick={() => navigate('/cases/new')}
          style={{
            background: 'var(--accent)',
            color: 'var(--bg)',
            border: 'none',
            fontFamily: 'var(--font-cond)',
            fontSize: 13,
            fontWeight: 600,
            letterSpacing: '0.1em',
            padding: '10px 20px',
            borderRadius: 4,
            cursor: 'pointer',
            textTransform: 'uppercase',
          }}
        >
          + Submit Dump
        </button>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 24 }}>
        <input
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(1) }}
          placeholder="Search cases..."
          style={{
            background: 'var(--surface)',
            border: '1px solid var(--border2)',
            color: 'var(--text)',
            fontFamily: 'var(--font-mono)',
            fontSize: 12,
            padding: '8px 14px',
            borderRadius: 4,
            outline: 'none',
            width: 260,
          }}
        />
        <select
          value={statusFilter}
          onChange={e => { setStatusFilter(e.target.value); setPage(1) }}
          style={{
            background: 'var(--surface)',
            border: '1px solid var(--border2)',
            color: statusFilter ? 'var(--text-bright)' : 'var(--text-dim)',
            fontFamily: 'var(--font-mono)',
            fontSize: 12,
            padding: '8px 14px',
            borderRadius: 4,
            outline: 'none',
          }}
        >
          <option value="">All statuses</option>
          <option value="queued">Queued</option>
          <option value="analyzing">Analyzing</option>
          <option value="ai_analysis">AI Analysis</option>
          <option value="complete">Complete</option>
          <option value="failed">Failed</option>
        </select>
      </div>

      {/* Stats row */}
      {data && (
        <div style={{ display: 'flex', gap: 20, marginBottom: 24 }}>
          <StatPill label="Total" value={data.total} />
          <StatPill label="Complete" value={data.items.filter(c => c.status === 'complete').length} color="var(--green)" />
          <StatPill label="Running" value={data.items.filter(c => ['analyzing','ai_analysis','detecting'].includes(c.status)).length} color="var(--accent)" />
          <StatPill label="Failed" value={data.items.filter(c => c.status === 'failed').length} color="var(--red)" />
        </div>
      )}

      {/* Case table */}
      <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              {['ID', 'Name', 'OS', 'Status', 'Size', 'Submitted', ''].map(h => (
                <th key={h} style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 10,
                  color: 'var(--text-dim)',
                  letterSpacing: '0.12em',
                  textAlign: 'left',
                  padding: '10px 16px',
                  textTransform: 'uppercase',
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr><td colSpan={7} style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>Loading...</td></tr>
            ) : data?.items.length === 0 ? (
              <tr><td colSpan={7} style={{ padding: 60, textAlign: 'center', color: 'var(--text-dim)' }}>No cases yet. Submit your first memory dump.</td></tr>
            ) : data?.items.map(c => (
              <CaseRow key={c.id} case_={c} onClick={() => navigate(`/cases/${c.id}`)} />
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {data && data.total > data.page_size && (
        <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 20 }}>
          <PageBtn onClick={() => setPage(p => Math.max(1, p-1))} disabled={page === 1}>←</PageBtn>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)', padding: '6px 12px' }}>
            {page} / {Math.ceil(data.total / data.page_size)}
          </span>
          <PageBtn onClick={() => setPage(p => p+1)} disabled={page >= Math.ceil(data.total / data.page_size)}>→</PageBtn>
        </div>
      )}
    </div>
  )
}

function CaseRow({ case_: c, onClick }: { case_: Case; onClick: () => void }) {
  const statusColor = STATUS_COLOR[c.status]
  const isPulsing = STATUS_PULSE[c.status]
  const [confirmDelete, setConfirmDelete] = useState(false)
  const { mutate: deleteCase, isPending: isDeleting } = useDeleteCase()

  return (
    <tr
      onClick={onClick}
      style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer', transition: 'background 0.1s' }}
      onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface2)')}
      onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
    >
      <td style={{ padding: '12px 16px' }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', letterSpacing: '0.05em' }}>
          {c.short_id}
        </span>
      </td>
      <td style={{ padding: '12px 16px' }}>
        <div style={{ color: 'var(--text-bright)', fontSize: 13, fontWeight: 500, maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {c.name}
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', marginTop: 2 }}>
          {c.original_filename}
        </div>
      </td>
      <td style={{ padding: '12px 16px' }}>
        <OsBadge os={c.detected_os} />
      </td>
      <td style={{ padding: '12px 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          {isPulsing && (
            <span style={{
              width: 7, height: 7, borderRadius: '50%',
              background: statusColor,
              flexShrink: 0,
              animation: 'pulse 1.5s infinite',
            }} />
          )}
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: statusColor, letterSpacing: '0.06em' }}>
            {c.status.toUpperCase()}
          </span>
        </div>
      </td>
      <td style={{ padding: '12px 16px' }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }}>
          {formatBytes(c.file_size_bytes)}
        </span>
      </td>
      <td style={{ padding: '12px 16px' }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }}>
          {formatDate(c.created_at)}
        </span>
      </td>
      <td style={{ padding: '8px 16px', textAlign: 'right', whiteSpace: 'nowrap' }} onClick={e => e.stopPropagation()}>
        {confirmDelete ? (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <button
              onClick={() => deleteCase(c.id)}
              disabled={isDeleting}
              style={{ background: 'var(--red)', color: '#fff', border: 'none', fontFamily: 'var(--font-mono)', fontSize: 10, padding: '3px 8px', borderRadius: 3, cursor: isDeleting ? 'not-allowed' : 'pointer', letterSpacing: '0.06em' }}
            >{isDeleting ? '...' : 'Confirm'}</button>
            <button
              onClick={() => setConfirmDelete(false)}
              style={{ background: 'none', border: 'none', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 10, cursor: 'pointer', padding: '3px 4px' }}
            >✕</button>
          </span>
        ) : (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
            <span style={{ color: 'var(--text-dim)', fontSize: 16 }}>→</span>
            <button
              onClick={() => setConfirmDelete(true)}
              title="Delete case"
              style={{ background: 'none', border: 'none', color: 'rgba(255,61,87,0.5)', fontSize: 14, cursor: 'pointer', padding: '2px 4px', lineHeight: 1 }}
            >✕</button>
          </span>
        )}
      </td>
    </tr>
  )
}

function OsBadge({ os }: { os: string }) {
  const colors: Record<string, [string, string]> = {
    windows: ['rgba(0,120,212,0.15)', '#4ea8de'],
    linux:   ['rgba(46,232,138,0.10)', 'var(--green)'],
    macos:   ['rgba(255,107,53,0.12)', 'var(--accent2)'],
    unknown: ['rgba(74,100,128,0.15)', 'var(--text-dim)'],
  }
  const [bg, fg] = colors[os] ?? colors.unknown
  return (
    <span style={{ background: bg, color: fg, fontFamily: 'var(--font-mono)', fontSize: 10, padding: '2px 8px', borderRadius: 3, letterSpacing: '0.08em' }}>
      {os.toUpperCase()}
    </span>
  )
}

function StatPill({ label, value, color = 'var(--text)' }: { label: string; value: number; color?: string }) {
  return (
    <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, padding: '10px 16px', minWidth: 80 }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.12em', marginBottom: 4 }}>{label.toUpperCase()}</div>
      <div style={{ fontFamily: 'var(--font-cond)', fontSize: 22, fontWeight: 600, color }}>{value}</div>
    </div>
  )
}

function PageBtn({ children, onClick, disabled }: { children: React.ReactNode; onClick: () => void; disabled: boolean }) {
  return (
    <button onClick={onClick} disabled={disabled} style={{
      background: 'var(--surface)', border: '1px solid var(--border2)',
      color: disabled ? 'var(--text-dim)' : 'var(--text)',
      fontFamily: 'var(--font-mono)', fontSize: 13, padding: '6px 12px', borderRadius: 4,
      cursor: disabled ? 'default' : 'pointer',
    }}>{children}</button>
  )
}

function formatBytes(n: number) {
  if (n >= 1e9) return `${(n/1e9).toFixed(1)} GB`
  if (n >= 1e6) return `${(n/1e6).toFixed(1)} MB`
  return `${(n/1e3).toFixed(0)} KB`
}

function formatDate(s: string) {
  return new Date(s).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}
