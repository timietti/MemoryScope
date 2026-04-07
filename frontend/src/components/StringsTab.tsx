// frontend/src/components/StringsTab.tsx
import React, { useState, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { casesApi } from '../api/client'

// ── Types ─────────────────────────────────────────────────────────────────────

interface StringsRun {
  id: string
  status: 'pending' | 'running' | 'complete' | 'failed' | 'timeout' | 'skipped'
  line_count: number | null
  compressed_size: number | null
  started_at: string | null
  completed_at: string | null
  error_message: string | null
}

interface SearchResult {
  total_matches: number
  is_capped: boolean
  page: number
  page_size: number
  results: string[]
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

const PAGE_SIZE = 200

// ── Component ─────────────────────────────────────────────────────────────────

export default function StringsTab({ caseId }: { caseId: string }) {
  const [query, setQuery] = useState('')
  const [submittedQuery, setSubmittedQuery] = useState('')
  const [page, setPage] = useState(1)
  const inputRef = useRef<HTMLInputElement>(null)

  // Poll status while running (every 10 s), settle when complete/failed
  const { data: status, isLoading: statusLoading } = useQuery<StringsRun>({
    queryKey: ['strings', caseId],
    queryFn: () => casesApi.strings.status(caseId),
    refetchInterval: (query) => {
      const s = query.state.data?.status
      if (!s) return 10_000
      return s === 'running' || s === 'pending' ? 10_000 : false
    },
    staleTime: 5_000,
  })

  // Search — only fires when status is complete and a query or page changes
  const searchEnabled = status?.status === 'complete'
  const { data: results, isFetching: searching, error: searchError } = useQuery<SearchResult>({
    queryKey: ['strings-search', caseId, submittedQuery, page],
    queryFn: () => casesApi.strings.search(caseId, {
      q: submittedQuery,
      page,
      page_size: PAGE_SIZE,
    }),
    enabled: searchEnabled,
    staleTime: 60_000,
  })

  const handleSearch = () => {
    setPage(1)
    setSubmittedQuery(query)
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleSearch()
  }

  // ── Render status states ───────────────────────────────────────────────────

  if (statusLoading) {
    return (
      <div style={styles.center}>
        <div style={styles.dimMono}>Loading...</div>
      </div>
    )
  }

  if (!status) {
    return (
      <div style={styles.center}>
        <div style={styles.dimMono}>No strings extraction record found.</div>
      </div>
    )
  }

  const isPending = status.status === 'pending'
  const isRunning = status.status === 'running'
  const isComplete = status.status === 'complete'
  const isFailed = status.status === 'failed' || status.status === 'timeout'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* ── Status banner ───────────────────────────────────────────────── */}
      {(isPending || isRunning) && (
        <StatusBanner color="var(--accent)" bg="rgba(0,200,255,0.06)" border="rgba(0,200,255,0.2)">
          <Spinner /> STRINGS EXTRACTION {isRunning ? 'RUNNING' : 'QUEUED'} — Large dumps may take several minutes. The rest of the case is fully usable in the meantime.
        </StatusBanner>
      )}

      {isFailed && (
        <StatusBanner color="var(--red, #ff3d57)" bg="rgba(255,61,87,0.06)" border="rgba(255,61,87,0.25)">
          STRINGS EXTRACTION FAILED{status.error_message ? ` — ${status.error_message}` : ''}
        </StatusBanner>
      )}

      {isComplete && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
          <MetaChip label="LINES" value={(status.line_count ?? 0).toLocaleString()} />
          {status.compressed_size != null && (
            <MetaChip label="STORED" value={formatBytes(status.compressed_size)} />
          )}
        </div>
      )}

      {/* ── Search bar (only when complete) ─────────────────────────────── */}
      {isComplete && (
        <>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <input
              ref={inputRef}
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="regex  ·  use AND / OR / NOT  ·  e.g.  cmd.exe AND NOT explorer"
              style={styles.input}
              spellCheck={false}
            />
            <button onClick={handleSearch} disabled={searching} style={styles.searchBtn}>
              {searching ? '…' : 'Search'}
            </button>
          </div>

          {/* filter syntax hint */}
          <div style={styles.hint}>
            Operators: <code style={styles.code}>AND</code> <code style={styles.code}>OR</code> <code style={styles.code}>NOT</code> — grouping with <code style={styles.code}>(</code> <code style={styles.code}>)</code> — each token is a case-insensitive regex
          </div>
        </>
      )}

      {/* ── Results ─────────────────────────────────────────────────────── */}
      {isComplete && results && (
        <>
          <ResultsMeta results={results} />
          <ResultsTable results={results.results} />
          <Pagination
            page={results.page}
            pageSize={results.page_size}
            total={results.total_matches}
            isCapped={results.is_capped}
            onPage={setPage}
          />
        </>
      )}

      {searchError && (
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--red, #ff3d57)' }}>
          {(searchError as any)?.response?.data?.detail ?? 'Search failed'}
        </div>
      )}
    </div>
  )
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatusBanner({ children, color, bg, border }: { children: React.ReactNode; color: string; bg: string; border: string }) {
  return (
    <div style={{
      padding: '10px 16px',
      background: bg,
      border: `1px solid ${border}`,
      borderRadius: 6,
      fontFamily: 'var(--font-mono)',
      fontSize: 11,
      color,
      letterSpacing: '0.06em',
      display: 'flex',
      alignItems: 'center',
      gap: 10,
    }}>
      {children}
    </div>
  )
}

function Spinner() {
  return (
    <span style={{
      display: 'inline-block',
      width: 10,
      height: 10,
      border: '2px solid currentColor',
      borderTopColor: 'transparent',
      borderRadius: '50%',
      animation: 'spin 0.8s linear infinite',
    }} />
  )
}

function MetaChip({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: 'flex', gap: 6, alignItems: 'baseline' }}>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', letterSpacing: '0.1em' }}>{label}</span>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-bright)' }}>{value}</span>
    </div>
  )
}

function ResultsMeta({ results }: { results: SearchResult }) {
  return (
    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', display: 'flex', gap: 12, alignItems: 'center' }}>
      {results.total_matches === 0
        ? 'No matches'
        : <>
            {results.is_capped
              ? <><span style={{ color: 'var(--yellow, #f5c518)' }}>⚠</span> Showing first {results.total_matches.toLocaleString()} matches — refine your filter to see more</>
              : <>{results.total_matches.toLocaleString()} match{results.total_matches !== 1 ? 'es' : ''}</>
            }
          </>
      }
    </div>
  )
}

function ResultsTable({ results }: { results: string[] }) {
  if (results.length === 0) return null
  return (
    <div style={{
      border: '1px solid var(--border)',
      borderRadius: 6,
      overflow: 'hidden',
      fontFamily: 'var(--font-mono)',
      fontSize: 12,
    }}>
      {results.map((line, i) => (
        <div
          key={i}
          style={{
            display: 'flex',
            gap: 0,
            background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)',
            borderBottom: i < results.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none',
          }}
        >
          <span style={{
            minWidth: 52,
            padding: '4px 10px',
            color: 'var(--text-dim)',
            fontSize: 10,
            userSelect: 'none',
            borderRight: '1px solid var(--border)',
            flexShrink: 0,
            textAlign: 'right',
          }}>
            {i + 1}
          </span>
          <span style={{
            padding: '4px 12px',
            color: 'var(--text)',
            whiteSpace: 'pre',
            overflowX: 'auto',
            wordBreak: 'break-all',
          }}>
            {line}
          </span>
        </div>
      ))}
    </div>
  )
}

function Pagination({ page, pageSize, total, isCapped, onPage }: {
  page: number
  pageSize: number
  total: number
  isCapped: boolean
  onPage: (p: number) => void
}) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  if (totalPages <= 1) return null
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
      <button
        onClick={() => onPage(page - 1)}
        disabled={page <= 1}
        style={styles.pageBtn}
      >
        ← Prev
      </button>
      <span style={{ color: 'var(--text-dim)' }}>
        Page {page} / {totalPages}{isCapped ? ' (capped)' : ''}
      </span>
      <button
        onClick={() => onPage(page + 1)}
        disabled={page >= totalPages}
        style={styles.pageBtn}
      >
        Next →
      </button>
    </div>
  )
}

// ── Styles ────────────────────────────────────────────────────────────────────

const styles = {
  center: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: 200,
  } as React.CSSProperties,
  dimMono: {
    fontFamily: 'var(--font-mono)',
    fontSize: 12,
    color: 'var(--text-dim)',
  } as React.CSSProperties,
  input: {
    flex: 1,
    background: 'var(--surface)',
    border: '1px solid var(--border2)',
    borderRadius: 4,
    color: 'var(--text)',
    fontFamily: 'var(--font-mono)',
    fontSize: 12,
    padding: '8px 12px',
    outline: 'none',
  } as React.CSSProperties,
  searchBtn: {
    background: 'var(--accent)',
    border: 'none',
    borderRadius: 4,
    color: '#000',
    fontFamily: 'var(--font-cond)',
    fontSize: 12,
    fontWeight: 600,
    letterSpacing: '0.08em',
    padding: '8px 20px',
    cursor: 'pointer',
    textTransform: 'uppercase',
    flexShrink: 0,
  } as React.CSSProperties,
  hint: {
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
    color: 'var(--text-dim)',
  } as React.CSSProperties,
  code: {
    background: 'rgba(255,255,255,0.06)',
    borderRadius: 3,
    padding: '1px 5px',
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
  } as React.CSSProperties,
  pageBtn: {
    background: 'none',
    border: '1px solid var(--border2)',
    borderRadius: 4,
    color: 'var(--text)',
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
    padding: '5px 12px',
    cursor: 'pointer',
  } as React.CSSProperties,
}
