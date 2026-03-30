// frontend/src/pages/AIStats.tsx
import { useQuery } from '@tanstack/react-query'
import { statsApi } from '../api/client'

export default function AIStats() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['stats', 'ai'],
    queryFn: statsApi.ai,
    staleTime: 60_000,
  })

  if (isLoading) return <LoadingShell />
  if (error || !data) return (
    <div style={{ padding: '32px 40px', fontFamily: 'var(--font-mono)', fontSize: 13 }}>
      <div style={{ color: 'var(--red)', marginBottom: 8 }}>Failed to load AI stats.</div>
      <div style={{ color: 'var(--text-dim)', fontSize: 11 }}>{String((error as any)?.message ?? error ?? '')}</div>
    </div>
  )

  const { daily, totals_30d: t, by_model, pricing_note } = data
  const maxCost = Math.max(...daily.map((d: any) => d.cost_usd), 0)

  // Compute a nice round Y-axis ceiling so tick labels are clean numbers
  const yTop = (() => {
    if (maxCost <= 0) return 0.01
    const mag = Math.pow(10, Math.floor(Math.log10(maxCost)))
    const norm = maxCost / mag
    const nice = norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10
    return nice * mag
  })()

  const fmtCost = (v: number) => {
    if (v === 0) return '$0'
    if (v < 0.001) return `$${v.toFixed(6)}`
    if (v < 0.01)  return `$${v.toFixed(5)}`
    if (v < 0.1)   return `$${v.toFixed(4)}`
    if (v < 1)     return `$${v.toFixed(3)}`
    return `$${v.toFixed(2)}`
  }

  return (
    <div style={{ padding: '32px 40px', maxWidth: 1000 }}>
      {/* Header */}
      <div style={{ marginBottom: 32 }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent)', letterSpacing: '0.15em', marginBottom: 6 }}>AI RESOURCES</div>
        <h1 style={{ fontFamily: 'var(--font-cond)', fontSize: 28, fontWeight: 600, color: 'var(--text-bright)' }}>Usage & Cost</h1>
        <p style={{ color: 'var(--text-dim)', marginTop: 6, fontSize: 13 }}>Last 30 days · {pricing_note}</p>
      </div>

      {/* Summary cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 32 }}>
        <StatCard label="Total Cost (30d)"    value={`$${t.cost_usd.toFixed(4)}`}          accent />
        <StatCard label="Total Tokens (30d)"  value={fmtNum(t.total_tokens)}               />
        <StatCard label="Cases Analyzed"      value={String(t.cases_analyzed)}             />
        <StatCard label="Avg Cost / Case"     value={t.cases_analyzed ? `$${t.avg_cost_per_case.toFixed(4)}` : '—'} />
      </div>

      {/* Debug: show report count if no tokens recorded */}
      {t.total_tokens === 0 && t.report_count != null && (
        <div style={{ marginBottom: 16, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, padding: '10px 16px' }}>
          {t.report_count === 0
            ? 'No completed reports found in the last 30 days. Run an AI analysis to populate this page.'
            : `${t.report_count} report(s) found but token_usage is not recorded (older reports generated before token tracking was added).`}
        </div>
      )}

      {/* Billing link */}
      <div style={{ marginBottom: 32 }}>
        <SectionLabel>API Billing</SectionLabel>
        <a
          href="https://console.anthropic.com/settings/billing"
          target="_blank"
          rel="noreferrer"
          style={{ display: 'inline-flex', alignItems: 'center', gap: 10, background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: '14px 20px', textDecoration: 'none', color: 'inherit' }}
        >
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text)' }}>View balance &amp; invoices at</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--accent)' }}>console.anthropic.com/settings/billing</span>
          <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>↗</span>
        </a>
      </div>

      {/* Daily cost chart */}
      <div style={{ marginBottom: 32 }}>
        <SectionLabel>Daily Cost — Last 30 Days</SectionLabel>
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: '20px 20px 12px' }}>
          <div style={{ display: 'flex', gap: 8 }}>
            {/* Y-axis labels */}
            <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', alignItems: 'flex-end', height: 120, flexShrink: 0 }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>{fmtCost(yTop)}</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>{fmtCost(yTop / 2)}</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>$0</span>
            </div>
            {/* Bars + x-axis */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
              <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 120, borderLeft: '1px solid var(--border2)' }}>
                {daily.map((d: any) => {
                  const h = Math.max((d.cost_usd / yTop) * 100, d.cost_usd > 0 ? 2 : 0)
                  return (
                    <div key={d.date} title={`${d.date}\n${fmtCost(d.cost_usd)}\n${fmtNum(d.input_tokens + d.output_tokens)} tokens\n${d.cases} case(s)`}
                      style={{ flex: 1, display: 'flex', alignItems: 'flex-end', height: '100%', cursor: 'default' }}>
                      <div style={{ width: '100%', height: `${h}%`, background: d.cost_usd > 0 ? 'var(--accent)' : 'var(--border)', borderRadius: '2px 2px 0 0', minHeight: 1, transition: 'height 0.3s ease' }} />
                    </div>
                  )
                })}
              </div>
              {/* X-axis labels — show first, middle, last */}
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6, paddingTop: 6, borderTop: '1px solid var(--border)' }}>
                {[daily[0], daily[14], daily[29]].map((d: any) => (
                  <span key={d.date} style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>
                    {d.date.slice(5)}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Daily token breakdown */}
      <div style={{ marginBottom: 32 }}>
        <SectionLabel>Daily Token Breakdown</SectionLabel>
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Date', 'Cases', 'Input Tokens', 'Output Tokens', 'Cost (USD)'].map(h => (
                  <th key={h} style={{ padding: '10px 16px', textAlign: 'left', fontWeight: 500, fontSize: 10, color: 'var(--text-dim)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[...daily].reverse().filter((d: any) => d.cases > 0).map((d: any) => (
                <tr key={d.date} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '9px 16px', color: 'var(--text-bright)' }}>{d.date}</td>
                  <td style={{ padding: '9px 16px', color: 'var(--text)' }}>{d.cases}</td>
                  <td style={{ padding: '9px 16px', color: 'var(--text)' }}>{fmtNum(d.input_tokens)}</td>
                  <td style={{ padding: '9px 16px', color: 'var(--text)' }}>{fmtNum(d.output_tokens)}</td>
                  <td style={{ padding: '9px 16px', color: 'var(--accent)' }}>${d.cost_usd.toFixed(4)}</td>
                </tr>
              ))}
              {daily.every((d: any) => d.cases === 0) && (
                <tr>
                  <td colSpan={5} style={{ padding: '20px 16px', color: 'var(--text-dim)', textAlign: 'center' }}>No analyses in the last 30 days</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Model breakdown */}
      {by_model.length > 0 && (
        <div>
          <SectionLabel>Usage by Model</SectionLabel>
          <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Model', 'Reports', 'Input Tokens', 'Output Tokens', 'Est. Cost'].map(h => (
                    <th key={h} style={{ padding: '10px 16px', textAlign: 'left', fontWeight: 500, fontSize: 10, color: 'var(--text-dim)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {by_model.map((m: any) => (
                  <tr key={m.model} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '9px 16px', color: 'var(--text-bright)' }}>{m.model}</td>
                    <td style={{ padding: '9px 16px', color: 'var(--text)' }}>{m.reports}</td>
                    <td style={{ padding: '9px 16px', color: 'var(--text)' }}>{fmtNum(m.input_tokens)}</td>
                    <td style={{ padding: '9px 16px', color: 'var(--text)' }}>{fmtNum(m.output_tokens)}</td>
                    <td style={{ padding: '9px 16px', color: 'var(--accent)' }}>${m.cost_usd.toFixed(4)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

function StatCard({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div style={{ background: 'var(--surface)', border: `1px solid ${accent ? 'rgba(0,200,255,0.2)' : 'var(--border)'}`, borderRadius: 8, padding: '16px 20px' }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 8 }}>{label}</div>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 22, fontWeight: 700, color: accent ? 'var(--accent)' : 'var(--text-bright)' }}>{value}</div>
    </div>
  )
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 10 }}>
      {children}
    </div>
  )
}

function LoadingShell() {
  return (
    <div style={{ padding: '32px 40px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', fontSize: 12 }}>
      Loading...
    </div>
  )
}

function fmtNum(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000)     return `${(n / 1_000).toFixed(1)}K`
  return String(n)
}
