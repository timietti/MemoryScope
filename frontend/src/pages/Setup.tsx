// frontend/src/pages/Setup.tsx
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { apiClient } from '../api/client'

type Step = 'welcome' | 'account' | 'ai' | 'finish'
const STEPS: Step[] = ['welcome', 'account', 'ai', 'finish']

interface WizardState {
  // account
  email: string
  display_name: string
  password: string
  password2: string
  // ai
  anthropic_api_key: string
  primary_model: string
  fast_model: string
}

const DEFAULTS: WizardState = {
  email: '',
  display_name: '',
  password: '',
  password2: '',
  anthropic_api_key: '',
  primary_model: 'claude-opus-4-5',
  fast_model: 'claude-sonnet-4-5',
}

// ── Shared input style ─────────────────────────────────────────────────────────

const inp: React.CSSProperties = {
  width: '100%', boxSizing: 'border-box',
  background: 'var(--bg)', border: '1px solid var(--border)',
  borderRadius: 4, color: 'var(--text)', fontFamily: 'var(--font-mono)',
  fontSize: 12, padding: '7px 10px', outline: 'none',
}

function Field({
  label, value, onChange, type = 'text', hint,
}: {
  label: string; value: string; onChange: (v: string) => void;
  type?: string; hint?: string;
}) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label style={{ display: 'block', fontFamily: 'var(--font-mono)', fontSize: 10,
        color: 'var(--text-dim)', letterSpacing: '0.1em', textTransform: 'uppercase',
        marginBottom: 5 }}>
        {label}
      </label>
      <input type={type} value={value} onChange={e => onChange(e.target.value)} style={inp} />
      {hint && <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', marginTop: 3 }}>{hint}</div>}
    </div>
  )
}

// ── Step panels ────────────────────────────────────────────────────────────────

function WelcomeStep() {
  return (
    <div style={{ textAlign: 'center', padding: '12px 0 24px' }}>
      <div style={{ fontSize: 40, marginBottom: 16 }}>🔬</div>
      <p style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text)',
        lineHeight: 1.6, margin: 0 }}>
        Welcome to <strong style={{ color: 'var(--text-bright)' }}>MemoryScope</strong>.
      </p>
      <p style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)',
        lineHeight: 1.7, marginTop: 12 }}>
        This wizard will help you create your admin account and configure the key
        settings needed to start analysing memory dumps. You can change everything
        later from the Admin panel.
      </p>
    </div>
  )
}

function AccountStep({ s, set }: { s: WizardState; set: (k: keyof WizardState, v: string) => void }) {
  return (
    <>
      <Field label="Email"        value={s.email}        onChange={v => set('email', v)} type="email" />
      <Field label="Display Name" value={s.display_name} onChange={v => set('display_name', v)} />
      <Field label="Password"     value={s.password}     onChange={v => set('password', v)} type="password" />
      <Field label="Confirm Password" value={s.password2} onChange={v => set('password2', v)} type="password" />
    </>
  )
}

function AIStep({ s, set }: { s: WizardState; set: (k: keyof WizardState, v: string) => void }) {
  return (
    <>
      <Field label="Anthropic API Key" value={s.anthropic_api_key} onChange={v => set('anthropic_api_key', v)}
        type="password" hint="Required for AI analysis. Leave blank to configure later." />
      <Field label="Primary Model" value={s.primary_model} onChange={v => set('primary_model', v)}
        hint="Used for the main analysis report." />
      <Field label="Fast Model"    value={s.fast_model}    onChange={v => set('fast_model', v)}
        hint="Used for sub-agents and summarisation." />
    </>
  )
}


function FinishStep({ summary }: { summary: WizardState }) {
  const Row = ({ label, value }: { label: string; value: string }) => (
    <div style={{ display: 'flex', gap: 12, fontFamily: 'var(--font-mono)', fontSize: 11,
      padding: '4px 0', borderBottom: '1px solid var(--border2)' }}>
      <span style={{ color: 'var(--text-dim)', minWidth: 160 }}>{label}</span>
      <span style={{ color: 'var(--text)', wordBreak: 'break-all' }}>{value || '—'}</span>
    </div>
  )
  return (
    <div>
      <p style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)', marginBottom: 16 }}>
        Review your settings and click <strong style={{ color: 'var(--text)' }}>Launch MemoryScope</strong> to complete setup.
      </p>
      <Row label="Admin Email"      value={summary.email} />
      <Row label="Display Name"     value={summary.display_name} />
      <Row label="Anthropic Key"    value={summary.anthropic_api_key ? '••••••••' : '(not set)'} />
      <Row label="Primary Model"    value={summary.primary_model} />
      <Row label="Fast Model"       value={summary.fast_model} />
    </div>
  )
}

// ── Validation ────────────────────────────────────────────────────────────────

function validate(step: Step, s: WizardState): string | null {
  if (step === 'account') {
    if (!s.email)        return 'Email is required'
    if (!s.display_name) return 'Display name is required'
    if (!s.password)     return 'Password is required'
    if (s.password.length < 8) return 'Password must be at least 8 characters'
    if (s.password !== s.password2) return 'Passwords do not match'
  }
  if (step === 'ai') {
    if (!s.primary_model) return 'Primary model is required'
    if (!s.fast_model)    return 'Fast model is required'
  }
  return null
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function Setup() {
  const navigate = useNavigate()
  const [step, setStep] = useState<Step>('welcome')
  const [state, setState] = useState<WizardState>(DEFAULTS)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const stepIdx = STEPS.indexOf(step)
  const isLast  = step === 'finish'

  function set(k: keyof WizardState, v: string) {
    setState(prev => ({ ...prev, [k]: v }))
  }

  function handleNext() {
    const err = validate(step, state)
    if (err) { setError(err); return }
    setError('')
    const next = STEPS[stepIdx + 1]
    if (next) setStep(next)
  }

  function handleBack() {
    setError('')
    const prev = STEPS[stepIdx - 1]
    if (prev) setStep(prev)
  }

  async function handleSubmit() {
    setError('')
    setSubmitting(true)
    try {
      const { data } = await apiClient.post('/setup/complete', {
        email:             state.email,
        display_name:      state.display_name,
        password:          state.password,
        anthropic_api_key: state.anthropic_api_key,
        primary_model:     state.primary_model,
        fast_model:        state.fast_model,
      })
      localStorage.setItem('access_token',  data.access_token)
      localStorage.setItem('refresh_token', data.refresh_token)
      navigate('/cases', { replace: true })
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg ?? 'Setup failed. Please check your values and try again.')
    } finally {
      setSubmitting(false)
    }
  }

  const STEP_LABELS: Record<Step, string> = {
    welcome:    'Welcome',
    account:    'Admin Account',
    ai:         'AI Provider',
    finish:     'Finish',
  }

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
      <div style={{ width: 480, background: 'var(--surface)',
        border: '1px solid var(--border)', borderRadius: 10, padding: '40px 40px 32px' }}>

        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{ fontFamily: 'var(--font-cond)', fontSize: 26, fontWeight: 700,
            color: 'var(--text-bright)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
            Memory<span style={{ color: 'var(--accent)' }}>Scope</span>
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)',
            letterSpacing: '0.18em', marginTop: 4 }}>
            INITIAL SETUP
          </div>
        </div>

        {/* Step indicator */}
        <div style={{ display: 'flex', justifyContent: 'center', gap: 6, marginBottom: 28 }}>
          {STEPS.map((s, i) => (
            <div key={s} style={{
              width: 28, height: 4, borderRadius: 2,
              background: i <= stepIdx ? 'var(--accent)' : 'var(--border)',
              transition: 'background 0.2s',
            }} />
          ))}
        </div>

        {/* Step title */}
        <div style={{ fontFamily: 'var(--font-cond)', fontSize: 15, fontWeight: 700,
          letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-bright)',
          marginBottom: 20 }}>
          {STEP_LABELS[step]}
        </div>

        {/* Step content */}
        {step === 'welcome'    && <WelcomeStep />}
        {step === 'account'    && <AccountStep s={state} set={set} />}
        {step === 'ai'         && <AIStep      s={state} set={set} />}
        {step === 'finish'     && <FinishStep summary={state} />}

        {/* Error */}
        {error && (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--red)',
            marginBottom: 14 }}>
            {error}
          </div>
        )}

        {/* Navigation */}
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8 }}>
          <button
            onClick={handleBack}
            disabled={stepIdx === 0}
            style={{
              background: 'none', border: '1px solid var(--border)', borderRadius: 4,
              color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 12,
              padding: '8px 20px', cursor: stepIdx === 0 ? 'default' : 'pointer',
              opacity: stepIdx === 0 ? 0.3 : 1,
            }}>
            Back
          </button>

          {isLast ? (
            <button
              onClick={handleSubmit}
              disabled={submitting}
              style={{
                background: 'var(--accent)', border: 'none', borderRadius: 4,
                color: '#000', fontFamily: 'var(--font-cond)', fontSize: 13,
                fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase',
                padding: '9px 28px', cursor: submitting ? 'default' : 'pointer',
                opacity: submitting ? 0.6 : 1,
              }}>
              {submitting ? 'Setting up…' : 'Launch MemoryScope'}
            </button>
          ) : (
            <button
              onClick={handleNext}
              style={{
                background: 'var(--accent)', border: 'none', borderRadius: 4,
                color: '#000', fontFamily: 'var(--font-cond)', fontSize: 13,
                fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase',
                padding: '9px 28px', cursor: 'pointer',
              }}>
              Next
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
