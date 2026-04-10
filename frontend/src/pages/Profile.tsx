// frontend/src/pages/Profile.tsx
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { authApi } from '../api/client'

export default function Profile() {
  const qc = useQueryClient()

  const { data: me, isLoading } = useQuery({
    queryKey: ['me'],
    queryFn: () => authApi.me(),
    staleTime: 60_000,
  })

  // Profile info state
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [username, setUsername] = useState('')
  const [profileInited, setProfileInited] = useState(false)

  // Populate form once data arrives
  if (me && !profileInited) {
    setDisplayName(me.display_name)
    setEmail(me.email)
    setUsername(me.username ?? '')
    setProfileInited(true)
  }

  // Password state
  const [currentPw, setCurrentPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [confirmPw, setConfirmPw] = useState('')

  const [profileMsg, setProfileMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null)
  const [pwMsg, setPwMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null)

  const updateMutation = useMutation({
    mutationFn: authApi.updateMe,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['me'] })
    },
  })

  const handleProfileSave = async () => {
    setProfileMsg(null)
    try {
      await updateMutation.mutateAsync({
        display_name: displayName.trim(),
        email: email.trim(),
        username: username.trim() || undefined,
      })
      setProfileMsg({ type: 'ok', text: 'Profile updated.' })
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? 'Update failed.'
      setProfileMsg({ type: 'err', text: msg })
    }
  }

  const handlePasswordSave = async () => {
    setPwMsg(null)
    if (newPw !== confirmPw) {
      setPwMsg({ type: 'err', text: 'New passwords do not match.' })
      return
    }
    if (newPw.length < 8) {
      setPwMsg({ type: 'err', text: 'Password must be at least 8 characters.' })
      return
    }
    try {
      await updateMutation.mutateAsync({
        current_password: currentPw,
        new_password: newPw,
      })
      setCurrentPw('')
      setNewPw('')
      setConfirmPw('')
      setPwMsg({ type: 'ok', text: 'Password changed.' })
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? 'Update failed.'
      setPwMsg({ type: 'err', text: msg })
    }
  }

  if (isLoading || !me) {
    return (
      <div style={{ padding: 40, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
        Loading…
      </div>
    )
  }

  const isSso = !!me.sso_provider

  return (
    <div style={{ padding: '40px 48px', maxWidth: 600 }}>
      <h1 style={{
        fontFamily: 'var(--font-cond)',
        fontSize: 22,
        fontWeight: 700,
        letterSpacing: '0.06em',
        textTransform: 'uppercase',
        color: 'var(--text-bright)',
        marginBottom: 32,
      }}>
        Profile
      </h1>

      {/* Profile info */}
      <Section title="Account Details">
        <Field label="Display Name">
          <input
            value={displayName}
            onChange={e => setDisplayName(e.target.value)}
            style={inputStyle}
          />
        </Field>
        <Field label="Email">
          <input
            value={email}
            onChange={e => setEmail(e.target.value)}
            style={inputStyle}
          />
        </Field>
        <Field label="Username">
          <input
            value={username}
            onChange={e => setUsername(e.target.value)}
            style={inputStyle}
            placeholder="Used to log in"
          />
        </Field>
        <Field label="Role">
          <div style={{ ...inputStyle, background: 'none', border: 'none', paddingLeft: 0,
            color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 11,
            textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            {me.role}
          </div>
        </Field>
        {isSso && (
          <Field label="SSO Provider">
            <div style={{ ...inputStyle, background: 'none', border: 'none', paddingLeft: 0,
              color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
              {me.sso_provider}
            </div>
          </Field>
        )}
        {profileMsg && <Feedback msg={profileMsg} />}
        <div style={{ marginTop: 20 }}>
          <SaveButton
            onClick={handleProfileSave}
            loading={updateMutation.isPending}
            label="Save Changes"
          />
        </div>
      </Section>

      {/* Password change */}
      {!isSso && (
        <Section title="Change Password" style={{ marginTop: 36 }}>
          <Field label="Current Password">
            <input
              type="password"
              value={currentPw}
              onChange={e => setCurrentPw(e.target.value)}
              style={inputStyle}
            />
          </Field>
          <Field label="New Password">
            <input
              type="password"
              value={newPw}
              onChange={e => setNewPw(e.target.value)}
              style={inputStyle}
            />
          </Field>
          <Field label="Confirm New Password">
            <input
              type="password"
              value={confirmPw}
              onChange={e => setConfirmPw(e.target.value)}
              style={inputStyle}
            />
          </Field>
          {pwMsg && <Feedback msg={pwMsg} />}
          <div style={{ marginTop: 20 }}>
            <SaveButton
              onClick={handlePasswordSave}
              loading={updateMutation.isPending}
              label="Change Password"
            />
          </div>
        </Section>
      )}
    </div>
  )
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Section({ title, children, style }: {
  title: string
  children: React.ReactNode
  style?: React.CSSProperties
}) {
  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderRadius: 6,
      padding: '24px 28px',
      ...style,
    }}>
      <div style={{
        fontFamily: 'var(--font-cond)',
        fontSize: 11,
        fontWeight: 600,
        letterSpacing: '0.12em',
        textTransform: 'uppercase',
        color: 'var(--text-dim)',
        marginBottom: 20,
        borderBottom: '1px solid var(--border)',
        paddingBottom: 10,
      }}>
        {title}
      </div>
      {children}
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 10,
        color: 'var(--text-dim)',
        letterSpacing: '0.1em',
        textTransform: 'uppercase',
        marginBottom: 6,
      }}>
        {label}
      </div>
      {children}
    </div>
  )
}

function Feedback({ msg }: { msg: { type: 'ok' | 'err'; text: string } }) {
  return (
    <div style={{
      marginTop: 12,
      fontFamily: 'var(--font-mono)',
      fontSize: 11,
      color: msg.type === 'ok' ? 'var(--green)' : 'var(--red)',
    }}>
      {msg.text}
    </div>
  )
}

function SaveButton({ onClick, loading, label }: {
  onClick: () => void
  loading: boolean
  label: string
}) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      style={{
        background: 'var(--accent)',
        color: '#000',
        border: 'none',
        borderRadius: 4,
        fontFamily: 'var(--font-cond)',
        fontSize: 12,
        fontWeight: 700,
        letterSpacing: '0.1em',
        textTransform: 'uppercase',
        padding: '8px 20px',
        cursor: loading ? 'not-allowed' : 'pointer',
        opacity: loading ? 0.6 : 1,
      }}
    >
      {loading ? 'Saving…' : label}
    </button>
  )
}

const inputStyle: React.CSSProperties = {
  width: '100%',
  background: 'var(--bg)',
  border: '1px solid var(--border2)',
  borderRadius: 4,
  color: 'var(--text)',
  fontFamily: 'var(--font-mono)',
  fontSize: 12,
  padding: '8px 12px',
  boxSizing: 'border-box',
  outline: 'none',
}
