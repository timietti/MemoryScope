// frontend/src/pages/Admin.tsx
import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { adminApi } from '../api/client'
import type { AdminUser, AdminSettings, SystemHealth } from '../types'

type Tab = 'users' | 'settings' | 'system'

export default function Admin() {
  const [tab, setTab] = useState<Tab>('users')

  return (
    <div style={{ padding: '32px 40px', maxWidth: 1100 }}>
      <h1 style={{ fontFamily: 'var(--font-cond)', fontSize: 24, fontWeight: 700,
        letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-bright)',
        marginBottom: 24 }}>
        Administration
      </h1>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid var(--border)', marginBottom: 28 }}>
        {(['users', 'settings', 'system'] as Tab[]).map(t => (
          <button key={t} onClick={() => setTab(t)} style={{
            background: tab === t ? 'var(--surface)' : 'none',
            border: '1px solid var(--border)',
            borderBottom: tab === t ? '1px solid var(--surface)' : '1px solid var(--border)',
            marginBottom: tab === t ? -1 : 0,
            color: tab === t ? 'var(--accent)' : 'var(--text-dim)',
            fontFamily: 'var(--font-cond)',
            fontSize: 12,
            letterSpacing: '0.1em',
            textTransform: 'uppercase',
            padding: '8px 18px',
            cursor: 'pointer',
            borderRadius: '4px 4px 0 0',
          }}>
            {t === 'users' ? 'Users' : t === 'settings' ? 'Settings' : 'System'}
          </button>
        ))}
      </div>

      {tab === 'users' && <UsersTab />}
      {tab === 'settings' && <SettingsTab />}
      {tab === 'system' && <SystemTab />}
    </div>
  )
}


// ── Users Tab ────────────────────────────────────────────────────────────────

function UsersTab() {
  const qc = useQueryClient()
  const { data: users = [], isLoading } = useQuery<AdminUser[]>({
    queryKey: ['admin', 'users'],
    queryFn: () => adminApi.users.list(),
  })

  const [showCreate, setShowCreate] = useState(false)
  const [editUser, setEditUser] = useState<AdminUser | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)

  const deleteMutation = useMutation({
    mutationFn: (id: string) => adminApi.users.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      setConfirmDelete(null)
    },
  })

  if (isLoading) return <Spinner />

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>
          {users.length} user{users.length !== 1 ? 's' : ''}
        </span>
        <button onClick={() => setShowCreate(true)} style={btnStyle('accent')}>
          + New User
        </button>
      </div>

      <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)' }}>
            {['Display Name', 'Email', 'Role', 'Active', 'Last Login', 'Actions'].map(h => (
              <th key={h} style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--text-dim)',
                letterSpacing: '0.08em', fontWeight: 600, textTransform: 'uppercase', fontSize: 10 }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {users.map(u => (
            <tr key={u.id} style={{ borderBottom: '1px solid var(--border2)' }}>
              <td style={td()}>{u.display_name}</td>
              <td style={td()}>{u.email}</td>
              <td style={td()}>
                <RoleBadge role={u.role} />
              </td>
              <td style={td()}>
                <span style={{ color: u.is_active ? 'var(--green)' : 'var(--red)' }}>
                  {u.is_active ? 'Yes' : 'No'}
                </span>
              </td>
              <td style={{ ...td(), color: 'var(--text-dim)' }}>
                {u.last_login_at ? new Date(u.last_login_at).toLocaleDateString() : '—'}
              </td>
              <td style={td()}>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button onClick={() => setEditUser(u)} style={btnStyle('dim')}>Edit</button>
                  {confirmDelete === u.id ? (
                    <>
                      <button onClick={() => deleteMutation.mutate(u.id)} style={btnStyle('danger')}>Confirm</button>
                      <button onClick={() => setConfirmDelete(null)} style={btnStyle('dim')}>Cancel</button>
                    </>
                  ) : (
                    <button onClick={() => setConfirmDelete(u.id)} style={btnStyle('danger')}>Delete</button>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {showCreate && <CreateUserModal onClose={() => setShowCreate(false)} />}
      {editUser && <EditUserModal user={editUser} onClose={() => setEditUser(null)} />}
    </div>
  )
}

function CreateUserModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({ email: '', display_name: '', password: '', role: 'analyst' })
  const [error, setError] = useState('')

  const mutation = useMutation({
    mutationFn: () => adminApi.users.create(form),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      onClose()
    },
    onError: (e: any) => setError(e?.response?.data?.detail ?? 'Failed to create user'),
  })

  return (
    <Modal title="New User" onClose={onClose}>
      <Field label="Email">
        <input style={inputStyle()} value={form.email}
          onChange={e => setForm(f => ({ ...f, email: e.target.value }))} />
      </Field>
      <Field label="Display Name">
        <input style={inputStyle()} value={form.display_name}
          onChange={e => setForm(f => ({ ...f, display_name: e.target.value }))} />
      </Field>
      <Field label="Password">
        <input type="password" style={inputStyle()} value={form.password}
          onChange={e => setForm(f => ({ ...f, password: e.target.value }))} />
      </Field>
      <Field label="Role">
        <select style={inputStyle()} value={form.role}
          onChange={e => setForm(f => ({ ...f, role: e.target.value }))}>
          <option value="analyst">Analyst</option>
          <option value="admin">Admin</option>
        </select>
      </Field>
      {error && <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 8 }}>{error}</div>}
      <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
        <button onClick={() => mutation.mutate()} disabled={mutation.isPending} style={btnStyle('accent')}>
          {mutation.isPending ? 'Creating…' : 'Create'}
        </button>
        <button onClick={onClose} style={btnStyle('dim')}>Cancel</button>
      </div>
    </Modal>
  )
}

function EditUserModal({ user, onClose }: { user: AdminUser; onClose: () => void }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({
    display_name: user.display_name,
    role: user.role,
    is_active: user.is_active,
    password: '',
  })
  const [error, setError] = useState('')

  const mutation = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = {
        display_name: form.display_name,
        role: form.role,
        is_active: form.is_active,
      }
      if (form.password) body.password = form.password
      return adminApi.users.update(user.id, body)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      onClose()
    },
    onError: (e: any) => setError(e?.response?.data?.detail ?? 'Failed to update user'),
  })

  return (
    <Modal title={`Edit: ${user.email}`} onClose={onClose}>
      <Field label="Display Name">
        <input style={inputStyle()} value={form.display_name}
          onChange={e => setForm(f => ({ ...f, display_name: e.target.value }))} />
      </Field>
      <Field label="Role">
        <select style={inputStyle()} value={form.role}
          onChange={e => setForm(f => ({ ...f, role: e.target.value as any }))}>
          <option value="analyst">Analyst</option>
          <option value="admin">Admin</option>
        </select>
      </Field>
      <Field label="Active">
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
          <input type="checkbox" checked={form.is_active}
            onChange={e => setForm(f => ({ ...f, is_active: e.target.checked }))} />
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>Account active</span>
        </label>
      </Field>
      <Field label="New Password (leave blank to keep)">
        <input type="password" style={inputStyle()} value={form.password}
          onChange={e => setForm(f => ({ ...f, password: e.target.value }))} />
      </Field>
      {error && <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 8 }}>{error}</div>}
      <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
        <button onClick={() => mutation.mutate()} disabled={mutation.isPending} style={btnStyle('accent')}>
          {mutation.isPending ? 'Saving…' : 'Save'}
        </button>
        <button onClick={onClose} style={btnStyle('dim')}>Cancel</button>
      </div>
    </Modal>
  )
}


// ── Settings Tab ─────────────────────────────────────────────────────────────

function SettingsTab() {
  const qc = useQueryClient()
  const { data: s, isLoading } = useQuery<AdminSettings>({
    queryKey: ['admin', 'settings'],
    queryFn: () => adminApi.settings.get(),
  })
  const [edits, setEdits] = useState<Record<string, string | number>>({})
  const [saved, setSaved] = useState(false)

  const mutation = useMutation({
    mutationFn: () => adminApi.settings.patch(edits),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'settings'] })
      setEdits({})
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    },
  })

  if (isLoading || !s) return <Spinner />

  const set = (key: string, val: string | number) => setEdits(p => ({ ...p, [key]: val }))

  const ro = (label: string, value: string) => (
    <SettingRow label={label}><ReadOnly>{value}</ReadOnly></SettingRow>
  )
  const num = (key: keyof AdminSettings, label: string) => (
    <SettingRow label={label}>
      <input type="number" style={inputStyle()} value={edits[key] !== undefined ? edits[key] : (s[key] as number)}
        onChange={e => set(key, Number(e.target.value))} />
    </SettingRow>
  )
  const str = (key: keyof AdminSettings, label: string) => (
    <SettingRow label={label}>
      <input style={{ ...inputStyle(), width: 320 }} value={edits[key] !== undefined ? String(edits[key]) : String(s[key])}
        onChange={e => set(key, e.target.value)} />
    </SettingRow>
  )
  const secret = (key: string, label: string, currentMasked: string) => (
    <SettingRow label={label}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flex: 1 }}>
        <input type="password" placeholder={currentMasked}
          style={{ ...inputStyle(), width: 260 }}
          value={edits[key] !== undefined ? String(edits[key]) : ''}
          onChange={e => set(key, e.target.value)} />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
          {currentMasked}
        </span>
      </div>
    </SettingRow>
  )

  return (
    <div>
      <SectionHeader>App</SectionHeader>
      {ro('Environment', s.env)}
      {ro('API Prefix', s.api_prefix)}
      {secret('secret_key', 'SECRET_KEY', s.secret_key)}

      <SectionHeader>Database</SectionHeader>
      {ro('DATABASE_URL', s.database_url)}

      <SectionHeader>Redis</SectionHeader>
      {ro('REDIS_URL', s.redis_url)}

      <SectionHeader>Storage</SectionHeader>
      {ro('S3 Endpoint', s.s3_endpoint)}
      {ro('Bucket: Dumps', s.s3_bucket_dumps)}
      {ro('Bucket: Reports', s.s3_bucket_reports)}
      {secret('s3_access_key', 'S3_ACCESS_KEY', s.s3_access_key)}
      {secret('s3_secret_key', 'S3_SECRET_KEY', s.s3_secret_key)}

      <SectionHeader>Volatility</SectionHeader>
      {ro('Volatility Path', s.volatility_path)}
      {ro('Symbol Cache Path', s.symbol_cache_path)}
      {ro('dwarf2json Path', s.dwarf2json_path)}
      {ro('Worker Tmp Dir', s.worker_tmp_dir)}
      {num('plugin_timeout_seconds', 'Plugin Timeout (seconds)')}
      <SettingRow label="Max Dump Size (bytes)">
        <input type="number" style={inputStyle()}
          value={edits['max_dump_size_bytes'] !== undefined ? edits['max_dump_size_bytes'] : s.max_dump_size_bytes}
          onChange={e => set('max_dump_size_bytes', Number(e.target.value))} />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', marginLeft: 8 }}>
          ({(s.max_dump_size_bytes / 1024 ** 3).toFixed(0)} GB)
        </span>
      </SettingRow>

      <SectionHeader>AI</SectionHeader>
      {str('primary_model', 'Primary Model')}
      {str('fast_model', 'Fast Model')}
      {num('ai_max_context_tokens', 'Max Context Tokens')}
      {num('summarise_threshold_chars', 'Summarise Threshold (chars)')}
      {secret('anthropic_api_key', 'ANTHROPIC_API_KEY', s.anthropic_api_key)}
      {secret('openai_api_key', 'OPENAI_API_KEY', s.openai_api_key)}

      <SectionHeader>Enrichment</SectionHeader>
      {num('vt_rate_limit_per_min', 'VT Rate Limit (per min)')}
      {secret('virustotal_api_key', 'VIRUSTOTAL_API_KEY', s.virustotal_api_key)}

      <SectionHeader>Auth</SectionHeader>
      {ro('JWT Algorithm', s.jwt_algorithm)}
      {num('jwt_access_expire_minutes', 'Access Token Expiry (minutes)')}
      {num('jwt_refresh_expire_days', 'Refresh Token Expiry (days)')}

      <SectionHeader>Celery</SectionHeader>
      {num('celery_concurrency', 'Worker Concurrency')}

      <SectionHeader>Retention</SectionHeader>
      {num('dump_retention_days', 'Dump Retention (days)')}
      {num('report_retention_days', 'Report Retention (days)')}

      <div style={{ marginTop: 24, display: 'flex', gap: 10, alignItems: 'center' }}>
        <button onClick={() => mutation.mutate()}
          disabled={mutation.isPending || Object.keys(edits).length === 0}
          style={btnStyle('accent')}>
          {mutation.isPending ? 'Saving…' : 'Apply Changes'}
        </button>
        {saved && <span style={{ color: 'var(--green)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>Saved</span>}
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
          Runtime only — restart to persist to .env
        </span>
      </div>
    </div>
  )
}


// ── System Tab ───────────────────────────────────────────────────────────────

function SystemTab() {
  const { data: health, isLoading, refetch } = useQuery<SystemHealth>({
    queryKey: ['admin', 'system', 'health'],
    queryFn: () => adminApi.system.health(),
    refetchInterval: 15_000,
  })

  const restartMutation = useMutation({
    mutationFn: () => adminApi.system.restartWorkers(),
  })

  if (isLoading) return <Spinner />

  const StatusDot = ({ ok }: { ok: boolean }) => (
    <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
      background: ok ? 'var(--green)' : 'var(--red)', marginRight: 8 }} />
  )

  return (
    <div style={{ display: 'grid', gap: 24 }}>
      <div>
        <SectionHeader>Service Status</SectionHeader>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 12 }}>
          <StatCard label="API">
            <StatusDot ok={health?.api === 'ok'} />
            {health?.api ?? '—'}
          </StatCard>
          <StatCard label="Database">
            <StatusDot ok={health?.database === 'ok'} />
            {health?.database ?? '—'}
          </StatCard>
          <StatCard label="Celery Workers">
            <span style={{ color: (health?.worker_count ?? 0) > 0 ? 'var(--green)' : 'var(--yellow)' }}>
              {health?.worker_count ?? 0} active
            </span>
          </StatCard>
        </div>
      </div>

      <div>
        <SectionHeader>Statistics</SectionHeader>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 12 }}>
          <StatCard label="Total Cases">{health?.total_cases ?? 0}</StatCard>
          <StatCard label="Total Reports">{health?.total_reports ?? 0}</StatCard>
        </div>
      </div>

      <div>
        <SectionHeader>Environment</SectionHeader>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, display: 'grid', gap: 6 }}>
          <div><span style={{ color: 'var(--text-dim)', minWidth: 140, display: 'inline-block' }}>Platform</span>{health?.platform}</div>
          <div><span style={{ color: 'var(--text-dim)', minWidth: 140, display: 'inline-block' }}>Python</span>{health?.python_version}</div>
        </div>
      </div>

      <div>
        <SectionHeader>Actions</SectionHeader>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <button onClick={() => refetch()} style={btnStyle('dim')}>Refresh Status</button>
          <button
            onClick={() => { if (window.confirm('Send restart signal to all Celery workers?')) restartMutation.mutate() }}
            disabled={restartMutation.isPending}
            style={btnStyle('warning')}>
            {restartMutation.isPending ? 'Sending…' : 'Restart Workers'}
          </button>
        </div>
        {restartMutation.isSuccess && (
          <div style={{ marginTop: 8, color: 'var(--green)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            Restart signal sent to workers.
          </div>
        )}
      </div>
    </div>
  )
}


// ── Shared components ─────────────────────────────────────────────────────────

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex',
      alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
      <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6,
        padding: 28, minWidth: 400, maxWidth: 520 }}>
        <h2 style={{ fontFamily: 'var(--font-cond)', fontSize: 16, letterSpacing: '0.06em',
          textTransform: 'uppercase', color: 'var(--text-bright)', marginBottom: 20 }}>
          {title}
        </h2>
        {children}
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <label style={{ display: 'block', fontFamily: 'var(--font-mono)', fontSize: 10,
        color: 'var(--text-dim)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 6 }}>
        {label}
      </label>
      {children}
    </div>
  )
}

function SettingRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '8px 0',
      borderBottom: '1px solid var(--border2)' }}>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)',
        minWidth: 220 }}>{label}</span>
      {children}
    </div>
  )
}

function SectionHeader({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ fontFamily: 'var(--font-cond)', fontSize: 11, fontWeight: 700, letterSpacing: '0.12em',
      textTransform: 'uppercase', color: 'var(--text-dim)', marginTop: 20, marginBottom: 10,
      paddingBottom: 4, borderBottom: '1px solid var(--border)' }}>
      {children}
    </div>
  )
}

function StatCard({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 4,
      padding: '14px 16px' }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)',
        letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 8 }}>{label}</div>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 16, color: 'var(--text-bright)' }}>
        {children}
      </div>
    </div>
  )
}

function RoleBadge({ role }: { role: string }) {
  const color = role === 'admin' ? 'var(--accent)' : role === 'analyst' ? 'var(--accent2)' : 'var(--text-dim)'
  return (
    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: '0.08em',
      textTransform: 'uppercase', color, border: `1px solid ${color}`, borderRadius: 3,
      padding: '1px 6px' }}>
      {role}
    </span>
  )
}

function ReadOnly({ children }: { children: React.ReactNode }) {
  return (
    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>
      {children}
    </span>
  )
}

function Spinner() {
  return (
    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)', padding: 20 }}>
      Loading…
    </div>
  )
}

// ── Style helpers ─────────────────────────────────────────────────────────────

function inputStyle(): React.CSSProperties {
  return {
    background: 'var(--bg)',
    border: '1px solid var(--border)',
    borderRadius: 4,
    color: 'var(--text)',
    fontFamily: 'var(--font-mono)',
    fontSize: 12,
    padding: '6px 10px',
    width: '100%',
    boxSizing: 'border-box',
  }
}

function btnStyle(variant: 'accent' | 'dim' | 'danger' | 'warning'): React.CSSProperties {
  const colors = {
    accent:  { color: 'var(--accent)',   border: 'var(--accent)' },
    dim:     { color: 'var(--text-dim)', border: 'var(--border)' },
    danger:  { color: 'var(--red)',    border: 'var(--red)' },
    warning: { color: 'var(--yellow)',  border: 'var(--yellow)' },
  }
  const c = colors[variant]
  return {
    background: 'none',
    border: `1px solid ${c.border}`,
    borderRadius: 4,
    color: c.color,
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
    letterSpacing: '0.08em',
    padding: '5px 12px',
    cursor: 'pointer',
  }
}

function td(): React.CSSProperties {
  return { padding: '8px 10px', color: 'var(--text)' }
}
