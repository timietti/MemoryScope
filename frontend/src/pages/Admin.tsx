// frontend/src/pages/Admin.tsx
import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { adminApi } from '../api/client'
import type { AdminUser, AdminSettings, SystemHealth, StorageInfo } from '../types'

type Tab = 'users' | 'settings' | 'system' | 'logs'

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
        {(['users', 'settings', 'system', 'logs'] as Tab[]).map(t => (
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
            {t === 'users' ? 'Users' : t === 'settings' ? 'Settings' : t === 'system' ? 'System' : 'Logs'}
          </button>
        ))}
      </div>

      {tab === 'users' && <UsersTab />}
      {tab === 'settings' && <SettingsTab />}
      {tab === 'system' && <SystemTab />}
      {tab === 'logs' && <LogsTab />}
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
          <option value="viewer">Viewer</option>
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
          <option value="viewer">Viewer</option>
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


// ── Info tooltip ──────────────────────────────────────────────────────────────

const SETTING_DESCRIPTIONS: Record<string, string> = {
  // App
  env:        'Runtime environment: development, production, or test. Controls debug behaviour and logging verbosity.',
  api_prefix: 'URL prefix for all API routes (e.g. /api/v1). Changing this requires a frontend rebuild.',
  secret_key: 'Random secret used to sign JWT tokens. Changing it invalidates all active sessions.',
  // Database
  database_url: 'Full PostgreSQL async connection string (postgresql+asyncpg://). Restart required to take effect.',
  // Redis
  redis_url: 'Redis connection URL used by Celery as broker and result backend.',
  // Storage
  s3_endpoint:     'MinIO / S3 endpoint URL. Use http://localhost:9000 for local dev.',
  s3_bucket_dumps: 'Object storage bucket where raw memory dump files are stored.',
  s3_bucket_reports: 'Object storage bucket where generated PDF reports are stored.',
  s3_access_key:   'S3 / MinIO access key ID (username).',
  s3_secret_key:   'S3 / MinIO secret access key (password).',
  // Volatility
  volatility_path:      'Path to the Volatility 3 vol.py script.',
  symbol_cache_path:    'Directory where Volatility 3 ISF symbol tables are stored. Subdirectories linux/ and mac/ are used automatically.',
  dwarf2json_path:      'Path or name of the dwarf2json binary, used to build Linux ISF symbol tables from debug packages.',
  worker_tmp_dir:       'Temporary working directory for Celery workers. Must have enough space for the largest dump file.',
  plugin_timeout_seconds: 'Maximum seconds a single Volatility plugin is allowed to run before it is killed and marked as timed out.',
  max_dump_size_bytes:  'Maximum allowed upload size for memory dump files. Uploads exceeding this are rejected.',
  max_cases_per_hour_per_user: 'Maximum number of case submissions a single user can make per hour. Resets every 60 minutes.',
  // AI
  primary_model:            'Model used by the main orchestrator agent when Anthropic is the provider (e.g. claude-opus-4-6).',
  fast_model:               'Model used for sub-agents when Anthropic is the provider (e.g. claude-sonnet-4-6).',
  ai_max_context_tokens:    'Token budget passed to each AI call. Increase for very large plugin outputs; decrease to reduce cost.',
  summarise_threshold_chars: 'Plugin output longer than this character count is summarised before being sent to the AI to save tokens.',
  anthropic_api_key:    'Anthropic API key. When set, Anthropic Claude is used as the AI provider.',
  fallback_api_url:     'Base URL of an OpenAI-compatible endpoint used when Anthropic API key is empty (e.g. http://ollama:11434/v1). Leave empty to use the default OpenAI endpoint.',
  fallback_api_key:     'API key for the fallback endpoint. Use any non-empty string (e.g. "ollama") for local models that do not require authentication.',
  fallback_model:       'Model name to use with the fallback endpoint for both orchestrator and sub-agent calls (e.g. llama3.2, gpt-4o, mistral). The model must support tool/function calling.',
  // Enrichment
  vt_rate_limit_per_min: 'Maximum VirusTotal API requests per minute. Free tier is 4/min; paid tiers allow more.',
  vt_max_iocs:           'Maximum number of IOCs submitted to VirusTotal per enrichment run. Hashes are prioritised over IPs. Known-good hashes (CIRCL hashlookup) do not count toward this limit.',
  virustotal_api_key:    'VirusTotal API key for IOC enrichment lookups. Leave empty to disable enrichment.',
  // Auth
  jwt_algorithm:             'Algorithm used to sign JWT tokens (e.g. HS256). Changing requires all clients to re-authenticate.',
  jwt_access_expire_minutes: 'How long an access token remains valid before the client must refresh it.',
  jwt_refresh_expire_days:   'How long a refresh token remains valid. After expiry the user must log in again.',
  // Logging (read-only in settings, shown here for reference)
  log_file: 'Path to the rotating log file written by both the API and Celery workers. Shown in Admin → Logs → Application Log.',
  // MCP Server
  mcp_enabled: 'When enabled, the MCP (Model Context Protocol) server is accessible at /mcp/sse. Connect Claude Desktop or any MCP client to query cases, plugin outputs, IOCs, and reports without using the web UI. Toggling this takes effect immediately without a restart.',
  // Watch Folder
  watch_dir_enabled:       'When enabled, the worker polls the watch directory and automatically imports any new dump files as cases.',
  watch_dir:               'Absolute path to the directory the worker monitors for new dump files. The worker must have read access.',
  watch_dir_poll_interval: 'How often (in seconds) the worker checks the watch directory for new files.',
  watch_dir_stable_age:    'A file must remain unmodified for this many seconds before it is imported, to avoid reading a dump that is still being written.',
  // Celery
  celery_concurrency: 'Number of parallel worker processes per Celery worker node. Higher values consume more CPU and memory.',
  strings_max_workers: 'Maximum number of parallel processes used during strings extraction from a memory dump. Capped at the number of CPU cores available to the worker. Higher values reduce extraction time but increase CPU load during analysis.',
  // Retention
  dump_retention_days:   'Number of days raw dump files are kept in object storage before automatic deletion.',
  report_retention_days: 'Number of days generated reports are retained before automatic deletion.',
  // OIDC / SSO
  oidc_provider_name:         'Display name for the OIDC provider shown on the login page (e.g. "Okta", "Azure AD").',
  oidc_discovery_url:         'OIDC discovery endpoint URL (https://idp.example.com/.well-known/openid-configuration).',
  oidc_client_id:             'OAuth2 client ID registered with your OIDC provider.',
  oidc_client_secret:         'OAuth2 client secret registered with your OIDC provider. Keep this confidential.',
  oidc_redirect_uri:          'Redirect URI registered with the OIDC provider — must match exactly (e.g. https://app.example.com/api/v1/oidc/callback).',
  oidc_frontend_callback_url: 'Frontend URL the browser is redirected to after OIDC authentication completes.',
  oidc_role_claim:            'JWT claim name used for role/group mapping (e.g. "groups" or "roles").',
  oidc_admin_group:           'Group or role value in the OIDC token that grants admin access.',
  oidc_viewer_group:          'Group or role value in the OIDC token that grants viewer (read-only) access. Users matching neither admin nor viewer groups are provisioned as analysts.',
  oidc_jit_provisioning:      'When enabled, new user accounts are created automatically on first OIDC login if the email is not yet registered.',
  // LDAP / LDAPS
  ldap_enabled:           'Master switch for LDAP authentication. When enabled, login attempts are tried against the LDAP directory first.',
  ldap_url:               'LDAP server URL. Use ldap://host:389 for plain/StartTLS or ldaps://host:636 for LDAPS.',
  ldap_use_starttls:      'Upgrade a plain LDAP (ldap://) connection to TLS using StartTLS. Ignored for ldaps:// connections.',
  ldap_tls_verify:        'Verify the server TLS certificate. Disable only in development environments with self-signed certificates.',
  ldap_bind_dn:           'Distinguished Name of the service account used to search the directory (e.g. CN=memoryscope,OU=ServiceAccounts,DC=example,DC=com).',
  ldap_bind_password:     'Password for the service account. Stored encrypted.',
  ldap_base_dn:           'Base Distinguished Name for user searches (e.g. DC=example,DC=com).',
  ldap_user_filter:       'LDAP filter for locating users. {username} is replaced with whatever the user types in the login form. Use (mail={username}) if users log in with their full email address (recommended for FreeIPA/Active Directory). Use (uid={username}) or (sAMAccountName={username}) if users log in with a short username only.',
  ldap_attr_email:        'LDAP attribute holding the user\'s email address (default: mail).',
  ldap_attr_display_name: 'LDAP attribute used as the display name (default: displayName).',
  ldap_group_base_dn:     'Base DN for group membership searches. Defaults to Base DN if left empty.',
  ldap_admin_group:       'Full DN of the group whose members are granted the admin role (e.g. CN=MemoryScopeAdmins,OU=Groups,DC=example,DC=com).',
  ldap_analyst_group:     'Full DN of the group whose members are granted the analyst role.',
  ldap_viewer_group:      'Full DN of the group whose members are granted the viewer (read-only) role.',
  ldap_jit_provisioning:  'Automatically create a local user account on the first successful LDAP login. If disabled, users must be pre-created in MemoryScope.',
}

function InfoTip({ field }: { field: string }) {
  const [visible, setVisible] = useState(false)
  const desc = SETTING_DESCRIPTIONS[field]
  if (!desc) return null
  return (
    <div style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}>
      <button
        type="button"
        onMouseEnter={() => setVisible(true)}
        onMouseLeave={() => setVisible(false)}
        onClick={() => setVisible(v => !v)}
        style={{ background: 'none', border: '1px solid var(--border)', borderRadius: '50%',
          color: 'var(--text-dim)', cursor: 'pointer', width: 18, height: 18,
          fontFamily: 'var(--font-mono)', fontSize: 10, lineHeight: 1,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0, padding: 0 }}
      >i</button>
      {visible && (
        <div style={{ position: 'absolute', left: 22, top: '50%', transform: 'translateY(-50%)',
          background: 'var(--surface2)', border: '1px solid var(--border2)', borderRadius: 4,
          padding: '8px 12px', width: 300, zIndex: 200,
          fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text)',
          lineHeight: 1.5, boxShadow: '0 4px 16px rgba(0,0,0,0.5)' }}>
          {desc}
        </div>
      )}
    </div>
  )
}


// ── Settings Tab ─────────────────────────────────────────────────────────────

type PanelEdits = Record<string, string | number | boolean>

function usePanelMutation() {
  const qc = useQueryClient()
  const [edits, setEdits] = useState<PanelEdits>({})
  const [saved, setSaved] = useState(false)
  const mutation = useMutation({
    mutationFn: () => adminApi.settings.patch(edits),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'settings'] })
      setEdits({})
      setSaved(true)
      setTimeout(() => setSaved(false), 2500)
    },
  })
  const set = (k: string, v: string | number | boolean) => setEdits(p => ({ ...p, [k]: v }))
  const dirty = Object.keys(edits).length > 0
  const discard = () => setEdits({})
  return { edits, set, mutation, dirty, saved, discard }
}

function SettingPanel({ title, defaultOpen = false, note, children }: {
  title: string; defaultOpen?: boolean; note?: string; children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 4, overflow: 'hidden' }}>
      <button onClick={() => setOpen(o => !o)} style={{
        width: '100%', background: 'var(--surface2)', border: 'none', padding: '10px 16px',
        display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', textAlign: 'left',
        fontFamily: 'var(--font-cond)', fontSize: 11, fontWeight: 700, letterSpacing: '0.12em',
        textTransform: 'uppercase', color: 'var(--text-dim)',
      }}>
        <span style={{ fontSize: 8, opacity: 0.7 }}>{open ? '▼' : '▶'}</span>
        {title}
      </button>
      {open && (
        <div style={{ padding: '8px 16px 16px', background: 'var(--surface)' }}>
          {note && (
            <div style={{
              margin: '8px 0 4px', padding: '7px 10px', borderRadius: 4,
              border: '1px solid rgba(255,200,0,0.3)',
              fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--yellow)', lineHeight: 1.5,
            }}>
              {note}
            </div>
          )}
          {children}
        </div>
      )}
    </div>
  )
}

function SaveBar({ mutation, dirty, saved, onDiscard }: {
  mutation: { mutate: () => void; isPending: boolean };
  dirty: boolean; saved: boolean; onDiscard: () => void;
}) {
  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 16,
      paddingTop: 12, borderTop: '1px solid var(--border2)' }}>
      <button onClick={() => mutation.mutate()} disabled={mutation.isPending || !dirty}
        style={btnStyle('accent')}>
        {mutation.isPending ? 'Saving…' : 'Save'}
      </button>
      {dirty && <button onClick={onDiscard} style={btnStyle('dim')}>Discard</button>}
      {saved && <span style={{ color: 'var(--green)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>Saved</span>}
    </div>
  )
}

function TFRow({ label, field, value, onChange, placeholder }: {
  label: string; field: string; value: string; onChange: (v: string) => void; placeholder?: string;
}) {
  return (
    <SettingRow label={label} field={field}>
      <input style={{ ...inputStyle(), width: 320 }} value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} />
    </SettingRow>
  )
}

function NFRow({ label, field, value, onChange, suffix }: {
  label: string; field: string; value: number; onChange: (v: number) => void; suffix?: string;
}) {
  return (
    <SettingRow label={label} field={field}>
      <input type="number" style={inputStyle()} value={value} onChange={e => onChange(Number(e.target.value))} />
      {suffix && <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', marginLeft: 6 }}>{suffix}</span>}
    </SettingRow>
  )
}

function SFRow({ label, field, hasCurrent, editValue, edited, onChange }: {
  label: string; field: string; hasCurrent: boolean; editValue: string; edited: boolean; onChange: (v: string) => void;
}) {
  const [revealed, setRevealed] = useState(false)
  const isClearing = hasCurrent && edited && editValue === ''
  return (
    <SettingRow label={label} field={field}>
      <div style={{ display: 'flex', gap: 6, alignItems: 'center', flex: 1 }}>
        <input
          type={revealed ? 'text' : 'password'}
          placeholder={hasCurrent && !isClearing ? '••••••••' : '(not set)'}
          style={{ ...inputStyle(), width: 300, ...(isClearing ? { borderColor: 'var(--red, #ff3d57)' } : {}) }}
          value={editValue}
          onChange={e => onChange(e.target.value)}
        />
        <button type="button" onClick={() => setRevealed(r => !r)}
          style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 4,
            color: revealed ? 'var(--accent)' : 'var(--text-dim)', cursor: 'pointer',
            padding: '5px 8px', fontSize: 13, lineHeight: 1 }}>
          {revealed ? '🙈' : '👁'}
        </button>
        {hasCurrent && !isClearing && (
          <button type="button" onClick={() => onChange('')}
            style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 4,
              color: 'var(--text-dim)', cursor: 'pointer',
              padding: '3px 8px', fontSize: 11, lineHeight: 1 }}>
            Clear
          </button>
        )}
        {isClearing && (
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--red, #ff3d57)' }}>
            will be cleared on save
          </span>
        )}
      </div>
    </SettingRow>
  )
}

function BFRow({ label, field, value, onChange }: {
  label: string; field: string; value: boolean; onChange: (v: boolean) => void;
}) {
  return (
    <SettingRow label={label} field={field}>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
        <input type="checkbox" checked={value} onChange={e => onChange(e.target.checked)} />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>
          {value ? 'Enabled' : 'Disabled'}
        </span>
      </label>
    </SettingRow>
  )
}

function RORow({ label, field, value }: { label: string; field?: string; value: string }) {
  return <SettingRow label={label} field={field}><ReadOnly>{value}</ReadOnly></SettingRow>
}

function ROSecretRow({ label, field, value }: { label: string; field?: string; value: string }) {
  const [revealed, setRevealed] = useState(false)
  return (
    <SettingRow label={label} field={field}>
      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>
          {revealed ? (value || '(not set)') : (value ? '••••••••' : '(not set)')}
        </span>
        {value && (
          <button type="button" onClick={() => setRevealed(r => !r)}
            style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 4,
              color: revealed ? 'var(--accent)' : 'var(--text-dim)', cursor: 'pointer',
              padding: '3px 7px', fontSize: 12 }}>
            {revealed ? '🙈' : '👁'}
          </button>
        )}
      </div>
    </SettingRow>
  )
}

function SettingsTab() {
  const { data: s, isLoading } = useQuery<AdminSettings>({
    queryKey: ['admin', 'settings'],
    queryFn: () => adminApi.settings.get(),
  })
  if (isLoading || !s) return <Spinner />
  return (
    <div style={{ display: 'grid', gap: 8 }}>
      <BootstrapPanel s={s} />
      <AIPanel s={s} />
      <AuthPanel s={s} />
      <CeleryPanel s={s} />
      <EnrichmentPanel s={s} />
      <LdapPanel s={s} />
      <MCPPanel s={s} />
      <OIDCPanel s={s} />
      <RetentionPanel s={s} />
      <VolatilityPanel s={s} />
      <WatchFolderPanel s={s} />
    </div>
  )
}

function BootstrapPanel({ s }: { s: AdminSettings }) {
  return (
    <SettingPanel title="Bootstrap — read only (change via .env + restart)">
      <RORow       label="Environment"     field="env"              value={s.env} />
      <RORow       label="API Prefix"      field="api_prefix"       value={s.api_prefix} />
      <ROSecretRow label="SECRET_KEY"      field="secret_key"       value={s.secret_key} />
      <RORow       label="DATABASE_URL"    field="database_url"     value={s.database_url} />
      <RORow       label="REDIS_URL"       field="redis_url"        value={s.redis_url} />
      <RORow       label="S3 Endpoint"     field="s3_endpoint"      value={s.s3_endpoint} />
      <RORow       label="Bucket: Dumps"   field="s3_bucket_dumps"   value={s.s3_bucket_dumps} />
      <RORow       label="Bucket: Reports" field="s3_bucket_reports" value={s.s3_bucket_reports} />
      <ROSecretRow label="S3_ACCESS_KEY"   field="s3_access_key"    value={s.s3_access_key} />
      <ROSecretRow label="S3_SECRET_KEY"   field="s3_secret_key"    value={s.s3_secret_key} />
    </SettingPanel>
  )
}

function AIPanel({ s }: { s: AdminSettings }) {
  const { edits, set, mutation, dirty, saved, discard } = usePanelMutation()
  const str = (k: keyof AdminSettings) => edits[k] !== undefined ? String(edits[k]) : String(s[k] ?? '')
  const num = (k: keyof AdminSettings) => edits[k] !== undefined ? Number(edits[k]) : Number(s[k] ?? 0)
  const sec = (k: string) => edits[k] !== undefined ? String(edits[k]) : ''
  return (
    <SettingPanel title="AI">
      <TFRow label="Primary Model"            field="primary_model"            value={str('primary_model')}            onChange={v => set('primary_model', v)} />
      <TFRow label="Fast Model"               field="fast_model"               value={str('fast_model')}               onChange={v => set('fast_model', v)} />
      <NFRow label="Max Context Tokens"       field="ai_max_context_tokens"    value={num('ai_max_context_tokens')}    onChange={v => set('ai_max_context_tokens', v)} />
      <NFRow label="Summarise Threshold (chars)" field="summarise_threshold_chars" value={num('summarise_threshold_chars')} onChange={v => set('summarise_threshold_chars', v)} />
      <SFRow label="ANTHROPIC_API_KEY"        field="anthropic_api_key"        hasCurrent={!!s.anthropic_api_key}  editValue={sec('anthropic_api_key')}  edited={edits['anthropic_api_key'] !== undefined}  onChange={v => set('anthropic_api_key', v)} />
      <TFRow label="Fallback API URL"         field="fallback_api_url"         value={str('fallback_api_url')}         onChange={v => set('fallback_api_url', v)} />
      <SFRow label="Fallback API Key"         field="fallback_api_key"         hasCurrent={!!s.fallback_api_key}   editValue={sec('fallback_api_key')}   edited={edits['fallback_api_key'] !== undefined}   onChange={v => set('fallback_api_key', v)} />
      <TFRow label="Fallback Model"           field="fallback_model"           value={str('fallback_model')}           onChange={v => set('fallback_model', v)} />
      <SaveBar mutation={mutation} dirty={dirty} saved={saved} onDiscard={discard} />
    </SettingPanel>
  )
}

function EnrichmentPanel({ s }: { s: AdminSettings }) {
  const { edits, set, mutation, dirty, saved, discard } = usePanelMutation()
  const num = (k: keyof AdminSettings) => edits[k] !== undefined ? Number(edits[k]) : Number(s[k] ?? 0)
  const sec = (k: string) => edits[k] !== undefined ? String(edits[k]) : ''
  return (
    <SettingPanel title="Enrichment">
      <NFRow label="VT Rate Limit (per min)" field="vt_rate_limit_per_min" value={num('vt_rate_limit_per_min')} onChange={v => set('vt_rate_limit_per_min', v)} />
      <NFRow label="VT Max IOCs per run"     field="vt_max_iocs"          value={num('vt_max_iocs')}           onChange={v => set('vt_max_iocs', v)} />
      <SFRow label="VIRUSTOTAL_API_KEY"      field="virustotal_api_key"   hasCurrent={!!s.virustotal_api_key}  editValue={sec('virustotal_api_key')} edited={edits['virustotal_api_key'] !== undefined} onChange={v => set('virustotal_api_key', v)} />
      <SaveBar mutation={mutation} dirty={dirty} saved={saved} onDiscard={discard} />
    </SettingPanel>
  )
}

function VolatilityPanel({ s }: { s: AdminSettings }) {
  const { edits, set, mutation, dirty, saved, discard } = usePanelMutation()
  const str = (k: keyof AdminSettings) => edits[k] !== undefined ? String(edits[k]) : String(s[k] ?? '')
  const num = (k: keyof AdminSettings) => edits[k] !== undefined ? Number(edits[k]) : Number(s[k] ?? 0)
  return (
    <SettingPanel title="Volatility" note="Path changes take effect on the next analysis run. Restart workers after changing concurrency.">
      <TFRow label="Volatility Path"     field="volatility_path"    value={str('volatility_path')}    onChange={v => set('volatility_path', v)} />
      <TFRow label="Symbol Cache Path"   field="symbol_cache_path"  value={str('symbol_cache_path')}  onChange={v => set('symbol_cache_path', v)} />
      <TFRow label="dwarf2json Path"     field="dwarf2json_path"    value={str('dwarf2json_path')}     onChange={v => set('dwarf2json_path', v)} />
      <TFRow label="Worker Tmp Dir"      field="worker_tmp_dir"     value={str('worker_tmp_dir')}      onChange={v => set('worker_tmp_dir', v)} />
      <NFRow label="Plugin Timeout (s)"  field="plugin_timeout_seconds" value={num('plugin_timeout_seconds')} onChange={v => set('plugin_timeout_seconds', v)} />
      <SettingRow label="Max Dump Size (bytes)" field="max_dump_size_bytes">
        <input type="number" style={inputStyle()}
          value={edits['max_dump_size_bytes'] !== undefined ? Number(edits['max_dump_size_bytes']) : s.max_dump_size_bytes}
          onChange={e => set('max_dump_size_bytes', Number(e.target.value))} />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', marginLeft: 8 }}>
          ({(s.max_dump_size_bytes / 1024 ** 3).toFixed(0)} GB)
        </span>
      </SettingRow>
      <NFRow label="Upload Rate Limit (cases/hr/user)" field="max_cases_per_hour_per_user" value={num('max_cases_per_hour_per_user')} onChange={v => set('max_cases_per_hour_per_user', v)} />
      <SaveBar mutation={mutation} dirty={dirty} saved={saved} onDiscard={discard} />
    </SettingPanel>
  )
}

function MCPPanel({ s }: { s: AdminSettings }) {
  const { edits, set, mutation, dirty, saved, discard } = usePanelMutation()
  const bool = (k: keyof AdminSettings) => edits[k] !== undefined ? Boolean(edits[k]) : Boolean(s[k])
  const enabled = bool('mcp_enabled')
  const [copied, setCopied] = React.useState(false)

  const sseUrl = `${window.location.origin.replace(/^http:/, 'https:')}/mcp/sse`
  const claudeConfig = JSON.stringify(
    {
      mcpServers: {
        memoryscope: {
          command: 'npx',
          args: ['-y', 'mcp-remote', sseUrl],
          env: { NODE_TLS_REJECT_UNAUTHORIZED: '0' },
        },
      },
    },
    null, 2
  )

  const handleCopy = () => {
    navigator.clipboard.writeText(claudeConfig).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <SettingPanel title="MCP Server"
      note="Model Context Protocol interface for Claude Desktop (1.0+). When enabled, paste the config below into claude_desktop_config.json and restart Claude Desktop. No server restart required to toggle.">
      <BFRow label="Enabled" field="mcp_enabled" value={enabled} onChange={v => set('mcp_enabled', v)} />
      {enabled && (
        <>
          <SettingRow label="SSE Endpoint" field="mcp_endpoint">
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>
              {sseUrl}
            </span>
          </SettingRow>
          <SettingRow label="Claude Desktop Config" field="mcp_config">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, width: '100%' }}>
              <pre style={{
                margin: 0, padding: '10px 12px',
                background: 'var(--bg)', border: '1px solid var(--border)',
                borderRadius: 4, fontFamily: 'var(--font-mono)', fontSize: 11,
                color: 'var(--text-dim)', whiteSpace: 'pre', overflowX: 'auto',
              }}>
                {claudeConfig}
              </pre>
              <button type="button" onClick={handleCopy} style={{
                alignSelf: 'flex-start',
                background: copied ? 'var(--accent)' : 'none',
                border: '1px solid var(--border)',
                borderRadius: 4,
                color: copied ? 'var(--bg)' : 'var(--text-dim)',
                cursor: 'pointer', fontFamily: 'var(--font-mono)',
                fontSize: 11, padding: '4px 10px',
                transition: 'background 0.15s, color 0.15s',
              }}>
                {copied ? 'Copied!' : 'Copy to clipboard'}
              </button>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', lineHeight: 1.6 }}>
                Paste into <strong>claude_desktop_config.json</strong> under the <code>mcpServers</code> key.
                Requires <strong>Node.js</strong> installed on the machine running Claude Desktop.<br />
                If you see <strong>spawn npx ENOENT</strong>: Claude Desktop can't find npx on its PATH.
                Fix by replacing <code>"npx"</code> with the full path —
                run <code>where npx</code> (Windows) or <code>which npx</code> (Mac/Linux) in a terminal to find it,
                e.g. <code>C:\Program Files\nodejs\npx.cmd</code>.<br />
                Alternatively, install globally first: <code>npm install -g mcp-remote</code>,
                then replace <code>"command"</code> with <code>"mcp-remote"</code> and remove <code>"mcp-remote"</code> from <code>"args"</code>.<br />
                <code>NODE_TLS_REJECT_UNAUTHORIZED: "0"</code> skips TLS verification — safe for self-signed homelab certs.
              </span>
            </div>
          </SettingRow>
        </>
      )}
      <SaveBar mutation={mutation} dirty={dirty} saved={saved} onDiscard={discard} />
    </SettingPanel>
  )
}

function WatchFolderPanel({ s }: { s: AdminSettings }) {
  const { edits, set, mutation, dirty, saved, discard } = usePanelMutation()
  const str  = (k: keyof AdminSettings) => edits[k] !== undefined ? String(edits[k])  : String(s[k] ?? '')
  const num  = (k: keyof AdminSettings) => edits[k] !== undefined ? Number(edits[k])  : Number(s[k] ?? 0)
  const bool = (k: keyof AdminSettings) => edits[k] !== undefined ? Boolean(edits[k]) : Boolean(s[k])
  return (
    <SettingPanel title="Watch Folder"
      note="Dumps dropped into the watch directory are automatically imported as new cases and triaged. Requires a worker restart after enabling.">
      <BFRow label="Enabled"               field="watch_dir_enabled"       value={bool('watch_dir_enabled')}       onChange={v => set('watch_dir_enabled', v)} />
      <TFRow label="Directory Path"        field="watch_dir"               value={str('watch_dir')}                onChange={v => set('watch_dir', v)}
        />
      <NFRow label="Poll Interval (s)"     field="watch_dir_poll_interval" value={num('watch_dir_poll_interval')}  onChange={v => set('watch_dir_poll_interval', v)} />
      <NFRow label="Stable Age (s)"        field="watch_dir_stable_age"    value={num('watch_dir_stable_age')}     onChange={v => set('watch_dir_stable_age', v)} />
      <SaveBar mutation={mutation} dirty={dirty} saved={saved} onDiscard={discard} />
    </SettingPanel>
  )
}

function AuthPanel({ s }: { s: AdminSettings }) {
  const { edits, set, mutation, dirty, saved, discard } = usePanelMutation()
  const str = (k: keyof AdminSettings) => edits[k] !== undefined ? String(edits[k]) : String(s[k] ?? '')
  const num = (k: keyof AdminSettings) => edits[k] !== undefined ? Number(edits[k]) : Number(s[k] ?? 0)
  return (
    <SettingPanel title="Auth">
      <TFRow label="JWT Algorithm"               field="jwt_algorithm"            value={str('jwt_algorithm')}            onChange={v => set('jwt_algorithm', v)} />
      <NFRow label="Access Token Expiry (min)"   field="jwt_access_expire_minutes" value={num('jwt_access_expire_minutes')} onChange={v => set('jwt_access_expire_minutes', v)} />
      <NFRow label="Refresh Token Expiry (days)" field="jwt_refresh_expire_days"  value={num('jwt_refresh_expire_days')}  onChange={v => set('jwt_refresh_expire_days', v)} />
      <SaveBar mutation={mutation} dirty={dirty} saved={saved} onDiscard={discard} />
    </SettingPanel>
  )
}

function CeleryPanel({ s }: { s: AdminSettings }) {
  const { edits, set, mutation, dirty, saved, discard } = usePanelMutation()
  const num = (k: keyof AdminSettings) => edits[k] !== undefined ? Number(edits[k]) : Number(s[k] ?? 0)
  return (
    <SettingPanel title="Celery" note="Concurrency changes require a worker restart to take effect.">
      <NFRow label="Worker Concurrency" field="celery_concurrency" value={num('celery_concurrency')} onChange={v => set('celery_concurrency', v)} />
      <NFRow label="Strings Max Workers" field="strings_max_workers" value={num('strings_max_workers')} onChange={v => set('strings_max_workers', v)} />
      <SaveBar mutation={mutation} dirty={dirty} saved={saved} onDiscard={discard} />
    </SettingPanel>
  )
}

function RetentionPanel({ s }: { s: AdminSettings }) {
  const { edits, set, mutation, dirty, saved, discard } = usePanelMutation()
  const num = (k: keyof AdminSettings) => edits[k] !== undefined ? Number(edits[k]) : Number(s[k] ?? 0)
  return (
    <SettingPanel title="Retention">
      <NFRow label="Dump Retention (days)"   field="dump_retention_days"   value={num('dump_retention_days')}   onChange={v => set('dump_retention_days', v)} />
      <NFRow label="Report Retention (days)" field="report_retention_days" value={num('report_retention_days')} onChange={v => set('report_retention_days', v)} />
      <SaveBar mutation={mutation} dirty={dirty} saved={saved} onDiscard={discard} />
    </SettingPanel>
  )
}

function OIDCPanel({ s }: { s: AdminSettings }) {
  const { edits, set, mutation, dirty, saved, discard } = usePanelMutation()
  const str = (k: keyof AdminSettings) => edits[k] !== undefined ? String(edits[k]) : String(s[k] ?? '')
  const bool = (k: keyof AdminSettings) => edits[k] !== undefined ? Boolean(edits[k]) : Boolean(s[k])
  const sec = (k: string) => edits[k] !== undefined ? String(edits[k]) : ''

  const [testResult, setTestResult] = useState<{ ok: boolean; issuer?: string; error?: string } | null>(null)
  const [testing, setTesting] = useState(false)
  async function handleTest() {
    setTesting(true)
    setTestResult(null)
    try {
      const res = await adminApi.settings.testOidc()
      setTestResult(res)
    } catch {
      setTestResult({ ok: false, error: 'Request failed' })
    } finally {
      setTesting(false)
    }
  }

  return (
    <SettingPanel title="OIDC / SSO">
      <BFRow label="Enable SSO"             field="oidc_enabled"                value={bool('oidc_enabled')}               onChange={v => set('oidc_enabled', v)} />
      <TFRow label="Provider Name"          field="oidc_provider_name"          value={str('oidc_provider_name')}          onChange={v => set('oidc_provider_name', v)} />
      <TFRow label="Discovery URL"          field="oidc_discovery_url"          value={str('oidc_discovery_url')}          onChange={v => set('oidc_discovery_url', v)} />
      <TFRow label="Client ID"              field="oidc_client_id"              value={str('oidc_client_id')}              onChange={v => set('oidc_client_id', v)} />
      <SFRow label="Client Secret"          field="oidc_client_secret"          hasCurrent={!!s.oidc_client_secret}       editValue={sec('oidc_client_secret')} edited={edits['oidc_client_secret'] !== undefined} onChange={v => set('oidc_client_secret', v)} />
      <TFRow label="Redirect URI"           field="oidc_redirect_uri"           value={str('oidc_redirect_uri')}           onChange={v => set('oidc_redirect_uri', v)} />
      <TFRow label="Frontend Callback URL"  field="oidc_frontend_callback_url"  value={str('oidc_frontend_callback_url')}  onChange={v => set('oidc_frontend_callback_url', v)} />
      <TFRow label="Role Claim"             field="oidc_role_claim"             value={str('oidc_role_claim')}             onChange={v => set('oidc_role_claim', v)} />
      <TFRow label="Admin Group"            field="oidc_admin_group"            value={str('oidc_admin_group')}            onChange={v => set('oidc_admin_group', v)} />
      <TFRow label="Viewer Group"           field="oidc_viewer_group"           value={str('oidc_viewer_group')}           onChange={v => set('oidc_viewer_group', v)} />
      <BFRow label="JIT Provisioning"       field="oidc_jit_provisioning"       value={bool('oidc_jit_provisioning')}      onChange={v => set('oidc_jit_provisioning', v)} />
      <BFRow label="Verify SSL Certificate" field="oidc_verify_ssl"             value={bool('oidc_verify_ssl')}            onChange={v => set('oidc_verify_ssl', v)} />

      {/* Test connection */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 8, paddingTop: 8,
        borderTop: '1px solid var(--border2)' }}>
        <button onClick={handleTest} disabled={testing || !s.oidc_discovery_url} style={btnStyle('dim')}>
          {testing ? 'Testing…' : 'Test Connection'}
        </button>
        {testResult && (
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11,
            color: testResult.ok ? 'var(--green)' : 'var(--red)' }}>
            {testResult.ok
              ? `OK — issuer: ${testResult.issuer ?? '(none)'}`
              : `Failed: ${testResult.error}`}
          </span>
        )}
      </div>

      <SaveBar mutation={mutation} dirty={dirty} saved={saved} onDiscard={discard} />
    </SettingPanel>
  )
}


// ── LDAP Panel ───────────────────────────────────────────────────────────────

function LdapPanel({ s }: { s: AdminSettings }) {
  const { edits, set, mutation, dirty, saved, discard } = usePanelMutation()
  const str = (k: keyof AdminSettings) => edits[k] !== undefined ? String(edits[k]) : String(s[k] ?? '')
  const bool = (k: keyof AdminSettings) => edits[k] !== undefined ? Boolean(edits[k]) : Boolean(s[k])
  const sec = (k: string) => edits[k] !== undefined ? String(edits[k]) : ''

  const [testResult, setTestResult] = useState<{ ok: boolean; message?: string; error?: string } | null>(null)
  const [testing, setTesting] = useState(false)
  async function handleTest() {
    setTesting(true)
    setTestResult(null)
    try {
      const res = await adminApi.settings.testLdap()
      setTestResult(res)
    } catch {
      setTestResult({ ok: false, error: 'Request failed' })
    } finally {
      setTesting(false)
    }
  }

  return (
    <SettingPanel title="LDAP / LDAPS">
      <BFRow label="Enable LDAP"          field="ldap_enabled"          value={bool('ldap_enabled')}         onChange={v => set('ldap_enabled', v)} />
      <TFRow label="Server URL"           field="ldap_url"              value={str('ldap_url')}              onChange={v => set('ldap_url', v)}           placeholder="ldap://dc.example.com:389 or ldaps://dc.example.com:636" />
      <BFRow label="Use StartTLS"         field="ldap_use_starttls"     value={bool('ldap_use_starttls')}    onChange={v => set('ldap_use_starttls', v)} />
      <BFRow label="Verify TLS Cert"      field="ldap_tls_verify"       value={bool('ldap_tls_verify')}      onChange={v => set('ldap_tls_verify', v)} />

      <TFRow label="Bind DN"              field="ldap_bind_dn"          value={str('ldap_bind_dn')}          onChange={v => set('ldap_bind_dn', v)}           placeholder="CN=svc-memoryscope,OU=ServiceAccounts,DC=example,DC=com" />
      <SFRow label="Bind Password"        field="ldap_bind_password"    hasCurrent={!!s.ldap_bind_password}  editValue={sec('ldap_bind_password')} edited={edits['ldap_bind_password'] !== undefined} onChange={v => set('ldap_bind_password', v)} />
      <TFRow label="Base DN"              field="ldap_base_dn"          value={str('ldap_base_dn')}          onChange={v => set('ldap_base_dn', v)}           placeholder="DC=example,DC=com" />
      <TFRow label="User Filter"          field="ldap_user_filter"      value={str('ldap_user_filter')}      onChange={v => set('ldap_user_filter', v)}       placeholder="(mail={username}) or (uid={username})" />
      <TFRow label="Email Attribute"      field="ldap_attr_email"       value={str('ldap_attr_email')}       onChange={v => set('ldap_attr_email', v)}        placeholder="mail" />
      <TFRow label="Display Name Attr"    field="ldap_attr_display_name" value={str('ldap_attr_display_name')} onChange={v => set('ldap_attr_display_name', v)} placeholder="displayName" />

      <TFRow label="Group Search Base DN" field="ldap_group_base_dn"    value={str('ldap_group_base_dn')}    onChange={v => set('ldap_group_base_dn', v)}     placeholder="OU=Groups,DC=example,DC=com (default: Base DN)" />
      <TFRow label="Admin Group DN"       field="ldap_admin_group"      value={str('ldap_admin_group')}      onChange={v => set('ldap_admin_group', v)}       placeholder="CN=MemoryScopeAdmins,OU=Groups,DC=example,DC=com" />
      <TFRow label="Analyst Group DN"     field="ldap_analyst_group"    value={str('ldap_analyst_group')}    onChange={v => set('ldap_analyst_group', v)}     placeholder="CN=MemoryScopeAnalysts,OU=Groups,DC=example,DC=com" />
      <TFRow label="Viewer Group DN"      field="ldap_viewer_group"     value={str('ldap_viewer_group')}     onChange={v => set('ldap_viewer_group', v)}      placeholder="CN=MemoryScopeViewers,OU=Groups,DC=example,DC=com" />
      <BFRow label="JIT Provisioning"     field="ldap_jit_provisioning" value={bool('ldap_jit_provisioning')} onChange={v => set('ldap_jit_provisioning', v)} />

      {/* Test connection */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 8, paddingTop: 8,
        borderTop: '1px solid var(--border2)' }}>
        <button onClick={handleTest} disabled={testing || !s.ldap_url} style={btnStyle('dim')}>
          {testing ? 'Testing…' : 'Test Connection'}
        </button>
        {testResult && (
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11,
            color: testResult.ok ? 'var(--green)' : 'var(--red)' }}>
            {testResult.ok
              ? `OK — ${testResult.message ?? 'connection successful'}`
              : `Failed: ${testResult.error}`}
          </span>
        )}
      </div>

      <SaveBar mutation={mutation} dirty={dirty} saved={saved} onDiscard={discard} />
    </SettingPanel>
  )
}


// ── System Tab ───────────────────────────────────────────────────────────────

function fmtBytes(n: number): string {
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(1)} GB`
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)} MB`
  if (n >= 1024)      return `${(n / 1024).toFixed(1)} KB`
  return `${n} B`
}

// MinIO refuses writes below 5% free; warn at 15% to give headroom
const WARN_PCT = 15
const CRIT_PCT = 8   // very close to MinIO's hard limit

function DiskBar({ total, used, free }: { total: number; used: number; free: number }) {
  const usedPct  = Math.round((used  / total) * 100)
  const freePct  = Math.round((free  / total) * 100)
  const isCrit   = freePct <= CRIT_PCT
  const isWarn   = freePct <= WARN_PCT
  const barColor = isCrit ? 'var(--red, #ff3d57)' : isWarn ? 'var(--yellow, #f5c518)' : 'var(--accent)'

  return (
    <div style={{ display: 'grid', gap: 8 }}>
      {(isWarn) && (
        <div style={{
          padding: '8px 14px',
          background: isCrit ? 'rgba(255,61,87,0.08)' : 'rgba(245,197,24,0.08)',
          border: `1px solid ${isCrit ? 'rgba(255,61,87,0.35)' : 'rgba(245,197,24,0.3)'}`,
          borderRadius: 6,
          fontFamily: 'var(--font-mono)',
          fontSize: 11,
          color: isCrit ? 'var(--red, #ff3d57)' : 'var(--yellow, #f5c518)',
          letterSpacing: '0.06em',
        }}>
          {isCrit
            ? `⚠ CRITICAL: only ${freePct}% free — MinIO will refuse writes below 5%. Expand disk immediately.`
            : `⚠ LOW DISK: ${freePct}% free (${fmtBytes(free)} remaining). See expand instructions below.`}
        </div>
      )}
      {/* Bar */}
      <div style={{ height: 12, borderRadius: 6, background: 'var(--border)', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${usedPct}%`, background: barColor, borderRadius: 6, transition: 'width 0.4s' }} />
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }}>
        <span>{fmtBytes(used)} used ({usedPct}%)</span>
        <span>{fmtBytes(free)} free of {fmtBytes(total)}</span>
      </div>
    </div>
  )
}

function ExpandDiskGuide({ diskType, diskDevice }: { diskType: string; diskDevice: string }) {
  const preStyle: React.CSSProperties = {
    marginTop: 10,
    padding: '12px 16px',
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 6,
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
    color: 'var(--text)',
    overflowX: 'auto',
    lineHeight: 1.7,
    whiteSpace: 'pre',
  }
  const dim: React.CSSProperties = { marginTop: 8, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }

  if (diskType === 'lvm') {
    // Extract VG name from device path: /dev/mapper/ubuntu--vg-ubuntu--lv → ubuntu-vg
    // LVM encodes hyphens as double-hyphens in the mapper name
    const mapperName = diskDevice.replace('/dev/mapper/', '')
    // Reverse double-hyphen encoding to recover VG-LV: ubuntu--vg-ubuntu--lv → ubuntu-vg/ubuntu-lv
    const vgLv = mapperName.replace(/--/g, '\x00').replace(/-/, '/').replace(/\x00/g, '-')
    const [vg] = vgLv.split('/')
    return (
      <div>
        <SectionHeader>Expand Disk (LVM)</SectionHeader>
        <p style={dim}>Run on the host to extend the logical volume and filesystem:</p>
        <pre style={preStyle}>{`# 1. Check free space in the volume group
sudo vgdisplay ${vg}

# 2. Extend the logical volume — adjust size as needed
sudo lvextend -L +20G ${diskDevice}

# 3. Grow the filesystem (works for ext4 and xfs)
sudo resize2fs ${diskDevice} 2>/dev/null || sudo xfs_growfs ${diskDevice}

# 4. Verify
df -h /`}</pre>
        <p style={dim}>If the VG has no free extents, attach a new disk then run <code>pvcreate /dev/sdX</code> + <code>vgextend {vg} /dev/sdX</code> first.</p>
      </div>
    )
  }

  if (diskType === 'zfs') {
    return (
      <div>
        <SectionHeader>Expand Disk (ZFS)</SectionHeader>
        <p style={dim}>ZFS pools expand automatically when underlying devices grow. Run on the host:</p>
        <pre style={preStyle}>{`# List pools and their status
sudo zpool status
sudo zpool list

# After expanding the underlying disk/partition, tell ZFS to use the new space
sudo zpool online -e <pool-name> <device>

# Verify
df -h /`}</pre>
        <p style={dim}>If adding a new disk: <code>sudo zpool add &lt;pool-name&gt; /dev/sdX</code></p>
      </div>
    )
  }

  if (diskType === 'mdraid') {
    return (
      <div>
        <SectionHeader>Expand Disk (mdraid)</SectionHeader>
        <p style={dim}>MD RAID expansion depends on the RAID level and number of members. Run on the host:</p>
        <pre style={preStyle}>{`# Check array status
sudo mdadm --detail ${diskDevice}

# After replacing/growing underlying disks, grow the array
sudo mdadm --grow ${diskDevice} --size=max

# Then resize the filesystem
sudo resize2fs ${diskDevice} 2>/dev/null || sudo xfs_growfs ${diskDevice}

# Verify
df -h /`}</pre>
      </div>
    )
  }

  if (diskType === 'raw') {
    return (
      <div>
        <SectionHeader>Expand Disk</SectionHeader>
        <p style={dim}>
          Device: <code>{diskDevice}</code> — plain partition detected. How to expand depends on your environment:
        </p>
        <pre style={preStyle}>{`# Cloud VM (AWS/GCP/Azure): resize the volume in the cloud console first, then:
sudo growpart ${diskDevice.replace(/[0-9]+$/, '')} <partition-number>
sudo resize2fs ${diskDevice} 2>/dev/null || sudo xfs_growfs ${diskDevice}

# Bare metal / VM with a resizable virtual disk:
# 1. Extend the disk in your hypervisor (VMware, VirtualBox, Proxmox, etc.)
# 2. Use parted or fdisk to extend the partition
# 3. Then resize the filesystem as above`}</pre>
      </div>
    )
  }

  // Unknown / unrecognised
  return (
    <div>
      <SectionHeader>Expand Disk</SectionHeader>
      <p style={dim}>
        Storage type could not be determined (device: <code>{diskDevice || 'unknown'}</code>).
        Expand the partition or volume using the appropriate tool for your environment
        (LVM: <code>lvextend</code>, ZFS: <code>zpool</code>, cloud: resize via provider console + <code>growpart</code>),
        then resize the filesystem with <code>resize2fs</code> or <code>xfs_growfs</code>.
      </p>
    </div>
  )
}

function SystemTab() {
  const { data: health, isLoading, refetch } = useQuery<SystemHealth>({
    queryKey: ['admin', 'system', 'health'],
    queryFn: () => adminApi.system.health(),
    refetchInterval: 8_000,
  })

  const { data: storage, isLoading: storageLoading, refetch: refetchStorage } = useQuery<StorageInfo>({
    queryKey: ['admin', 'system', 'storage'],
    queryFn: () => adminApi.system.storage(),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  const restartMutation = useMutation({
    mutationFn: () => adminApi.system.restartWorkers(),
  })

  if (isLoading) return <Spinner />

  const StatusDot = ({ ok }: { ok: boolean }) => (
    <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
      background: ok ? 'var(--green)' : 'var(--red)', marginRight: 8 }} />
  )

  const freePct = health ? Math.round((health.disk_free_bytes / health.disk_total_bytes) * 100) : 100

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
            <span style={{ color: (health?.worker_count ?? 0) > 0 ? 'var(--green)' : 'var(--red)' }}>
              {health?.worker_count ?? 0} online
            </span>
          </StatCard>
        </div>
      </div>

      {/* ── Disk Usage + Expand instructions ────────────────────────────────── */}
      {health && (
        <div style={{ display: 'grid', gap: 20 }}>
          <div>
            <SectionHeader>Host Disk (MinIO partition)</SectionHeader>
            <DiskBar
              total={health.disk_total_bytes}
              used={health.disk_used_bytes}
              free={health.disk_free_bytes}
            />
            <div style={{ marginTop: 6, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }}>
              MinIO refuses all writes when free space drops below 5% ({fmtBytes(health.disk_total_bytes * 0.05)}).
              Warning threshold shown at {WARN_PCT}%.
            </div>
          </div>
          <ExpandDiskGuide diskType={health.disk_type} diskDevice={health.disk_device} />
        </div>
      )}

      {/* ── MinIO Bucket Usage ──────────────────────────────────────────────── */}
      <div>
        <SectionHeader>Object Storage Usage</SectionHeader>
        {storageLoading ? (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>Calculating bucket sizes…</div>
        ) : storage ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12 }}>
            <StatCard label="Dumps bucket">
              <div>{fmtBytes(storage.dumps_bytes)}</div>
              <div style={{ fontSize: 10, color: 'var(--text-dim)', marginTop: 2 }}>{storage.dumps_objects.toLocaleString()} objects</div>
            </StatCard>
            <StatCard label="Reports bucket">
              <div>{fmtBytes(storage.reports_bytes)}</div>
              <div style={{ fontSize: 10, color: 'var(--text-dim)', marginTop: 2 }}>{storage.reports_objects.toLocaleString()} objects</div>
            </StatCard>
            <StatCard label="Total stored">
              <div>{fmtBytes(storage.dumps_bytes + storage.reports_bytes)}</div>
            </StatCard>
          </div>
        ) : null}
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
          <button onClick={() => { refetch(); refetchStorage() }} style={btnStyle('dim')}>Refresh Status</button>
          <button
            onClick={() => { if (window.confirm('Send restart signal to all Celery workers?')) restartMutation.mutate() }}
            disabled={restartMutation.isPending}
            style={btnStyle('warning')}>
            {restartMutation.isPending ? 'Sending…' : 'Restart Workers'}
          </button>
        </div>
        {restartMutation.isSuccess && (
          <div style={{ marginTop: 8, color: 'var(--green)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            Pool restarted — {restartMutation.data?.workers ?? 0} worker(s) acknowledged.
          </div>
        )}
        {restartMutation.isError && (
          <div style={{ marginTop: 8, color: 'var(--red)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            {(restartMutation.error as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? 'Restart failed'}
          </div>
        )}
      </div>
    </div>
  )
}


// ── Logs Tab ──────────────────────────────────────────────────────────────────

type LogSubTab = 'audit' | 'app'

const LEVEL_COLOR: Record<string, string> = {
  DEBUG:    'var(--text-dim)',
  INFO:     'var(--text)',
  WARNING:  'var(--yellow)',
  ERROR:    'var(--red)',
  CRITICAL: 'var(--red)',
}

function LogsTab() {
  const [sub, setSub] = useState<LogSubTab>('audit')
  return (
    <div>
      <div style={{ display: 'flex', gap: 12, marginBottom: 20 }}>
        {(['audit', 'app'] as LogSubTab[]).map(s => (
          <button key={s} onClick={() => setSub(s)} style={{
            background: 'none', border: 'none', cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: '0.1em',
            textTransform: 'uppercase',
            color: sub === s ? 'var(--accent)' : 'var(--text-dim)',
            borderBottom: sub === s ? '2px solid var(--accent)' : '2px solid transparent',
            paddingBottom: 4,
          }}>
            {s === 'audit' ? 'Audit Log' : 'Application Log'}
          </button>
        ))}
      </div>
      {sub === 'audit' ? <AuditLog /> : <AppLog />}
    </div>
  )
}

function AuditLog() {
  const [page, setPage] = useState(1)
  const [eventType, setEventType] = useState('')
  const [source, setSource] = useState('')
  const pageSize = 50

  const { data: eventTypes = [] } = useQuery<string[]>({
    queryKey: ['admin', 'logs', 'audit', 'event-types', source],
    queryFn: () => adminApi.logs.auditEventTypes(source || undefined),
    staleTime: 60_000,
  })

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['admin', 'logs', 'audit', page, eventType, source],
    queryFn: () => adminApi.logs.audit({ page, page_size: pageSize, event_type: eventType || undefined, source: source || undefined }),
    refetchInterval: 30_000,
  })

  return (
    <div>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 14, flexWrap: 'wrap' }}>
        <select style={{ ...inputStyle(), width: 140 }} value={source}
          onChange={e => { setSource(e.target.value); setEventType(''); setPage(1) }}>
          <option value="">All sources</option>
          <option value="user">User events</option>
          <option value="case">Case events</option>
        </select>
        <select style={{ ...inputStyle(), width: 220 }} value={eventType}
          onChange={e => { setEventType(e.target.value); setPage(1) }}>
          <option value="">All event types</option>
          {eventTypes.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <button onClick={() => refetch()} style={btnStyle('dim')}>Refresh</button>
        {data && (
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', marginLeft: 'auto' }}>
            {data.total} events
          </span>
        )}
      </div>

      {isLoading ? <Spinner /> : (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              {['Time', 'Source', 'Event', 'Target', 'Actor', 'Payload'].map(h => (
                <th key={h} style={{ textAlign: 'left', padding: '5px 8px', color: 'var(--text-dim)',
                  letterSpacing: '0.08em', fontWeight: 600, textTransform: 'uppercase', fontSize: 10 }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {(data?.items ?? []).map((e: any) => (
              <tr key={e.id} style={{ borderBottom: '1px solid var(--border2)' }}>
                <td style={{ padding: '6px 8px', color: 'var(--text-dim)', whiteSpace: 'nowrap' }}>
                  {new Date(e.created_at).toLocaleString()}
                </td>
                <td style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: '0.06em',
                    textTransform: 'uppercase', padding: '2px 6px', borderRadius: 3,
                    color: e.source === 'user' ? 'var(--accent2)' : 'var(--accent)',
                    border: `1px solid ${e.source === 'user' ? 'var(--accent2)' : 'var(--accent)'}` }}>
                    {e.source}
                  </span>
                </td>
                <td style={{ padding: '6px 8px', color: 'var(--text)', whiteSpace: 'nowrap' }}>
                  {e.event_type}
                </td>
                <td style={{ padding: '6px 8px', color: e.source === 'user' ? 'var(--accent2)' : 'var(--accent)' }}>
                  {e.target_name ?? '—'}
                </td>
                <td style={{ padding: '6px 8px', color: 'var(--text-dim)' }}>
                  {e.actor_name ?? '—'}
                </td>
                <td style={{ padding: '6px 8px', color: 'var(--text-dim)', maxWidth: 320,
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {Object.keys(e.payload).length ? JSON.stringify(e.payload) : '{}'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {data && data.total > pageSize && (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 12 }}>
          <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} style={btnStyle('dim')}>←</button>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }}>
            {page} / {Math.ceil(data.total / pageSize)}
          </span>
          <button onClick={() => setPage(p => p + 1)} disabled={page >= Math.ceil(data.total / pageSize)} style={btnStyle('dim')}>→</button>
        </div>
      )}
    </div>
  )
}

const LOG_SOURCES = [
  { value: 'api',          label: 'API' },
  { value: 'worker',       label: 'Worker' },
  { value: 'beat',         label: 'Beat' },
  { value: 'nginx-access', label: 'Nginx Access' },
  { value: 'nginx-error',  label: 'Nginx Error' },
]

function AppLog() {
  const [lines, setLines] = useState(200)
  const [level, setLevel] = useState('ALL')
  const [source, setSource] = useState('api')
  const [autoRefresh, setAutoRefresh] = useState(false)

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['admin', 'logs', 'app', lines, level, source],
    queryFn: () => adminApi.logs.app({ lines, level, source }),
    refetchInterval: autoRefresh ? 10_000 : false,
  })

  const logLines: any[] = data?.lines ?? []

  return (
    <div>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 14, flexWrap: 'wrap' }}>
        <select style={{ ...inputStyle(), width: 130 }} value={source} onChange={e => setSource(e.target.value)}>
          {LOG_SOURCES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
        </select>
        <select style={{ ...inputStyle(), width: 140 }} value={level} onChange={e => setLevel(e.target.value)}>
          {['ALL', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'].map(l => (
            <option key={l} value={l}>{l}</option>
          ))}
        </select>
        <select style={{ ...inputStyle(), width: 120 }} value={lines} onChange={e => setLines(Number(e.target.value))}>
          {[100, 200, 500, 1000, 2000].map(n => <option key={n} value={n}>{n} lines</option>)}
        </select>
        <button onClick={() => refetch()} style={btnStyle('dim')}>Refresh</button>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer',
          fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }}>
          <input type="checkbox" checked={autoRefresh} onChange={e => setAutoRefresh(e.target.checked)} />
          Auto-refresh (10s)
        </label>
        {data?.log_file && (
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', marginLeft: 'auto' }}>
            {data.log_file}
          </span>
        )}
      </div>

      {isLoading ? <Spinner /> : (
        <div style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 4,
          padding: '12px 0', maxHeight: 600, overflowY: 'auto', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
          {logLines.length === 0 ? (
            <div style={{ padding: '12px 16px', color: 'var(--text-dim)' }}>
              No log entries found.{!data?.log_file?.includes('/') ? ' Log file not configured.' : ''}
            </div>
          ) : logLines.map((line: any, i: number) => (
            <div key={i} style={{ display: 'flex', gap: 12, padding: '2px 12px',
              background: line.level === 'ERROR' || line.level === 'CRITICAL'
                ? 'rgba(255,61,87,0.05)' : 'none' }}>
              <span style={{ color: 'var(--text-dim)', whiteSpace: 'nowrap', flexShrink: 0 }}>
                {line.timestamp}
              </span>
              <span style={{ color: LEVEL_COLOR[line.level] ?? 'var(--text)', whiteSpace: 'nowrap',
                flexShrink: 0, minWidth: 60 }}>
                {line.level}
              </span>
              <span style={{ color: 'var(--text-dim)', whiteSpace: 'nowrap', flexShrink: 0,
                maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                [{line.logger}]
              </span>
              <span style={{ color: 'var(--text)', wordBreak: 'break-all' }}>{line.message}</span>
            </div>
          ))}
        </div>
      )}
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

function SettingRow({ label, field, children }: { label: string; field?: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0',
      borderBottom: '1px solid var(--border2)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 230 }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>{label}</span>
        {field && <InfoTip field={field} />}
      </div>
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
  const color = role === 'admin' ? 'var(--accent)' : role === 'analyst' ? 'var(--accent2)' : role === 'viewer' ? 'var(--text-muted, #888)' : 'var(--text-dim)'
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
