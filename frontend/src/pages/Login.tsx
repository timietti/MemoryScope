// frontend/src/pages/Login.tsx
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { authApi } from '../api/client'

export default function Login() {
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      // OAuth2 form expects URLSearchParams
      const params = new URLSearchParams()
      params.append('username', email)
      params.append('password', password)
      const { access_token } = await authApi.login(email, password)
      localStorage.setItem('access_token', access_token)
      navigate('/cases')
    } catch {
      setError('Invalid email or password')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh', background: 'var(--bg)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        width: 360,
        background: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: 10,
        padding: '40px 36px',
      }}>
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{ fontFamily: 'var(--font-cond)', fontSize: 26, fontWeight: 700, color: 'var(--text-bright)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
            Memory<span style={{ color: 'var(--accent)' }}>Scope</span>
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.18em', marginTop: 4 }}>
            FORENSICS PLATFORM
          </div>
        </div>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', letterSpacing: '0.12em', display: 'block', marginBottom: 7 }}>EMAIL</label>
            <input
              type="email" value={email} onChange={e => setEmail(e.target.value)}
              required autoFocus
              style={{ width: '100%', background: 'var(--surface2)', border: '1px solid var(--border2)', color: 'var(--text-bright)', fontFamily: 'var(--font-ui)', fontSize: 13, padding: '10px 14px', borderRadius: 5, outline: 'none', boxSizing: 'border-box' }}
            />
          </div>
          <div style={{ marginBottom: 24 }}>
            <label style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', letterSpacing: '0.12em', display: 'block', marginBottom: 7 }}>PASSWORD</label>
            <input
              type="password" value={password} onChange={e => setPassword(e.target.value)}
              required
              style={{ width: '100%', background: 'var(--surface2)', border: '1px solid var(--border2)', color: 'var(--text-bright)', fontFamily: 'var(--font-ui)', fontSize: 13, padding: '10px 14px', borderRadius: 5, outline: 'none', boxSizing: 'border-box' }}
            />
          </div>
          {error && (
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--red)', marginBottom: 16 }}>{error}</div>
          )}
          <button type="submit" disabled={loading} style={{
            width: '100%', background: loading ? 'var(--border2)' : 'var(--accent)',
            color: 'var(--bg)', border: 'none', fontFamily: 'var(--font-cond)',
            fontSize: 14, fontWeight: 600, letterSpacing: '0.1em', padding: '12px',
            borderRadius: 5, cursor: loading ? 'default' : 'pointer', textTransform: 'uppercase',
          }}>
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  )
}
