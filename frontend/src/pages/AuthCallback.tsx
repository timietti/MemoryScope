// frontend/src/pages/AuthCallback.tsx
// Receives the SSO token pair from the backend redirect and stores it.
// The backend redirects here after a successful OIDC callback:
//   /auth/callback?access_token=...&refresh_token=...
// On error:
//   /auth/callback?error=<code>

import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'

const ERROR_MESSAGES: Record<string, string> = {
  invalid_state:        'Login session expired or was tampered with. Please try again.',
  token_exchange_failed:'The identity provider returned an error. Please try again.',
  token_invalid:        'Identity token could not be verified. Please contact your administrator.',
  not_provisioned:      'Your account has not been set up in MemoryScope. Please contact your administrator.',
  account_disabled:     'Your account has been disabled. Please contact your administrator.',
  email_not_verified:   'Your email address is not verified with the identity provider.',
  nonce_mismatch:       'Security check failed. Please try again.',
  missing_params:       'Invalid callback URL. Please try again.',
  discovery_failed:     'Could not reach the identity provider. Please try again later.',
  no_email:             'The identity provider did not supply an email address.',
}

export default function AuthCallback() {
  const navigate = useNavigate()
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const accessToken  = params.get('access_token')
    const refreshToken = params.get('refresh_token')
    const errorCode    = params.get('error')

    if (errorCode) {
      setError(ERROR_MESSAGES[errorCode] ?? `Login failed (${errorCode}). Please try again.`)
      return
    }

    if (!accessToken || !refreshToken) {
      setError('Incomplete response from identity provider. Please try again.')
      return
    }

    localStorage.setItem('access_token', accessToken)
    localStorage.setItem('refresh_token', refreshToken)
    navigate('/cases', { replace: true })
  }, [navigate])

  return (
    <div style={{
      minHeight: '100vh', background: 'var(--bg)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        width: 400,
        background: 'var(--surface)',
        border: `1px solid ${error ? 'rgba(255,61,87,0.4)' : 'var(--border)'}`,
        borderRadius: 10,
        padding: '40px 36px',
        textAlign: 'center',
      }}>
        <div style={{
          fontFamily: 'var(--font-cond)', fontSize: 26, fontWeight: 700,
          color: 'var(--text-bright)', letterSpacing: '0.04em', textTransform: 'uppercase',
          marginBottom: 24,
        }}>
          Memory<span style={{ color: 'var(--accent)' }}>Scope</span>
        </div>

        {error ? (
          <>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--red)',
              marginBottom: 20, lineHeight: 1.7,
            }}>
              {error}
            </div>
            <button
              onClick={() => navigate('/login', { replace: true })}
              style={{
                background: 'none', border: '1px solid var(--border2)',
                color: 'var(--text)', fontFamily: 'var(--font-cond)',
                fontSize: 13, fontWeight: 500, letterSpacing: '0.08em',
                padding: '9px 24px', borderRadius: 5, cursor: 'pointer',
                textTransform: 'uppercase',
              }}
            >
              Back to Login
            </button>
          </>
        ) : (
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 11,
            color: 'var(--text-dim)', letterSpacing: '0.1em',
          }}>
            SIGNING IN...
          </div>
        )}
      </div>
    </div>
  )
}
