// frontend/src/components/shared/Layout.tsx
import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { authApi } from '../../api/client'

export default function Layout() {
  const navigate = useNavigate()

  const { data: me } = useQuery({
    queryKey: ['me'],
    queryFn: () => authApi.me(),
    staleTime: 60_000,
  })

  const handleLogout = () => {
    authApi.logout()
    navigate('/login')
  }

  const isAdmin = me?.role === 'admin'

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg)' }}>
      {/* Sidebar */}
      <aside style={{
        width: 220,
        background: 'var(--surface)',
        borderRight: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
        position: 'fixed',
        top: 0, left: 0, bottom: 0,
        zIndex: 100,
      }}>
        {/* Logo */}
        <div style={{
          padding: '24px 20px 20px',
          borderBottom: '1px solid var(--border)',
        }}>
          <div style={{
            fontFamily: 'var(--font-cond)',
            fontSize: 20,
            fontWeight: 700,
            letterSpacing: '0.06em',
            color: 'var(--text-bright)',
            textTransform: 'uppercase',
          }}>
            Memory<span style={{ color: 'var(--accent)' }}>Scope</span>
          </div>
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 9,
            color: 'var(--text-dim)',
            letterSpacing: '0.15em',
            marginTop: 3,
          }}>
            FORENSICS PLATFORM
          </div>
        </div>

        {/* Nav */}
        <nav style={{ padding: '16px 0', flex: 1 }}>
          <NavItem to="/cases" icon="⬡" label="Cases" />
          <NavItem to="/cases/new" icon="⊕" label="New Analysis" accent />
          <NavItem to="/stats" icon="◈" label="AI Resources" />
          {isAdmin && <NavItem to="/admin" icon="⚙" label="Admin" />}
        </nav>

        {/* Footer */}
        <div style={{ padding: '12px 20px 16px', borderTop: '1px solid var(--border)' }}>
          {me && (
            <div style={{ marginBottom: 8 }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11,
                color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {me.display_name}
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9,
                color: 'var(--text-dim)', letterSpacing: '0.08em', textTransform: 'uppercase', marginTop: 1 }}>
                {me.role}
              </div>
            </div>
          )}
          <button
            onClick={handleLogout}
            style={{
              background: 'none',
              border: '1px solid var(--border2)',
              color: 'var(--text-dim)',
              fontFamily: 'var(--font-mono)',
              fontSize: 11,
              padding: '6px 12px',
              borderRadius: 4,
              cursor: 'pointer',
              width: '100%',
              letterSpacing: '0.08em',
            }}
          >
            LOGOUT
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main style={{ marginLeft: 220, flex: 1, minHeight: '100vh', overflow: 'auto' }}>
        <Outlet />
      </main>
    </div>
  )
}

function NavItem({ to, icon, label, accent }: {
  to: string; icon: string; label: string; accent?: boolean
}) {
  return (
    <NavLink to={to} style={({ isActive }) => ({
      display: 'flex',
      alignItems: 'center',
      gap: 10,
      padding: '9px 20px',
      textDecoration: 'none',
      fontFamily: 'var(--font-cond)',
      fontSize: 13,
      fontWeight: 500,
      letterSpacing: '0.08em',
      textTransform: 'uppercase',
      color: isActive ? 'var(--accent)' : accent ? 'var(--accent2)' : 'var(--text)',
      background: isActive ? 'rgba(0,200,255,0.06)' : 'none',
      borderLeft: isActive ? '2px solid var(--accent)' : '2px solid transparent',
      transition: 'all 0.15s ease',
    })}>
      <span style={{ fontSize: 16, opacity: 0.8 }}>{icon}</span>
      {label}
    </NavLink>
  )
}
