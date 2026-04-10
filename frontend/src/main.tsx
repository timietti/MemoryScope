// frontend/src/main.tsx
import React, { useEffect, useState } from 'react'
import ReactDOM from 'react-dom/client'
import { createBrowserRouter, RouterProvider, Navigate, useNavigate, Outlet } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Layout from './components/shared/Layout'
import Dashboard from './pages/Dashboard'
import CaseDetail from './pages/CaseDetail'
import Submit from './pages/Submit'
import Login from './pages/Login'
import AuthCallback from './pages/AuthCallback'
import AIStats from './pages/AIStats'
import Admin from './pages/Admin'
import Profile from './pages/Profile'
import Setup from './pages/Setup'
import { apiClient, authApi } from './api/client'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, staleTime: 30_000 },
  },
})

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('access_token')
  return token ? <>{children}</> : <Navigate to="/login" replace />
}

function ViewerGuard({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false)
  const [isViewer, setIsViewer] = useState(false)

  useEffect(() => {
    authApi.me()
      .then(me => setIsViewer(me.role === 'viewer'))
      .catch(() => {})
      .finally(() => setReady(true))
  }, [])

  if (!ready) return null
  return isViewer ? <Navigate to="/cases" replace /> : <>{children}</>
}

/**
 * Checks /setup/status on mount. If needs_setup is true, redirects to /setup.
 * Renders nothing (null) while the check is in flight to avoid a flash of the
 * wrong page.
 */
function SetupGuard() {
  const navigate = useNavigate()
  const [checked, setChecked] = useState(false)

  useEffect(() => {
    apiClient.get('/setup/status')
      .then(({ data }) => {
        if (data.needs_setup) {
          navigate('/setup', { replace: true })
        }
      })
      .catch(() => { /* network error — let the app render normally */ })
      .finally(() => setChecked(true))
  }, [navigate])

  if (!checked) return null
  return <Outlet />
}

/**
 * Allows access to /setup only when needs_setup is true.
 * Redirects to /login once setup has been completed.
 */
function SetupRoute() {
  const [state, setState] = useState<'loading' | 'allow' | 'deny'>('loading')

  useEffect(() => {
    apiClient.get('/setup/status')
      .then(({ data }) => setState(data.needs_setup ? 'allow' : 'deny'))
      .catch(() => setState('deny'))
  }, [])

  if (state === 'loading') return null
  if (state === 'deny') return <Navigate to="/login" replace />
  return <Setup />
}

const router = createBrowserRouter([
  { path: '/setup', element: <SetupRoute /> },
  { path: '/login', element: <Login /> },
  { path: '/auth/callback', element: <AuthCallback /> },
  {
    // SetupGuard wraps all real routes so it only fires once per navigation to
    // the root path group, not on every sub-route re-render.
    path: '/',
    element: <SetupGuard />,
    children: [
      {
        path: '/',
        element: <PrivateRoute><Layout /></PrivateRoute>,
        children: [
          { index: true, element: <Navigate to="/cases" replace /> },
          { path: 'cases', element: <Dashboard /> },
          { path: 'cases/new', element: <ViewerGuard><Submit /></ViewerGuard> },
          { path: 'cases/:id', element: <CaseDetail /> },
          { path: 'cases/:id/:tab', element: <CaseDetail /> },
          { path: 'stats', element: <AIStats /> },
          { path: 'admin', element: <Admin /> },
          { path: 'profile', element: <Profile /> },
        ],
      },
    ],
  },
])

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </React.StrictMode>
)
