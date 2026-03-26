// frontend/src/main.tsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import { createBrowserRouter, RouterProvider, Navigate } from 'react-router-dom'
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

const router = createBrowserRouter([
  { path: '/login', element: <Login /> },
  { path: '/auth/callback', element: <AuthCallback /> },
  {
    path: '/',
    element: <PrivateRoute><Layout /></PrivateRoute>,
    children: [
      { index: true, element: <Navigate to="/cases" replace /> },
      { path: 'cases', element: <Dashboard /> },
      { path: 'cases/new', element: <Submit /> },
      { path: 'cases/:id', element: <CaseDetail /> },
      { path: 'cases/:id/:tab', element: <CaseDetail /> },
      { path: 'stats', element: <AIStats /> },
      { path: 'admin', element: <Admin /> },
      { path: 'profile', element: <Profile /> },
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
