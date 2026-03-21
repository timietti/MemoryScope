// frontend/src/App.tsx
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/shared/Layout'
import Dashboard from './pages/Dashboard'
import CaseDetail from './pages/CaseDetail'
import Submit from './pages/Submit'
import Login from './pages/Login'

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('access_token')
  return token ? <>{children}</> : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<PrivateRoute><Layout /></PrivateRoute>}>
        <Route index element={<Navigate to="/cases" replace />} />
        <Route path="cases" element={<Dashboard />} />
        <Route path="cases/new" element={<Submit />} />
        <Route path="cases/:id" element={<CaseDetail />} />
        <Route path="cases/:id/:tab" element={<CaseDetail />} />
      </Route>
    </Routes>
  )
}
