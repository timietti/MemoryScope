// frontend/src/api/client.ts
import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? ''

export const apiClient = axios.create({
  baseURL: `${BASE_URL}/api/v1`,
  timeout: 30_000,
})

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// ── Silent token refresh ──────────────────────────────────────────────────────
// On 401: try to get a new access token using the refresh token.
// Multiple concurrent failures are queued so only one refresh call is made.

let _refreshing = false
let _queue: Array<{ resolve: (t: string) => void; reject: (e: unknown) => void }> = []

function _clearSession() {
  localStorage.removeItem('access_token')
  localStorage.removeItem('refresh_token')
  window.location.href = '/login'
}

apiClient.interceptors.response.use(
  (r) => r,
  async (err) => {
    const original = err.config
    // Only intercept 401s; never retry auth endpoints or already-retried requests
    if (
      err.response?.status !== 401 ||
      original._retry ||
      original.url?.includes('/auth/')
    ) {
      return Promise.reject(err)
    }

    original._retry = true

    if (_refreshing) {
      // Wait for the in-flight refresh to finish then retry
      return new Promise((resolve, reject) => {
        _queue.push({ resolve, reject })
      }).then((newToken) => {
        original.headers.Authorization = `Bearer ${newToken}`
        return apiClient(original)
      })
    }

    _refreshing = true
    const refreshToken = localStorage.getItem('refresh_token')

    if (!refreshToken) {
      _refreshing = false
      _clearSession()
      return Promise.reject(err)
    }

    try {
      const { data } = await axios.post(
        `${BASE_URL}/api/v1/auth/refresh`,
        { refresh_token: refreshToken },
      )
      localStorage.setItem('access_token', data.access_token)
      localStorage.setItem('refresh_token', data.refresh_token)

      _queue.forEach(({ resolve }) => resolve(data.access_token))
      _queue = []

      original.headers.Authorization = `Bearer ${data.access_token}`
      return apiClient(original)
    } catch {
      _queue.forEach(({ reject }) => reject(err))
      _queue = []
      _clearSession()
      return Promise.reject(err)
    } finally {
      _refreshing = false
    }
  },
)

export const casesApi = {
  list: (params: { page?: number; page_size?: number; status?: string; search?: string }) =>
    apiClient.get('/cases', { params }).then(r => r.data),
  get: (id: string) =>
    apiClient.get(`/cases/${id}`).then(r => r.data),
  submit: (formData: FormData, onProgress?: (pct: number) => void, signal?: AbortSignal) =>
    apiClient.post('/cases', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress: (e) => {
        if (onProgress && e.total) onProgress(Math.round((e.loaded / e.total) * 100))
      },
      timeout: 7_200_000,
      signal,
    }).then(r => r.data),
  reanalyze: (id: string) => apiClient.post(`/cases/${id}/reanalyze`).then(r => r.data),
  runPlugins: (id: string, pluginNames: string[]) =>
    apiClient.post(`/cases/${id}/plugins/run`, { plugin_names: pluginNames }).then(r => r.data),
  enrich: (id: string) => apiClient.post(`/cases/${id}/enrich`).then(r => r.data),
  analyze: (id: string) => apiClient.post(`/cases/${id}/analyze`).then(r => r.data),
  delete: (id: string) => apiClient.delete(`/cases/${id}`),
  plugins: {
    list: (caseId: string, domain?: string) =>
      apiClient.get(`/cases/${caseId}/plugins`, { params: { domain } }).then(r => r.data),
    get: (caseId: string, pluginName: string) =>
      apiClient.get(`/cases/${caseId}/plugins/${encodeURIComponent(pluginName)}`).then(r => r.data),
    downloadOne: (caseId: string, pluginName: string) =>
      apiClient.get(`/cases/${caseId}/plugins/${encodeURIComponent(pluginName)}/download`, { responseType: 'blob' }).then(r => r.data),
    downloadAll: (caseId: string) =>
      apiClient.get(`/cases/${caseId}/plugins/download`, { responseType: 'blob' }).then(r => r.data),
  },
  kb: {
    list: (caseId: string) => apiClient.get(`/cases/${caseId}/kb`).then(r => r.data),
  },
  report: {
    get: (caseId: string) =>
      apiClient.get(`/cases/${caseId}/report`).then(r => r.data),
    history: (caseId: string) =>
      apiClient.get(`/cases/${caseId}/report/history`).then(r => r.data),
    downloadPdf: (caseId: string) =>
      apiClient.get(`/cases/${caseId}/report/pdf`, { responseType: 'blob' }).then(r => r.data),
  },
  iocs: {
    list: (caseId: string, params?: { severity?: string; ioc_type?: string }) =>
      apiClient.get(`/cases/${caseId}/iocs`, { params }).then(r => r.data),
  },
  strings: {
    status: (caseId: string) =>
      apiClient.get(`/cases/${caseId}/strings`).then(r => r.data),
    search: (caseId: string, params: { q?: string; page?: number; page_size?: number }) =>
      apiClient.get(`/cases/${caseId}/strings/search`, { params }).then(r => r.data),
  },
  chat: {
    history: (caseId: string) =>
      apiClient.get(`/cases/${caseId}/chat/history`).then(r => r.data as Array<{ id: number; role: string; content: string; created_at: string }>),
    append: (caseId: string, role: 'user' | 'assistant', content: string) =>
      apiClient.post(`/cases/${caseId}/chat/messages`, { role, content }).then(r => r.data),
    clear: (caseId: string) =>
      apiClient.delete(`/cases/${caseId}/chat/history`),
  },
}

export const statsApi = {
  ai: () => apiClient.get('/stats/ai').then(r => r.data),
}

export const kbApi = {
  list:   (params?: { search?: string; tag?: string }) => apiClient.get('/kb', { params }).then(r => r.data),
  get:    (id: string) => apiClient.get(`/kb/${id}`).then(r => r.data),
  create: (body: { title: string; content: string; tags?: string[] }) =>
    apiClient.post('/kb', body).then(r => r.data),
  update: (id: string, body: { title?: string; content?: string; tags?: string[] }) =>
    apiClient.put(`/kb/${id}`, body).then(r => r.data),
  delete: (id: string) => apiClient.delete(`/kb/${id}`),
  attachToCase: (articleId: string, caseId: string) =>
    apiClient.post(`/kb/${articleId}/cases/${caseId}`),
  detachFromCase: (articleId: string, caseId: string) =>
    apiClient.delete(`/kb/${articleId}/cases/${caseId}`),
}

export const adminApi = {
  users: {
    list: () => apiClient.get('/admin/users').then(r => r.data),
    create: (body: { email: string; display_name: string; password: string; role?: string }) =>
      apiClient.post('/admin/users', body).then(r => r.data),
    update: (id: string, body: { display_name?: string; role?: string; is_active?: boolean; password?: string }) =>
      apiClient.patch(`/admin/users/${id}`, body).then(r => r.data),
    delete: (id: string) => apiClient.delete(`/admin/users/${id}`),
  },
  settings: {
    get: () => apiClient.get('/admin/settings').then(r => r.data),
    patch: (body: Record<string, unknown>) => apiClient.patch('/admin/settings', body).then(r => r.data),
    testOidc: () => apiClient.get('/admin/settings/oidc/test').then(r => r.data),
    testLdap: () => apiClient.get('/admin/settings/ldap/test').then(r => r.data),
  },
  system: {
    health: () => apiClient.get('/admin/system/health').then(r => r.data),
    storage: () => apiClient.get('/admin/system/storage').then(r => r.data),
    restartWorkers: () => apiClient.post('/admin/system/worker/restart').then(r => r.data),
  },
  logs: {
    audit: (params: { page?: number; page_size?: number; event_type?: string; source?: string }) =>
      apiClient.get('/admin/logs/audit', { params }).then(r => r.data),
    auditEventTypes: (source?: string) => apiClient.get('/admin/logs/audit/event-types', { params: source ? { source } : undefined }).then(r => r.data),
    app: (params: { lines?: number; level?: string; source?: string }) =>
      apiClient.get('/admin/logs/app', { params }).then(r => r.data),
  },
}

export const oidcApi = {
  config: () => apiClient.get('/auth/oidc/config').then(r => r.data),
  exchangeCode: (code: string) =>
    apiClient.post('/auth/oidc/token-exchange', { code }).then(r => r.data),
}

export const authApi = {
  login: (email: string, password: string) => {
    const params = new URLSearchParams()
    params.append('username', email)
    params.append('password', password)
    return apiClient.post('/auth/token', params, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    }).then(r => r.data)
  },
  me: () => apiClient.get('/auth/me').then(r => r.data),
  updateMe: (body: { email?: string; display_name?: string; current_password?: string; new_password?: string }) =>
    apiClient.patch('/auth/me', body).then(r => r.data),
  logout: () => {
    const refreshToken = localStorage.getItem('refresh_token')
    if (refreshToken) {
      // Fire-and-forget: revoke server-side even if the call fails
      apiClient.post('/auth/logout', { refresh_token: refreshToken }).catch(() => {})
    }
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
  },
}
