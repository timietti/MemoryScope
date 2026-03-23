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

apiClient.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('access_token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
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
  },
  kb: {
    list: (caseId: string) => apiClient.get(`/cases/${caseId}/kb`).then(r => r.data),
  },
  report: {
    get: (caseId: string) =>
      apiClient.get(`/cases/${caseId}/report`).then(r => r.data),
    downloadPdf: (caseId: string) =>
      apiClient.get(`/cases/${caseId}/report/pdf`, { responseType: 'blob' }).then(r => r.data),
  },
  iocs: {
    list: (caseId: string, params?: { severity?: string; ioc_type?: string }) =>
      apiClient.get(`/cases/${caseId}/iocs`, { params }).then(r => r.data),
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
}
