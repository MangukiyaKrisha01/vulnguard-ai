import axios from 'axios'

const api = axios.create({
  baseURL: '',
  headers: { 'Content-Type': 'application/json' },
  timeout: 15000,
})

// Attach stored token on every request
api.interceptors.request.use(config => {
  const token = localStorage.getItem('vg_token')
  if (token) config.headers['Authorization'] = `Bearer ${token}`
  return config
})

// Handle auth expiry globally
api.interceptors.response.use(
  res => res,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem('vg_token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export default api
