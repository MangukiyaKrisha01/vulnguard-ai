import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function LoginPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ identifier: '', password: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async e => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(form.identifier, form.password)
      navigate('/dashboard')
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  const fillDemo = () => setForm({ identifier: 'demo', password: 'Demo@12345' })

  return (
    <div className="min-h-screen bg-cyber-bg grid-bg flex items-center justify-center px-4">
      <div className="w-full max-w-md animate-slide-up">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="text-5xl mb-3">🛡️</div>
          <h1 className="text-2xl font-bold font-mono text-cyber-accent animate-glow">VulnGuard AI</h1>
          <p className="text-cyber-muted text-sm mt-1">OWASP Vulnerability Scanner</p>
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold text-cyber-text mb-5">Sign In</h2>

          {error && (
            <div className="bg-red-900/30 border border-red-800/50 text-red-400 text-sm rounded-lg px-4 py-3 mb-4">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-cyber-muted text-xs font-mono mb-1.5">Username or Email</label>
              <input
                type="text"
                className="input-field"
                placeholder="demo"
                value={form.identifier}
                onChange={e => setForm(f => ({ ...f, identifier: e.target.value }))}
                required
              />
            </div>
            <div>
              <label className="block text-cyber-muted text-xs font-mono mb-1.5">Password</label>
              <input
                type="password"
                className="input-field"
                placeholder="••••••••"
                value={form.password}
                onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                required
              />
            </div>
            <button type="submit" className="btn-primary w-full mt-2" disabled={loading}>
              {loading ? 'Authenticating...' : 'Sign In'}
            </button>
          </form>

          <div className="mt-4 text-center text-cyber-muted text-xs">
            Don't have an account?{' '}
            <Link to="/register" className="text-cyber-accent hover:underline">Register</Link>
          </div>
        </div>

        {/* Demo credentials card */}
        <div className="mt-4 card bg-cyan-500/5 border-cyan-500/20 cursor-pointer hover:border-cyan-400/40 transition-colors"
             onClick={fillDemo}>
          <div className="text-cyber-accent text-xs font-mono font-semibold mb-1">🔑 Demo Credentials (click to fill)</div>
          <div className="text-cyber-muted text-xs font-mono">username: demo &nbsp;|&nbsp; password: Demo@12345</div>
        </div>

        <p className="text-center text-cyber-muted text-xs mt-4 leading-relaxed">
          ⚠️ For authorized penetration testing and lab environments only.<br />
          Do not scan systems without explicit written permission.
        </p>
      </div>
    </div>
  )
}
