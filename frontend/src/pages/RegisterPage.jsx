import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function RegisterPage() {
  const { register } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ username: '', email: '', password: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async e => {
    e.preventDefault()
    setError('')
    if (form.password.length < 8) { setError('Password must be at least 8 characters'); return }
    setLoading(true)
    try {
      await register(form.username, form.email, form.password)
      navigate('/dashboard')
    } catch (err) {
      setError(err.response?.data?.error || 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-cyber-bg grid-bg flex items-center justify-center px-4">
      <div className="w-full max-w-md animate-slide-up">
        <div className="text-center mb-8">
          <div className="text-5xl mb-3">🛡️</div>
          <h1 className="text-2xl font-bold font-mono text-cyber-accent animate-glow">VulnGuard AI</h1>
          <p className="text-cyber-muted text-sm mt-1">Create Your Account</p>
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold text-cyber-text mb-5">Register</h2>

          {error && (
            <div className="bg-red-900/30 border border-red-800/50 text-red-400 text-sm rounded-lg px-4 py-3 mb-4">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-cyber-muted text-xs font-mono mb-1.5">Username</label>
              <input type="text" className="input-field" placeholder="johndoe"
                value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))} required />
            </div>
            <div>
              <label className="block text-cyber-muted text-xs font-mono mb-1.5">Email</label>
              <input type="email" className="input-field" placeholder="john@example.com"
                value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))} required />
            </div>
            <div>
              <label className="block text-cyber-muted text-xs font-mono mb-1.5">Password (min 8 chars)</label>
              <input type="password" className="input-field" placeholder="••••••••"
                value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} required />
            </div>
            <button type="submit" className="btn-primary w-full mt-2" disabled={loading}>
              {loading ? 'Creating account...' : 'Create Account'}
            </button>
          </form>

          <div className="mt-4 text-center text-cyber-muted text-xs">
            Already have an account?{' '}
            <Link to="/login" className="text-cyber-accent hover:underline">Sign in</Link>
          </div>
        </div>

        <p className="text-center text-cyber-muted text-xs mt-4 leading-relaxed">
          ⚠️ Authorized testing only. Do not scan systems you don't have permission to test.
        </p>
      </div>
    </div>
  )
}
