import React, { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'

const SCAN_TYPES = [
  { value: 'quick', label: 'Quick Scan', desc: 'Headers & basic checks only, single page' },
  { value: 'standard', label: 'Standard Scan', desc: 'Full OWASP checks + crawl (recommended)' },
  { value: 'deep', label: 'Deep Scan', desc: 'Maximum depth crawl with all modules' },
]

const TEST_TARGETS = [
  'http://localhost:3000',
  'http://dvwa.local',
  'http://juice-shop.local:3000',
  'http://metasploitable.local',
  'http://testphp.vulnweb.com',
]

export default function ScannerPage() {
  const navigate = useNavigate()
  const [form, setForm] = useState({ target_url: '', scan_type: 'standard', scan_depth: 2 })
  const [error, setError] = useState('')
  const [scanning, setScanning] = useState(false)
  const [activeScan, setActiveScan] = useState(null)  // { id, status, progress, logs }
  const pollRef = useRef(null)

  const stopPolling = () => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null } }

  useEffect(() => () => stopPolling(), [])

  const startPolling = (scanId) => {
    stopPolling()
    pollRef.current = setInterval(async () => {
      try {
        const res = await api.get(`/api/scan/status/${scanId}`)
        const { scan, logs } = res.data
        setActiveScan(prev => ({ ...prev, ...scan, logs }))
        if (scan.status === 'completed' || scan.status === 'failed') {
          stopPolling()
          setScanning(false)
          if (scan.status === 'completed') {
            setTimeout(() => navigate(`/scan/${scanId}`), 1200)
          }
        }
      } catch {
        stopPolling()
        setScanning(false)
      }
    }, 1500)
  }

  const handleSubmit = async e => {
    e.preventDefault()
    setError('')
    if (!form.target_url.startsWith('http')) {
      setError('Target URL must start with http:// or https://')
      return
    }
    setScanning(true)
    try {
      const res = await api.post('/api/scan/start', form)
      const scan = res.data.scan
      setActiveScan({ ...scan, logs: [] })
      startPolling(scan.id)
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to start scan')
      setScanning(false)
    }
  }

  const depthForType = (type) => type === 'quick' ? 0 : type === 'deep' ? 3 : 2

  return (
    <div className="max-w-2xl mx-auto space-y-6 animate-fade-in">
      <div>
        <h1 className="text-xl font-bold text-cyber-text">New Vulnerability Scan</h1>
        <p className="text-cyber-muted text-sm mt-0.5">
          Configure and launch an OWASP Top-10 scan against an authorized target.
        </p>
      </div>

      {/* Disclaimer */}
      <div className="bg-yellow-500/5 border border-yellow-500/25 rounded-xl p-4">
        <div className="flex gap-3">
          <span className="text-yellow-400 text-lg flex-shrink-0">⚠️</span>
          <div className="text-yellow-400/80 text-sm leading-relaxed">
            <strong>Legal & Ethical Notice:</strong> This tool must only be used against systems you own
            or have explicit written authorization to test. Unauthorized scanning is illegal and unethical.
            Recommended targets: DVWA, OWASP Juice Shop, Metasploitable, WebGoat (local instances only).
          </div>
        </div>
      </div>

      {/* Scan form */}
      <div className="card">
        <h2 className="text-cyber-text font-semibold mb-4">Scan Configuration</h2>
        {error && (
          <div className="bg-red-900/30 border border-red-800/50 text-red-400 text-sm rounded-lg px-4 py-3 mb-4">
            {error}
          </div>
        )}
        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-cyber-muted text-xs font-mono mb-1.5">Target URL *</label>
            <input
              type="url"
              className="input-field font-mono"
              placeholder="http://localhost:3000"
              value={form.target_url}
              onChange={e => setForm(f => ({ ...f, target_url: e.target.value }))}
              required
              disabled={scanning}
            />
            <div className="mt-2 flex flex-wrap gap-1.5">
              {TEST_TARGETS.map(t => (
                <button key={t} type="button"
                  onClick={() => setForm(f => ({ ...f, target_url: t }))}
                  className="text-xs font-mono text-cyber-muted hover:text-cyber-accent bg-cyber-surface border border-cyber-border rounded px-2 py-1 transition-colors">
                  {t}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-cyber-muted text-xs font-mono mb-2">Scan Type</label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {SCAN_TYPES.map(st => (
                <label key={st.value}
                  className={`cursor-pointer border rounded-lg p-3 transition-all ${
                    form.scan_type === st.value
                      ? 'border-cyber-accent bg-cyan-500/5'
                      : 'border-cyber-border hover:border-cyber-accent/40'
                  }`}>
                  <input type="radio" name="scan_type" value={st.value} className="sr-only"
                    checked={form.scan_type === st.value}
                    onChange={() => setForm(f => ({ ...f, scan_type: st.value, scan_depth: depthForType(st.value) }))}
                    disabled={scanning} />
                  <div className="text-cyber-text text-sm font-semibold">{st.label}</div>
                  <div className="text-cyber-muted text-xs mt-0.5">{st.desc}</div>
                </label>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-cyber-muted text-xs font-mono mb-1.5">
              Crawl Depth: <span className="text-cyber-accent">{form.scan_depth}</span>
            </label>
            <input type="range" min={0} max={3} step={1} value={form.scan_depth}
              onChange={e => setForm(f => ({ ...f, scan_depth: parseInt(e.target.value) }))}
              className="w-full accent-cyan-500" disabled={scanning} />
            <div className="flex justify-between text-cyber-muted text-xs mt-1 font-mono">
              <span>0 – Single page</span><span>1</span><span>2</span><span>3 – Full crawl</span>
            </div>
          </div>

          <button type="submit" className="btn-primary w-full" disabled={scanning}>
            {scanning ? 'Scan Running...' : '⌖  Launch Scan'}
          </button>
        </form>
      </div>

      {/* Active scan progress */}
      {activeScan && (
        <div className="card space-y-4 animate-slide-up">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-cyber-text font-semibold text-sm">
                Scan #{activeScan.id} — {activeScan.status}
              </div>
              <div className="text-cyber-muted text-xs font-mono mt-0.5">{activeScan.target_url}</div>
            </div>
            <StatusPill status={activeScan.status} />
          </div>

          {/* Progress bar */}
          <div className="space-y-1">
            <div className="flex justify-between text-xs text-cyber-muted font-mono">
              <span>Progress</span><span>{activeScan.progress}%</span>
            </div>
            <div className="h-2 bg-cyber-surface rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-600 to-cyan-400 rounded-full transition-all duration-500"
                style={{ width: `${activeScan.progress}%` }}
              />
            </div>
          </div>

          <div className="text-cyber-muted text-xs font-mono">
            Pages crawled: {activeScan.pages_crawled}
          </div>

          {/* Live logs */}
          <div className="bg-cyber-surface rounded-lg p-3 h-40 overflow-y-auto font-mono text-xs space-y-1">
            {(activeScan.logs || []).map((log, i) => (
              <div key={i} className={
                log.level === 'error' ? 'text-cyber-red' :
                log.level === 'warning' ? 'text-yellow-400' : 'text-cyber-muted'
              }>
                <span className="text-cyber-border mr-2">[{log.timestamp?.slice(11,19)}]</span>
                {log.message}
              </div>
            ))}
            {(!activeScan.logs || activeScan.logs.length === 0) && (
              <div className="text-cyber-border">Waiting for scanner output...</div>
            )}
          </div>

          {activeScan.status === 'failed' && activeScan.error_message && (
            <div className="bg-red-900/20 border border-red-800/50 text-red-400 text-xs rounded-lg p-3 font-mono">
              Error: {activeScan.error_message}
            </div>
          )}

          {activeScan.status === 'completed' && (
            <div className="bg-green-900/20 border border-green-800/50 text-green-400 text-sm rounded-lg p-3 text-center">
              ✓ Scan complete! Redirecting to results...
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function StatusPill({ status }) {
  const map = {
    completed: 'bg-green-900/40 text-green-400 border-green-800/50',
    running:   'bg-cyan-900/40 text-cyan-400 border-cyan-800/50 animate-pulse',
    queued:    'bg-slate-800 text-slate-300 border-slate-700',
    failed:    'bg-red-900/40 text-red-400 border-red-800/50',
  }
  return <span className={`text-xs font-mono px-2.5 py-1 rounded border ${map[status] || map.queued}`}>{status}</span>
}
