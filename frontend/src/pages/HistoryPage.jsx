import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import api from '../api/client'

export default function HistoryPage() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [deleting, setDeleting] = useState(null)

  const load = () => {
    api.get('/api/scan/history')
      .then(res => setScans(res.data.scans))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const handleDelete = async (scanId) => {
    if (!confirm('Delete this scan and all its findings? This cannot be undone.')) return
    setDeleting(scanId)
    try {
      await api.delete(`/api/scan/${scanId}`)
      setScans(s => s.filter(x => x.id !== scanId))
    } catch {
      alert('Failed to delete scan')
    } finally {
      setDeleting(null)
    }
  }

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="text-cyber-accent font-mono animate-pulse">Loading history...</div>
    </div>
  )

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-cyber-text">Scan History</h1>
          <p className="text-cyber-muted text-sm mt-0.5">{scans.length} scan{scans.length !== 1 ? 's' : ''} recorded</p>
        </div>
        <Link to="/scanner" className="btn-primary text-sm">+ New Scan</Link>
      </div>

      {scans.length === 0 ? (
        <div className="card text-center py-16">
          <div className="text-4xl mb-3">🔍</div>
          <p className="text-cyber-text font-semibold">No scans yet</p>
          <p className="text-cyber-muted text-sm mt-1">Start your first scan to see results here.</p>
          <Link to="/scanner" className="btn-primary inline-block mt-4 text-sm">Launch a Scan</Link>
        </div>
      ) : (
        <div className="space-y-3">
          {scans.map(scan => {
            const sc = scan.severity_counts || {}
            return (
              <div key={scan.id} className="card hover:border-cyber-accent/30 transition-colors">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-cyber-muted font-mono text-xs">#{scan.id}</span>
                      <StatusBadge status={scan.status} />
                      <span className="text-cyber-muted text-xs">{scan.scan_type} · depth {scan.scan_depth}</span>
                    </div>
                    <div className="text-cyber-text font-mono text-sm mt-1 truncate">{scan.target_url}</div>
                    <div className="text-cyber-muted text-xs mt-1">
                      {scan.pages_crawled} pages · {scan.total_findings} findings ·{' '}
                      {scan.started_at ? new Date(scan.started_at).toLocaleString() : ''}
                    </div>
                  </div>

                  {/* Severity pills */}
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {sc.Critical > 0 && <SevPill label="C" count={sc.Critical} color="text-red-400 bg-red-900/30 border-red-800/40" />}
                    {sc.High > 0 && <SevPill label="H" count={sc.High} color="text-orange-400 bg-orange-900/30 border-orange-800/40" />}
                    {sc.Medium > 0 && <SevPill label="M" count={sc.Medium} color="text-yellow-400 bg-yellow-900/30 border-yellow-800/40" />}
                    {sc.Low > 0 && <SevPill label="L" count={sc.Low} color="text-blue-400 bg-blue-900/30 border-blue-800/40" />}
                  </div>

                  <div className="flex gap-2 flex-shrink-0">
                    {scan.status === 'completed' && (
                      <Link to={`/scan/${scan.id}`} className="btn-ghost text-xs py-1.5">View Results</Link>
                    )}
                    {scan.status === 'running' && (
                      <Link to="/scanner" className="btn-ghost text-xs py-1.5 text-cyber-accent border-cyber-accent/50 animate-pulse">
                        In Progress...
                      </Link>
                    )}
                    <button
                      onClick={() => handleDelete(scan.id)}
                      disabled={deleting === scan.id}
                      className="btn-danger text-xs py-1.5 px-3">
                      {deleting === scan.id ? '...' : '✕'}
                    </button>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

function StatusBadge({ status }) {
  const map = {
    completed: 'bg-green-900/40 text-green-400 border border-green-800/50',
    running:   'bg-cyan-900/40 text-cyan-400 border border-cyan-800/50 animate-pulse',
    queued:    'bg-slate-800 text-slate-400 border border-slate-700',
    failed:    'bg-red-900/40 text-red-400 border border-red-800/50',
  }
  return (
    <span className={`text-xs font-mono px-2 py-0.5 rounded ${map[status] || map.queued}`}>{status}</span>
  )
}

function SevPill({ label, count, color }) {
  return (
    <span className={`text-xs font-mono px-2 py-0.5 rounded border ${color}`}>
      {label}:{count}
    </span>
  )
}
