import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Doughnut, Bar } from 'react-chartjs-2'
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend,
  CategoryScale, LinearScale, BarElement, Title
} from 'chart.js'
import api from '../api/client'
import StatCard from '../components/StatCard'

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, Title)

const SEV_COLORS = {
  Critical: '#7f1d1d',
  High: '#dc2626',
  Medium: '#d97706',
  Low: '#2563eb',
  Informational: '#64748b',
}

export default function DashboardPage() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    api.get('/api/dashboard/stats')
      .then(res => setStats(res.data))
      .catch(() => setError('Failed to load dashboard stats'))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="text-cyber-accent font-mono animate-pulse">Loading dashboard...</div>
    </div>
  )
  if (error) return <div className="text-cyber-red font-mono">{error}</div>

  const sc = stats.severity_counts || {}
  const severityChart = {
    labels: Object.keys(sc),
    datasets: [{
      data: Object.values(sc),
      backgroundColor: Object.keys(sc).map(k => SEV_COLORS[k] || '#64748b'),
      borderColor: '#0d1321',
      borderWidth: 2,
    }]
  }

  const catLabels = Object.keys(stats.category_counts || {}).slice(0, 8)
  const catValues = catLabels.map(k => stats.category_counts[k])
  const categoryChart = {
    labels: catLabels,
    datasets: [{
      label: 'Findings',
      data: catValues,
      backgroundColor: '#06b6d4',
      borderRadius: 4,
    }]
  }

  const chartOpts = {
    responsive: true,
    plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } },
  }
  const barOpts = {
    ...chartOpts,
    indexAxis: 'y',
    scales: {
      x: { ticks: { color: '#64748b' }, grid: { color: '#1e2d45' } },
      y: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { color: '#1e2d45' } },
    },
    plugins: { legend: { display: false } },
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-cyber-text">Security Dashboard</h1>
          <p className="text-cyber-muted text-sm mt-0.5">Overview of all vulnerability scan activity</p>
        </div>
        <Link to="/scanner" className="btn-primary text-sm">+ New Scan</Link>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon="🔍" label="Total Scans" value={stats.total_scans} />
        <StatCard icon="⚠️" label="Total Findings" value={stats.total_findings} color="text-cyber-orange" />
        <StatCard icon="🔴" label="Critical / High" value={(sc.Critical || 0) + (sc.High || 0)} color="text-cyber-red" />
        <StatCard icon="✅" label="Completed Scans" value={stats.completed_scans} color="text-cyber-green" />
      </div>

      {/* Severity breakdown sub-stats */}
      <div className="grid grid-cols-5 gap-3">
        {Object.entries(sc).map(([sev, cnt]) => (
          <div key={sev} className="card text-center hover:border-cyber-accent/30 transition-colors">
            <div className="text-lg font-bold font-mono" style={{ color: SEV_COLORS[sev] }}>{cnt}</div>
            <div className="text-cyber-muted text-xs mt-0.5">{sev}</div>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-cyber-text font-semibold text-sm mb-4">Findings by Severity</h3>
          {stats.total_findings > 0
            ? <div className="flex justify-center"><div style={{ maxWidth: 260 }}><Doughnut data={severityChart} options={chartOpts} /></div></div>
            : <EmptyChart message="No findings yet. Run a scan to populate this chart." />
          }
        </div>
        <div className="card">
          <h3 className="text-cyber-text font-semibold text-sm mb-4">Findings by Category</h3>
          {catLabels.length > 0
            ? <Bar data={categoryChart} options={barOpts} />
            : <EmptyChart message="No findings yet. Run a scan to populate this chart." />
          }
        </div>
      </div>

      {/* Recent scans */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-cyber-text font-semibold text-sm">Recent Scans</h3>
          <Link to="/history" className="text-cyber-accent text-xs hover:underline">View all →</Link>
        </div>
        {stats.recent_scans.length === 0
          ? <p className="text-cyber-muted text-sm">No scans yet. <Link to="/scanner" className="text-cyber-accent hover:underline">Start your first scan</Link>.</p>
          : (
            <div className="divide-y divide-cyber-border">
              {stats.recent_scans.map(scan => (
                <div key={scan.id} className="flex items-center justify-between py-3">
                  <div className="min-w-0">
                    <div className="text-cyber-text text-sm font-mono truncate">{scan.target_url}</div>
                    <div className="text-cyber-muted text-xs mt-0.5">
                      {scan.pages_crawled} pages crawled · {scan.total_findings} findings
                    </div>
                  </div>
                  <div className="flex items-center gap-3 flex-shrink-0 ml-4">
                    <StatusBadge status={scan.status} />
                    {scan.status === 'completed' && (
                      <Link to={`/scan/${scan.id}`} className="text-cyber-accent text-xs hover:underline">View →</Link>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
      </div>
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
    <span className={`text-xs font-mono px-2 py-0.5 rounded ${map[status] || map.queued}`}>
      {status}
    </span>
  )
}

function EmptyChart({ message }) {
  return (
    <div className="flex items-center justify-center h-40 text-cyber-muted text-sm text-center px-4">
      {message}
    </div>
  )
}
