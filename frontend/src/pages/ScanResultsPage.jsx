import React, { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import api from '../api/client'
import FindingCard from '../components/FindingCard'
import SeverityBadge from '../components/SeverityBadge'

const ALL_SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational']

export default function ScanResultsPage() {
  const { scanId } = useParams()
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filterSev, setFilterSev] = useState('all')
  const [filterSearch, setFilterSearch] = useState('')
  const [exporting, setExporting] = useState('')

  useEffect(() => {
    api.get(`/api/scan/results/${scanId}`)
      .then(res => {
        setScan(res.data.scan)
        const sorted = [...(res.data.scan.findings || [])].sort((a, b) => b.cvss_score - a.cvss_score)
        setFindings(sorted)
      })
      .catch(() => setError('Failed to load scan results'))
      .finally(() => setLoading(false))
  }, [scanId])

  const handleExport = async (format) => {
    setExporting(format)
    try {
      const res = await api.get(`/api/report/download/${scanId}/${format}`, { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([res.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `VulnGuard_Scan_${scanId}.${format}`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    } catch (err) {
      alert('Export failed: ' + (err.response?.data?.error || err.message))
    } finally {
      setExporting('')
    }
  }

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="text-cyber-accent font-mono animate-pulse">Loading results...</div>
    </div>
  )
  if (error) return <div className="text-cyber-red font-mono">{error}</div>
  if (!scan) return null

  const sc = scan.severity_counts || {}
  const filtered = findings.filter(f => {
    const matchSev = filterSev === 'all' || f.severity === filterSev
    const matchSearch = !filterSearch || f.title.toLowerCase().includes(filterSearch.toLowerCase()) ||
                        f.affected_url.toLowerCase().includes(filterSearch.toLowerCase()) ||
                        f.category.toLowerCase().includes(filterSearch.toLowerCase())
    return matchSev && matchSearch
  })

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Link to="/history" className="text-cyber-muted text-xs hover:text-cyber-accent">← History</Link>
          </div>
          <h1 className="text-xl font-bold text-cyber-text">Scan Results #{scan.id}</h1>
          <p className="text-cyber-muted text-sm font-mono mt-0.5">{scan.target_url}</p>
        </div>

        {/* Export buttons */}
        {scan.status === 'completed' && (
          <div className="flex gap-2 flex-wrap">
            {['pdf', 'json', 'csv'].map(fmt => (
              <button key={fmt} onClick={() => handleExport(fmt)} disabled={!!exporting}
                className="btn-ghost text-xs uppercase font-mono">
                {exporting === fmt ? '...' : `⬇ ${fmt.toUpperCase()}`}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Scan metadata */}
      <div className="card">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <MetaItem label="Status" value={scan.status} accent={scan.status === 'completed'} />
          <MetaItem label="Pages Crawled" value={scan.pages_crawled} />
          <MetaItem label="Total Findings" value={scan.total_findings} />
          <MetaItem label="Scan Type" value={scan.scan_type} />
          <MetaItem label="Started" value={scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'} />
          <MetaItem label="Completed" value={scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '—'} />
          <MetaItem label="Depth" value={scan.scan_depth} />
          <MetaItem label="Duration" value={
            scan.started_at && scan.completed_at
              ? `${Math.round((new Date(scan.completed_at) - new Date(scan.started_at)) / 1000)}s`
              : '—'
          } />
        </div>
      </div>

      {/* Severity counts */}
      <div className="grid grid-cols-5 gap-3">
        {ALL_SEVERITIES.map(sev => (
          <button key={sev}
            onClick={() => setFilterSev(f => f === sev ? 'all' : sev)}
            className={`card text-center transition-all hover:border-cyber-accent/30 ${filterSev === sev ? 'border-cyber-accent' : ''}`}>
            <div className="text-xl font-bold font-mono"
              style={{ color: { Critical:'#ef4444',High:'#f97316',Medium:'#f59e0b',Low:'#3b82f6',Informational:'#64748b' }[sev] }}>
              {sc[sev] || 0}
            </div>
            <div className="text-cyber-muted text-xs mt-0.5">{sev}</div>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <input
          type="text"
          placeholder="Search findings..."
          className="input-field max-w-xs text-sm"
          value={filterSearch}
          onChange={e => setFilterSearch(e.target.value)}
        />
        <div className="flex gap-2 flex-wrap">
          <button onClick={() => setFilterSev('all')}
            className={`text-xs font-mono px-3 py-1.5 rounded border transition-colors ${
              filterSev === 'all' ? 'border-cyber-accent text-cyber-accent bg-cyan-500/5' : 'border-cyber-border text-cyber-muted hover:border-cyber-accent/50'
            }`}>All</button>
          {ALL_SEVERITIES.map(s => (
            <button key={s} onClick={() => setFilterSev(f => f === s ? 'all' : s)}
              className={`text-xs font-mono px-3 py-1.5 rounded border transition-colors ${
                filterSev === s ? 'border-cyber-accent text-cyber-accent bg-cyan-500/5' : 'border-cyber-border text-cyber-muted hover:border-cyber-accent/50'
              }`}>{s}</button>
          ))}
        </div>
        <span className="text-cyber-muted text-xs ml-auto">
          {filtered.length} of {findings.length} findings
        </span>
      </div>

      {/* Findings */}
      {filtered.length === 0
        ? <div className="card text-center py-12 text-cyber-muted">
            {findings.length === 0 ? 'No findings were detected for this scan.' : 'No findings match the current filter.'}
          </div>
        : (
          <div className="space-y-3">
            {filtered.map((f, i) => <FindingCard key={f.id} finding={f} index={i + 1} />)}
          </div>
        )
      }
    </div>
  )
}

function MetaItem({ label, value, accent }) {
  return (
    <div>
      <div className="text-cyber-muted text-xs font-mono">{label}</div>
      <div className={`text-sm font-medium mt-0.5 ${accent ? 'text-cyber-green' : 'text-cyber-text'}`}>{value}</div>
    </div>
  )
}
