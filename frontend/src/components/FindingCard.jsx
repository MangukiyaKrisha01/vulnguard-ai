import React, { useState } from 'react'
import SeverityBadge from './SeverityBadge'

export default function FindingCard({ finding, index }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="card hover:border-cyber-accent/30 transition-all duration-200 animate-slide-up">
      <button
        className="w-full text-left"
        onClick={() => setExpanded(e => !e)}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 min-w-0">
            <span className="text-cyber-muted font-mono text-xs mt-1 flex-shrink-0">#{String(index).padStart(2,'0')}</span>
            <div className="min-w-0">
              <div className="text-cyber-text font-semibold text-sm leading-snug">{finding.title}</div>
              <div className="text-cyber-muted text-xs mt-1 font-mono truncate">{finding.affected_url}</div>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <SeverityBadge severity={finding.severity} />
            <span className="text-cyber-muted text-xs font-mono">CVSS {finding.cvss_score}</span>
            <span className={`text-cyber-muted transition-transform duration-200 ${expanded ? 'rotate-180' : ''}`}>▾</span>
          </div>
        </div>
      </button>

      {expanded && (
        <div className="mt-4 pt-4 border-t border-cyber-border space-y-3 animate-fade-in">
          <InfoRow label="OWASP" value={finding.owasp_mapping} mono />
          <InfoRow label="Category" value={finding.category} />
          <InfoRow label="Description" value={finding.description} />
          <InfoRow label="Risk" value={finding.risk_explanation} />
          <InfoRow label="Remediation" value={finding.remediation} highlight />
          {finding.ai_insight && (
            <div className="bg-cyan-500/5 border border-cyan-500/20 rounded-lg p-3">
              <div className="text-cyber-accent text-xs font-mono font-semibold mb-1">🤖 AI Security Insight</div>
              <div className="text-cyber-text text-sm leading-relaxed">{finding.ai_insight}</div>
            </div>
          )}
          {finding.evidence && (
            <div className="bg-cyber-surface rounded-lg p-3">
              <div className="text-cyber-muted text-xs font-mono font-semibold mb-1">Evidence</div>
              <div className="text-cyber-muted text-xs font-mono break-all">{finding.evidence}</div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function InfoRow({ label, value, mono, highlight }) {
  return (
    <div>
      <div className="text-cyber-muted text-xs font-mono font-semibold mb-0.5">{label}</div>
      <div className={`text-sm leading-relaxed ${mono ? 'font-mono text-cyber-accent' : ''} ${highlight ? 'text-cyber-green' : 'text-cyber-text'}`}>
        {value}
      </div>
    </div>
  )
}
