import React from 'react'

export default function StatCard({ icon, label, value, color = 'text-cyber-accent', sub }) {
  return (
    <div className="card flex items-center gap-4 hover:border-cyber-accent/40 transition-colors">
      <div className={`text-3xl ${color}`}>{icon}</div>
      <div className="min-w-0">
        <div className={`text-2xl font-bold font-mono ${color}`}>{value ?? '—'}</div>
        <div className="text-cyber-muted text-sm">{label}</div>
        {sub && <div className="text-cyber-muted text-xs mt-0.5">{sub}</div>}
      </div>
    </div>
  )
}
