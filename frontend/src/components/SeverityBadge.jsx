import React from 'react'

const SEVERITY_CLASSES = {
  Critical:      'badge-critical',
  High:          'badge-high',
  Medium:        'badge-medium',
  Low:           'badge-low',
  Informational: 'badge-informational',
}

export default function SeverityBadge({ severity }) {
  return (
    <span className={SEVERITY_CLASSES[severity] || 'badge-informational'}>
      {severity}
    </span>
  )
}
