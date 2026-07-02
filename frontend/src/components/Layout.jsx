import React, { useState } from 'react'
import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const navItems = [
  { to: '/dashboard', icon: '⬡', label: 'Dashboard' },
  { to: '/scanner', icon: '⌖', label: 'New Scan' },
  { to: '/history', icon: '◫', label: 'Scan History' },
]

export default function Layout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const handleLogout = () => { logout(); navigate('/login') }

  return (
    <div className="flex min-h-screen bg-cyber-bg grid-bg">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div className="fixed inset-0 bg-black/60 z-20 lg:hidden" onClick={() => setSidebarOpen(false)} />
      )}

      {/* Sidebar */}
      <aside className={`
        fixed lg:sticky top-0 left-0 h-screen w-64 bg-cyber-surface border-r border-cyber-border
        flex flex-col z-30 transition-transform duration-300
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
      `}>
        {/* Logo */}
        <div className="flex items-center gap-3 px-6 py-5 border-b border-cyber-border">
          <div className="text-2xl">🛡️</div>
          <div>
            <div className="text-cyber-accent font-mono font-bold text-base tracking-wider">VulnGuard</div>
            <div className="text-cyber-muted text-xs font-mono">AI Scanner v1.0</div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-6 space-y-1">
          {navItems.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-3 rounded-lg font-medium text-sm transition-all duration-150
                 ${isActive
                   ? 'bg-cyan-500/10 text-cyber-accent border border-cyan-500/20'
                   : 'text-cyber-muted hover:text-cyber-text hover:bg-white/5'}`
              }
            >
              <span className="text-lg leading-none">{item.icon}</span>
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Disclaimer */}
        <div className="mx-3 mb-3 p-3 bg-yellow-500/5 border border-yellow-500/20 rounded-lg">
          <p className="text-yellow-500/80 text-xs leading-relaxed">
            ⚠️ Authorized testing only. Do not scan systems you don't own or have explicit permission to test.
          </p>
        </div>

        {/* User */}
        <div className="px-4 py-4 border-t border-cyber-border flex items-center justify-between">
          <div className="min-w-0">
            <div className="text-cyber-text text-sm font-medium truncate">{user?.username}</div>
            <div className="text-cyber-muted text-xs truncate">{user?.email}</div>
          </div>
          <button onClick={handleLogout} title="Logout"
            className="text-cyber-muted hover:text-cyber-red transition-colors ml-2 text-xl flex-shrink-0">
            ⏻
          </button>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar (mobile) */}
        <header className="lg:hidden flex items-center justify-between px-4 py-3 border-b border-cyber-border bg-cyber-surface">
          <button onClick={() => setSidebarOpen(true)} className="text-cyber-muted hover:text-cyber-accent text-2xl">☰</button>
          <span className="text-cyber-accent font-mono font-bold text-sm">VulnGuard AI</span>
          <div />
        </header>

        <main className="flex-1 overflow-auto p-6 animate-fade-in">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
