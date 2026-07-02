/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg:      '#0a0e1a',
          surface: '#0d1321',
          card:    '#111827',
          border:  '#1e2d45',
          accent:  '#06b6d4',
          green:   '#10b981',
          red:     '#ef4444',
          orange:  '#f59e0b',
          purple:  '#8b5cf6',
          text:    '#e2e8f0',
          muted:   '#64748b',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan-line': 'scanLine 2s linear infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'fade-in': 'fadeIn 0.4s ease-out',
        'slide-up': 'slideUp 0.3s ease-out',
      },
      keyframes: {
        scanLine: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        glow: {
          from: { textShadow: '0 0 4px #06b6d4, 0 0 8px #06b6d4' },
          to:   { textShadow: '0 0 8px #06b6d4, 0 0 16px #06b6d4, 0 0 24px #06b6d4' },
        },
        fadeIn: {
          from: { opacity: 0 },
          to:   { opacity: 1 },
        },
        slideUp: {
          from: { opacity: 0, transform: 'translateY(16px)' },
          to:   { opacity: 1, transform: 'translateY(0)' },
        },
      }
    }
  },
  plugins: []
}
