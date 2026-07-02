# 🛡️ VulnGuard AI — OWASP Vulnerability Scanner

> **An AI-powered, full-stack web vulnerability scanner** built for authorized penetration testing of OWASP Juice Shop, DVWA, Metasploitable, and other intentionally vulnerable lab targets.

---

## ⚠️ Legal & Ethical Disclaimer

> **VulnGuard AI is strictly for authorized use only.**
> Only scan web applications you own or have explicit, written permission to test.
> Unauthorized scanning of systems is illegal under computer fraud laws in most jurisdictions (e.g. CFAA, Computer Misuse Act).
> The authors assume no liability for misuse of this tool.

**Recommended targets:** DVWA, OWASP Juice Shop, Metasploitable, WebGoat, bWAPP (local instances only)

---

## 📸 Features at a Glance

| Feature | Details |
|---|---|
| **Auth** | JWT-based register/login, bcrypt hashing, session persistence |
| **Scanner Engine** | Crawls pages, discovers forms/params, runs 15+ OWASP checks |
| **OWASP Modules** | XSS (reflected), SQLi (error + boolean), headers, cookies, CSRF, open redirect, clickjacking, CORS, robots.txt, sensitive info, directory listing, HTTP methods, server banner |
| **AI Insights** | Contextual remediation guidance per finding |
| **Reports** | PDF (ReportLab), JSON, CSV export |
| **Dashboard** | Doughnut + bar charts, severity stats, recent scans |
| **History** | Full scan history with delete, per-scan result view |
| **UI** | Dark cybersecurity theme, Tailwind CSS, mobile-responsive, animated |
| **Deployment** | Docker + docker-compose, production-grade gunicorn + nginx |

---

## 🏗️ Architecture

```
vulnguard-ai/
├── backend/                   # Flask Python backend
│   ├── app.py                 # Application factory, routes registration, DB seeding
│   ├── auth.py                # JWT auth, register/login blueprint
│   ├── config.py              # Environment-based configuration
│   ├── models.py              # SQLAlchemy models: User, Scan, Finding, ScanLog
│   ├── routes/
│   │   ├── scan_routes.py     # /api/scan/* endpoints (start, status, results, history, delete)
│   │   ├── dashboard_routes.py # /api/dashboard/stats
│   │   └── report_routes.py   # /api/report/download/* (pdf, json, csv)
│   ├── scanner/
│   │   ├── engine.py          # Crawler + orchestration (BFS, rate-limited, multi-module)
│   │   └── modules/
│   │       ├── headers.py     # Security headers, cookies, CORS, server banner
│   │       ├── xss.py         # Reflected XSS with marker payloads
│   │       ├── sqli.py        # Error-based + boolean-based SQL injection
│   │       └── misc_checks.py # CSRF, open redirect, dir listing, robots.txt, sensitive info
│   ├── reports/
│   │   └── pdf_generator.py   # ReportLab PDF report builder
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
├── frontend/                  # React + Tailwind frontend
│   ├── src/
│   │   ├── App.jsx            # Routes, auth guards
│   │   ├── context/AuthContext.jsx  # JWT auth context
│   │   ├── api/client.js      # Axios instance with interceptors
│   │   ├── components/        # Layout, FindingCard, SeverityBadge, StatCard
│   │   └── pages/             # Login, Register, Dashboard, Scanner, Results, History
│   ├── Dockerfile
│   ├── nginx.conf
│   └── package.json
└── docker-compose.yml
```

---

## 🚀 Quick Start

### Option A — Docker (Recommended, zero setup)

```bash
git clone https://github.com/youruser/vulnguard-ai.git
cd vulnguard-ai
docker-compose up --build
```

Open **http://localhost** in your browser.

**Demo account (auto-seeded):**
- Username: `demo`
- Password: `Demo@12345`

---

### Option B — Local Development

**Backend:**
```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # Edit .env with your secrets
python app.py
# → Backend running on http://localhost:5000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
# → Frontend running on http://localhost:5173
```

The Vite dev server proxies `/api/*` to `http://localhost:5000` automatically.

---

## 🔌 API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/register` | — | Create account |
| POST | `/api/login` | — | Get JWT token |
| GET | `/api/me` | ✓ | Current user |
| POST | `/api/scan/start` | ✓ | Launch new scan |
| GET | `/api/scan/status/:id` | ✓ | Poll progress + live logs |
| GET | `/api/scan/results/:id` | ✓ | Full results with findings |
| GET | `/api/scan/history` | ✓ | All scans for user |
| DELETE | `/api/scan/:id` | ✓ | Delete scan |
| GET | `/api/dashboard/stats` | ✓ | Aggregate stats + charts data |
| GET | `/api/report/download/:id/pdf` | ✓ | Download PDF report |
| GET | `/api/report/download/:id/json` | ✓ | Download JSON report |
| GET | `/api/report/download/:id/csv` | ✓ | Download CSV report |
| GET | `/api/health` | — | Service health check |

### Scan Start Payload
```json
{
  "target_url": "http://juice-shop.local:3000",
  "scan_type": "standard",
  "scan_depth": 2
}
```

---

## 🔍 Vulnerability Detection Modules

| Module | Detection Method | OWASP Mapping |
|--------|-----------------|---------------|
| Missing Security Headers | Response header analysis (CSP, HSTS, X-Frame-Options, etc.) | A05:2021 |
| Reflected XSS | Marker payload injection + reflection check | A03:2021 |
| SQL Injection | Error-based (signature matching) + boolean-based (length diff) | A03:2021 |
| Insecure Cookies | Set-Cookie flag analysis (Secure, HttpOnly, SameSite) | A05:2021 |
| CSRF Token Absence | POST form input inspection | A01:2021 |
| Open Redirect | Parameter-driven redirect + Location header check | A01:2021 |
| Clickjacking | X-Frame-Options / frame-ancestors check | A05:2021 |
| CORS Misconfiguration | ACAO + ACAC header analysis | A05:2021 |
| Server Banner Disclosure | Server / X-Powered-By header version strings | A05:2021 |
| robots.txt Sensitive Paths | Keyword matching on Disallow entries | A01:2021 |
| Sensitive Info Exposure | Regex patterns (API keys, private keys, IPs) in HTML | A02/A05:2021 |
| Directory Listing | Index-of indicator check on discovered paths | A05:2021 |
| Dangerous HTTP Methods | OPTIONS response Allow header analysis | A05:2021 |

---

## 🔒 Security Implementation

- **JWT Auth** — HS256 signed tokens, configurable expiry, Authorization header bearer
- **Password Hashing** — bcrypt with automatic salt generation
- **Rate Limiting** — Flask-Limiter (300/hour global, 10/min on auth endpoints)
- **CORS** — Explicit origin allow-list (not `*`)
- **Input Validation** — URL scheme check, depth clamping, email regex
- **SQL Safety** — SQLAlchemy ORM; no raw string concatenation
- **Scanner Safety** — Bounded crawl depth/page limits; non-destructive payloads only

---

## 🐳 Docker Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | (required) | Flask secret key |
| `JWT_SECRET` | (required) | JWT signing key |
| `JWT_EXPIRES_HOURS` | `12` | Token lifetime in hours |
| `CORS_ORIGINS` | `http://localhost` | Comma-separated allowed origins |
| `MAX_CRAWL_PAGES` | `25` | Max pages per scan |
| `MAX_CRAWL_DEPTH` | `3` | Max crawl depth |
| `REQUEST_TIMEOUT` | `8` | HTTP request timeout (seconds) |
| `RATE_LIMIT_DELAY` | `0.15` | Delay between requests (seconds) |

---

## 🎓 About This Project

VulnGuard AI was built as a **final-year major project** demonstrating:

- End-to-end full-stack development (React + Flask)
- Practical application of OWASP Top-10 vulnerability detection
- Secure software engineering (JWT, bcrypt, rate limiting, parameterized queries)
- Modern DevOps practices (Docker, gunicorn, nginx, environment-based config)
- Professional PDF report generation for penetration testing workflows

---

## 🔮 Future Improvements

- [ ] WebSocket live scan updates (replace polling)
- [ ] Stored XSS detection module
- [ ] Authentication bypass testing
- [ ] Subdomain enumeration
- [ ] CVE correlation for detected software versions
- [ ] Scheduled/recurring scans
- [ ] Team/multi-user workspaces
- [ ] Integration with NVD API for enriched CVE data
- [ ] Nuclei template execution integration

---

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

Built for educational and authorized security testing purposes only.
