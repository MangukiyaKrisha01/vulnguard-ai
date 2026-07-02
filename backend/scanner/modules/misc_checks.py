"""
Module: Misc OWASP checks
- Open Redirect
- CSRF token absence on state-changing forms
- Directory listing exposure
- HTTP methods exposure (OPTIONS / TRACE)
- robots.txt exposure of sensitive paths
- Sensitive information exposure in HTML comments / responses
- Weak authentication pages (autocomplete on password fields, no rate-limit hints)
"""
import re

CSRF_FIELD_HINTS = ["csrf", "token", "authenticity_token", "_token", "nonce"]

SENSITIVE_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Generic API Key": re.compile(r"(?i)api[_-]?key[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']"),
    "Private Key Block": re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) ?KEY-----"),
    "Email Address (in comment)": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}"),
    "Internal IP Address": re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
}


def check_open_redirect(session, url, get_params, findings_factory, timeout=8):
    results = []
    redirect_params = [p for p in get_params if p.lower() in
                        ("redirect", "url", "next", "return", "returnurl", "redir", "destination", "continue")]
    test_target = "https://example-external-test.invalid/"

    for param in redirect_params:
        try:
            resp = session.get(url, params={param: test_target}, timeout=timeout, allow_redirects=False)
        except Exception:
            continue
        location = resp.headers.get("Location", "")
        if resp.status_code in (301, 302, 303, 307, 308) and test_target.rstrip("/") in location:
            results.append(findings_factory(
                title=f"Open Redirect via parameter '{param}'",
                category="Open Redirect",
                description=f"The parameter '{param}' on {url} controls the Location header of a redirect "
                            f"response without validating that the destination is an internal/trusted URL.",
                affected_url=url,
                severity="Medium",
                cvss=5.4,
                risk="Attackers can craft links that appear to point to the trusted domain but redirect victims "
                     "to phishing or malware sites, abusing the target's reputation.",
                remediation="Validate redirect destinations against an allow-list of internal paths, or use "
                            "indirect mapping (e.g. an id mapped server-side to a URL) instead of raw URLs.",
                owasp="A01:2021 - Broken Access Control",
                ai_insight="Avoid placing raw URLs in redirect parameters; map to an internal allow-list of "
                           "known-safe destinations and reject anything else.",
                evidence=f"Param '{param}'={test_target} -> Location: {location}",
            ))
    return results


def check_csrf(url, forms, findings_factory):
    results = []
    for form in forms:
        method = form.get("method", "GET").upper()
        if method != "POST":
            continue
        inputs_lower = [i.lower() for i in form.get("inputs", [])]
        has_csrf_field = any(any(hint in field for hint in CSRF_FIELD_HINTS) for field in inputs_lower)
        if not has_csrf_field:
            results.append(findings_factory(
                title="State-Changing Form Without CSRF Token",
                category="Cross-Site Request Forgery (CSRF)",
                description=f"A POST form at {form.get('action') or url} does not appear to include a CSRF token "
                            f"field among its inputs ({', '.join(form.get('inputs', [])) or 'none detected'}).",
                affected_url=form.get("action") or url,
                severity="Medium",
                cvss=5.7,
                risk="Without anti-CSRF tokens, an attacker can trick an authenticated user's browser into "
                     "submitting unwanted state-changing requests (e.g. changing email, transferring funds).",
                remediation="Implement per-session (or per-request) anti-CSRF tokens validated server-side for "
                            "all state-changing requests, and set cookies with SameSite=Strict/Lax.",
                owasp="A01:2021 - Broken Access Control",
                ai_insight="Use a framework-provided CSRF protection middleware (e.g. Flask-WTF CSRFProtect, "
                           "Django's CsrfViewMiddleware) rather than hand-rolling token validation.",
                evidence=f"Form fields: {form.get('inputs', [])}",
            ))
    return results


def check_directory_listing(session, base_url, discovered_dirs, findings_factory, timeout=8):
    results = []
    indicators = ["Index of /", "Directory listing for", "<title>Index of"]
    for d in discovered_dirs:
        try:
            resp = session.get(d, timeout=timeout)
        except Exception:
            continue
        if resp.status_code == 200 and any(ind in resp.text for ind in indicators):
            results.append(findings_factory(
                title="Directory Listing Enabled",
                category="Security Misconfiguration",
                description=f"The directory {d} returns a browsable file listing instead of a 403/404 or index page.",
                affected_url=d,
                severity="Medium",
                cvss=5.3,
                risk="Exposed directory listings can reveal backup files, source code, configuration files, or "
                     "other sensitive artifacts not meant for public access.",
                remediation="Disable directory listing/autoindex in the web server configuration and ensure an "
                            "index file or explicit deny is in place for each directory.",
                owasp="A05:2021 - Security Misconfiguration",
                ai_insight="Set 'Options -Indexes' (Apache) or 'autoindex off;' (nginx) and audit exposed "
                           "directories for sensitive files.",
                evidence=f"Listing indicator found at {d}",
            ))
    return results


def check_http_methods(session, url, findings_factory, timeout=8):
    results = []
    try:
        resp = session.options(url, timeout=timeout)
        allow = resp.headers.get("Allow", "")
        risky = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow.upper()]
        if risky:
            results.append(findings_factory(
                title="Potentially Dangerous HTTP Methods Enabled",
                category="Security Misconfiguration",
                description=f"The OPTIONS response for {url} advertises potentially dangerous HTTP methods: "
                            f"{', '.join(risky)}.",
                affected_url=url,
                severity="Low",
                cvss=4.3,
                risk="Methods like PUT/DELETE/TRACE, if not properly access-controlled, can allow file upload, "
                     "resource deletion, or cross-site tracing (XST) attacks that bypass HttpOnly cookie protection.",
                remediation="Disable unused HTTP methods at the web server or framework routing layer; ensure "
                            "any required methods enforce authentication and authorization.",
                owasp="A05:2021 - Security Misconfiguration",
                ai_insight="Explicitly allow only GET/POST/HEAD (or what's required) at the reverse proxy, and "
                           "return 405 for everything else.",
                evidence=f"Allow: {allow}",
            ))
    except Exception:
        pass
    return results


def check_robots_txt(session, base_url, findings_factory, timeout=8):
    results = []
    robots_url = base_url.rstrip("/") + "/robots.txt"
    try:
        resp = session.get(robots_url, timeout=timeout)
    except Exception:
        return results

    if resp.status_code == 200 and resp.text.strip():
        sensitive_hits = []
        for line in resp.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow"):
                path = line.split(":", 1)[-1].strip()
                if any(kw in path.lower() for kw in
                       ["admin", "backup", "config", "private", "secret", "db", "internal", ".git", ".env"]):
                    sensitive_hits.append(path)

        if sensitive_hits:
            results.append(findings_factory(
                title="robots.txt Discloses Sensitive Paths",
                category="Information Disclosure",
                description=f"robots.txt at {robots_url} lists potentially sensitive paths intended to be hidden "
                            f"from search engines: {', '.join(sensitive_hits)}.",
                affected_url=robots_url,
                severity="Low",
                cvss=4.0,
                risk="robots.txt is publicly fetchable and effectively provides attackers a roadmap of paths the "
                     "site operator considers sensitive (admin panels, backups, config files).",
                remediation="Do not rely on robots.txt to hide sensitive paths; enforce real authentication/"
                            "authorization, and avoid listing sensitive paths there at all.",
                owasp="A01:2021 - Broken Access Control",
                ai_insight="Treat robots.txt as fully public; any path that must stay private needs server-side "
                           "access control, not just exclusion from crawling.",
                evidence=f"Disallowed paths: {sensitive_hits}",
            ))
    return results


def check_sensitive_info(url, html, findings_factory):
    results = []
    found_types = []
    evidence_samples = []
    for label, pattern in SENSITIVE_PATTERNS.items():
        matches = pattern.findall(html)
        if matches:
            found_types.append(label)
            evidence_samples.append(f"{label}: {str(matches[0])[:60]}")

    if found_types:
        results.append(findings_factory(
            title="Sensitive Information Exposure in Page Source",
            category="Sensitive Data Exposure",
            description=f"The page at {url} appears to contain sensitive data patterns in its HTML/response body: "
                        f"{', '.join(found_types)}.",
            affected_url=url,
            severity="High" if "Private Key Block" in found_types or "AWS Access Key" in found_types else "Medium",
            cvss=7.5 if "Private Key Block" in found_types else 5.5,
            risk="Leaked keys, credentials, or internal infrastructure details in client-visible source can be "
                 "harvested by automated scrapers and used for direct compromise or further reconnaissance.",
            remediation="Remove secrets/keys from client-side code and HTML comments; use environment variables "
                        "and server-side secret management; strip debug/comment output in production builds.",
            owasp="A02:2021 - Cryptographic Failures / A05:2021 - Security Misconfiguration",
            ai_insight="Run a pre-deploy secret scanner (e.g. gitleaks, truffleHog) in CI to catch leaked keys "
                       "before they reach production.",
            evidence="; ".join(evidence_samples),
        ))
    return results
