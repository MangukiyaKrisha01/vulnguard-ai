"""
Module: Missing/Misconfigured Security Headers
Detects absence of standard hardening headers, plus clickjacking & CORS issues
that are header-driven.
"""

AI_INSIGHTS = {
    "csp": "Implement a strict Content-Security-Policy header (e.g. default-src 'self') to mitigate XSS and data-injection attacks.",
    "hsts": "Add Strict-Transport-Security with a long max-age and includeSubDomains to force HTTPS and prevent downgrade attacks.",
    "xfo": "Set X-Frame-Options: DENY or SAMEORIGIN (or use frame-ancestors in CSP) to prevent clickjacking.",
    "xcto": "Add X-Content-Type-Options: nosniff to stop browsers from MIME-sniffing responses away from the declared content type.",
    "referrer": "Set a Referrer-Policy such as strict-origin-when-cross-origin to limit referrer leakage.",
    "permissions": "Define a Permissions-Policy to restrict access to sensitive browser APIs (camera, geolocation, microphone).",
    "cors": "Avoid Access-Control-Allow-Origin: * combined with credentials; restrict CORS to an explicit allow-list of trusted origins.",
    "server": "Suppress or genericize the Server/X-Powered-By header to avoid disclosing exact software versions to attackers.",
    "cookie": "Set Secure, HttpOnly, and SameSite=Strict (or Lax) attributes on all session cookies.",
}


def analyze_headers(url, headers, findings_factory):
    """
    headers: requests.Response.headers (case-insensitive dict-like)
    findings_factory: callable(title, category, description, affected_url, severity,
                                cvss, risk, remediation, owasp, ai_insight, evidence) -> Finding dict
    """
    results = []
    h = {k.lower(): v for k, v in headers.items()}

    if "content-security-policy" not in h:
        results.append(findings_factory(
            title="Missing Content-Security-Policy Header",
            category="Security Misconfiguration",
            description="The response does not include a Content-Security-Policy header, leaving the application "
                         "without a key defense layer against cross-site scripting and data injection attacks.",
            affected_url=url,
            severity="Medium",
            cvss=5.3,
            risk="Without CSP, any successful injection (e.g. XSS) can execute arbitrary scripts, load external "
                 "resources, or exfiltrate data with no browser-level restriction.",
            remediation="Define a restrictive Content-Security-Policy, starting from default-src 'self' and "
                        "explicitly allow-listing required script/style/image sources.",
            owasp="A05:2021 - Security Misconfiguration",
            ai_insight=AI_INSIGHTS["csp"],
            evidence=f"Response headers did not contain 'Content-Security-Policy' for {url}",
        ))

    if "strict-transport-security" not in h and url.startswith("https://"):
        results.append(findings_factory(
            title="Missing Strict-Transport-Security (HSTS) Header",
            category="Security Misconfiguration",
            description="HTTPS is in use but the HSTS header is absent, so browsers will not automatically enforce "
                         "HTTPS on subsequent visits.",
            affected_url=url,
            severity="Low",
            cvss=3.7,
            risk="Users may be susceptible to SSL-stripping or downgrade attacks on untrusted networks.",
            remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
            owasp="A05:2021 - Security Misconfiguration",
            ai_insight=AI_INSIGHTS["hsts"],
            evidence=f"No 'Strict-Transport-Security' header on HTTPS response from {url}",
        ))

    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        results.append(findings_factory(
            title="Clickjacking — Missing X-Frame-Options / frame-ancestors",
            category="Clickjacking",
            description="Neither X-Frame-Options nor a CSP frame-ancestors directive is present, allowing the page "
                         "to be embedded in a malicious iframe.",
            affected_url=url,
            severity="Medium",
            cvss=4.3,
            risk="An attacker can overlay invisible iframes over the legitimate page to trick users into clicking "
                 "unintended UI elements (e.g. transferring funds, changing settings).",
            remediation="Add 'X-Frame-Options: DENY' (or SAMEORIGIN) and/or a CSP 'frame-ancestors' directive.",
            owasp="A05:2021 - Security Misconfiguration",
            ai_insight=AI_INSIGHTS["xfo"],
            evidence=f"Missing X-Frame-Options on {url}",
        ))

    if "x-content-type-options" not in h:
        results.append(findings_factory(
            title="Missing X-Content-Type-Options Header",
            category="Security Misconfiguration",
            description="The X-Content-Type-Options header is not set, permitting browsers to MIME-sniff responses.",
            affected_url=url,
            severity="Low",
            cvss=3.1,
            risk="MIME-sniffing can let an attacker-controlled upload be interpreted as executable script/HTML.",
            remediation="Add 'X-Content-Type-Options: nosniff' to all responses.",
            owasp="A05:2021 - Security Misconfiguration",
            ai_insight=AI_INSIGHTS["xcto"],
            evidence=f"Missing X-Content-Type-Options on {url}",
        ))

    if "referrer-policy" not in h:
        results.append(findings_factory(
            title="Missing Referrer-Policy Header",
            category="Security Misconfiguration",
            description="No Referrer-Policy is set, so the full URL (potentially containing tokens) may leak to "
                         "third-party sites via the Referer header.",
            affected_url=url,
            severity="Informational",
            cvss=2.0,
            risk="Sensitive query parameters or path segments could be exposed to external domains linked from the page.",
            remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
            owasp="A05:2021 - Security Misconfiguration",
            ai_insight=AI_INSIGHTS["referrer"],
            evidence=f"Missing Referrer-Policy on {url}",
        ))

    if "permissions-policy" not in h:
        results.append(findings_factory(
            title="Missing Permissions-Policy Header",
            category="Security Misconfiguration",
            description="No Permissions-Policy header restricts access to powerful browser features.",
            affected_url=url,
            severity="Informational",
            cvss=2.0,
            risk="If the page is ever compromised via XSS, the attacker's script has unrestricted access to "
                 "browser APIs like camera, microphone, or geolocation.",
            remediation="Add a Permissions-Policy header restricting unused features, e.g. "
                        "'camera=(), microphone=(), geolocation=()'.",
            owasp="A05:2021 - Security Misconfiguration",
            ai_insight=AI_INSIGHTS["permissions"],
            evidence=f"Missing Permissions-Policy on {url}",
        ))

    server_header = h.get("server", "")
    if server_header and any(ch.isdigit() for ch in server_header):
        results.append(findings_factory(
            title="Server Banner / Version Disclosure",
            category="Information Disclosure",
            description=f"The Server header discloses detailed software/version information: '{server_header}'.",
            affected_url=url,
            severity="Low",
            cvss=3.1,
            risk="Specific version strings let attackers quickly match the stack against known CVEs.",
            remediation="Configure the web server/reverse proxy to suppress or genericize the Server header.",
            owasp="A05:2021 - Security Misconfiguration",
            ai_insight=AI_INSIGHTS["server"],
            evidence=f"Server: {server_header}",
        ))

    x_powered_by = h.get("x-powered-by")
    if x_powered_by:
        results.append(findings_factory(
            title="X-Powered-By Header Discloses Technology Stack",
            category="Information Disclosure",
            description=f"The X-Powered-By header reveals backend technology: '{x_powered_by}'.",
            affected_url=url,
            severity="Informational",
            cvss=2.0,
            risk="Discloses framework/language details useful for attacker reconnaissance.",
            remediation="Remove or disable the X-Powered-By header in the application/server configuration.",
            owasp="A05:2021 - Security Misconfiguration",
            ai_insight=AI_INSIGHTS["server"],
            evidence=f"X-Powered-By: {x_powered_by}",
        ))

    acao = h.get("access-control-allow-origin")
    acac = h.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        results.append(findings_factory(
            title="Insecure CORS Configuration (Wildcard Origin + Credentials)",
            category="CORS Misconfiguration",
            description="The server returns 'Access-Control-Allow-Origin: *' together with "
                        "'Access-Control-Allow-Credentials: true', which browsers should reject but which often "
                        "indicates a deeper misconfiguration (e.g. reflecting the Origin header dynamically).",
            affected_url=url,
            severity="High",
            cvss=7.5,
            risk="If origin reflection is used instead of a real wildcard, any malicious site can make "
                 "credentialed requests and read authenticated responses, leading to full account compromise.",
            remediation="Use an explicit allow-list of trusted origins for CORS; never combine wildcard origins "
                        "with credentialed requests.",
            owasp="A05:2021 - Security Misconfiguration",
            ai_insight=AI_INSIGHTS["cors"],
            evidence=f"Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true on {url}",
        ))
    elif acao == "*":
        results.append(findings_factory(
            title="Permissive CORS Policy (Wildcard Origin)",
            category="CORS Misconfiguration",
            description="The server allows cross-origin requests from any origin via 'Access-Control-Allow-Origin: *'.",
            affected_url=url,
            severity="Low",
            cvss=4.0,
            risk="Any website can read non-credentialed responses from this endpoint, which may expose data not "
                 "intended for public/third-party consumption.",
            remediation="Restrict Access-Control-Allow-Origin to a known list of trusted domains.",
            owasp="A05:2021 - Security Misconfiguration",
            ai_insight=AI_INSIGHTS["cors"],
            evidence=f"Access-Control-Allow-Origin: * on {url}",
        ))

    return results


def analyze_cookies(url, response, findings_factory):
    results = []
    set_cookie_headers = response.raw.headers.get_all("Set-Cookie") if hasattr(response.raw.headers, "get_all") else None
    cookies = set_cookie_headers or ([response.headers.get("Set-Cookie")] if response.headers.get("Set-Cookie") else [])

    for cookie_str in cookies:
        if not cookie_str:
            continue
        lower = cookie_str.lower()
        issues = []
        if "secure" not in lower:
            issues.append("missing Secure flag")
        if "httponly" not in lower:
            issues.append("missing HttpOnly flag")
        if "samesite" not in lower:
            issues.append("missing SameSite attribute")

        if issues:
            cookie_name = cookie_str.split("=")[0].strip()
            results.append(findings_factory(
                title=f"Insecure Cookie Configuration: '{cookie_name}'",
                category="Insecure Cookies",
                description=f"Cookie '{cookie_name}' is set without proper protective attributes: {', '.join(issues)}.",
                affected_url=url,
                severity="Medium" if "httponly" in [i.split()[1] for i in issues] or True else "Low",
                cvss=5.0,
                risk="Missing HttpOnly allows JavaScript (e.g. via XSS) to steal the cookie. Missing Secure allows "
                     "transmission over plaintext HTTP. Missing SameSite increases CSRF exposure.",
                remediation="Set Secure, HttpOnly, and SameSite=Strict/Lax on all session and authentication cookies.",
                owasp="A05:2021 - Security Misconfiguration",
                ai_insight=AI_INSIGHTS["cookie"],
                evidence=cookie_str[:200],
            ))
    return results
