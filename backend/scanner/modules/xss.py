"""
Module: Cross-Site Scripting (XSS) Detection
Sends benign, non-executing marker payloads to forms/parameters and checks
whether they are reflected unescaped in the response. This is detection-only
(no payload ever executes JS against a real browser) and safe for lab targets.
"""
import re
import uuid

MARKER_PAYLOADS = [
    "<script>__VG_MARK__</script>",
    "\"'><__VG_MARK__>",
    "<img src=x onerror=__VG_MARK__>",
]

AI_INSIGHT = (
    "Encode all user-controlled output using context-aware escaping (HTML entity encoding for HTML body, "
    "attribute encoding for attribute values, JS string escaping inside scripts). Adopt a templating engine "
    "with auto-escaping enabled by default, and add a strict Content-Security-Policy as defense in depth."
)


def test_reflected_xss(session, url, forms, get_params, findings_factory, timeout=8):
    results = []
    seen = set()

    def check_reflection(test_url, body, label, param_name):
        for payload_template in MARKER_PAYLOADS:
            marker = "VG" + uuid.uuid4().hex[:8]
            payload = payload_template.replace("__VG_MARK__", marker)
            try:
                if label == "GET":
                    resp = session.get(test_url, params={param_name: payload}, timeout=timeout)
                else:
                    resp = session.post(test_url, data={param_name: payload}, timeout=timeout)
            except Exception:
                continue

            if marker in resp.text and payload.split(marker)[0] in resp.text:
                key = (test_url, param_name)
                if key in seen:
                    continue
                seen.add(key)
                results.append(findings_factory(
                    title=f"Reflected Cross-Site Scripting (XSS) in parameter '{param_name}'",
                    category="Cross-Site Scripting (XSS)",
                    description=f"The parameter '{param_name}' on {test_url} reflects attacker-controlled input "
                                f"back into the HTML response without sufficient encoding, as confirmed by an "
                                f"unescaped marker payload appearing in the response body.",
                    affected_url=test_url,
                    severity="High",
                    cvss=6.1,
                    risk="An attacker can craft a malicious link or form submission that executes arbitrary "
                         "JavaScript in a victim's browser session, enabling session hijacking, credential theft, "
                         "or defacement.",
                    remediation="Apply context-aware output encoding for all reflected user input, validate input "
                                "against an allow-list where possible, and deploy a strict CSP.",
                    owasp="A03:2021 - Injection",
                    ai_insight=AI_INSIGHT,
                    evidence=f"Marker '{marker}' reflected unescaped via param '{param_name}' ({label})",
                ))
                return  # one finding per param is enough

    # Test GET query parameters
    for param_name in get_params:
        check_reflection(url, None, "GET", param_name)

    # Test discovered forms
    for form in forms:
        action = form.get("action") or url
        method = form.get("method", "GET").upper()
        for field in form.get("inputs", []):
            check_reflection(action, None, method if method in ("GET", "POST") else "GET", field)

    return results
