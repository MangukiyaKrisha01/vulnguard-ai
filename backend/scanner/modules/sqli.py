"""
Module: Basic SQL Injection Detection
Uses error-based and boolean-based heuristics with safe, non-destructive
payloads. This intentionally avoids time-based/stacked-query payloads that
could degrade or damage a target.
"""
import re
import time

ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "you have an error in your sql",
    "unclosed quotation mark", "quoted string not properly terminated",
    "sqlite3.OperationalError", "sqlite_query", "pg_query", "psql:",
    "ORA-01756", "ORA-00933", "Microsoft OLE DB Provider for ODBC Drivers",
    "Warning: mysql_", "valid MySQL result", "PostgreSQL query failed",
    "supplied argument is not a valid MySQL", "Unclosed quotation mark after the character string",
]

ERROR_PAYLOADS = ["'", "\"", "' OR '1'='1", "1' ORDER BY 1--", "')"]
BOOLEAN_TRUE = "' OR '1'='1' -- "
BOOLEAN_FALSE = "' AND '1'='2' -- "

AI_INSIGHT = (
    "Replace dynamic string-concatenated SQL with parameterized queries / prepared statements (or a vetted ORM). "
    "Apply least-privilege database accounts and validate input types/lengths server-side as defense in depth."
)


def test_sql_injection(session, url, forms, get_params, findings_factory, timeout=8):
    results = []
    tested = set()

    def baseline_length(test_url, params):
        try:
            r = session.get(test_url, params=params, timeout=timeout)
            return r
        except Exception:
            return None

    def test_param(test_url, param_name, method="GET", post_data=None):
        key = (test_url, param_name)
        if key in tested:
            return
        tested.add(key)

        # Error-based
        for payload in ERROR_PAYLOADS:
            try:
                if method == "GET":
                    resp = session.get(test_url, params={param_name: payload}, timeout=timeout)
                else:
                    data = dict(post_data or {})
                    data[param_name] = payload
                    resp = session.post(test_url, data=data, timeout=timeout)
            except Exception:
                continue

            body_lower = resp.text.lower()
            for sig in ERROR_SIGNATURES:
                if sig.lower() in body_lower:
                    results.append(findings_factory(
                        title=f"Possible SQL Injection (Error-Based) in parameter '{param_name}'",
                        category="SQL Injection",
                        description=f"Submitting a SQL meta-character payload to parameter '{param_name}' on "
                                    f"{test_url} triggered a database error message ('{sig}') reflected in the "
                                    f"response, indicating unsanitized input is reaching a SQL query.",
                        affected_url=test_url,
                        severity="Critical",
                        cvss=9.1,
                        risk="An attacker can manipulate the SQL query structure to read, modify, or delete "
                             "arbitrary database records, bypass authentication, or in some configurations "
                             "execute OS commands via the database.",
                        remediation="Use parameterized queries / prepared statements for all database access; "
                                    "never concatenate user input into SQL strings. Disable verbose DB error output.",
                        owasp="A03:2021 - Injection",
                        ai_insight=AI_INSIGHT,
                        evidence=f"Payload '{payload}' on param '{param_name}' triggered signature: '{sig}'",
                    ))
                    return

        # Boolean-based heuristic (compare response length true vs false)
        try:
            if method == "GET":
                r_true = session.get(test_url, params={param_name: BOOLEAN_TRUE}, timeout=timeout)
                r_false = session.get(test_url, params={param_name: BOOLEAN_FALSE}, timeout=timeout)
            else:
                data_t = dict(post_data or {}); data_t[param_name] = BOOLEAN_TRUE
                data_f = dict(post_data or {}); data_f[param_name] = BOOLEAN_FALSE
                r_true = session.post(test_url, data=data_t, timeout=timeout)
                r_false = session.post(test_url, data=data_f, timeout=timeout)

            len_true, len_false = len(r_true.text), len(r_false.text)
            if len_true != len_false and abs(len_true - len_false) > 25 and r_true.status_code == 200:
                results.append(findings_factory(
                    title=f"Possible SQL Injection (Boolean-Based) in parameter '{param_name}'",
                    category="SQL Injection",
                    description=f"Parameter '{param_name}' on {test_url} produced significantly different "
                                f"response content for an always-true vs. always-false SQL condition "
                                f"({len_true} vs {len_false} bytes), suggesting the input influences query logic.",
                    affected_url=test_url,
                    severity="High",
                    cvss=8.2,
                    risk="An attacker may be able to perform blind boolean-based SQL injection to extract data "
                         "character-by-character without seeing direct error output.",
                    remediation="Use parameterized queries / prepared statements for all database access and "
                                "apply strict server-side input validation.",
                    owasp="A03:2021 - Injection",
                    ai_insight=AI_INSIGHT,
                    evidence=f"TRUE payload length={len_true}, FALSE payload length={len_false}",
                ))
        except Exception:
            pass

    for param_name in get_params:
        test_param(url, param_name, "GET")

    for form in forms:
        action = form.get("action") or url
        method = form.get("method", "GET").upper()
        post_data = {f: "test" for f in form.get("inputs", [])}
        for field in form.get("inputs", []):
            test_param(action, field, method if method in ("GET", "POST") else "GET", post_data)

    return results
