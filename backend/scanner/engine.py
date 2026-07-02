"""
VulnGuard AI - Scanner Engine
Crawls a target (bounded by MAX_CRAWL_PAGES / MAX_CRAWL_DEPTH), discovers
forms/parameters/links, and runs all vulnerability detection modules against
each discovered page. Designed for authorized lab/local targets only.
"""
import time
import random
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

from scanner.modules import headers as headers_module
from scanner.modules import xss as xss_module
from scanner.modules import sqli as sqli_module
from scanner.modules import misc_checks

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VulnGuardAI-Scanner/1.0",
    "Mozilla/5.0 (X11; Linux x86_64) VulnGuardAI-Scanner/1.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) VulnGuardAI-Scanner/1.0",
]


class ScanEngine:
    def __init__(self, target_url, scan_depth=2, max_pages=25, timeout=8, rate_delay=0.15, log_callback=None,
                 progress_callback=None):
        self.target_url = target_url.rstrip("/")
        parsed = urlparse(self.target_url)
        self.base_domain = parsed.netloc
        self.scheme = parsed.scheme or "http"
        self.scan_depth = scan_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.rate_delay = rate_delay
        self.log_callback = log_callback or (lambda msg, level="info": None)
        self.progress_callback = progress_callback or (lambda pct: None)

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

        self.visited = set()
        self.findings = []
        self.pages_crawled = 0

    def log(self, message, level="info"):
        self.log_callback(message, level)

    def _make_finding(self, title, category, description, affected_url, severity, cvss, risk,
                       remediation, owasp, ai_insight, evidence=""):
        return {
            "title": title,
            "category": category,
            "description": description,
            "affected_url": affected_url,
            "severity": severity,
            "cvss_score": cvss,
            "risk_explanation": risk,
            "remediation": remediation,
            "owasp_mapping": owasp,
            "ai_insight": ai_insight,
            "evidence": evidence,
        }

    def _same_domain(self, url):
        return urlparse(url).netloc == self.base_domain

    def _extract_forms(self, soup, page_url):
        forms = []
        for form_tag in soup.find_all("form"):
            action = form_tag.get("action") or page_url
            action = urljoin(page_url, action)
            method = (form_tag.get("method") or "GET").upper()
            inputs = []
            for inp in form_tag.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append(name)
            if inputs:
                forms.append({"action": action, "method": method, "inputs": inputs})
        return forms

    def _extract_links(self, soup, page_url):
        links = set()
        for a in soup.find_all("a", href=True):
            href = urljoin(page_url, a["href"])
            href = href.split("#")[0]
            if self._same_domain(href) and href.startswith(("http://", "https://")):
                links.add(href)
        return links

    def crawl_and_scan(self):
        queue = deque([(self.target_url, 0)])
        directories_seen = set()
        total_budget = self.max_pages

        self.log(f"Starting scan of {self.target_url} (depth={self.scan_depth}, max_pages={self.max_pages})")

        # robots.txt check (once)
        try:
            self.findings.extend(misc_checks.check_robots_txt(
                self.session, f"{self.scheme}://{self.base_domain}", self._make_finding, self.timeout))
        except Exception as e:
            self.log(f"robots.txt check failed: {e}", "warning")

        while queue and self.pages_crawled < self.max_pages:
            url, depth = queue.popleft()
            if url in self.visited or depth > self.scan_depth:
                continue
            self.visited.add(url)

            try:
                time.sleep(self.rate_delay)
                resp = self.session.get(url, timeout=self.timeout)
            except requests.exceptions.RequestException as e:
                self.log(f"Failed to fetch {url}: {e}", "warning")
                continue

            self.pages_crawled += 1
            self.log(f"[{self.pages_crawled}/{total_budget}] Crawled {url} (status {resp.status_code})")
            self.progress_callback(min(95, int((self.pages_crawled / total_budget) * 70)))

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type and resp.text:
                pass  # still allow header checks on non-HTML

            # --- Header-based checks (every page) ---
            self.findings.extend(headers_module.analyze_headers(url, resp.headers, self._make_finding))
            self.findings.extend(headers_module.analyze_cookies(url, resp, self._make_finding))
            self.findings.extend(misc_checks.check_http_methods(self.session, url, self._make_finding, self.timeout))

            parsed_url = urlparse(url)
            directory = parsed_url._replace(path="/".join(parsed_url.path.split("/")[:-1]) + "/").geturl()
            directories_seen.add(directory)

            if "text/html" in content_type:
                soup = BeautifulSoup(resp.text, "html.parser")
                forms = self._extract_forms(soup, url)
                get_params = list(parse_qs(parsed_url.query).keys())

                self.log(f"Discovered {len(forms)} form(s) and {len(get_params)} query param(s) on {url}")

                # --- Injection / logic checks ---
                self.findings.extend(misc_checks.check_sensitive_info(url, resp.text, self._make_finding))
                self.findings.extend(misc_checks.check_csrf(url, forms, self._make_finding))
                self.findings.extend(misc_checks.check_open_redirect(
                    self.session, url, get_params, self._make_finding, self.timeout))

                try:
                    self.findings.extend(xss_module.test_reflected_xss(
                        self.session, url, forms, get_params, self._make_finding, self.timeout))
                except Exception as e:
                    self.log(f"XSS module error on {url}: {e}", "warning")

                try:
                    self.findings.extend(sqli_module.test_sql_injection(
                        self.session, url, forms, get_params, self._make_finding, self.timeout))
                except Exception as e:
                    self.log(f"SQLi module error on {url}: {e}", "warning")

                # Queue child links
                if depth < self.scan_depth:
                    for link in self._extract_links(soup, url):
                        if link not in self.visited:
                            queue.append((link, depth + 1))

        # Directory listing check across discovered directories (bounded)
        try:
            self.findings.extend(misc_checks.check_directory_listing(
                self.session, self.target_url, list(directories_seen)[:15], self._make_finding, self.timeout))
        except Exception as e:
            self.log(f"Directory listing check failed: {e}", "warning")

        self.progress_callback(100)
        self.log(f"Scan complete. {self.pages_crawled} page(s) crawled, {len(self.findings)} finding(s).")
        return self.findings, self.pages_crawled
