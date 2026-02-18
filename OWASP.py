"""
OWASP Top 10 (2021) Interactive Penetration Testing Tool
---------------------------------------------------------
LEGAL DISCLAIMER: Only use this tool against systems you own or have
explicit written permission to test. Unauthorized scanning is illegal.
"""

import requests
import urllib.parse
import sys
import re
from requests.exceptions import (
    ConnectionError, Timeout, SSLError, RequestException
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT = 10  # seconds — FIX: original had no timeout (hangs forever)

OWASP_MENU = {
    "1":  "A01 — Broken Access Control",
    "2":  "A02 — Cryptographic Failures",
    "3":  "A03 — Injection (SQL & XSS)",
    "4":  "A04 — Insecure Design (Directory Traversal)",
    "5":  "A05 — Security Misconfiguration",
    "6":  "A06 — Vulnerable & Outdated Components",
    "7":  "A07 — Identification & Authentication Failures",
    "8":  "A08 — Software & Data Integrity Failures",
    "9":  "A09 — Security Logging & Monitoring Failures",
    "10": "A10 — Server-Side Request Forgery (SSRF)",
    "0":  "Run ALL tests",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """
    FIX 1: Original accepted bare URLs like 'example.com' which cause
    requests to raise MissingSchema. Prepend https:// when no scheme given.
    """
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def safe_get(url: str, *, params=None, headers=None, verify=True,
             allow_redirects=True) -> requests.Response | None:
    """
    Wrapper around requests.get with timeout and broad exception handling.
    FIX 2: None of the original methods had try/except — any network error
    would crash the entire tool mid-run.
    """
    try:
        return requests.get(
            url,
            params=params,
            headers=headers,
            verify=verify,
            allow_redirects=allow_redirects,
            timeout=REQUEST_TIMEOUT,
        )
    except SSLError as e:
        print(f"    [!] SSL error: {e}")
    except ConnectionError:
        print(f"    [!] Could not connect to {url}")
    except Timeout:
        print(f"    [!] Request timed out ({REQUEST_TIMEOUT}s)")
    except RequestException as e:
        print(f"    [!] Request error: {e}")
    return None


def section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def result(vulnerable: bool, detail: str):
    tag = "  [VULNERABLE]" if vulnerable else "  [OK]"
    print(f"{tag} {detail}")


# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) Test Class
# ---------------------------------------------------------------------------

class OWASPPentest:

    def __init__(self, target_url: str):
        # FIX 3: Original did no URL normalisation — now handled here.
        self.target_url = normalize_url(target_url)
        self.findings: list[str] = []

    # ------------------------------------------------------------------
    # A01 — Broken Access Control
    # ------------------------------------------------------------------
    def test_broken_access_control(self):
        section("A01 — Broken Access Control")
        protected_endpoints = [
            "/admin", "/admin/dashboard", "/admin/users",
            "/user/settings", "/user/data",
            "/api/admin", "/api/users", "/config",
        ]
       
        for endpoint in protected_endpoints:
            url = f"{self.target_url}{endpoint}"
            resp = safe_get(url)
            if resp is None:
                continue
            if resp.status_code == 200:
                detail = f"Endpoint accessible without auth: {url} (HTTP 200)"
                result(True, detail)
                self.findings.append(detail)
            elif resp.status_code in (401, 403):
                result(False, f"Access control enforced at {url} ({resp.status_code})")
            elif resp.status_code == 404:
                print(f"  [--] Endpoint not found: {url}")
            else:
                print(f"  [?]  Unexpected status {resp.status_code} at {url}")

    # ------------------------------------------------------------------
    # A02 — Cryptographic Failures
    # ------------------------------------------------------------------
    def test_cryptographic_failures(self):
        section("A02 — Cryptographic Failures")

        # Non-HTTPS check
        if not self.target_url.startswith("https://"):
            detail = "Site not using HTTPS — data in transit is unencrypted."
            result(True, detail)
            self.findings.append(detail)
        else:
            result(False, "HTTPS in use.")

        # SSL certificate validation
        resp = safe_get(self.target_url, verify=True)
        if resp is None:
            # safe_get already printed the SSL error
            detail = "SSL certificate validation failed — possible expired or self-signed cert."
            result(True, detail)
            self.findings.append(detail)
        else:
            result(False, "SSL certificate validated successfully.")

        # Strict-Transport-Security header
        if resp:
            if "Strict-Transport-Security" not in resp.headers:
                detail = "Missing Strict-Transport-Security (HSTS) header."
                result(True, detail)
                self.findings.append(detail)
            else:
                result(False, "HSTS header present.")

    # ------------------------------------------------------------------
    # A03 — Injection (SQL + XSS)
    # ------------------------------------------------------------------
    def test_injection(self):
        section("A03 — Injection (SQL Injection & XSS)")

        # --- SQL Injection ---
        print("\n  [SQL Injection]")
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "1; DROP TABLE users--",
        ]
        sql_error_patterns = [
            "sql syntax", "mysql_fetch", "unclosed quotation",
            "database error", "odbc", "ora-", "sqlite", "pg::",
            "syntax error", "microsoft jet",
        ]
        for payload in sql_payloads:
            resp = safe_get(f"{self.target_url}", params={"query": payload, "id": payload})
            if resp and any(p in resp.text.lower() for p in sql_error_patterns):
                detail = f"Potential SQL Injection — error string in response (payload: {payload!r})"
                result(True, detail)
                self.findings.append(detail)
                break
        else:
            result(False, "No obvious SQL Injection error strings detected.")

        # --- XSS ---
        print("\n  [Cross-Site Scripting (XSS)]")
        xss_payloads = [
            "<script>alert('xss')</script>",
            '"><img src=x onerror=alert(1)>',
            "javascript:alert(1)",
        ]
        for payload in xss_payloads:
            resp = safe_get(f"{self.target_url}", params={"q": payload, "search": payload})
            if resp and payload in resp.text:
                detail = f"Potential Reflected XSS — payload echoed back (payload: {payload!r})"
                result(True, detail)
                self.findings.append(detail)
                break
        else:
            result(False, "No obvious Reflected XSS detected.")

    # ------------------------------------------------------------------
    # A04 — Insecure Design (Directory Traversal)
    # ------------------------------------------------------------------
    def test_insecure_design(self):
        section("A04 — Insecure Design (Directory Traversal / Path Traversal)")
        traversal_payloads = [
            "../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]
        for payload in traversal_payloads:
            resp = safe_get(f"{self.target_url}", params={"file": payload, "path": payload})
            if resp and ("root:x:" in resp.text or "[boot loader]" in resp.text):
                detail = f"Potential Path Traversal — system file content in response."
                result(True, detail)
                self.findings.append(detail)
                return
        result(False, "No obvious Path Traversal detected.")

    # ------------------------------------------------------------------
    # A05 — Security Misconfiguration
    # ------------------------------------------------------------------
    def test_security_misconfiguration(self):
        section("A05 — Security Misconfiguration")
        resp = safe_get(self.target_url)
        if resp is None:
            return

        headers = resp.headers
        findings_local = []

        # Information-leaking headers
        for h in ("X-Powered-By", "Server", "X-AspNet-Version", "X-Runtime"):
            if h in headers:
                findings_local.append(f"Leaking header present: {h}: {headers[h]}")

        # Missing security headers
        security_headers = {
            "X-Content-Type-Options": "Prevents MIME-sniffing",
            "X-Frame-Options": "Clickjacking protection",
            "Content-Security-Policy": "XSS / data injection policy",
            "Referrer-Policy": "Controls referrer information",
            "Permissions-Policy": "Feature/permission control",
        }
        for h, desc in security_headers.items():
            if h not in headers:
                findings_local.append(f"Missing security header: {h} ({desc})")

        # Directory listing (common exposed paths)
        for path in ("/", "/.git/", "/.env", "/backup", "/phpinfo.php"):
            r = safe_get(f"{self.target_url}{path}")
            if r and r.status_code == 200:
                if "Index of /" in r.text or "[core]" in r.text or "phpinfo" in r.text.lower():
                    findings_local.append(f"Exposed sensitive path: {self.target_url}{path}")

        for f in findings_local:
            result(True, f)
            self.findings.append(f)

        if not findings_local:
            result(False, "No obvious Security Misconfiguration detected.")

    # ------------------------------------------------------------------
    # A06 — Vulnerable & Outdated Components
    # ------------------------------------------------------------------
    def test_outdated_components(self):
        section("A06 — Vulnerable & Outdated Components")
        resp = safe_get(self.target_url)
        if resp is None:
            return

        version_patterns = {
            "Server": r"(Apache|nginx|IIS)[\s/]([\d.]+)",
            "X-Powered-By": r"(PHP|ASP\.NET|Express)[\s/]?([\d.]+)?",
        }
        found_any = False
        for header, pattern in version_patterns.items():
            value = resp.headers.get(header, "")
            match = re.search(pattern, value, re.IGNORECASE)
            if match:
                detail = f"Version disclosure in '{header}': {value}"
                result(True, detail)
                self.findings.append(detail)
                found_any = True

        # Check for common outdated library hints in page source
        old_libs = {
            "jquery-1.": "jQuery 1.x (EOL, multiple XSS/RCE CVEs)",
            "jquery-2.": "jQuery 2.x (EOL)",
            "bootstrap/3": "Bootstrap 3.x (EOL)",
            "angular.js/1": "AngularJS 1.x (EOL)",
        }
        if resp.text:
            for pattern, label in old_libs.items():
                if pattern in resp.text.lower():
                    detail = f"Potentially outdated library detected in page source: {label}"
                    result(True, detail)
                    self.findings.append(detail)
                    found_any = True

        if not found_any:
            result(False, "No obvious outdated component disclosures detected.")

    # ------------------------------------------------------------------
    # A07 — Identification & Authentication Failures
    # ------------------------------------------------------------------
    def test_auth_failures(self):
        section("A07 — Identification & Authentication Failures")
        login_endpoints = ["/login", "/admin/login", "/api/login", "/signin"]

        for endpoint in login_endpoints:
            url = f"{self.target_url}{endpoint}"
            # Test common weak credentials
            weak_creds = [
                {"username": "admin", "password": "admin"},
                {"username": "admin", "password": "password"},
                {"username": "root",  "password": "root"},
            ]
            resp_get = safe_get(url)
            if resp_get is None or resp_get.status_code == 404:
                continue

            print(f"  [*] Login endpoint found: {url}")
            for creds in weak_creds:
                try:
                    post_resp = requests.post(
                        url, data=creds, timeout=REQUEST_TIMEOUT, allow_redirects=True
                    )
                    # Heuristic: successful login usually redirects or returns 200
                    # without re-displaying a login form
                    if post_resp.status_code in (200, 302) and "login" not in post_resp.url:
                        detail = f"Weak credentials accepted at {url} ({creds['username']}:{creds['password']})"
                        result(True, detail)
                        self.findings.append(detail)
                except RequestException:
                    pass

        # Check for missing account lockout (rudimentary — 10 fast requests)
        for endpoint in login_endpoints:
            url = f"{self.target_url}{endpoint}"
            responses = []
            for _ in range(10):
                r = safe_get(url, params={"username": "admin", "password": "wrongpass"})
                if r:
                    responses.append(r.status_code)
            if responses and all(c == 200 for c in responses):
                detail = f"No rate-limiting / lockout detected on {url} after 10 rapid requests."
                result(True, detail)
                self.findings.append(detail)

        if not any("auth" in f.lower() or "credential" in f.lower() or "lockout" in f.lower()
                   for f in self.findings):
            result(False, "No obvious authentication failures detected.")

    # ------------------------------------------------------------------
    # A08 — Software & Data Integrity Failures
    # ------------------------------------------------------------------
    def test_integrity_failures(self):
        section("A08 — Software & Data Integrity Failures")
        resp = safe_get(self.target_url)
        if resp is None:
            return

        # Look for CDN scripts loaded over HTTP (not HTTPS)
        http_scripts = re.findall(r'src=["\']http://[^"\']+["\']', resp.text, re.IGNORECASE)
        # Look for <script> tags missing integrity= attribute
        all_scripts = re.findall(r'<script[^>]+src=["\'][^"\']+["\'][^>]*>', resp.text, re.IGNORECASE)
        missing_sri = [s for s in all_scripts if "integrity=" not in s.lower()]

        found = False
        for src in http_scripts:
            detail = f"External script loaded over HTTP (no encryption): {src}"
            result(True, detail)
            self.findings.append(detail)
            found = True

        if missing_sri:
            detail = f"{len(missing_sri)} external <script> tag(s) missing Subresource Integrity (SRI) attribute."
            result(True, detail)
            self.findings.append(detail)
            found = True

        if not found:
            result(False, "No obvious integrity failure signals detected.")

    # ------------------------------------------------------------------
    # A09 — Security Logging & Monitoring Failures
    # ------------------------------------------------------------------
    def test_logging_failures(self):
        section("A09 — Security Logging & Monitoring Failures")
        # This is difficult to verify externally; we look for diagnostic
        # pages that hint at inadequate log/error handling.
        debug_paths = [
            "/debug", "/trace", "/actuator", "/actuator/env",
            "/actuator/health", "/swagger-ui.html", "/api-docs",
            "/server-status", "/?debug=true", "/?XDEBUG_SESSION_START=1",
        ]
        found = False
        for path in debug_paths:
            url = f"{self.target_url}{path}"
            resp = safe_get(url)
            if resp and resp.status_code == 200 and len(resp.text) > 100:
                detail = f"Exposed diagnostic/debug endpoint: {url}"
                result(True, detail)
                self.findings.append(detail)
                found = True

        # Check for verbose error messages by sending a bad request
        resp = safe_get(f"{self.target_url}/nonexistent-path-xyz987")
        if resp and resp.status_code in (200, 500):
            for keyword in ("stack trace", "exception", "traceback", "at com.", "line ", "error in /"):
                if keyword in resp.text.lower():
                    detail = "Verbose error/stack trace exposed in HTTP response."
                    result(True, detail)
                    self.findings.append(detail)
                    found = True
                    break

        if not found:
            result(False, "No obvious logging/monitoring failure indicators detected.")

    # ------------------------------------------------------------------
    # A10 — Server-Side Request Forgery (SSRF)
    # ------------------------------------------------------------------
    def test_ssrf(self):
        section("A10 — Server-Side Request Forgery (SSRF)")
       
        ssrf_payloads = {
            "http://127.0.0.1/":                "localhost loopback",
            "http://169.254.169.254/latest/":   "AWS instance metadata",
            "http://metadata.google.internal/": "GCP metadata",
            "http://0.0.0.0/":                  "null-route loopback",
        }
        found = False
        for payload, label in ssrf_payloads.items():
            for param in ("url", "uri", "path", "src", "redirect", "dest", "image"):
                resp = safe_get(self.target_url, params={param: payload})
                if resp and resp.status_code == 200 and len(resp.text) > 0:
                    # Heuristic — cloud metadata returns specific strings
                    for indicator in ("ami-id", "instance-id", "computeMetadata", "local-ipv4"):
                        if indicator in resp.text:
                            detail = f"SSRF confirmed — {label} metadata in response (param={param!r})"
                            result(True, detail)
                            self.findings.append(detail)
                            found = True
        if not found:
            result(False, "No SSRF indicators detected (external confirmation may be needed).")

    # ------------------------------------------------------------------
    # Run all tests + summary
    # ------------------------------------------------------------------
    def run_all_tests(self):
        tests = [
            self.test_broken_access_control,
            self.test_cryptographic_failures,
            self.test_injection,
            self.test_insecure_design,
            self.test_security_misconfiguration,
            self.test_outdated_components,
            self.test_auth_failures,
            self.test_integrity_failures,
            self.test_logging_failures,
            self.test_ssrf,
        ]
        for test in tests:
            test()
        self.print_summary()

    def print_summary(self):
        print(f"\n{'='*60}")
        print(f"  SCAN SUMMARY — {self.target_url}")
        print(f"{'='*60}")
        if self.findings:
            print(f"  {len(self.findings)} potential issue(s) found:\n")
            for i, finding in enumerate(self.findings, 1):
                print(f"  {i:>2}. {finding}")
        else:
            print("  No vulnerabilities detected in this scan.")
        print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# Interactive CLI
# ---------------------------------------------------------------------------

TEST_MAP = {
    "1":  "test_broken_access_control",
    "2":  "test_cryptographic_failures",
    "3":  "test_injection",
    "4":  "test_insecure_design",
    "5":  "test_security_misconfiguration",
    "6":  "test_outdated_components",
    "7":  "test_auth_failures",
    "8":  "test_integrity_failures",
    "9":  "test_logging_failures",
    "10": "test_ssrf",
}


def print_banner():
    print("\n" + "=" * 60)
    print("  OWASP Top 10 (2021) Interactive Penetration Testing Tool")
    print("=" * 60)
    print("  ⚠  Only test systems you own or have written permission to test.")
    print("=" * 60)


def print_menu():
    print("\nSelect a test to run:")
    print("-" * 60)
    for key, label in OWASP_MENU.items():
        print(f"  {key:>2}. {label}")
    print("-" * 60)


def main():
    print_banner()

    while True:
        
        raw_url = input("\nEnter target URL (e.g. https://example.com): ").strip()
        if not raw_url:
            print("[!] URL cannot be empty.")
            continue
        target_url = normalize_url(raw_url)
        print(f"[*] Target set to: {target_url}")

        pentest = OWASPPentest(target_url)

        print_menu()
        choice = input("Enter choice: ").strip()

        if choice == "0":
            pentest.run_all_tests()
        elif choice in TEST_MAP:
            method = getattr(pentest, TEST_MAP[choice])
            method()
            pentest.print_summary()
        else:
            print("[!] Invalid choice. Please try again.")
            continue

        again = input("\nRun another scan? (yes/no): ").strip().lower()
        if again not in ("yes", "y"):
            print("\n[*] Exiting. Stay ethical. Goodbye!")
            sys.exit(0)


if __name__ == "__main__":
    main()
