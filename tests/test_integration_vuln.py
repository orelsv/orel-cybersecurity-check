"""Spin up a deliberately vulnerable local server and confirm oscan catches it.

Covers the full active path end-to-end: reflected XSS, SQL error, an exposed
admin endpoint, and weak cookie/header hygiene - without any external target.
"""

import re
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import pytest

from oscan.checks.headers import check_security_headers
from oscan.checks.cookies import check_cookies
from oscan.checks.injection import check_injection
from oscan.checks.auth import check_admin_endpoints
from oscan.checks.cors import check_cors
from oscan.checks.api import check_api_docs, check_excessive_data, check_verbose_errors
from oscan.core.context import ScanContext, Target
from oscan.core.http import HttpClient
from oscan.core.finding import Severity


class _VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, ctype, body, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        # Vulnerable CORS: reflect any Origin.
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        q = (qs.get("q", [""])[0])

        if path == "/":
            body = ('<html><body><h1>Shop</h1>'
                    '<a href="/search?q=test">search</a>'
                    '<a href="/blind?id=1">item</a>'
                    '<a href="/nosql?q=x">find</a>'
                    '<a href="/fetch?url=x">load</a></body></html>')
            self._send(200, "text/html", body, extra=[("Set-Cookie", "sid=abc123; Path=/")])
        elif path == "/swagger.json":
            self._send(200, "application/json", b'{"openapi":"3.0.0","paths":{}}')
        elif path == "/api/users":
            self._send(200, "application/json",
                       b'[{"id":1,"name":"alice","password_hash":"$2b$10$abc","ssn":"111-22-3333"}]')
        elif path == "/nosql":
            body = "<html><body>ok</body></html>"
            if any(c in q for c in ('"', "{", "\\")):
                body = "MongoServerError: unknown operator: $oscan"
            self._send(200, "text/html", body)
        elif path == "/fetch":
            url = qs.get("url", [""])[0]
            if "169.254.169.254" in url or "metadata.google" in url:
                self._send(200, "text/plain", "instance-id: i-0abc\nami-id: ami-123")
            else:
                self._send(200, "text/html", "<html><body>ok</body></html>")
        elif path.startswith("/oscan-nonexistent"):
            # Verbose error / stack trace.
            self._send(500, "text/html",
                       "<html><body><h2>Werkzeug Debugger</h2>"
                       "Traceback (most recent call last):\n  File app.py line 42</body></html>")
        elif path == "/blind":
            # Pure blind SQLi: a sleep payload delays the response, but nothing is
            # reflected and no SQL error is ever returned.
            ident = qs.get("id", [""])[0]
            if re.search(r"(SLEEP|pg_sleep)\(", ident, re.I):
                time.sleep(0.6)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")
        elif path == "/search":
            # Reflect q unencoded (XSS) and emit a SQL error when a quote appears.
            body = f"<html><body>Results for: {q}</body></html>"
            if "'" in q:
                body += "<pre>You have an error in your SQL syntax near ...</pre>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body.encode())
        elif path == "/admin":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"users": ["admin", "alice"]}')
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")


@pytest.fixture
def vuln_server():
    server = HTTPServer(("127.0.0.1", 0), _VulnHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def _ctx(url):
    ctx = ScanContext(target=Target(url=url), http=HttpClient(min_interval=0.0),
                      profile="active", intrusive_allowed=True)
    return ctx


def test_weak_headers_and_cookies(vuln_server):
    ctx = _ctx(vuln_server)
    try:
        hdr_ids = {f.id for f in check_security_headers(ctx) if f.severity is not Severity.INFO}
        cookie_ids = {f.id for f in check_cookies(ctx)}
    finally:
        ctx.http.close()
    assert "HDR-004" in hdr_ids          # missing CSP
    assert "COOKIE-002" in cookie_ids    # missing HttpOnly


def test_reflected_xss_and_sql_detected(vuln_server):
    ctx = _ctx(vuln_server)
    try:
        ids = {f.id for f in check_injection(ctx)}
    finally:
        ctx.http.close()
    assert "INJ-XSS" in ids
    assert "INJ-SQL" in ids


def test_time_based_blind_sqli_detected(vuln_server):
    ctx = _ctx(vuln_server)
    # Small delay/threshold so the test is fast (server sleeps 0.6s on /blind).
    ctx.options = {"sqli_delay": 0.5, "sqli_threshold": 0.4}
    try:
        ids = {f.id for f in check_injection(ctx)}
    finally:
        ctx.http.close()
    assert "INJ-SQL-TIME" in ids


def test_exposed_admin_endpoint(vuln_server):
    ctx = _ctx(vuln_server)
    try:
        findings = check_admin_endpoints(ctx)
    finally:
        ctx.http.close()
    serious = [f for f in findings if f.severity is Severity.HIGH]
    assert any(f.id == "AUTH-001" for f in serious)


def test_nosqli_and_ssrf_detected(vuln_server):
    ctx = _ctx(vuln_server)
    try:
        ids = {f.id for f in check_injection(ctx)}
    finally:
        ctx.http.close()
    assert "INJ-NOSQL" in ids
    assert "INJ-SSRF" in ids


def test_cors_reflection_flagged(vuln_server):
    ctx = _ctx(vuln_server)
    try:
        findings = check_cors(ctx)
    finally:
        ctx.http.close()
    f = {x.id: x for x in findings}
    assert "CORS-001" in f and f["CORS-001"].severity is Severity.HIGH


def test_api_docs_and_verbose_errors(vuln_server):
    ctx = _ctx(vuln_server)
    try:
        doc_ids = {f.id for f in check_api_docs(ctx) if f.severity is not Severity.INFO}
        err_ids = {f.id for f in check_verbose_errors(ctx)}
    finally:
        ctx.http.close()
    assert "API-001" in doc_ids     # exposed swagger.json
    assert "API-004" in err_ids     # stack trace


def test_excessive_data_exposure(vuln_server):
    ctx = _ctx(vuln_server + "/api/users")
    try:
        ids = {f.id for f in check_excessive_data(ctx)}
    finally:
        ctx.http.close()
    assert "API-003" in ids
