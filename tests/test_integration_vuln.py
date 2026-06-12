"""Spin up a deliberately vulnerable local server and confirm oscan catches it.

Covers the full active path end-to-end: reflected XSS, SQL error, an exposed
admin endpoint, and weak cookie/header hygiene — without any external target.
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import pytest

from oscan.checks.headers import check_security_headers
from oscan.checks.cookies import check_cookies
from oscan.checks.injection import check_injection
from oscan.checks.auth import check_admin_endpoints
from oscan.core.context import ScanContext, Target
from oscan.core.http import HttpClient
from oscan.core.finding import Severity


class _VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        q = (qs.get("q", [""])[0])

        if path == "/":
            body = ('<html><body><h1>Shop</h1>'
                    '<a href="/search?q=test">search</a></body></html>')
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "sid=abc123; Path=/")  # no HttpOnly/SameSite
            self.end_headers()
            self.wfile.write(body.encode())
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


def test_exposed_admin_endpoint(vuln_server):
    ctx = _ctx(vuln_server)
    try:
        findings = check_admin_endpoints(ctx)
    finally:
        ctx.http.close()
    serious = [f for f in findings if f.severity is Severity.HIGH]
    assert any(f.id == "AUTH-001" for f in serious)
