"""A deliberately gentle HTTP client.

Every request goes through a global throttle so that even the `active` profile
stays well below anything resembling load. The client never follows redirects
silently (we want to *inspect* the HTTP->HTTPS hop) and caches GETs so checks
can share one fetch of the home page.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx

DEFAULT_UA = "oscan/0.1 (+self-assessment; https://github.com/orelsv/orel-cybersecurity-check)"


@dataclass
class TLSInfo:
    version: Optional[str] = None
    not_after: Optional[str] = None
    subject: Optional[str] = None
    error: Optional[str] = None


@dataclass
class HttpClient:
    timeout: float = 10.0
    min_interval: float = 0.3          # seconds between requests (global throttle)
    verify: bool = True
    user_agent: str = DEFAULT_UA
    _client: httpx.Client = field(init=False, repr=False)
    _last: float = field(default=0.0, init=False, repr=False)
    _cache: dict = field(default_factory=dict, init=False, repr=False)
    request_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self._client = httpx.Client(
            timeout=self.timeout,
            follow_redirects=False,
            verify=self.verify,
            headers={"User-Agent": self.user_agent},
        )

    def _throttle(self) -> None:
        delta = time.monotonic() - self._last
        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self._last = time.monotonic()

    def get(self, url: str, *, follow_redirects: bool = False, params: dict | None = None,
            headers: dict | None = None):
        self._throttle()
        self.request_count += 1
        return self._client.get(url, follow_redirects=follow_redirects, params=params, headers=headers)

    def post(self, url: str, *, data: dict | None = None, follow_redirects: bool = False):
        self._throttle()
        self.request_count += 1
        return self._client.post(url, data=data, follow_redirects=follow_redirects)

    def get_cached(self, url: str):
        """GET with a per-client cache (used for the home page that many checks read)."""
        if url not in self._cache:
            self._cache[url] = self.get(url, follow_redirects=True)
        return self._cache[url]

    def close(self) -> None:
        self._client.close()


def tls_info(url: str, *, timeout: float = 8.0) -> TLSInfo:
    """Open a TLS connection just to read the negotiated version and certificate.

    Uses the stdlib ssl module directly because httpx does not surface the
    negotiated protocol version cleanly.
    """
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.scheme != "https":
        return TLSInfo(error="target is not https")
    host = parsed.hostname or ""
    port = parsed.port or 443
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                subject = ""
                if cert:
                    for rdn in cert.get("subject", ()):  # type: ignore[assignment]
                        for k, v in rdn:
                            if k == "commonName":
                                subject = v
                return TLSInfo(
                    version=ssock.version(),
                    not_after=cert.get("notAfter") if cert else None,
                    subject=subject or None,
                )
    except ssl.SSLCertVerificationError as exc:
        return TLSInfo(error=f"certificate verification failed: {exc.verify_message}")
    except Exception as exc:  # noqa: BLE001
        return TLSInfo(error=f"{type(exc).__name__}: {exc}")
