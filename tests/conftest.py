"""Shared fakes so check tests never touch the network."""

from __future__ import annotations

from oscan.core.context import ScanContext, Target


class FakeHeaders:
    def __init__(self, pairs):
        self._pairs = list(pairs)  # list of (key, value), duplicates allowed

    def items(self):
        return list(self._pairs)

    def get(self, key, default=None):
        for k, v in self._pairs:
            if k.lower() == key.lower():
                return v
        return default

    def get_list(self, key):
        return [v for k, v in self._pairs if k.lower() == key.lower()]


class FakeResponse:
    def __init__(self, url, headers, status_code=200, text=""):
        self.url = url
        self.headers = FakeHeaders(headers)
        self.status_code = status_code
        self.text = text


class FakeHttp:
    """Returns a fixed response for get_cached / get."""

    def __init__(self, response):
        self._response = response
        self.request_count = 0

    def get_cached(self, url):
        return self._response

    def get(self, url, follow_redirects=False, params=None):
        self.request_count += 1
        return self._response

    def close(self):
        pass


def make_ctx(url, headers, profile="passive", text=""):
    resp = FakeResponse(url, headers, text=text)
    return ScanContext(target=Target(url=url), http=FakeHttp(resp), profile=profile)
