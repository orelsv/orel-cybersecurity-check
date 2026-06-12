import sys
import types

from oscan.report import enrich
from oscan.core.finding import Finding, Severity


def test_parse_plain_array():
    out = enrich._parse('[{"id": "A", "explanation": "hello"}]')
    assert out == {"A": "hello"}


def test_parse_code_fenced():
    text = '```json\n[{"id": "A", "explanation": "x"}]\n```'
    assert enrich._parse(text) == {"A": "x"}


def test_parse_prose_wrapped():
    text = 'Sure! Here you go:\n[{"id":"B","explanation":"y"}]\nHope that helps.'
    assert enrich._parse(text) == {"B": "y"}


def test_parse_garbage_returns_empty():
    assert enrich._parse("not json at all") == {}


def test_noop_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    f = Finding(id="X", title="t", severity=Severity.HIGH, category="c", why="w")
    enrich.enrich_findings([f])
    assert f.enrichment == ""


def _install_fake_anthropic(monkeypatch, response_text):
    class _Block:
        type = "text"
        text = response_text

    class _Resp:
        content = [_Block()]

    class _Messages:
        def create(self, **kwargs):
            return _Resp()

    class _Client:
        def __init__(self, *a, **k):
            self.messages = _Messages()

    fake = types.SimpleNamespace(Anthropic=_Client)
    monkeypatch.setitem(sys.modules, "anthropic", fake)


def test_enrich_applies_explanations(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    _install_fake_anthropic(monkeypatch, '[{"id": "X", "explanation": "plain words"}]')
    f = Finding(id="X", title="t", severity=Severity.HIGH, category="c", why="w")
    enrich.enrich_findings([f])
    assert f.enrichment == "plain words"


def test_enrich_skips_info_findings(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    _install_fake_anthropic(monkeypatch, '[{"id": "X", "explanation": "should not apply"}]')
    info = Finding(id="X", title="t", severity=Severity.INFO, category="c")
    enrich.enrich_findings([info])
    assert info.enrichment == ""
