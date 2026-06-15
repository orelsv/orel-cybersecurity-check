"""Optional Claude enrichment layer.

Detection is 100% deterministic and already done by the checks; this layer only
rewrites each finding's "why it matters" into one plain-language sentence a
non-expert can act on (the NetzSchild audience). It is a no-op unless the
`anthropic` package is installed AND an API key is present, so the tool works
fully offline.

Pattern borrowed from the Chat-With-Your-Entra project: the LLM is a
presentation layer, never the detection oracle. Numbers and severities come
from code; only the narrative comes from the model.
"""

from __future__ import annotations

import json
import os

from ..core.finding import Finding, Severity

# Cheap, fast model is the right default for high-volume, simple rephrasing.
# Override with OSCAN_ENRICH_MODEL if you want Sonnet/Opus.
DEFAULT_MODEL = "claude-haiku-4-5"
_MAX_FINDINGS = 40  # bound the prompt size / cost

_SYSTEM = (
    "You are a security explainer for non-experts. You will receive a JSON array "
    "of vulnerability findings (id, title, severity, technical 'why'). For each, "
    "write ONE short, plain-language sentence (max 25 words) explaining the real "
    "risk to a non-technical site owner. Do not invent new findings, do not change "
    "severity, do not give code. Respond with ONLY a JSON array of objects "
    '{"id": "...", "explanation": "..."} and nothing else.'
)


def _enabled() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def enrich_findings(findings: list[Finding]) -> None:
    """Fill `enrichment` on each real finding in place. Silent no-op on any problem."""
    if not _enabled():
        return
    try:
        import anthropic  # imported lazily so the package stays optional
    except ImportError:
        return

    targets = [f for f in findings if f.severity is not Severity.INFO][:_MAX_FINDINGS]
    if not targets:
        return

    payload = [
        {"id": f.id, "title": f.title, "severity": f.severity.value, "why": f.why} for f in targets
    ]

    try:
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model=os.environ.get("OSCAN_ENRICH_MODEL", DEFAULT_MODEL),
            max_tokens=2000,
            system=_SYSTEM,
            messages=[{"role": "user", "content": json.dumps(payload, ensure_ascii=False)}],
        )
    except Exception:
        return

    text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
    mapping = _parse(text)
    if not mapping:
        return

    # Multiple findings can share an id (e.g. one per cookie); apply to all matches.
    for f in targets:
        if f.id in mapping and not f.enrichment:
            f.enrichment = mapping[f.id]


def _parse(text: str) -> dict:
    """Defensively pull the JSON array out of the model response (it may add prose
    or code fences despite instructions - the Entra project's hard-won lesson)."""
    text = text.strip()
    if "```" in text:
        # strip a ```json ... ``` fence if present
        parts = text.split("```")
        for part in parts:
            part = part.strip()
            if part.startswith("json"):
                part = part[4:].strip()
            if part.startswith("["):
                text = part
                break
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end == -1:
        return {}
    try:
        data = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return {}
    out = {}
    for item in data:
        if isinstance(item, dict) and "id" in item and "explanation" in item:
            out[str(item["id"])] = str(item["explanation"])
    return out
