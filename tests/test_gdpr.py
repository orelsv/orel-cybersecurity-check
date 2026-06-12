from conftest import make_ctx

from oscan.checks.gdpr import check_gdpr
from oscan.core.finding import Severity

_BAD = """
<html><head>
<script src="https://www.googletagmanager.com/gtag/js?id=G-XYZ"></script>
<link href="https://fonts.googleapis.com/css?family=Roboto" rel="stylesheet">
</head><body><h1>Shop</h1></body></html>
"""

_GOOD = """
<html><head><script src="/static/app.js"></script></head>
<body>
<div id="cookieconsent">We use cookies. <button>Accept</button></div>
<a href="/privacy-policy">Privacy Policy</a>
</body></html>
"""


def ids(findings):
    return {f.id for f in findings}


def test_trackers_and_fonts_without_consent_flagged():
    ctx = make_ctx(
        "https://shop.example",
        [("set-cookie", "_ga=GA1.2.3; Path=/")],
        text=_BAD,
    )
    f = check_gdpr(ctx)
    got = ids(f)
    assert "GDPR-001" in got   # tracking cookie before consent
    assert "GDPR-002" in got   # third-party tracker
    assert "GDPR-003" in got   # google fonts
    assert "GDPR-004" in got   # no consent banner
    assert "GDPR-005" in got   # no privacy policy


def test_consent_and_privacy_pass():
    ctx = make_ctx("https://clean.example", [], text=_GOOD)
    f = check_gdpr(ctx)
    real = [x for x in f if x.severity is not Severity.INFO]
    assert real == []
