from oscan.core.finding import Finding, Severity
from oscan.core.scoring import summarize


def f(sev):
    return Finding(id="X", title="t", severity=sev, category="c")


def test_clean_scan_is_grade_a():
    s = summarize([f(Severity.INFO), f(Severity.INFO)])
    assert s.risk_score == 0
    assert s.grade == "A"
    assert s.total_findings == 0


def test_critical_drives_score_and_ttc():
    s = summarize([f(Severity.CRITICAL)])
    assert s.risk_score == 40
    assert s.time_to_compromise == "minutes to hours"


def test_score_caps_at_100():
    s = summarize([f(Severity.CRITICAL)] * 5)  # 5 * 40 = 200 -> capped
    assert s.risk_score == 100
    assert s.grade == "F"


def test_counts_exclude_info():
    s = summarize([f(Severity.HIGH), f(Severity.LOW), f(Severity.INFO)])
    assert s.counts == {"High": 1, "Low": 1}
    assert s.total_findings == 2
