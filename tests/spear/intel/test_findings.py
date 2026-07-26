import pytest

from deepsec.spear.intel.findings import (
    SEVERITY_WEIGHTS,
    annotate_compliance,
    diff_assessments,
    finding_risk,
    findings_diff_tool,
    findings_report_tool,
    format_diff,
    format_risk_report,
    score_findings,
)

SQLI = {"title": "SQL Injection in login", "severity": "Critical", "description": "union select"}
XSS = {"title": "Reflected XSS in search", "severity": "Medium", "description": "xss payload"}
INFO = {"title": "Server banner", "severity": "Info"}
REJECTED = {"title": "False positive", "severity": "High", "lifecycle_status": "rejected"}


def test_finding_risk_uses_severity_weight():
    assert finding_risk(SQLI) == SEVERITY_WEIGHTS["critical"]
    assert finding_risk(INFO) == SEVERITY_WEIGHTS["info"]


def test_finding_risk_prefers_cvss():
    assert finding_risk({"severity": "Low", "cvss_score": 9.1}) == 9.1
    assert finding_risk({"severity": "High", "cvss_score": 0}) == SEVERITY_WEIGHTS["high"]


def test_score_findings_counts_and_total():
    score = score_findings([SQLI, XSS, INFO, REJECTED])  # rejected excluded by default
    assert score.open_count == 3
    assert score.counts["Critical"] == 1
    assert score.counts["Medium"] == 1
    assert score.counts["Info"] == 1
    assert score.counts["High"] == 0  # rejected High not counted
    assert score.total == round(10.0 + 5.0 + 0.5, 1)
    assert score.band == "Critical"


def test_score_findings_open_only_false_includes_rejected():
    score = score_findings([SQLI, REJECTED], open_only=False)
    assert score.open_count == 2
    assert score.counts["High"] == 1


def test_annotate_compliance_attaches_controls():
    annotated = annotate_compliance(SQLI)
    assert "compliance" in annotated
    ids = {c["control_id"] for c in annotated["compliance"]}
    assert "A03:2021" in ids
    # original not mutated
    assert "compliance" not in SQLI


def test_diff_new_fixed_persistent():
    old = {"findings": [SQLI, XSS], "target": "example.com"}
    # XSS persists (same title), SQLI fixed, a new RCE appears
    new = {
        "findings": [
            {"title": "Reflected XSS in search", "severity": "Medium"},
            {"title": "RCE via upload", "severity": "Critical"},
        ],
        "target": "example.com",
    }
    report = diff_assessments(old, new)
    assert report.target == "example.com"
    assert {e.title for e in report.new} == {"RCE via upload"}
    assert {e.title for e in report.fixed} == {"SQL Injection in login"}
    assert {e.title for e in report.persistent} == {"Reflected XSS in search"}


def test_diff_detects_severity_regression():
    old = [{"title": "Weak TLS", "severity": "Low"}]
    new = [{"title": "Weak TLS", "severity": "High"}]
    report = diff_assessments(old, new)
    assert len(report.persistent) == 1
    assert report.persistent[0].old_severity == "Low"
    assert len(report.regressions) == 1


def test_diff_accepts_raw_lists():
    report = diff_assessments([], [SQLI])
    assert len(report.new) == 1


def test_format_risk_report_with_compliance():
    findings = [SQLI, XSS]
    out = format_risk_report(findings, score_findings(findings), with_compliance=True)
    assert "# Findings Risk Summary" in out
    assert "Top Risks" in out
    assert "Compliance Control Coverage" in out


def test_format_diff_sections():
    report = diff_assessments([XSS], [SQLI])
    out = format_diff(report)
    assert "Assessment Diff" in out
    assert "+1 new" in out
    assert "-1 fixed" in out


@pytest.mark.asyncio
async def test_report_tool_session_fallback():
    class _F:
        def model_dump(self):
            return SQLI

    class _S:
        findings = [_F()]

    class _A:
        session_state = _S()

    out = await findings_report_tool(agent=_A(), args={})
    assert "Findings Risk Summary" in out
    assert "SQL Injection" in out


@pytest.mark.asyncio
async def test_report_tool_no_findings():
    out = await findings_report_tool(agent=None, args={})
    assert out.startswith("[findings_report]")


@pytest.mark.asyncio
async def test_diff_tool_explicit_arrays():
    out = await findings_diff_tool(
        agent=None, args={"baseline": [XSS], "current": [SQLI], "target": "t"}
    )
    assert "Assessment Diff: t" in out
    assert "+1 new" in out
