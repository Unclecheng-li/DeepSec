import pytest

from deepsec.spear.intel.compliance import (
    compliance_map_tool,
    format_report,
    list_frameworks,
    map_findings,
    normalize_frameworks,
)

SQLI = {
    "title": "SQL Injection in login",
    "severity": "Critical",
    "description": "union select extracts data",
    "evidence": "' OR 1=1 --",
}
WEAK_TLS = {
    "title": "Weak TLS ciphers",
    "severity": "Medium",
    "description": "expired cert, weak encryption",
}


def test_normalize_frameworks_aliases_and_default():
    assert normalize_frameworks(None) == ["pci", "nist", "owasp", "iso"]
    assert normalize_frameworks(["OWASP Top 10"]) == ["owasp"]
    assert set(normalize_frameworks(["pci-dss", "ISO 27001"])) == {"pci", "iso"}


def test_list_frameworks_counts():
    fws = {f["key"]: f["controls"] for f in list_frameworks()}
    assert fws["owasp"] == 10
    assert fws["pci"] > 0 and fws["nist"] > 0 and fws["iso"] > 0


def test_map_sqli_hits_injection_controls():
    report = map_findings([SQLI])
    ids = {(m.control.framework, m.control.control_id) for m in report.mappings}
    assert any(cid == "A03:2021" for _, cid in ids)
    assert any(cid == "6.2.4" for _, cid in ids)
    # Critical severity -> fail status
    assert all(m.status == "fail" for m in report.mappings if m.control.control_id == "A03:2021")


def test_framework_filter_limits_output():
    report = map_findings([SQLI], frameworks=["owasp"])
    assert report.mappings
    assert all(m.control.framework.startswith("OWASP") for m in report.mappings)


def test_dedup_same_control_same_finding_once():
    report = map_findings([SQLI])
    keys = [f"{m.control.framework}:{m.control.control_id}:{m.finding_title}" for m in report.mappings]
    assert len(keys) == len(set(keys))


def test_medium_severity_uses_default_status():
    # network/firewall rule has default "warn"; weak TLS rule default "fail".
    report = map_findings([WEAK_TLS], frameworks=["pci"])
    tls = [m for m in report.mappings if m.control.control_id == "4.2.1"]
    assert tls and tls[0].status == "fail"  # crypto rule default fail, medium keeps default


def test_format_report_structure():
    out = format_report(map_findings([SQLI], target="example.com"))
    assert "# Compliance Mapping Report" in out
    assert "example.com" in out
    assert "## Executive Summary" in out
    assert "## Gap Analysis" in out


@pytest.mark.asyncio
async def test_tool_with_explicit_findings():
    out = await compliance_map_tool(agent=None, args={"findings": [SQLI], "target": "t"})
    assert "Compliance Mapping Report" in out
    assert "A03:2021" in out


@pytest.mark.asyncio
async def test_tool_no_findings_message():
    out = await compliance_map_tool(agent=None, args={})
    assert out.startswith("[compliance_map]") and "No findings" in out


@pytest.mark.asyncio
async def test_tool_pulls_from_session_state():
    class _Finding:
        def model_dump(self):
            return SQLI

    class _Session:
        findings = [_Finding()]

    class _Agent:
        session_state = _Session()

    out = await compliance_map_tool(agent=_Agent(), args={})
    assert "A03:2021" in out


@pytest.mark.asyncio
async def test_tool_no_matching_mappings():
    out = await compliance_map_tool(
        agent=None, args={"findings": [{"title": "nothing relevant", "severity": "Info"}]}
    )
    assert "No control mappings" in out
