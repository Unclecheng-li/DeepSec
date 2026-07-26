import pytest

from deepsec.spear.intel.remediation import (
    RemediationEngine,
    RemediationType,
    remediation_advice_tool,
)

SQLI = {"title": "SQL Injection in login", "severity": "Critical", "description": "union select"}


def test_engine_has_rules():
    assert RemediationEngine.get_rule_count() >= 15


def test_remediate_sqli_returns_steps():
    eng = RemediationEngine()
    rem = eng.remediate_finding(SQLI)
    assert rem.steps
    assert rem.source != "generic"  # matched a real rule
    assert "param" in rem.summary.lower() or "sql" in rem.summary.lower()
    # has at least one code or config step
    assert any(s.type in (RemediationType.CODE, RemediationType.CONFIG, RemediationType.COMMAND) for s in rem.steps)


def test_generic_fallback_for_unknown():
    eng = RemediationEngine()
    rem = eng.remediate_finding({"title": "totally unknown weirdness", "severity": "Low"})
    assert rem.source == "generic"
    assert rem.steps  # generic still offers guidance


def test_summary_markdown():
    eng = RemediationEngine()
    rems = eng.remediate_findings([SQLI])
    md = RemediationEngine.get_summary_markdown(rems)
    assert "Remediation Report" in md
    assert "Priority Summary" in md


@pytest.mark.asyncio
async def test_tool_with_query():
    out = await remediation_advice_tool(agent=None, args={"query": "cross-site scripting", "severity": "High"})
    assert "Remediation Report" in out


@pytest.mark.asyncio
async def test_tool_with_findings():
    out = await remediation_advice_tool(agent=None, args={"findings": [SQLI]})
    assert "Remediation Report" in out
    assert "##" in out


@pytest.mark.asyncio
async def test_tool_no_input():
    out = await remediation_advice_tool(agent=None, args={})
    assert out.startswith("[remediation_advice]")


@pytest.mark.asyncio
async def test_tool_session_fallback():
    class _F:
        def model_dump(self):
            return SQLI

    class _S:
        findings = [_F()]

    class _A:
        session_state = _S()

    out = await remediation_advice_tool(agent=_A(), args={})
    assert "Remediation Report" in out
