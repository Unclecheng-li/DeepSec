import json

import pytest

from deepsec.spear.intel.attack import AttackMapper, attack_map_tool

SQLI = {"title": "SQL Injection", "severity": "High", "description": "sql injection union select"}


def test_mapper_maps_findings_to_techniques():
    rep = AttackMapper().map_findings([SQLI], target="example.com")
    assert rep.mappings
    assert rep.target == "example.com"
    # each mapping references a technique id like T1xxx
    assert all(m.technique.id.startswith("T") for m in rep.mappings)


def test_tool_techniques_lookup():
    techs = AttackMapper.get_tool_techniques("nmap_scan")
    # may be empty if tool not mapped, but must be a list
    assert isinstance(techs, list)


def test_navigator_layer_is_valid_json():
    rep = AttackMapper().map_findings([SQLI], target="example.com")
    layer = json.loads(AttackMapper().generate_navigator_json(rep))
    assert layer["name"].startswith("VulnClaw")
    assert "techniques" in layer
    assert layer.get("domain") or layer.get("versions")


def test_format_report_markdown():
    rep = AttackMapper().map_findings([SQLI], target="example.com")
    out = AttackMapper.format_report(rep)
    assert "MITRE ATT&CK" in out


def test_list_tactics_and_techniques():
    assert len(AttackMapper.list_tactics()) > 0
    assert len(AttackMapper.list_techniques()) > 0


@pytest.mark.asyncio
async def test_tool_markdown_default():
    out = await attack_map_tool(agent=None, args={"findings": [SQLI], "target": "x"})
    assert "MITRE ATT&CK" in out


@pytest.mark.asyncio
async def test_tool_navigator_format():
    out = await attack_map_tool(agent=None, args={"findings": [SQLI], "format": "navigator"})
    layer = json.loads(out)
    assert "techniques" in layer


@pytest.mark.asyncio
async def test_tool_no_input():
    out = await attack_map_tool(agent=None, args={})
    assert out.startswith("[attack_map]")


@pytest.mark.asyncio
async def test_tool_no_matches():
    out = await attack_map_tool(agent=None, args={"findings": [{"title": "xyz", "severity": "Info"}]})
    assert out.startswith("[attack_map]")


@pytest.mark.asyncio
async def test_tool_session_fallback():
    class _F:
        def model_dump(self):
            return SQLI

    class _S:
        findings = [_F()]

    class _A:
        session_state = _S()

    out = await attack_map_tool(agent=_A(), args={})
    assert "MITRE ATT&CK" in out
