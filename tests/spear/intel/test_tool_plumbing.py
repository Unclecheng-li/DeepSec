import pytest

from deepsec.spear.intel import tools as intel_tools
from deepsec.spear.intel.tools import INTEL_TOOL_NAMES, dispatch_intel_tool, intel_tool_schemas


def test_schemas_expose_cve_lookup():
    names = {s["function"]["name"] for s in intel_tool_schemas()}
    assert "cve_lookup" in names


def test_intel_tool_names_match_schemas():
    schema_names = {s["function"]["name"] for s in intel_tool_schemas()}
    assert schema_names == set(INTEL_TOOL_NAMES)


@pytest.mark.asyncio
async def test_dispatch_unknown_tool_returns_structured_error():
    out = await dispatch_intel_tool(agent=None, tool_name="nope", args={})
    assert "[intel_error]" in out


@pytest.mark.asyncio
async def test_dispatch_routes_to_registered_handler(monkeypatch):
    async def fake(agent, args):
        return "ROUTED:" + args["query"]

    monkeypatch.setitem(intel_tools._HANDLERS, "cve_lookup", fake)
    out = await dispatch_intel_tool(agent=None, tool_name="cve_lookup", args={"query": "x"})
    assert out == "ROUTED:x"
