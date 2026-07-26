import pytest

from deepsec.spear.agent import builtin_tools as bt


def test_builder_includes_intel_schemas():
    schemas = bt.build_openai_tools(mcp_manager=None)
    names = {s["function"]["name"] for s in schemas}
    assert "cve_lookup" in names


@pytest.mark.asyncio
async def test_execute_routes_intel_tool(monkeypatch):
    from deepsec.spear.intel import tools as intel_tools

    async def fake(agent, args):
        return "OK:" + args["query"]

    monkeypatch.setitem(intel_tools._HANDLERS, "cve_lookup", fake)
    out = await bt.execute_mcp_tool(agent=_FakeAgent(), tool_name="cve_lookup", args={"query": "x"})
    assert out == "OK:x"


class _FakeAgent:
    session_state = None
