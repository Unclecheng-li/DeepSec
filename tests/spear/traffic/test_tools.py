"""Agent-facing traffic tools + builtin_tools wiring."""

from __future__ import annotations

import httpx

from deepsec.spear.agent.context import TaskConstraints
from deepsec.traffic import (
    CapturedExchange,
    CapturedRequest,
    CapturedResponse,
    ScopeChecker,
    ScopeMode,
    Target,
    TrafficCapture,
    TrafficStore,
)
from deepsec.traffic.tools import (
    TRAFFIC_TOOL_NAMES,
    dispatch_traffic_tool,
    traffic_repeat,
    traffic_tool_schemas,
)


def _store_with_two(tmp_path) -> TrafficStore:
    store = TrafficStore(tmp_path / "evidence" / "traffic")
    capture = TrafficCapture(
        store, ScopeChecker([Target(host="app.test")], mode=ScopeMode.SUBDOMAIN)
    )
    capture.capture(
        CapturedExchange(
            request=CapturedRequest(method="GET", url="http://app.test/login"),
            response=CapturedResponse(status=200, body=b"hi"),
        ),
        source="proxy",
    )
    capture.capture(
        CapturedExchange(
            request=CapturedRequest(method="POST", url="http://api.app.test/login"),
            response=CapturedResponse(status=403, body=b"no"),
        ),
        source="browser",
    )
    return store


def test_traffic_list_enumerates_and_filters(tmp_path):
    store = _store_with_two(tmp_path)
    out = dispatch_traffic_tool(store, "traffic_list", {})
    assert "共 2 条" in out
    assert "GET http://app.test/login" in out

    filtered = dispatch_traffic_tool(store, "traffic_list", {"source": "browser"})
    assert "api.app.test" in filtered
    assert "http://app.test/login" not in filtered


def test_traffic_view_returns_stored_pair(tmp_path):
    store = _store_with_two(tmp_path)
    rid = store.entries()[0]["request_id"]
    out = dispatch_traffic_tool(store, "traffic_view", {"request_id": rid})
    assert "── Request ──" in out
    assert "GET /login HTTP/1.1" in out
    assert "── Response ──" in out


def test_traffic_view_missing_id(tmp_path):
    store = _store_with_two(tmp_path)
    assert "未找到" in dispatch_traffic_tool(store, "traffic_view", {"request_id": "nope"})


def test_traffic_repeat_records_manual_replay(tmp_path):
    store = _store_with_two(tmp_path)
    rid = store.entries()[0]["request_id"]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, text="created")

    out = traffic_repeat(
        store, rid, {"method": "PUT"}, transport=httpx.MockTransport(handler)
    )
    assert "source=manual-replay" in out
    replays = [r for r in store.entries() if r["source"] == "manual-replay"]
    assert len(replays) == 1
    assert replays[0]["method"] == "PUT"
    assert replays[0]["status"] == 201


def test_traffic_sitemap_reflects_capture(tmp_path):
    store = _store_with_two(tmp_path)
    out = dispatch_traffic_tool(store, "traffic_sitemap", {})
    assert "app.test" in out
    assert "api.app.test" in out
    assert "/login" in out


def test_schemas_cover_all_tool_names():
    names = {s["function"]["name"] for s in traffic_tool_schemas()}
    assert names == set(TRAFFIC_TOOL_NAMES)


class _DummySession:
    def __init__(self, evidence_dir):
        self.target = "http://app.test"
        self.evidence_dir = evidence_dir
        self.task_constraints = TaskConstraints()


class _DummyAgent:
    def __init__(self, evidence_dir):
        self.session_state = _DummySession(evidence_dir)
        self.active_role = None
        self.mcp_manager = None


async def test_execute_mcp_tool_routes_traffic(tmp_path):
    import deepsec.spear.agent.builtin_tools as builtin_tools

    _store_with_two(tmp_path)  # writes captures under tmp_path/evidence/traffic
    # evidence_dir points at the evidence root; resolver appends /traffic.
    agent = _DummyAgent(str(tmp_path / "evidence"))
    out = await builtin_tools.execute_mcp_tool(agent, "traffic_list", {})
    assert "共 2 条" in out


def test_build_openai_tools_includes_traffic():
    from deepsec.spear.agent.builtin_tools import build_openai_tools

    tools = build_openai_tools(None)
    names = {t["function"]["name"] for t in tools}
    assert TRAFFIC_TOOL_NAMES <= names


async def test_traffic_repeat_blocked_by_host_constraint(tmp_path):
    """A url override to a blocked host is refused before any network call."""
    import deepsec.spear.agent.builtin_tools as builtin_tools

    store = _store_with_two(tmp_path)
    rid = store.entries()[0]["request_id"]
    agent = _DummyAgent(str(tmp_path / "evidence"))
    agent.session_state.task_constraints = TaskConstraints(blocked_hosts=["evil.test"])

    out = await builtin_tools.execute_mcp_tool(
        agent, "traffic_repeat", {"request_id": rid, "url": "http://evil.test/x"}
    )
    assert "constraint_violation" in out
    assert "evil.test" in out
    # No replay was recorded — the guard fired before dispatch.
    assert [r for r in store.entries() if r["source"] == "manual-replay"] == []


def test_traffic_repeat_guard_allows_in_scope_and_uses_stored_url(tmp_path):
    """The guard permits an in-scope target and derives it from the stored url."""
    from deepsec.spear.agent.builtin_tools import enforce_traffic_repeat_constraints

    store = _store_with_two(tmp_path)
    rid = store.entries()[0]["request_id"]  # http://app.test/login
    agent = _DummyAgent(str(tmp_path / "evidence"))
    agent.session_state.task_constraints = TaskConstraints(allowed_hosts=["app.test"])

    # No url override -> guard reads the stored request's host (app.test), allowed.
    assert enforce_traffic_repeat_constraints(agent, store, {"request_id": rid}) is None
    # An override to a non-allowed host is refused.
    blocked = enforce_traffic_repeat_constraints(
        agent, store, {"request_id": rid, "url": "http://other.test/"}
    )
    assert blocked is not None and "other.test" in blocked
