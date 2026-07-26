"""Tests for parallel tool-call execution in tool_call_manager."""

from __future__ import annotations

import asyncio
import time

import pytest

from deepsec.spear.agent.tool_call_manager import handle_tool_calls_with_results


class _Func:
    def __init__(self, name: str, arguments: str) -> None:
        self.name = name
        self.arguments = arguments


class _ToolCall:
    def __init__(self, call_id: str, name: str, arguments: str) -> None:
        self.id = call_id
        self.function = _Func(name, arguments)


class _Message:
    def __init__(self, tool_calls: list[_ToolCall]) -> None:
        self.tool_calls = tool_calls


class _Safety:
    def __init__(self, tool_parallel: bool = True, tool_max_concurrent: int = 5) -> None:
        self.tool_parallel = tool_parallel
        self.tool_max_concurrent = tool_max_concurrent


class _Config:
    def __init__(self, safety: _Safety) -> None:
        self.safety = safety


class _Agent:
    """Minimal agent stub whose tool execution is configurable per test."""

    def __init__(self, executor, safety: _Safety | None = None) -> None:
        from deepsec.spear.agent.context import ContextManager

        self.context = ContextManager()
        self.mcp_manager = None
        self.config = _Config(safety or _Safety())
        self._executor = executor

    async def _execute_mcp_tool(self, func_name, func_args):
        return await self._executor(func_name, func_args)


def _make_message(specs: list[tuple[str, str, str]]) -> _Message:
    """specs: list of (call_id, func_name, arguments_json)."""
    return _Message([_ToolCall(cid, name, args) for cid, name, args in specs])


@pytest.mark.asyncio
async def test_parallel_executes_all_calls_and_preserves_order():
    async def executor(func_name, func_args):
        await asyncio.sleep(0.05)
        return f"ran:{func_args['n']}"

    agent = _Agent(executor, _Safety(tool_parallel=True, tool_max_concurrent=5))
    message = _make_message(
        [(f"c{i}", "probe", f'{{"n":{i}}}') for i in range(5)]
    )

    start = time.monotonic()
    results, skipped = await handle_tool_calls_with_results(agent, message)
    elapsed = time.monotonic() - start

    assert skipped == []
    assert len(results) == 5
    # Order preserved: result i corresponds to tool_call i.
    for i, r in enumerate(results):
        assert r["tool_call_id"] == f"c{i}"
        assert r["content"].startswith("[tool:probe] [evidence:e")
        assert f"ran:{i}" in r["content"]
    # 5 calls of 0.05s each run concurrently → well under serial 0.25s.
    assert elapsed < 0.2


@pytest.mark.asyncio
async def test_error_isolation_one_failure_does_not_block_others():
    async def executor(func_name, func_args):
        if func_args["n"] == 2:
            raise RuntimeError("boom")
        return f"ran:{func_args['n']}"

    agent = _Agent(executor, _Safety(tool_parallel=True, tool_max_concurrent=5))
    message = _make_message(
        [(f"c{i}", "probe", f'{{"n":{i}}}') for i in range(4)]
    )

    results, skipped = await handle_tool_calls_with_results(agent, message)

    # The failing call is returned as tool-visible failure evidence; the model
    # can choose a fallback without the OpenAI tool-call protocol breaking.
    assert skipped == []
    assert [r["tool_call_id"] for r in results] == ["c0", "c1", "c2", "c3"]
    assert "Tool probe failed locally" in results[2]["content"]
    assert agent.context.state.agent_state.evidence[-1].tool == "probe"


@pytest.mark.asyncio
async def test_local_cancel_scope_failure_is_returned_to_model():
    async def executor(func_name, func_args):
        raise asyncio.CancelledError("Cancelled via cancel scope test")

    agent = _Agent(executor, _Safety(tool_parallel=False, tool_max_concurrent=1))
    message = _make_message([("c0", "navigate_page", '{"url":"https://example.com"}')])

    results, skipped = await handle_tool_calls_with_results(agent, message)

    assert skipped == []
    assert len(results) == 1
    assert results[0]["tool_call_id"] == "c0"
    assert "Tool navigate_page failed locally" in results[0]["content"]
    assert results[0]["duration_ms"] >= 0
    assert "tool-health evidence" in results[0]["correction"]
    assert agent.context.state.agent_state.evidence[0].tool == "navigate_page"
    assert agent.context.state.agent_state.tool_health["navigate_page"].status == "degraded"


@pytest.mark.asyncio
async def test_concurrency_capped_at_max_concurrent():
    state = {"active": 0, "peak": 0}
    lock = asyncio.Lock()

    async def executor(func_name, func_args):
        async with lock:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
        await asyncio.sleep(0.05)
        async with lock:
            state["active"] -= 1
        return f"ran:{func_args['n']}"

    agent = _Agent(executor, _Safety(tool_parallel=True, tool_max_concurrent=2))
    # 8 distinct calls, but dedup cap is 10, so all execute.
    message = _make_message(
        [(f"c{i}", "probe", f'{{"n":{i}}}') for i in range(8)]
    )

    results, _ = await handle_tool_calls_with_results(agent, message)

    assert len(results) == 8
    # Never more than max_concurrent (2) running at once.
    assert state["peak"] <= 2


@pytest.mark.asyncio
async def test_serial_fallback_when_parallel_disabled():
    order: list[int] = []

    async def executor(func_name, func_args):
        n = func_args["n"]
        order.append(n)
        # If serial, each call completes before the next starts.
        await asyncio.sleep(0.01)
        order.append(-n)
        return f"ran:{n}"

    agent = _Agent(executor, _Safety(tool_parallel=False, tool_max_concurrent=5))
    message = _make_message(
        [(f"c{i}", "probe", f'{{"n":{i}}}') for i in range(3)]
    )

    results, _ = await handle_tool_calls_with_results(agent, message)

    assert len(results) == 3
    # Serial execution: start/end of each call do not interleave.
    assert order == [0, 0, 1, -1, 2, -2] or order == [0, -0, 1, -1, 2, -2]


@pytest.mark.asyncio
async def test_single_call_runs_without_parallel_overhead():
    async def executor(func_name, func_args):
        return "ok"

    agent = _Agent(executor, _Safety(tool_parallel=True, tool_max_concurrent=5))
    message = _make_message([("c0", "probe", "{}")])

    results, skipped = await handle_tool_calls_with_results(agent, message)

    assert skipped == []
    assert len(results) == 1
    assert results[0]["content"].startswith("[tool:probe] [evidence:e")
    assert "ok" in results[0]["content"]
    assert results[0]["duration_ms"] >= 0


@pytest.mark.asyncio
async def test_bounded_tool_result_is_returned_inline_by_default():
    marker = "TAIL_MARKER_select-waf.php"

    async def executor(func_name, func_args):
        return "A" * 5000 + marker

    agent = _Agent(executor, _Safety(tool_parallel=True, tool_max_concurrent=5))
    message = _make_message([("c0", "fetch", '{"url":"https://example.com/"}')])

    results, skipped = await handle_tool_calls_with_results(agent, message)

    assert skipped == []
    assert marker in results[0]["content"]
    assert "raw output stored" not in results[0]["content"]
    record = agent.context.state.agent_state.evidence[0]
    assert record.truncated is False
    assert record.preview.endswith(marker)


@pytest.mark.asyncio
async def test_large_tool_result_uses_high_signal_preview_and_stores_raw():
    marker = "TAIL_MARKER_select-waf.php"

    async def executor(func_name, func_args):
        return "A" * 9000 + "\n<form><input name=\"id\"></form>\n" + marker

    agent = _Agent(executor, _Safety(tool_parallel=True, tool_max_concurrent=5))
    message = _make_message([("c0", "fetch", '{"url":"https://example.com/"}')])

    results, skipped = await handle_tool_calls_with_results(agent, message)

    assert skipped == []
    content = results[0]["content"]
    assert "raw output stored" in content
    assert "active-context high-signal preview" in content
    assert 'input name="id"' in content
    record = agent.context.state.agent_state.evidence[0]
    assert record.truncated is True
    assert marker in record.content
    assert marker in agent.context.state.agent_state.format_evidence_search(marker)


@pytest.mark.asyncio
async def test_redundant_evidence_view_is_suppressed_and_recorded():
    executed: list[dict] = []
    agent: _Agent

    async def executor(func_name, func_args):
        executed.append(dict(func_args))
        return agent.context.state.agent_state.format_evidence_view(**func_args)

    agent = _Agent(executor, _Safety(tool_parallel=False, tool_max_concurrent=1))
    record = agent.context.state.agent_state.remember_tool_result(
        tool="fetch",
        arguments={"url": "http://t/"},
        output="A" * 2000,
        status=200,
    )
    args = f'{{"evidence_id":"{record.id}","offset":0,"limit":12000}}'

    first, _ = await handle_tool_calls_with_results(
        agent,
        _make_message([("c0", "evidence_view", args)]),
    )
    second, _ = await handle_tool_calls_with_results(
        agent,
        _make_message([("c1", "evidence_view", args)]),
    )

    assert len(executed) == 1
    assert record.content in first[0]["content"]
    assert "Redundant evidence_view suppressed" in second[0]["content"]
    assert record.content not in second[0]["content"]
    assert [item.tool for item in agent.context.state.agent_state.tool_calls[-2:]] == [
        "evidence_view",
        "evidence_view",
    ]


@pytest.mark.asyncio
async def test_mcp_tool_executed_exactly_once_per_call():
    """Regression: _execute_single must not re-invoke mcp_manager.call_tool.

    Previously it called call_tool a second time to read structured_content,
    which ran every MCP-backed tool's side effect twice.
    """

    class _CountingMcp:
        def __init__(self) -> None:
            self.calls = 0

        async def call_tool(self, name, args):
            self.calls += 1
            return {"ok": True, "content": "done", "structured_content": {"n": args.get("n")}}

    mcp = _CountingMcp()

    class _McpAgent:
        def __init__(self) -> None:
            self.mcp_manager = mcp
            self.config = _Config(_Safety(tool_parallel=True, tool_max_concurrent=5))

        async def _execute_mcp_tool(self, func_name, func_args):
            # Mirror the real dispatch: genuine MCP tools go through call_tool once.
            result = await self.mcp_manager.call_tool(func_name, func_args)
            return str(result.get("content"))

    message = _make_message([(f"c{i}", "probe", f'{{"n":{i}}}') for i in range(3)])
    results, _ = await handle_tool_calls_with_results(_McpAgent(), message)

    assert len(results) == 3
    # Exactly one execution per tool call — not double.
    assert mcp.calls == 3


@pytest.mark.asyncio
async def test_missing_config_defaults_to_parallel():
    async def executor(func_name, func_args):
        await asyncio.sleep(0.05)
        return f"ran:{func_args['n']}"

    # Agent without a config attribute at all — should still parallelize.
    class _BareAgent:
        mcp_manager = None

        async def _execute_mcp_tool(self, func_name, func_args):
            return await executor(func_name, func_args)

    message = _make_message(
        [(f"c{i}", "probe", f'{{"n":{i}}}') for i in range(4)]
    )

    start = time.monotonic()
    results, _ = await handle_tool_calls_with_results(_BareAgent(), message)
    elapsed = time.monotonic() - start

    assert len(results) == 4
    assert elapsed < 0.18
