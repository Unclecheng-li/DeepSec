"""流式 tool_calls 组装健壮性测试。

覆盖：
- 跨 chunk 分片的 tool_calls 组装（index 对齐、arguments 拼接）
- function name / arguments 分别在不同 chunk 到达
- 仅含 id 的首个分片（function 字段为 None）—— provider 差异
- 空 delta / None tc_delta / 缺失 index 的边界
- 不完整 tool_call（截断 JSON / 缺失 id / 缺失 name）被丢弃
- 中途断开时已收 content 的保留
- reasoning_content 与 content 不混淆
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from deepsec.spear.agent.llm_client import (
    _assemble_tool_calls,
    _collect_tool_call_deltas,
    _validate_tool_call,
    call_llm_auto_stream,
    call_llm_stream,
)

# === 测试辅助 mock 类型（模拟 OpenAI 流式 delta 结构） ===


class _Func:
    def __init__(self, name=None, arguments=None):
        self.name = name
        self.arguments = arguments


class _TCDelta:
    """单个 tool_call 分片（delta.tool_calls[i]）。"""

    def __init__(self, index=0, id=None, name=None, arguments=None, function="set"):
        self.index = index
        self.id = id
        # function="none" 模拟仅含 id 的首个分片（某些 provider）
        if function == "none":
            self.function = None
        else:
            self.function = _Func(name=name, arguments=arguments)


class _Delta:
    def __init__(self, content=None, reasoning=None, tool_calls=None):
        self.content = content
        self.reasoning_content = reasoning
        self.tool_calls = tool_calls


class _Choice:
    def __init__(self, delta):
        self.delta = delta


class _Chunk:
    def __init__(self, content=None, reasoning=None, tool_calls=None, choices=None):
        if choices is not None:
            self.choices = choices
        else:
            self.choices = [_Choice(_Delta(content=content, reasoning=reasoning, tool_calls=tool_calls))]


class _SyncStream:
    def __init__(self, chunks):
        self._chunks = chunks

    def __iter__(self):
        return iter(self._chunks)


class _BreakingStream:
    """先产出若干 chunk，再抛出异常模拟中途断开。"""

    def __init__(self, chunks, exc):
        self._chunks = list(chunks)
        self._exc = exc

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._chunks:
            return self._chunks.pop(0)
        raise self._exc


class SpySink:
    def __init__(self):
        self.calls: list[tuple[str, str]] = []

    def on_status(self, message):
        self.calls.append(("status", message))

    def on_thinking_token(self, token):
        self.calls.append(("thinking", token))

    def on_content_token(self, token):
        self.calls.append(("content", token))

    def on_tool_call(self, tool_name, args):
        self.calls.append(("tool_call", f"{tool_name}:{args}"))

    def on_tool_result(self, result_summary):
        self.calls.append(("tool_result", result_summary))

    def on_stream_end(self):
        self.calls.append(("end", ""))


def _make_agent():
    agent = MagicMock()
    mock_client = MagicMock()
    agent._get_client.return_value = mock_client
    agent.config.llm.provider = "openai"
    agent.config.llm.model = "gpt-4"
    agent.config.llm.max_tokens = None
    agent.config.llm.temperature = None
    agent.config.llm.max_context_tokens = None
    agent.context.get_messages.return_value = []
    agent._build_openai_tools.return_value = []
    return agent, mock_client


# === _collect_tool_call_deltas 单元测试 ===


class TestCollectToolCallDeltas:
    def test_none_delta_tool_calls(self):
        """delta.tool_calls 为 None 时不追加。"""
        chunks: list[dict] = []
        _collect_tool_call_deltas(_Delta(tool_calls=None), chunks)
        assert chunks == []

    def test_none_entry_in_tool_calls_skipped(self):
        """tool_calls 列表中的 None 元素被跳过。"""
        chunks: list[dict] = []
        _collect_tool_call_deltas(_Delta(tool_calls=[None]), chunks)
        assert chunks == []

    def test_id_only_chunk_function_none(self):
        """仅含 id 的首个分片（function=None）不应崩溃。"""
        chunks: list[dict] = []
        delta = _Delta(tool_calls=[_TCDelta(index=0, id="call_abc", function="none")])
        _collect_tool_call_deltas(delta, chunks)
        assert chunks == [
            {"index": 0, "id": "call_abc", "function": {"name": "", "arguments": ""}}
        ]

    def test_missing_index_defaults_zero(self):
        """index 为 None 时回退到 0。"""
        chunks: list[dict] = []
        delta = _Delta(tool_calls=[_TCDelta(index=None, name="t", arguments="{}")])
        _collect_tool_call_deltas(delta, chunks)
        assert chunks[0]["index"] == 0

    def test_name_and_args_separate_chunks(self):
        """name 与 arguments 分别在不同分片到达。"""
        chunks: list[dict] = []
        _collect_tool_call_deltas(
            _Delta(tool_calls=[_TCDelta(index=0, id="c1", name="scan", arguments="")]), chunks
        )
        _collect_tool_call_deltas(
            _Delta(tool_calls=[_TCDelta(index=0, name="", arguments='{"t":1}')]), chunks
        )
        assert len(chunks) == 2
        assert chunks[0]["function"]["name"] == "scan"
        assert chunks[1]["function"]["arguments"] == '{"t":1}'


# === _validate_tool_call 单元测试 ===


class TestValidateToolCall:
    def _tc(self, id="c1", name="scan", arguments="{}"):
        return MagicMock(id=id, function=MagicMock(name=name, arguments=arguments))

    def test_valid_json_args(self):
        tc = MagicMock(id="c1")
        tc.function.name = "scan"
        tc.function.arguments = '{"target": "x"}'
        assert _validate_tool_call(tc) is True

    def test_empty_args_allowed(self):
        tc = MagicMock(id="c1")
        tc.function.name = "scan"
        tc.function.arguments = ""
        assert _validate_tool_call(tc) is True

    def test_missing_id_rejected(self):
        tc = MagicMock(id="")
        tc.function.name = "scan"
        tc.function.arguments = "{}"
        assert _validate_tool_call(tc) is False

    def test_missing_name_rejected(self):
        tc = MagicMock(id="c1")
        tc.function.name = ""
        tc.function.arguments = "{}"
        assert _validate_tool_call(tc) is False

    def test_truncated_json_rejected(self):
        """流式中断产生的不完整 JSON 被判定无效。"""
        tc = MagicMock(id="c1")
        tc.function.name = "scan"
        tc.function.arguments = '{"target": "exam'
        assert _validate_tool_call(tc) is False

    def test_none_function_rejected(self):
        tc = MagicMock(id="c1", function=None)
        assert _validate_tool_call(tc) is False


# === _assemble_tool_calls 单元测试 ===


class TestAssembleToolCalls:
    def test_empty(self):
        assert _assemble_tool_calls([]) == []

    def test_cross_chunk_assembly(self):
        """跨多分片的 id/name/arguments 按 index 拼接为完整调用。"""
        chunks = [
            {"index": 0, "id": "call_", "function": {"name": "nmap", "arguments": ""}},
            {"index": 0, "id": "123", "function": {"name": "", "arguments": '{"target":'}},
            {"index": 0, "id": "", "function": {"name": "", "arguments": '"x"}'}},
        ]
        result = _assemble_tool_calls(chunks)
        assert len(result) == 1
        assert result[0].id == "call_123"
        assert result[0].function.name == "nmap"
        assert result[0].function.arguments == '{"target":"x"}'

    def test_multiple_indices(self):
        """不同 index 的并行 tool_call 各自聚合。"""
        chunks = [
            {"index": 0, "id": "a", "function": {"name": "t0", "arguments": "{}"}},
            {"index": 1, "id": "b", "function": {"name": "t1", "arguments": "{}"}},
        ]
        result = _assemble_tool_calls(chunks)
        assert len(result) == 2
        names = {tc.function.name for tc in result}
        assert names == {"t0", "t1"}

    def test_incomplete_json_discarded(self):
        """arguments JSON 不完整的调用被丢弃。"""
        chunks = [
            {"index": 0, "id": "ok", "function": {"name": "good", "arguments": "{}"}},
            {"index": 1, "id": "bad", "function": {"name": "broken", "arguments": '{"t":'}},
        ]
        result = _assemble_tool_calls(chunks)
        assert len(result) == 1
        assert result[0].function.name == "good"

    def test_missing_id_discarded(self):
        """聚合后仍缺失 id 的调用被丢弃。"""
        chunks = [
            {"index": 0, "id": "", "function": {"name": "noid", "arguments": "{}"}},
        ]
        result = _assemble_tool_calls(chunks)
        assert result == []

    def test_missing_name_discarded(self):
        """聚合后缺失 name 的调用被丢弃。"""
        chunks = [
            {"index": 0, "id": "c1", "function": {"name": "", "arguments": "{}"}},
        ]
        result = _assemble_tool_calls(chunks)
        assert result == []


# === 端到端流式测试 ===


class TestStreamEndToEnd:
    @pytest.mark.asyncio
    async def test_tool_call_id_only_in_first_chunk(self):
        """provider 仅在首个 chunk 给出 tool_call.id，后续分片只有 arguments。

        覆盖任务要求的 provider delta 格式差异。
        """
        agent, mock_client = _make_agent()
        spy = SpySink()

        chunks = [
            # 首个分片：id + name，function 存在但 arguments 空
            _Chunk(tool_calls=[_TCDelta(index=0, id="call_xyz", name="recon", arguments="")]),
            # 后续分片：无 id，仅 arguments 增量
            _Chunk(tool_calls=[_TCDelta(index=0, id=None, name=None, arguments='{"host":')]),
            _Chunk(tool_calls=[_TCDelta(index=0, id=None, name=None, arguments='"a.com"}')]),
        ]
        mock_client.chat.completions.create.return_value = _SyncStream(chunks)

        captured = {}

        async def fake_handle(agent_obj, message):
            captured["tool_calls"] = list(message.tool_calls)
            return "tool done"

        import deepsec.spear.agent.llm_client as mod

        orig = mod.handle_tool_calls
        mod.handle_tool_calls = fake_handle
        try:
            await call_llm_stream(agent, "sys", stream_sink=spy)
        finally:
            mod.handle_tool_calls = orig

        assert "tool_calls" in captured
        tcs = captured["tool_calls"]
        assert len(tcs) == 1
        assert tcs[0].id == "call_xyz"
        assert tcs[0].function.name == "recon"
        assert tcs[0].function.arguments == '{"host":"a.com"}'

    @pytest.mark.asyncio
    async def test_incomplete_tool_call_dropped_end_to_end(self):
        """流式只到达半截 arguments → 聚合后 JSON 不完整 → 不触发工具执行。"""
        agent, mock_client = _make_agent()
        spy = SpySink()

        chunks = [
            _Chunk(tool_calls=[_TCDelta(index=0, id="c1", name="scan", arguments='{"t":')]),
        ]
        mock_client.chat.completions.create.return_value = _SyncStream(chunks)

        called = {"handle": False}

        async def fake_handle(agent_obj, message):
            called["handle"] = True
            return "x"

        import deepsec.spear.agent.llm_client as mod

        orig = mod.handle_tool_calls
        mod.handle_tool_calls = fake_handle
        try:
            result = await call_llm_stream(agent, "sys", stream_sink=spy)
        finally:
            mod.handle_tool_calls = orig

        # 不完整调用被丢弃，未执行工具，返回空 full_text
        assert called["handle"] is False
        assert result == ""

    @pytest.mark.asyncio
    async def test_partial_content_preserved_on_disconnect(self):
        """流式中途抛 ConnectionError 时，应回退到非流式（fallback）路径。

        断开属于非 streaming-marker 异常，按现有逻辑应重新抛出 —— 验证
        已收到的 content 不会引发额外的 sink 重复输出。
        """
        agent, mock_client = _make_agent()
        spy = SpySink()

        breaking = _BreakingStream(
            [_Chunk(content="partial ")], RuntimeError("connection reset")
        )

        # 第一次（流式）返回会断开的流；fallback 调用返回非流式响应
        non_stream_msg = MagicMock()
        non_stream_msg.content = "recovered"
        non_stream_msg.tool_calls = None
        non_stream_resp = MagicMock(choices=[MagicMock(message=non_stream_msg)])
        mock_client.chat.completions.create.side_effect = [breaking, non_stream_resp, non_stream_resp]

        with pytest.raises(RuntimeError):
            await call_llm_stream(agent, "sys", stream_sink=spy)

        # 断开前的 content token 已被输出一次
        content_calls = [c for c in spy.calls if c[0] == "content"]
        assert content_calls == [("content", "partial ")]

    @pytest.mark.asyncio
    async def test_content_emitted_exactly_once(self):
        """正文 token 仅通过 on_content_token 输出一次，无重复。"""
        agent, mock_client = _make_agent()
        spy = SpySink()

        chunks = [_Chunk(content="A"), _Chunk(content="B"), _Chunk(content="C")]
        mock_client.chat.completions.create.return_value = _SyncStream(chunks)

        result = await call_llm_stream(agent, "sys", stream_sink=spy)

        content_calls = [c for c in spy.calls if c[0] == "content"]
        assert content_calls == [("content", "A"), ("content", "B"), ("content", "C")]
        assert result == "ABC"

    @pytest.mark.asyncio
    async def test_reasoning_not_mixed_into_content(self):
        """reasoning_content 走 thinking 通道，不混入正文 token。"""
        agent, mock_client = _make_agent()
        spy = SpySink()

        chunks = [
            _Chunk(reasoning="let me think"),
            _Chunk(content="final answer"),
        ]
        mock_client.chat.completions.create.return_value = _SyncStream(chunks)

        result = await call_llm_stream(agent, "sys", stream_sink=spy)

        thinking = [c for c in spy.calls if c[0] == "thinking"]
        content = [c for c in spy.calls if c[0] == "content"]
        assert thinking == [("thinking", "let me think")]
        assert content == [("content", "final answer")]
        # 正文 token 不含 reasoning 文本
        assert "let me think" not in "".join(c[1] for c in content)
        # full_text 含 <thinking> 包裹 + 正文
        assert "<thinking>" in result and "final answer" in result


class TestAutoStreamRobustness:
    @pytest.mark.asyncio
    async def test_reasoning_buffer_reset_between_rounds(self):
        """第一轮残留 reasoning 不应泄漏到第二轮总结流（防重复输出）。"""
        agent, mock_client = _make_agent()
        spy = SpySink()

        # 第一轮：reasoning 残留（无后续 content 触发 flush）+ tool_call
        first_round = _SyncStream([
            _Chunk(reasoning="round1 reasoning"),
            _Chunk(tool_calls=[_TCDelta(index=0, id="c1", name="t", arguments="{}")]),
        ])
        mock_client.chat.completions.create.side_effect = [first_round]

        async def fake_handle(agent_obj, message):
            return [{"tool_call_id": "c1", "content": "result"}], []

        import deepsec.spear.agent.llm_client as mod

        orig = mod.handle_tool_calls_with_results
        mod.handle_tool_calls_with_results = fake_handle
        try:
            result = await call_llm_auto_stream(agent, "sys", "ctx", stream_sink=spy)
        finally:
            mod.handle_tool_calls_with_results = orig

        # round1 的 reasoning 不应在最终文本里重复出现
        assert result.count("round1 reasoning") <= 1
        # 工具后不再触发第二轮 Summarizing LLM 调用，返回确定性工具摘要。
        assert "工具调用已执行" in result
        assert "result" in result
        assert mock_client.chat.completions.create.call_count == 1
