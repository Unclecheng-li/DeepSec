"""Lightweight token estimation and sliding-window truncation for LLM context.

Pure-Python approximation (no tiktoken). Uses a ~4-chars-per-token heuristic
plus small per-message and per-field overheads to stay roughly aligned with
OpenAI-compatible tokenizers without external dependencies.
"""

from __future__ import annotations

import json
from typing import Any

# Approximate average characters per token for mixed English/Chinese text.
_CHARS_PER_TOKEN = 4.0
# Per-message structural overhead (role tokens, message framing).
_MESSAGE_OVERHEAD = 4
# Per-tool-call structural overhead (id, type, function wrapper).
_TOOL_CALL_OVERHEAD = 8

_TRUNCATION_NOTICE = (
    "[上下文截断] 为控制 token 用量，部分较早的历史消息已被移除，"
    "仅保留系统提示和最近的对话。"
)


def _text_tokens(text: str) -> int:
    """Estimate tokens for a raw string."""
    if not text:
        return 0
    return int(len(text) / _CHARS_PER_TOKEN) + 1


def _content_tokens(content: Any) -> int:
    """Estimate tokens for a message content field (str or multimodal list)."""
    if content is None:
        return 0
    if isinstance(content, str):
        return _text_tokens(content)
    if isinstance(content, list):
        total = 0
        for part in content:
            if isinstance(part, dict):
                # Text parts: {"type": "text", "text": "..."}
                if "text" in part and isinstance(part["text"], str):
                    total += _text_tokens(part["text"])
                # Image parts: fixed approximate cost, don't measure base64 length
                elif part.get("type") in ("image_url", "image"):
                    total += 256
                else:
                    total += _text_tokens(json.dumps(part, ensure_ascii=False))
            elif isinstance(part, str):
                total += _text_tokens(part)
        return total
    return _text_tokens(str(content))


def _tool_calls_tokens(tool_calls: Any) -> int:
    """Estimate tokens for an assistant message's tool_calls field."""
    if not tool_calls or not isinstance(tool_calls, list):
        return 0
    total = 0
    for tc in tool_calls:
        total += _TOOL_CALL_OVERHEAD
        if not isinstance(tc, dict):
            total += _text_tokens(str(tc))
            continue
        fn = tc.get("function", {})
        if isinstance(fn, dict):
            total += _text_tokens(str(fn.get("name", "")))
            total += _text_tokens(str(fn.get("arguments", "")))
        if tc.get("id"):
            total += _text_tokens(str(tc["id"]))
    return total


def estimate_message_tokens(message: dict) -> int:
    """Estimate the token count of a single chat message."""
    if not isinstance(message, dict):
        return _text_tokens(str(message)) + _MESSAGE_OVERHEAD
    total = _MESSAGE_OVERHEAD
    total += _text_tokens(str(message.get("role", "")))
    total += _content_tokens(message.get("content"))
    if "tool_calls" in message:
        total += _tool_calls_tokens(message.get("tool_calls"))
    if "tool_call_id" in message:
        total += _text_tokens(str(message["tool_call_id"]))
    if "name" in message:
        total += _text_tokens(str(message["name"]))
    return total


def estimate_tokens(messages: list[dict]) -> int:
    """Estimate the total token count of a list of chat messages."""
    if not messages:
        return 0
    return sum(estimate_message_tokens(m) for m in messages)


def truncate_messages(
    messages: list[dict],
    max_tokens: int,
    preserve_system: bool = True,
    min_recent: int = 4,
) -> list[dict]:
    """Sliding-window truncation to fit messages within max_tokens.

    Always keeps the system prompt (first message) when preserve_system is True,
    always keeps the most recent min_recent messages, and drops the oldest
    middle messages first. Inserts a system notice at the truncation point.
    """
    if not messages or max_tokens <= 0:
        return list(messages)
    if estimate_tokens(messages) <= max_tokens:
        return list(messages)

    system_msgs: list[dict] = []
    body = list(messages)
    if preserve_system and body and body[0].get("role") == "system":
        system_msgs = [body[0]]
        body = body[1:]

    min_recent = max(min_recent, 1)
    if len(body) <= min_recent:
        return system_msgs + body

    recent = body[-min_recent:]
    middle = body[:-min_recent]

    notice = {"role": "system", "content": _TRUNCATION_NOTICE}
    base_tokens = estimate_tokens(system_msgs) + estimate_tokens(recent)
    base_tokens += estimate_message_tokens(notice)

    kept_middle: list[dict] = []
    running = base_tokens
    # Add middle messages from newest to oldest until the budget is exhausted.
    for msg in reversed(middle):
        cost = estimate_message_tokens(msg)
        if running + cost > max_tokens:
            break
        running += cost
        kept_middle.insert(0, msg)

    truncated_any = len(kept_middle) < len(middle)
    result = list(system_msgs)
    if truncated_any:
        result.append(notice)
    result.extend(kept_middle)
    result.extend(recent)
    return result
