"""Text utility functions — shared across all layers.

修改者: Nyaecho
修改时间: 2026-07-08
修改原因: 消除 V2 残留 — strip_think_tags/format_think_tags 是纯文本工具函数，
         从 agent/think_filter.py 移至基础设施层，消除 cli/ 和 report/ 对 agent/ 的依赖。
"""

from __future__ import annotations

import re

# Closed think blocks: <think>...</think> or <thinking>...</thinking>
_THINK_CLOSED = re.compile(
    r"<(think|thinking|result_info|reasoning)>.*?</\1>",
    re.DOTALL | re.IGNORECASE,
)

# Unclosed think blocks: <thinking>... or <think>... (no closing tag, extends to end of text)
_THINK_UNCLOSED = re.compile(
    r"<(think|thinking|reasoning)>.*",
    re.DOTALL | re.IGNORECASE,
)


def strip_think_tags(text: str) -> str:
    """Remove all <think>/<thinking> blocks from text.

    Handles both closed and unclosed think tags.
    Many reasoning models (DeepSeek R1, etc.) output <thinking> without
    a closing </thinking> tag, causing the rest of the content to be
    swallowed as part of the thinking block.
    """
    text = _THINK_CLOSED.sub("", text)
    text = _THINK_UNCLOSED.sub("", text)
    return text.strip()


def format_think_tags(text: str, show: bool) -> str:
    """Format output based on show_thinking setting.

    If show=True:  keep think tags and content as-is (untouched).
    If show=False: strip think tags and their content entirely.
    """
    if show:
        return text
    return strip_think_tags(text)
