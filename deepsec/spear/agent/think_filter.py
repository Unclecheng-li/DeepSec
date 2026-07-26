"""VulnClaw Think Tag Filter — strip <think>/<thinking> blocks from LLM output.

修改者: Nyaecho
修改时间: 2026-07-08
修改原因: V2 修复 — 纯文本工具函数已移至 config/text_utils.py，
         此处重新导出以保持 agent/ 层向后兼容。
"""

from __future__ import annotations

from deepsec.config.text_utils import format_think_tags, strip_think_tags  # noqa: F401

__all__ = ["strip_think_tags", "format_think_tags"]
