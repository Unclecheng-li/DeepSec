"""Side-channel for preserving canonical raw tool output.

Some built-in tools return terminal-only prefixes or warnings while AgentState
should store the clean evidence body.  This module keeps that behavior explicit
and local to one tool execution.
"""

from __future__ import annotations

import json
from typing import Any

_ATTR_NAME = "_vulnclaw_raw_tool_output_overrides"


def _tool_key(tool: str, arguments: dict[str, Any] | None) -> str:
    args_key = json.dumps(dict(arguments or {}), sort_keys=True, ensure_ascii=False)
    return f"{tool}::{args_key}"


def set_raw_tool_output_override(
    agent: Any,
    *,
    tool: str,
    arguments: dict[str, Any] | None,
    output: str,
) -> None:
    """Store raw output for the next matching tool-result persistence call."""

    overrides = getattr(agent, _ATTR_NAME, None)
    if not isinstance(overrides, dict):
        overrides = {}
        setattr(agent, _ATTR_NAME, overrides)
    overrides[_tool_key(tool, arguments)] = str(output or "")


def pop_raw_tool_output_override(
    agent: Any,
    *,
    tool: str,
    arguments: dict[str, Any] | None,
) -> str | None:
    """Return and remove a raw-output override for a matching tool call."""

    overrides = getattr(agent, _ATTR_NAME, None)
    if not isinstance(overrides, dict):
        return None
    return overrides.pop(_tool_key(tool, arguments), None)
