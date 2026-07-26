"""MCP diagnostics schemas — shared view models for MCP service state.

修改者: Nyaecho
修改时间: 2026-07-08
修改原因: 消除 V6 违规 — MCP 诊断视图从 web/schemas.py 提取到 mcp/ 包，
         使 CLI 和 Web 入口层都能从基础设施层获取诊断数据。
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class MCPServiceView(BaseModel):
    """View model for a single MCP service's state."""

    name: str
    enabled: bool
    priority: int
    transport_type: str
    execution_mode: str
    health_status: str
    attach_attempted: bool = False
    attach_succeeded: bool = False
    running: bool
    can_execute: bool
    tool_count: int = 0
    tools: list[str] = Field(default_factory=list)
    error: Optional[str] = None
    last_error_type: Optional[str] = None
    started_at: Optional[str] = None
    description: str = ""
    call_count: int = 0
    success_count: int = 0
    failure_count: int = 0


class MCPDiagnosticsView(BaseModel):
    """View model for aggregated MCP diagnostics."""

    total_services: int = 0
    running_services: int = 0
    local_services: int = 0
    placeholder_services: int = 0
    tool_count: int = 0
    services: list[MCPServiceView] = Field(default_factory=list)
