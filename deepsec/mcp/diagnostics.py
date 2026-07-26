"""MCP diagnostics service — shared by CLI and Web entry layers.

修改者: Nyaecho
修改时间: 2026-07-08
修改原因: 消除 V6 违规 — get_mcp_diagnostics 从 web/services/mcp_service.py
         移至 mcp/ 基础设施层，消除 CLI/Web 入口层间的交叉依赖。
"""

from __future__ import annotations

from deepsec.config.settings import load_config
from deepsec.mcp.lifecycle import MCPLifecycleManager
from deepsec.mcp.schemas import MCPDiagnosticsView, MCPServiceView


def get_mcp_diagnostics() -> MCPDiagnosticsView:
    """Return a snapshot of MCP server state and capabilities."""
    config = load_config()
    manager = MCPLifecycleManager(config)
    try:
        manager.start_enabled_servers()
        registry_servers = manager.registry.get_all_servers()
        services: list[MCPServiceView] = []
        local_count = 0
        placeholder_count = 0

        for name, server_config in config.mcp.servers.items():
            state = registry_servers.get(name)
            execution_mode = state.execution_mode if state else "placeholder"
            running = bool(state.running) if state else False
            tools = list(manager.registry.get_server_tools(name))
            can_execute = execution_mode in {"local", "sdk", "subprocess", "sse"}

            if execution_mode == "local":
                local_count += 1
            elif execution_mode == "placeholder":
                placeholder_count += 1

            services.append(
                MCPServiceView(
                    name=name,
                    enabled=server_config.enabled,
                    priority=server_config.priority,
                    transport_type=server_config.transport.type,
                    execution_mode=execution_mode,
                    health_status=state.health_status if state else "unknown",
                    attach_attempted=state.attach_attempted if state else False,
                    attach_succeeded=state.attach_succeeded if state else False,
                    running=running,
                    can_execute=can_execute,
                    tool_count=len(tools),
                    tools=tools,
                    error=state.error if state else None,
                    last_error_type=state.last_error_type if state else None,
                    started_at=state.started_at if state else None,
                    description=server_config.description,
                    call_count=state.call_count if state else 0,
                    success_count=state.success_count if state else 0,
                    failure_count=state.failure_count if state else 0,
                )
            )

        return MCPDiagnosticsView(
            total_services=len(services),
            running_services=manager.running_count(),
            local_services=local_count,
            placeholder_services=placeholder_count,
            tool_count=manager.registry.tool_count,
            services=services,
        )
    finally:
        manager.stop_all()
