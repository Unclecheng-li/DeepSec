"""VulnClaw MCP Registry — service metadata and tool registration."""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class HealthStatus(str, Enum):
    """Health states for an MCP server."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    STARTING = "starting"
    STOPPING = "stopping"
    UNKNOWN = "unknown"


class MCPToolSchema(BaseModel):
    """Schema for a single MCP tool."""

    name: str = Field(description="Tool name")
    description: str = Field(default="", description="Tool description")
    input_schema: dict[str, Any] = Field(
        default_factory=lambda: {"type": "object", "properties": {}},
        description="JSON Schema for tool input",
    )
    server_name: str = Field(description="Owning MCP server name")


class MCPServerState(BaseModel):
    """Runtime state of an MCP server."""

    name: str
    running: bool = False
    pid: int | None = None
    tools: list[str] = Field(default_factory=list)
    error: str | None = None
    last_error_type: str | None = None
    started_at: str | None = None
    execution_mode: str = "placeholder"  # local/sdk/subprocess/sse/placeholder
    health_status: str = "unknown"  # healthy/degraded/unavailable/unknown
    attach_attempted: bool = False
    attach_succeeded: bool = False
    call_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    total_latency_ms: float = 0.0
    avg_latency_ms: float = 0.0
    restart_count: int = 0
    last_restart_time: str | None = None
    # Sliding window of recent call outcomes (True=success) used for health scoring.
    recent_outcomes: list[bool] = Field(default_factory=list)


class MCPRegistry:
    """Central registry for MCP servers and their tools.

    Maintains:
    - Server configurations and metadata
    - Tool schemas from each server
    - Runtime state (running/stopped, health)
    """

    def __init__(self) -> None:
        self._servers: dict[str, MCPServerState] = {}
        self._tools: dict[str, MCPToolSchema] = {}  # tool_name -> schema
        self._server_tools: dict[str, list[str]] = {}  # server_name -> [tool_names]

    def register_server(self, name: str) -> None:
        """Register a new MCP server."""
        if name not in self._servers:
            self._servers[name] = MCPServerState(name=name)
            self._server_tools[name] = []

    def set_server_running(self, name: str, running: bool, pid: Optional[int] = None) -> None:
        """Update server running state."""
        if name in self._servers:
            self._servers[name].running = running
            self._servers[name].pid = pid
            if running:
                from datetime import datetime

                self._servers[name].started_at = datetime.now().isoformat()

    def set_server_execution_mode(self, name: str, mode: str) -> None:
        """Update server execution mode: local/sdk/subprocess/sse/placeholder."""
        if name in self._servers:
            self._servers[name].execution_mode = mode

    def set_server_health(self, name: str, health_status: str) -> None:
        """Update server health status."""
        if name in self._servers:
            self._servers[name].health_status = health_status

    def set_server_attach_result(self, name: str, attempted: bool, succeeded: bool) -> None:
        """Record whether a real attach/connect attempt was made."""
        if name in self._servers:
            self._servers[name].attach_attempted = attempted
            self._servers[name].attach_succeeded = succeeded

    def set_server_error(self, name: str, error: str, error_type: str | None = None) -> None:
        """Record a server error."""
        if name in self._servers:
            self._servers[name].error = error
            self._servers[name].last_error_type = error_type
            self._servers[name].health_status = "degraded"

    HEALTH_WINDOW_SIZE = 20

    def record_tool_call(
        self, name: str, success: bool, latency_ms: float | None = None
    ) -> None:
        """Record per-server tool call statistics and update the health window."""
        if name not in self._servers:
            return
        state = self._servers[name]
        state.call_count += 1
        if success:
            state.success_count += 1
            if state.health_status == "unknown":
                state.health_status = "healthy"
        else:
            state.failure_count += 1
            if state.health_status == "unknown":
                state.health_status = "degraded"

        if latency_ms is not None and latency_ms >= 0:
            state.total_latency_ms += latency_ms
        if state.call_count > 0:
            state.avg_latency_ms = state.total_latency_ms / state.call_count

        state.recent_outcomes.append(bool(success))
        if len(state.recent_outcomes) > self.HEALTH_WINDOW_SIZE:
            state.recent_outcomes = state.recent_outcomes[-self.HEALTH_WINDOW_SIZE :]

    def set_last_call_latency(self, name: str, latency_ms: float) -> None:
        """Attribute latency to the most recent call and refresh the average."""
        state = self._servers.get(name)
        if state is None or latency_ms < 0:
            return
        state.total_latency_ms += latency_ms
        if state.call_count > 0:
            state.avg_latency_ms = state.total_latency_ms / state.call_count

    def record_restart(self, name: str) -> None:
        """Record that a server was restarted."""
        if name not in self._servers:
            return
        from datetime import datetime

        self._servers[name].restart_count += 1
        self._servers[name].last_restart_time = datetime.now().isoformat()

    def recent_success_rate(self, name: str) -> float | None:
        """Return success rate over the recent call window, or None if no calls yet."""
        state = self._servers.get(name)
        if state is None or not state.recent_outcomes:
            return None
        return sum(1 for ok in state.recent_outcomes if ok) / len(state.recent_outcomes)

    def get_server_stats(self, name: str) -> dict[str, Any]:
        """Return a runtime statistics snapshot for a server."""
        state = self._servers.get(name)
        if state is None:
            return {}

        uptime_seconds: float | None = None
        if state.running and state.started_at:
            from datetime import datetime

            try:
                started = datetime.fromisoformat(state.started_at)
                uptime_seconds = max(0.0, (datetime.now() - started).total_seconds())
            except ValueError:
                uptime_seconds = None

        return {
            "name": state.name,
            "running": state.running,
            "health_status": state.health_status,
            "execution_mode": state.execution_mode,
            "call_count": state.call_count,
            "success_count": state.success_count,
            "failure_count": state.failure_count,
            "avg_latency_ms": round(state.avg_latency_ms, 2),
            "recent_success_rate": self.recent_success_rate(name),
            "restart_count": state.restart_count,
            "last_restart_time": state.last_restart_time,
            "started_at": state.started_at,
            "uptime_seconds": uptime_seconds,
            "error": state.error,
            "last_error_type": state.last_error_type,
        }

    def register_tool(self, server_name: str, tool_schema: dict[str, Any]) -> None:
        """Register a tool from an MCP server."""
        tool_name = tool_schema.get("name", "")
        if not tool_name:
            return

        schema = MCPToolSchema(
            name=tool_name,
            description=tool_schema.get("description", ""),
            input_schema=tool_schema.get("inputSchema", {"type": "object", "properties": {}}),
            server_name=server_name,
        )

        self._tools[tool_name] = schema
        if server_name not in self._server_tools:
            self._server_tools[server_name] = []
        if tool_name not in self._server_tools[server_name]:
            self._server_tools[server_name].append(tool_name)

        # Update server state
        if server_name in self._servers:
            self._servers[server_name].tools = self._server_tools[server_name]

    def unregister_server(self, name: str) -> None:
        """Remove a server and all its tools."""
        if name in self._server_tools:
            for tool_name in self._server_tools[name]:
                self._tools.pop(tool_name, None)
            del self._server_tools[name]
        self._servers.pop(name, None)

    def clear_server_tools(self, server_name: str) -> None:
        """Clear all currently registered tools for a server."""
        if server_name not in self._server_tools:
            self._server_tools[server_name] = []
            return

        for tool_name in list(self._server_tools[server_name]):
            self._tools.pop(tool_name, None)
        self._server_tools[server_name] = []
        if server_name in self._servers:
            self._servers[server_name].tools = []

    def get_tool_schema(self, tool_name: str) -> Optional[MCPToolSchema]:
        """Get the schema for a specific tool."""
        return self._tools.get(tool_name)

    def get_all_tool_schemas(self) -> list[dict[str, Any]]:
        """Get all tool schemas in OpenAI function-calling format."""
        return [
            {
                "name": schema.name,
                "description": schema.description,
                "inputSchema": schema.input_schema,
            }
            for schema in self._tools.values()
        ]

    def get_server_for_tool(self, tool_name: str) -> Optional[str]:
        """Find which server owns a tool."""
        schema = self._tools.get(tool_name)
        return schema.server_name if schema else None

    def get_server_tools(self, server_name: str) -> list[str]:
        """Get all tool names for a server."""
        return self._server_tools.get(server_name, [])

    def get_running_servers(self) -> list[str]:
        """Get names of all running servers."""
        return [name for name, state in self._servers.items() if state.running]

    def get_all_servers(self) -> dict[str, MCPServerState]:
        """Get all server states."""
        return self._servers.copy()

    @property
    def tool_count(self) -> int:
        """Total number of registered tools."""
        return len(self._tools)

    @property
    def server_count(self) -> int:
        """Total number of registered servers."""
        return len(self._servers)
