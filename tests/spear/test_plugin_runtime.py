from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from deepsec.spear.agent.context import TaskConstraints
from deepsec.plugins import (
    PluginContext,
    PluginRegistry,
    PluginResult,
    PluginRuntime,
    VulnPlugin,
)


def runtime_config(
    *,
    enabled: bool = True,
    timeout: float = 1,
    max_requests: int = 30,
) -> SimpleNamespace:
    return SimpleNamespace(
        session=SimpleNamespace(
            plugin_runtime_enabled=enabled,
            plugin_default_timeout=timeout,
            plugin_max_requests_per_target=max_requests,
        )
    )


class EchoPlugin(VulnPlugin):
    plugin_id = "echo"
    requires_target = True

    def run(self, context: PluginContext) -> PluginResult:
        return PluginResult(
            plugin_id=self.plugin_id,
            stage=context.stage,
            metadata={"target": context.target, "options": context.options},
        )


class DisabledPlugin(EchoPlugin):
    plugin_id = "disabled"
    enabled = False


class DangerousPlugin(EchoPlugin):
    plugin_id = "danger"
    destructive = True


class SlowPlugin(VulnPlugin):
    plugin_id = "slow"

    async def run(self, context: PluginContext) -> PluginResult:
        await asyncio.sleep(0.05)
        return PluginResult(plugin_id=self.plugin_id, stage=context.stage)


class BrokenPlugin(VulnPlugin):
    plugin_id = "broken"

    def run(self, context: PluginContext) -> PluginResult:
        raise RuntimeError("boom")


def _runtime(*plugin_classes: type[VulnPlugin], config=None, allowed_targets=None) -> PluginRuntime:
    plugin_registry = PluginRegistry()
    for plugin_cls in plugin_classes:
        plugin_registry.register(plugin_cls)
    return PluginRuntime(
        plugin_registry,
        config=config or runtime_config(),
        allowed_targets=allowed_targets,
    )


@pytest.mark.asyncio
async def test_runtime_executes_plugin_by_id() -> None:
    runtime = _runtime(EchoPlugin)

    result = await runtime.execute(
        "echo",
        PluginContext(
            target="example.com",
            options={"path": "/health"},
            scope_targets={"example.com"},
        ),
    )

    assert result.ok is True
    assert result.plugin_id == "echo"
    assert result.metadata == {"target": "example.com", "options": {"path": "/health"}}
    assert result.remaining_requests == 29


@pytest.mark.asyncio
async def test_runtime_blocks_when_runtime_disabled() -> None:
    runtime = _runtime(EchoPlugin, config=runtime_config(enabled=False))

    result = await runtime.execute("echo", {"target": "example.com"})

    assert result.ok is False
    assert result.skipped is True
    assert result.error_type == "disabled"
    assert result.error == "Plugin runtime is disabled"


@pytest.mark.asyncio
async def test_runtime_blocks_disabled_plugin() -> None:
    runtime = _runtime(DisabledPlugin)

    result = await runtime.execute("disabled")

    assert result.ok is False
    assert result.error_type == "disabled"
    assert result.error == "Plugin is disabled"


@pytest.mark.asyncio
async def test_runtime_blocks_destructive_plugin_without_permission() -> None:
    runtime = _runtime(DangerousPlugin)

    blocked = await runtime.execute("danger", {"target": "example.com"})
    allowed = await runtime.execute(
        "danger",
        PluginContext(target="example.com", allow_destructive=True),
    )

    assert blocked.ok is False
    assert blocked.error_type == "blocked"
    assert allowed.ok is True


@pytest.mark.asyncio
async def test_runtime_enforces_target_constraints() -> None:
    runtime = _runtime(EchoPlugin, allowed_targets={"example.com"})

    missing = await runtime.execute("echo")
    outside_runtime = await runtime.execute("echo", {"target": "other.com"})
    outside_request = await runtime.execute(
        "echo",
        PluginContext(target="example.com", scope_targets={"api.example.com"}),
    )

    assert missing.error_type == "target_blocked"
    assert missing.error == "Plugin requires a target"
    assert outside_runtime.error_type == "target_blocked"
    assert outside_runtime.error == "Target is outside runtime scope"
    assert outside_request.error_type == "target_blocked"
    assert outside_request.error == "Target is outside request scope"


@pytest.mark.asyncio
async def test_runtime_enforces_task_constraints() -> None:
    runtime = _runtime(EchoPlugin)

    result = await runtime.execute(
        "echo",
        PluginContext(
            target="https://example.com:8443/admin",
            task_constraints=TaskConstraints(
                allowed_hosts=["example.com"],
                allowed_ports=[443],
                allowed_actions=["scan"],
                strict_mode=True,
            ),
        ),
    )

    assert result.ok is False
    assert result.error_type == "constraint_violation"
    assert "port '8443'" in result.error


@pytest.mark.asyncio
async def test_runtime_enforces_request_budget_per_target() -> None:
    runtime = _runtime(EchoPlugin, config=runtime_config(max_requests=1))
    context = PluginContext(target="example.com")

    first = await runtime.execute("echo", context)
    second = await runtime.execute("echo", context)

    assert first.ok is True
    assert first.remaining_requests == 0
    assert second.ok is False
    assert second.error_type == "budget_exhausted"


@pytest.mark.asyncio
async def test_runtime_converts_timeout_to_result() -> None:
    runtime = _runtime(SlowPlugin, config=runtime_config(timeout=0.01))

    result = await runtime.execute("slow")

    assert result.ok is False
    assert result.error_type == "timeout"
    assert result.error == "Plugin execution timed out"


@pytest.mark.asyncio
async def test_runtime_converts_exception_to_result() -> None:
    runtime = _runtime(BrokenPlugin)

    result = await runtime.execute("broken")

    assert result.ok is False
    assert result.error_type == "error"
    assert result.error == "RuntimeError: boom"
