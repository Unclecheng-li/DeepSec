from __future__ import annotations

from deepsec.config.schema import SessionConfig, VulnClawConfig
from deepsec.plugins import (
    PluginContext,
    PluginResult,
    PluginRuntime,
    PluginStage,
    VulnPlugin,
    create_builtin_runtime,
    registry,
)


def test_global_registry_registers_and_finds_builtin_plugin():
    plugin_id = "test.integration.registry"

    class IntegrationPlugin(VulnPlugin):
        plugin_id = "test.integration.registry"

        def run(self, context: PluginContext) -> PluginResult:
            return PluginResult(plugin_id=self.plugin_id, stage=context.stage)

    registry.unregister(plugin_id)
    registry.register(IntegrationPlugin)

    assert registry.get("builtin.web.headers") is not None
    assert registry.get(plugin_id) is IntegrationPlugin

    registry.unregister(plugin_id)


async def test_runtime_executes_builtin_plugin():
    runtime = create_builtin_runtime(VulnClawConfig())

    result = await runtime.execute(
        "builtin.web.headers",
        {
            "target": "https://example.com",
            "options": {"headers": {"server": "nginx"}},
        },
    )

    assert result.ok is True
    assert result.plugin_id == "builtin.web.headers"
    assert result.stage == PluginStage.DISCOVERY
    assert result.findings


def test_config_defaults_expose_plugin_runtime_and_budget_fields():
    config = SessionConfig()

    assert config.plugin_runtime_enabled is True
    assert config.plugin_default_timeout == 10
    assert config.plugin_max_requests_per_target == 30


def test_plugin_finding_converts_to_vuln_finding():
    from deepsec.plugins.integration import plugin_finding_to_vuln_finding
    from deepsec.plugins.result import PluginFinding, RiskLevel

    pf = PluginFinding(
        title="Missing security headers",
        risk=RiskLevel.HIGH,
        vuln_type="security_headers",
        description="缺少安全响应头",
        evidence={"missing": ["x-frame-options"]},
        remediation="补齐响应头",
        confidence=0.9,
    )
    vuln = plugin_finding_to_vuln_finding(pf, plugin_id="builtin.web.headers")

    assert vuln.severity == "High"
    assert vuln.vuln_type == "security_headers"
    assert "builtin.web.headers" in vuln.description
    assert "x-frame-options" in vuln.evidence
    assert vuln.evidence_level == "L2"


def test_merge_plugin_results_dedups_into_session():
    from deepsec.spear.agent.context import SessionState
    from deepsec.plugins.integration import merge_plugin_results_into_session
    from deepsec.plugins.result import PluginFinding, PluginResult, RiskLevel

    finding = PluginFinding(title="Weak CSP", risk=RiskLevel.LOW, vuln_type="security_headers")
    result = PluginResult(plugin_id="builtin.web.headers", findings=[finding])

    session = SessionState(target="t.com")
    added_first = merge_plugin_results_into_session(session, result)
    added_again = merge_plugin_results_into_session(session, result)

    assert added_first == 1
    assert added_again == 0  # 去重：相同 finding 不重复计入
    assert len(session.findings) == 1


async def test_disabled_runtime_does_not_execute_plugin():
    calls = 0

    class DisabledPlugin(VulnPlugin):
        plugin_id = "test.integration.disabled"

        def run(self, context: PluginContext) -> PluginResult:
            nonlocal calls
            calls += 1
            return PluginResult(plugin_id=self.plugin_id, stage=context.stage)

    config = VulnClawConfig()
    config.session.plugin_runtime_enabled = False
    plugin_registry = type(registry)()
    plugin_registry.register(DisabledPlugin)
    runtime = PluginRuntime(plugin_registry, config=config)

    result = await runtime.execute("test.integration.disabled", {"target": "https://example.com"})

    assert result.ok is False
    assert result.skipped is True
    assert result.error_type == "disabled"
    assert calls == 0
