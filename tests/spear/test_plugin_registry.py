import pytest
from pydantic import ValidationError

from deepsec.plugins import (
    PluginContext,
    PluginFinding,
    PluginRegistry,
    PluginResult,
    PluginStage,
    RiskLevel,
    VulnPlugin,
    registry,
)


class DemoPlugin(VulnPlugin):
    plugin_id = "demo"
    name = "Demo"
    version = "1.0.0"
    description = "Demo plugin"
    stages = (PluginStage.RECON, PluginStage.DISCOVERY)
    default_risk = RiskLevel.LOW

    def run(self, context: PluginContext) -> PluginResult:
        return PluginResult(
            plugin_id=self.plugin_id,
            stage=context.stage,
            findings=[
                PluginFinding(
                    title="Demo finding",
                    risk=self.default_risk,
                    target=context.target,
                    evidence={"url": context.target},
                    confidence=0.8,
                )
            ],
        )


class OtherPlugin(VulnPlugin):
    plugin_id = "other"
    stages = (PluginStage.REPORTING,)

    def run(self, context: PluginContext) -> PluginResult:
        return PluginResult(plugin_id=self.plugin_id, stage=context.stage)


def test_plugin_models_are_json_serializable():
    context = PluginContext(target="https://example.com", stage=PluginStage.RECON)
    result = DemoPlugin().run(context)

    dumped = result.model_dump(mode="json")

    assert dumped["plugin_id"] == "demo"
    assert dumped["stage"] == "recon"
    assert dumped["findings"][0]["risk"] == "low"
    assert dumped["findings"][0]["evidence"] == {"url": "https://example.com"}


def test_finding_validates_confidence_range():
    with pytest.raises(ValidationError):
        PluginFinding(title="bad confidence", confidence=1.1)


def test_base_plugin_requires_run_implementation():
    class MissingRun(VulnPlugin):
        plugin_id = "missing"

    with pytest.raises(TypeError):
        MissingRun()


def test_registry_register_get_and_metadata():
    plugin_registry = PluginRegistry()

    returned = plugin_registry.register(DemoPlugin)

    assert returned is DemoPlugin
    assert plugin_registry.count == 1
    assert plugin_registry.get("demo") is DemoPlugin
    assert plugin_registry.metadata() == [DemoPlugin.metadata()]


def test_registry_rejects_duplicate_plugin_ids():
    plugin_registry = PluginRegistry()
    plugin_registry.register(DemoPlugin)

    with pytest.raises(ValueError, match="Plugin already registered: demo"):
        plugin_registry.register(DemoPlugin)


def test_registry_rejects_missing_plugin_id():
    class MissingIdPlugin(VulnPlugin):
        plugin_id = ""

        def run(self, context: PluginContext) -> PluginResult:
            return PluginResult(plugin_id="missing", stage=context.stage)

    plugin_registry = PluginRegistry()

    with pytest.raises(ValueError, match="Plugin class must define plugin_id"):
        plugin_registry.register(MissingIdPlugin)


def test_registry_filters_plugins_by_stage():
    plugin_registry = PluginRegistry()
    plugin_registry.register(DemoPlugin)
    plugin_registry.register(OtherPlugin)

    assert plugin_registry.by_stage(PluginStage.RECON) == [DemoPlugin]
    assert plugin_registry.by_stage("reporting") == [OtherPlugin]


def test_registry_unregister_and_clear_are_idempotent():
    plugin_registry = PluginRegistry()
    plugin_registry.register(DemoPlugin)

    plugin_registry.unregister("demo")
    plugin_registry.unregister("demo")

    assert plugin_registry.count == 0

    plugin_registry.register(DemoPlugin)
    plugin_registry.clear()

    assert plugin_registry.list() == []


def test_global_registry_is_plugin_registry():
    assert isinstance(registry, PluginRegistry)
