from __future__ import annotations

from typing import TypeVar

from deepsec.plugins.base import VulnPlugin
from deepsec.plugins.result import PluginStage

PluginType = TypeVar("PluginType", bound=type[VulnPlugin])


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, type[VulnPlugin]] = {}

    def register(self, plugin_cls: PluginType, *, replace: bool = False) -> PluginType:
        plugin_id = getattr(plugin_cls, "plugin_id", "")
        if not plugin_id:
            raise ValueError("Plugin class must define plugin_id")
        if plugin_id in self._plugins and not replace:
            raise ValueError(f"Plugin already registered: {plugin_id}")
        self._plugins[plugin_id] = plugin_cls
        return plugin_cls

    def unregister(self, plugin_id: str) -> None:
        self._plugins.pop(plugin_id, None)

    def clear(self) -> None:
        self._plugins.clear()

    def get(self, plugin_id: str) -> type[VulnPlugin] | None:
        return self._plugins.get(plugin_id)

    def require(self, plugin_id: str) -> type[VulnPlugin]:
        plugin_cls = self.get(plugin_id)
        if plugin_cls is None:
            raise KeyError(f"Plugin not found: {plugin_id}")
        return plugin_cls

    def list(self) -> list[type[VulnPlugin]]:
        return list(self._plugins.values())

    def names(self) -> list[str]:
        return sorted(self._plugins)

    def metadata(self) -> list[dict[str, object]]:
        return [plugin_cls.metadata() for plugin_cls in self._plugins.values()]

    def by_stage(self, stage: PluginStage | str) -> list[type[VulnPlugin]]:
        stage_value = PluginStage(stage) if isinstance(stage, str) else stage
        return [plugin_cls for plugin_cls in self._plugins.values() if stage_value in plugin_cls.stages]

    def by_tag(self, tag: str) -> list[type[VulnPlugin]]:
        return [plugin_cls for plugin_cls in self._plugins.values() if tag in plugin_cls.tags]

    @property
    def count(self) -> int:
        return len(self._plugins)


registry = PluginRegistry()
