from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from deepsec.plugins.result import PluginResult, PluginStage, RiskLevel


class PluginContext(BaseModel):
    target: str = ""
    stage: PluginStage = PluginStage.DISCOVERY
    options: dict[str, Any] = Field(default_factory=dict)
    state: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: float | None = Field(default=None, gt=0)
    allow_destructive: bool = False
    scope_targets: set[str] = Field(default_factory=set)
    task_constraints: Any = None


class VulnPlugin(ABC):
    plugin_id: ClassVar[str]
    name: ClassVar[str] = ""
    version: ClassVar[str] = "0.1.0"
    description: ClassVar[str] = ""
    stages: ClassVar[tuple[PluginStage, ...]] = (PluginStage.DISCOVERY,)
    default_risk: ClassVar[RiskLevel] = RiskLevel.INFO
    enabled: ClassVar[bool] = True
    destructive: ClassVar[bool] = False
    requires_target: ClassVar[bool] = False
    timeout_seconds: ClassVar[float | None] = None
    tags: ClassVar[tuple[str, ...]] = ()
    request_cost: ClassVar[int] = 1

    @classmethod
    def metadata(cls) -> dict[str, Any]:
        return {
            "plugin_id": cls.plugin_id,
            "name": cls.name or cls.plugin_id,
            "version": cls.version,
            "description": cls.description,
            "stages": [stage.value for stage in cls.stages],
            "default_risk": cls.default_risk.value,
            "enabled": cls.enabled,
            "destructive": cls.destructive,
            "requires_target": cls.requires_target,
            "tags": list(cls.tags),
        }

    @abstractmethod
    def run(self, context: PluginContext) -> PluginResult:
        raise NotImplementedError
