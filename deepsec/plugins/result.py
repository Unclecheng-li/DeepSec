from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PluginStage(str, Enum):
    RECON = "recon"
    DISCOVERY = "discovery"
    VERIFICATION = "verification"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


PluginRisk = RiskLevel
PluginPhase = PluginStage


class PluginFinding(BaseModel):
    title: str
    risk: RiskLevel = RiskLevel.INFO
    target: str = ""
    vuln_type: str = ""
    description: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PluginResult(BaseModel):
    plugin_id: str
    stage: PluginStage = PluginStage.DISCOVERY
    ok: bool = True
    skipped: bool = False
    findings: list[PluginFinding] = Field(default_factory=list)
    messages: list[str] = Field(default_factory=list)
    error: str | None = None
    error_type: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    elapsed_seconds: float = 0.0
    remaining_requests: int | None = None

    @classmethod
    def skipped_result(
        cls,
        plugin_id: str,
        message: str,
        *,
        stage: PluginStage = PluginStage.DISCOVERY,
        error_type: str = "skipped",
        remaining_requests: int | None = None,
    ) -> "PluginResult":
        return cls(
            plugin_id=plugin_id,
            stage=stage,
            ok=False,
            skipped=True,
            messages=[message],
            error=message,
            error_type=error_type,
            remaining_requests=remaining_requests,
        )

    @classmethod
    def error_result(
        cls,
        plugin_id: str,
        message: str,
        *,
        stage: PluginStage = PluginStage.DISCOVERY,
        error_type: str = "error",
        remaining_requests: int | None = None,
    ) -> "PluginResult":
        return cls(
            plugin_id=plugin_id,
            stage=stage,
            ok=False,
            error=message,
            error_type=error_type,
            messages=[message],
            remaining_requests=remaining_requests,
        )
