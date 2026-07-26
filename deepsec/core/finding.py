"""Stable finding model shared by Shield, Spear, reports, and IDE bridges."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from typing import Any


class DeepSecMode(str, Enum):
    SHIELD = "shield"
    SPEAR = "spear"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    HALLUCINATED_PACKAGE = "hallucinated_package"
    HARDCODED_SECRET = "hardcoded_secret"
    INSECURE_CONFIG = "insecure_config"
    AI_PATTERN_ERROR = "ai_pattern_error"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    COMMAND_INJECTION = "command_injection"
    OPEN_REDIRECT = "open_redirect"
    INFORMATION_LEAKAGE = "information_leakage"
    MISSING_SECURITY_MEASURE = "missing_security_measure"
    PROMPT_INJECTION = "prompt_injection"
    TOOL_ABUSE = "tool_abuse"
    DATA_EXFILTRATION = "data_exfiltration"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    TYPOSQUATTING = "typosquatting"
    VULN_SQLI = "vuln_sqli"
    VULN_XSS = "vuln_xss"
    VULN_SSRF = "vuln_ssrf"
    VULN_SSTI = "vuln_ssti"
    VULN_RCE = "vuln_rce"
    VULN_AUTH_BYPASS = "vuln_auth_bypass"
    VULN_INFO_LEAK = "vuln_info_leak"
    VULN_BUSINESS_LOGIC = "vuln_business_logic"
    OTHER = "other"


@dataclass(slots=True)
class TextEdit:
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    new_text: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "startLine": self.start_line,
            "startColumn": self.start_column,
            "endLine": self.end_line,
            "endColumn": self.end_column,
            "newText": self.new_text,
        }


@dataclass(slots=True)
class DeepSecFinding:
    id: str
    mode: DeepSecMode
    type: FindingType
    severity: Severity
    title: str
    description: str
    target: str
    line: int | None = None
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    evidence: str = ""
    suggestion: str = ""
    poc: str | None = None
    detection_layer: str = ""
    detection_rule: str = ""
    confidence: float = 1.0
    verified: bool = False
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    file: str | None = None
    url: str | None = None
    chain_step: int | None = None
    chain_depends_on: list[str] = field(default_factory=list)
    fix: list[TextEdit] = field(default_factory=list)
    dismissed: bool = False
    dismissed_reason: str | None = None

    @classmethod
    def create(
        cls,
        *,
        mode: DeepSecMode,
        type: FindingType,
        severity: Severity,
        target: str,
        description: str,
        rule: str,
        layer: str,
        evidence: str = "",
        suggestion: str = "",
        line: int | None = None,
        column: int | None = None,
        end_line: int | None = None,
        end_column: int | None = None,
        confidence: float = 1.0,
        title: str | None = None,
    ) -> "DeepSecFinding":
        material = "\0".join([mode.value, type.value, target, str(line or 0), rule, evidence])
        identifier = f"ds_{sha256(material.encode('utf-8')).hexdigest()[:20]}"
        return cls(
            id=identifier,
            mode=mode,
            type=type,
            severity=severity,
            title=title or description,
            description=description,
            target=target,
            file=target if mode is DeepSecMode.SHIELD else None,
            line=line,
            column=column,
            end_line=end_line,
            end_column=end_column,
            evidence=evidence,
            suggestion=suggestion,
            detection_layer=layer,
            detection_rule=rule,
            confidence=max(0.0, min(1.0, confidence)),
        )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["mode"] = self.mode.value
        result["type"] = self.type.value
        result["severity"] = self.severity.value
        result["timestamp"] = self.timestamp.isoformat()
        result["fix"] = [edit.to_dict() for edit in self.fix]
        # Preserve the VibeGuard field names for an incremental IDE migration.
        result["message"] = self.description
        result["detection_layer"] = self.detection_layer
        result["detection_rule"] = self.detection_rule
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DeepSecFinding":
        timestamp = value.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        elif not isinstance(timestamp, datetime):
            timestamp = datetime.now(timezone.utc)
        raw_type = value.get("type", FindingType.OTHER.value)
        raw_severity = value.get("severity", Severity.INFO.value)
        return cls(
            id=str(value.get("id") or ""),
            mode=DeepSecMode(value.get("mode", DeepSecMode.SHIELD.value)),
            type=FindingType(raw_type) if raw_type in FindingType._value2member_map_ else FindingType.OTHER,
            severity=Severity(raw_severity) if raw_severity in Severity._value2member_map_ else Severity.INFO,
            title=str(value.get("title") or value.get("message") or raw_type),
            description=str(value.get("description") or value.get("message") or ""),
            target=str(value.get("target") or value.get("file") or value.get("url") or ""),
            line=value.get("line"),
            column=value.get("column"),
            end_line=value.get("end_line") or value.get("endLine"),
            end_column=value.get("end_column") or value.get("endColumn"),
            evidence=str(value.get("evidence") or ""),
            suggestion=str(value.get("suggestion") or ""),
            poc=value.get("poc"),
            detection_layer=str(value.get("detection_layer") or ""),
            detection_rule=str(value.get("detection_rule") or ""),
            confidence=float(value.get("confidence", 1.0)),
            verified=bool(value.get("verified", False)),
            timestamp=timestamp,
            file=value.get("file"),
            url=value.get("url"),
        )
