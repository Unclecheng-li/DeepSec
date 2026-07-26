"""Project-local ignore rules compatible with simple YAML policy files."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from deepsec.core.finding import DeepSecFinding


@dataclass(slots=True)
class IgnoreRules:
    finding_ids: set[str] = field(default_factory=set)
    rule_ids: set[str] = field(default_factory=set)
    files: dict[str, set[str]] = field(default_factory=dict)


def load_ignore_rules(path: Path | None) -> IgnoreRules:
    if path is None or not path.exists():
        return IgnoreRules()
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("Ignore rules must be a YAML mapping")
    files_raw = raw.get("files", {})
    files = {str(key): {str(item) for item in values} for key, values in files_raw.items() if isinstance(values, list)} if isinstance(files_raw, dict) else {}
    return IgnoreRules(
        finding_ids={str(item) for item in raw.get("finding_ids", []) if isinstance(item, str)},
        rule_ids={str(item) for item in raw.get("rule_ids", []) if isinstance(item, str)},
        files=files,
    )


def apply_ignore_rules(findings: list[DeepSecFinding], rules: IgnoreRules) -> list[DeepSecFinding]:
    result: list[DeepSecFinding] = []
    for finding in findings:
        ignored = finding.id in rules.finding_ids or finding.detection_rule in rules.rule_ids
        ignored = ignored or finding.detection_rule in rules.files.get(finding.target, set())
        if ignored:
            finding.dismissed = True
            finding.dismissed_reason = "ignored by DeepSec policy"
        result.append(finding)
    return result
