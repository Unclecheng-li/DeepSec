from __future__ import annotations

import re

from deepsec.core.finding import DeepSecFinding, DeepSecMode, FindingType, Severity


def scan_tool_abuse(text: str, target: str) -> list[DeepSecFinding]:
    pattern = re.compile(r"\b(?:exec|spawn|subprocess\.(?:run|Popen)|os\.system)\s*\([^\n]*(?:user|request|prompt|input|message)", re.I)
    findings: list[DeepSecFinding] = []
    for match in pattern.finditer(text):
        findings.append(DeepSecFinding.create(mode=DeepSecMode.SHIELD, type=FindingType.TOOL_ABUSE, severity=Severity.HIGH, target=target, description="Agent-controlled input appears to reach a command-execution tool.", rule="agent_tool_abuse_command_input", layer="Agent", evidence=match.group(0), suggestion="Use typed tool schemas, action allowlists, and explicit human approval before command execution.", line=text.count("\n", 0, match.start()) + 1, column=match.start() - text.rfind("\n", 0, match.start()), confidence=0.75))
    return findings
