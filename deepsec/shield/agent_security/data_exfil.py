from __future__ import annotations

import re

from deepsec.core.finding import DeepSecFinding, DeepSecMode, FindingType, Severity


def scan_data_exfiltration(text: str, target: str) -> list[DeepSecFinding]:
    pattern = re.compile(r"\b(?:requests\.(?:post|put)|fetch|axios\.(?:post|put))\s*\([^\n]*(?:os\.environ|process\.env|secrets?|credentials?|\.ssh|id_rsa)", re.I)
    findings: list[DeepSecFinding] = []
    for match in pattern.finditer(text):
        findings.append(DeepSecFinding.create(mode=DeepSecMode.SHIELD, type=FindingType.DATA_EXFILTRATION, severity=Severity.CRITICAL, target=target, description="Network request appears to include secrets or environment data.", rule="agent_data_exfiltration_secret_egress", layer="Agent", evidence=match.group(0), suggestion="Do not include secrets in agent context or tool payloads; apply outbound destination and data-loss policies.", line=text.count("\n", 0, match.start()) + 1, column=match.start() - text.rfind("\n", 0, match.start()), confidence=0.8))
    return findings
