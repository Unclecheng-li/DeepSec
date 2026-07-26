from __future__ import annotations

from deepsec.core.finding import DeepSecFinding


def unique_findings(findings: list[DeepSecFinding]) -> list[DeepSecFinding]:
    """Keep the first stable finding for a rule, location, and evidence tuple."""
    seen: set[tuple[str, str, int | None, str]] = set()
    result: list[DeepSecFinding] = []
    for finding in findings:
        key = (finding.detection_rule, finding.target, finding.line, finding.evidence)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result
