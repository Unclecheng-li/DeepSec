from __future__ import annotations

import re

from deepsec.core.finding import DeepSecFinding, DeepSecMode, FindingType, Severity


def scan_prompt_injection(text: str, target: str) -> list[DeepSecFinding]:
    pattern = re.compile(r"(?:ignore|override|bypass)\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions|rules)|(?:reveal|print|show)\s+(?:the\s+)?(?:system prompt|hidden instructions)|you are now", re.I)
    return [_finding(text, target, match.start(), match.group(0)) for match in pattern.finditer(text)]


def _finding(text: str, target: str, offset: int, evidence: str) -> DeepSecFinding:
    return DeepSecFinding.create(mode=DeepSecMode.SHIELD, type=FindingType.PROMPT_INJECTION, severity=Severity.HIGH, target=target, description="Prompt content contains a likely instruction-override pattern.", rule="agent_prompt_injection_instruction_override", layer="Agent", evidence=evidence, suggestion="Treat retrieved or user-controlled text as data; separate it from trusted instructions and validate tool intents.", line=text.count("\n", 0, offset) + 1, column=offset - text.rfind("\n", 0, offset), confidence=0.7)
