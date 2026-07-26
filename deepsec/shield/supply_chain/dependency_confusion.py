from __future__ import annotations

from pathlib import Path

from deepsec.core.finding import DeepSecFinding, DeepSecMode, FindingType, Severity


def scan_dependency_confusion(path: Path, private_packages: set[str] | None = None) -> list[DeepSecFinding]:
    """Flag explicitly declared private names that are fetched from a public index.

    DeepSec only reports when an organization provides its private package list;
    guessing private ownership would produce noisy and misleading results.
    """
    private_packages = {item.lower() for item in private_packages or set()}
    if not private_packages or path.name != "requirements.txt":
        return []
    text = path.read_text(encoding="utf-8", errors="ignore")
    uses_private_index = "--extra-index-url" in text or "--index-url" in text
    if uses_private_index:
        return []
    findings: list[DeepSecFinding] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        name = line.split("=", 1)[0].split("<", 1)[0].split(">", 1)[0].strip().lower()
        if name in private_packages:
            findings.append(DeepSecFinding.create(mode=DeepSecMode.SHIELD, type=FindingType.DEPENDENCY_CONFUSION, severity=Severity.HIGH, target=str(path), description=f'Private package "{name}" is resolved without an explicit private index.', rule="supply_chain_dependency_confusion", layer="SupplyChain", evidence=line.strip(), suggestion="Pin the private registry and require trusted package provenance.", line=line_number, confidence=0.8))
    return findings
