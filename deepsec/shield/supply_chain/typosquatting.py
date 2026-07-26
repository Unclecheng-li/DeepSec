from __future__ import annotations

from pathlib import Path

from deepsec.core.finding import DeepSecFinding, DeepSecMode, FindingType, Severity


KNOWN_PACKAGES = ("react", "express", "requests", "django", "flask", "fastapi", "numpy", "pandas", "lodash", "axios", "typescript", "pytest", "pydantic", "sqlalchemy")


def scan_typosquatting(path: Path) -> list[DeepSecFinding]:
    findings: list[DeepSecFinding] = []
    for package, line in _dependencies(path):
        normalized = package.lower().replace("_", "-")
        candidates = [known for known in KNOWN_PACKAGES if _distance(normalized, known) == 1]
        if candidates:
            findings.append(DeepSecFinding.create(mode=DeepSecMode.SHIELD, type=FindingType.TYPOSQUATTING, severity=Severity.HIGH, target=str(path), description=f'Package "{package}" is one edit away from a common package.', rule="supply_chain_typosquatting", layer="SupplyChain", evidence=package, suggestion=f"Verify the intended package name. Similar known package: {candidates[0]}.", line=line, confidence=0.65))
    return findings


def _dependencies(path: Path) -> list[tuple[str, int]]:
    if path.name == "requirements.txt":
        return [(line.split("=", 1)[0].split("<", 1)[0].split(">", 1)[0].strip(), index) for index, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1) if line.strip() and not line.lstrip().startswith("#")]
    if path.name == "package.json":
        import json
        raw = json.loads(path.read_text(encoding="utf-8"))
        names = set().union(*(raw.get(key, {}).keys() for key in ("dependencies", "devDependencies", "optionalDependencies") if isinstance(raw.get(key), dict)))
        return [(str(name), 1) for name in names]
    return []


def _distance(left: str, right: str) -> int:
    if abs(len(left) - len(right)) > 1:
        return 2
    row = list(range(len(right) + 1))
    for index, char in enumerate(left, 1):
        previous, row[0] = row[0], index
        for inner, other in enumerate(right, 1):
            old = row[inner]
            row[inner] = min(row[inner] + 1, row[inner - 1] + 1, previous + (char != other))
            previous = old
    return row[-1]
