"""Shield three-layer scanner and project traversal."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter

from deepsec.core.config import DeepSecConfig, load_config
from deepsec.core.finding import DeepSecFinding
from deepsec.core.llm import DeepSecLLM

from .agent_security import scan_data_exfiltration, scan_prompt_injection, scan_tool_abuse
from .dedup import unique_findings
from .ignore import IgnoreRules, apply_ignore_rules
from .rules.ai_audit import audit_semantics, audit_with_llm
from .rules.patterns import scan_patterns
from .rules.sast import scan_sast


SUPPORTED_SUFFIXES = {".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".ts": "typescript", ".tsx": "tsx", ".jsx": "jsx", ".java": "java", ".go": "go", ".rb": "ruby", ".php": "php", ".cs": "csharp", ".rs": "rust", ".yaml": "yaml", ".yml": "yaml", ".json": "json"}

# Code you did not write and cannot fix. Always skipped: a finding here is noise
# no matter how the scan is configured.
IGNORED_DIRECTORIES = {".git", ".deepsec", "node_modules", "bower_components", "dist", "out", "build", "coverage", ".venv", "venv", ".venv64", "__pycache__", "vendor", "third_party", "site-packages", ".next", ".nuxt", ".svelte-kit", "Pods", ".tox", ".mypy_cache", ".pytest_cache", ".gradle"}

# Code you did write, but where a hardcoded credential or an eval() is the point.
# Skipped by default, restored with ScanOptions(include_tests=True).
TEST_DIRECTORIES = {"test", "tests", "__tests__", "spec", "specs", "fixtures", "fixture", "testdata", "test_data", "examples", "example", "demo", "demos", "mocks", "__mocks__", "testvectors", "wycheproof", "benchmarks"}

# Build products and lockfiles: generated, minified, or vendored blobs where line
# numbers point at nothing a human can act on.
GENERATED_SUFFIXES = (".min.js", ".min.css", ".bundle.js", ".bundle.css", "-lock.json", ".lock.json", ".map", ".pb.go", "_pb2.py", ".g.dart", ".generated.ts")
TEST_FILE_MARKERS = (".test.", ".spec.", "_test.", "_spec.")

# Shield's own output. Reports embed the evidence strings they describe, so
# scanning a directory twice made the first run's report look like vulnerable
# source and produced findings at line numbers past the end of the real file.
REPORT_FILENAMES = {"deepsec-report.json", "deepsec-report.sarif", "deepsec.sarif", "deepsec-findings.json"}



@dataclass(slots=True)
class ScanOptions:
    l1: bool = True
    l2: bool = True
    l3: bool = False
    remote_l3: bool = False
    agent_audit: bool = False
    dedup: bool = True
    include_tests: bool = False
    ignore_rules: IgnoreRules = field(default_factory=IgnoreRules)


@dataclass(slots=True)
class ScanResult:
    findings: list[DeepSecFinding]
    elapsed_ms: float
    files_scanned: int
    layers: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"findings": [item.to_dict() for item in self.findings], "elapsedMs": round(self.elapsed_ms, 2), "filesScanned": self.files_scanned, "layers": list(self.layers)}


def scan_text(text: str, target: str, language: str | None = None, options: ScanOptions | None = None, config: DeepSecConfig | None = None) -> ScanResult:
    options = options or ScanOptions()
    started = perf_counter()
    findings: list[DeepSecFinding] = []
    layers: list[str] = []
    if options.l1:
        findings.extend(scan_patterns(text, target, language))
        layers.append("L1")
    if options.l2:
        findings.extend(scan_sast(text, target, language))
        layers.append("L2")
    if options.l3:
        findings.extend(audit_semantics(text, target, language))
        layers.append("L3")
        if options.remote_l3:
            active_config = config or load_config()
            findings.extend(asyncio.run(audit_with_llm(text, target, DeepSecLLM(active_config).shield_review)))
    if options.agent_audit:
        findings.extend(scan_prompt_injection(text, target))
        findings.extend(scan_tool_abuse(text, target))
        findings.extend(scan_data_exfiltration(text, target))
        layers.append("Agent")
    if options.dedup:
        findings = unique_findings(findings)
    findings = apply_ignore_rules(findings, options.ignore_rules)
    return ScanResult(findings=findings, elapsed_ms=(perf_counter() - started) * 1000, files_scanned=1, layers=tuple(layers))


def scan_path(
    path: Path,
    options: ScanOptions | None = None,
    config: DeepSecConfig | None = None,
    on_finding: Callable[[DeepSecFinding], None] | None = None,
) -> ScanResult:
    options = options or ScanOptions()
    started = perf_counter()
    files = _source_files(path, options.include_tests)
    all_findings: list[DeepSecFinding] = []
    layers: set[str] = set()
    for source in files:
        try:
            text = source.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        result = scan_text(text, str(source), SUPPORTED_SUFFIXES.get(source.suffix.lower()), options, config)
        for finding in result.findings:
            if on_finding is not None:
                on_finding(finding)
            all_findings.append(finding)
        layers.update(result.layers)
    if options.dedup:
        all_findings = unique_findings(all_findings)
    return ScanResult(findings=all_findings, elapsed_ms=(perf_counter() - started) * 1000, files_scanned=len(files), layers=tuple(sorted(layers)))


def _source_files(path: Path, include_tests: bool = False) -> list[Path]:
    path = path.expanduser().resolve()
    if path.is_file():
        return [path] if path.suffix.lower() in SUPPORTED_SUFFIXES else []
    if not path.is_dir():
        raise ValueError(f"Path does not exist: {path}")
    return [candidate for candidate in path.rglob("*") if candidate.is_file() and _is_scannable(candidate, candidate.relative_to(path), include_tests)]


def _is_scannable(candidate: Path, relative: Path, include_tests: bool) -> bool:
    if candidate.suffix.lower() not in SUPPORTED_SUFFIXES:
        return False
    name = candidate.name
    if name in REPORT_FILENAMES or name.lower().endswith(GENERATED_SUFFIXES):
        return False
    directories = relative.parts[:-1]
    # Virtualenvs are named .venv, .venv64, .venv311, venv, env... match by shape
    # rather than trying to enumerate every convention.
    if any(part in IGNORED_DIRECTORIES or part.startswith((".venv", "venv-", "venv3")) for part in directories):
        return False
    if include_tests:
        return True
    if any(part.lower() in TEST_DIRECTORIES for part in directories):
        return False
    return not any(marker in name.lower() for marker in TEST_FILE_MARKERS)
