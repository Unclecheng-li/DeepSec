"""Report rendering for Shield and Spear results."""

from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path
from typing import Iterable

from .finding import DeepSecFinding, Severity


def write_report(findings: Iterable[DeepSecFinding], output: Path, format_name: str) -> Path:
    items = list(findings)
    output.parent.mkdir(parents=True, exist_ok=True)
    normalized = format_name.lower()
    if normalized == "json":
        output.write_text(json.dumps({"findings": [item.to_dict() for item in items]}, indent=2) + "\n", encoding="utf-8")
    elif normalized == "sarif":
        output.write_text(json.dumps(to_sarif(items), indent=2) + "\n", encoding="utf-8")
    elif normalized in {"markdown", "md"}:
        output.write_text(to_markdown(items), encoding="utf-8")
    elif normalized == "html":
        output.write_text(to_html(items), encoding="utf-8")
    else:
        raise ValueError(f"Unsupported report format: {format_name}")
    return output


def to_markdown(findings: list[DeepSecFinding]) -> str:
    counts = Counter(item.severity.value for item in findings)
    lines = ["# DeepSec Security Report", "", f"Findings: **{len(findings)}**"]
    lines.append(" | ".join(f"{level}: {counts[level]}" for level in ("critical", "high", "medium", "low", "info")))
    for item in findings:
        location = item.target if item.line is None else f"{item.target}:{item.line}"
        lines.extend(["", f"## [{item.severity.value.upper()}] {item.title}", "", f"- Location: `{location}`", f"- Rule: `{item.detection_rule}`", f"- Layer: `{item.detection_layer}`"])
        lines.extend(["", item.description])
        if item.evidence:
            lines.extend(["", "```text", item.evidence, "```"])
        if item.suggestion:
            lines.extend(["", f"Remediation: {item.suggestion}"])
    return "\n".join(lines) + "\n"


def to_html(findings: list[DeepSecFinding]) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(item.severity.value)}</td>"
        f"<td>{html.escape(item.title)}</td>"
        f"<td>{html.escape(item.target)}{':' + str(item.line) if item.line else ''}</td>"
        f"<td>{html.escape(item.detection_rule)}</td>"
        "</tr>"
        for item in findings
    )
    return "<!doctype html><html><head><meta charset=\"utf-8\"><title>DeepSec Report</title></head><body><h1>DeepSec Security Report</h1><table><thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Rule</th></tr></thead><tbody>" + rows + "</tbody></table></body></html>\n"


def to_sarif(findings: list[DeepSecFinding]) -> dict[str, object]:
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for item in findings:
        rules.setdefault(item.detection_rule, {"id": item.detection_rule, "shortDescription": {"text": item.title}})
        level = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}[item.severity]
        location: dict[str, object] = {"physicalLocation": {"artifactLocation": {"uri": item.target}}}
        if item.line:
            location["physicalLocation"]["region"] = {"startLine": item.line, "startColumn": item.column or 1}  # type: ignore[index]
        results.append({"ruleId": item.detection_rule, "level": level, "message": {"text": item.description}, "locations": [location]})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "DeepSec", "rules": list(rules.values())}}, "results": results}]}
