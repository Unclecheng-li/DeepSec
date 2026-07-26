"""Minimal, dependency-free attack-chain HTML visualization."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Iterable

from deepsec.core.finding import DeepSecFinding


def attack_chain_data(findings: Iterable[DeepSecFinding]) -> dict[str, object]:
    """Return the stable DAG consumed by the TUI and report viewers."""
    items = sorted(findings, key=lambda item: (item.chain_step is None, item.chain_step or 0, item.id))
    nodes = [
        {
            "id": item.id,
            "title": item.title,
            "target": item.target,
            "severity": item.severity.value,
            "type": item.type.value,
            "step": item.chain_step,
            "verified": item.verified,
        }
        for item in items
    ]
    known = {node["id"] for node in nodes}
    edges = [
        {"from": dependency, "to": item.id}
        for item in items
        for dependency in item.chain_depends_on
        if dependency in known
    ]
    return {"nodes": nodes, "edges": edges}


def write_attack_chain_data(findings: Iterable[DeepSecFinding], output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(attack_chain_data(findings), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output


def write_attack_chain(findings: Iterable[DeepSecFinding], output: Path) -> Path:
    items = sorted(findings, key=lambda item: (item.chain_step is None, item.chain_step or 0, item.id))
    nodes = "".join(
        f"<li><strong>{html.escape(item.type.value)}</strong> [{html.escape(item.severity.value)}] "
        f"{html.escape(item.title)}<br><small>{html.escape(item.target)}</small></li>"
        for item in items
    ) or "<li>No linked Spear findings were supplied.</li>"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("<!doctype html><html><head><meta charset=\"utf-8\"><title>DeepSec Attack Chain</title></head><body><h1>DeepSec Attack Chain</h1><ol>" + nodes + "</ol></body></html>\n", encoding="utf-8")
    return output
