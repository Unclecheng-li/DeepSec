"""VulnClaw Finding Similarity — lightweight semantic deduplication.

修改者: Nyaecho
修改时间: 2026-07-08
修改原因: V2 修复 — 核心逻辑已移至 config/finding_similarity.py，
         此处重新导出以保持 agent/ 层向后兼容。
"""

from __future__ import annotations

from deepsec.config.finding_similarity import (  # noqa: F401
    _evidence_strength,
    _extract_location,
    _vuln_type_similarity,
    deduplicate_findings,
    finding_similarity,
    normalize_text,
    normalize_vuln_type,
    text_similarity,
    url_similarity,
)

__all__ = [
    "_evidence_strength",
    "_extract_location",
    "_vuln_type_similarity",
    "normalize_text",
    "normalize_vuln_type",
    "text_similarity",
    "url_similarity",
    "finding_similarity",
    "deduplicate_findings",
]
