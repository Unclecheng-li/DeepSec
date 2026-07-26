"""插件结果 → SessionState.findings 的桥接层。

把插件输出的 PluginFinding 转换为 Agent 使用的 VulnerabilityFinding，
并按 finding_id 去重合并进 SessionState，使插件结果进入报告生成链路。
"""

from __future__ import annotations

import json
from typing import Any

# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: 消除 V4 违规 — 叶子类型已移至 config/domain_models.py。
from deepsec.spear.agent.context import SessionState
from deepsec.config.domain_models import VulnerabilityFinding
from deepsec.plugins.result import PluginFinding, PluginResult, RiskLevel

# 插件风险等级 → 漏洞严重度（与 VulnerabilityFinding.severity 取值对齐）
RISK_TO_SEVERITY: dict[RiskLevel, str] = {
    RiskLevel.INFO: "Info",
    RiskLevel.LOW: "Low",
    RiskLevel.MEDIUM: "Medium",
    RiskLevel.HIGH: "High",
    RiskLevel.CRITICAL: "Critical",
}


def _evidence_level_for(confidence: float) -> str:
    """按置信度粗略映射证据等级（插件未主动联网验证，最高给 L2）。"""
    if confidence >= 0.8:
        return "L2"
    return "L1"


def plugin_finding_to_vuln_finding(
    finding: PluginFinding,
    *,
    plugin_id: str = "",
) -> VulnerabilityFinding:
    """把单条 PluginFinding 转换为 VulnerabilityFinding。"""
    evidence_obj = finding.evidence or {}
    try:
        evidence_text = (
            json.dumps(evidence_obj, ensure_ascii=False)
            if isinstance(evidence_obj, (dict, list))
            else str(evidence_obj)
        )
    except (TypeError, ValueError):
        evidence_text = str(evidence_obj)

    source = plugin_id or finding.metadata.get("plugin_id", "")
    description = finding.description
    if source:
        prefix = f"[插件:{source}] "
        description = f"{prefix}{description}" if description else prefix.strip()

    return VulnerabilityFinding(
        title=finding.title,
        severity=RISK_TO_SEVERITY.get(finding.risk, "Info"),
        vuln_type=finding.vuln_type,
        description=description,
        evidence=evidence_text[:500],
        remediation=finding.remediation,
        evidence_level=_evidence_level_for(finding.confidence),
        lifecycle_status="pending_verification",
    )


def merge_plugin_results_into_session(
    session: SessionState,
    results: PluginResult | list[PluginResult],
) -> int:
    """把一批插件结果中的 finding 合并进 session，返回新增（去重后）数量。"""
    if isinstance(results, PluginResult):
        results = [results]

    added = 0
    for result in results:
        for finding in result.findings:
            vuln = plugin_finding_to_vuln_finding(finding, plugin_id=result.plugin_id)
            if session.add_finding(vuln):
                added += 1
    return added


def summarize_plugin_results(results: list[PluginResult]) -> dict[str, Any]:
    """汇总一批插件结果，供 CLI / 报告展示。"""
    findings = sum(len(result.findings) for result in results)
    errors = [result for result in results if result.error and not result.skipped]
    skipped = [result for result in results if result.skipped]
    return {
        "plugins": len(results),
        "findings": findings,
        "errors": len(errors),
        "skipped": len(skipped),
    }
