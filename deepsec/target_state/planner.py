from __future__ import annotations

from datetime import datetime
from typing import Any

# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: 消除 V3 违规 — 叶子类型已移至 config/domain_models.py。
from deepsec.config.domain_models import PentestPhase


def build_resume_plan(raw: dict[str, Any]) -> dict[str, Any]:
    """Build a structured resume plan from target state."""
    findings = raw.get("findings", [])
    finding_meta = raw.get("finding_meta", {})
    recon_dims = raw.get("recon_dimensions_completed", {}) or {}
    recon_meta = raw.get("recon_meta", {}) or {}
    runtime_meta = raw.get("runtime_meta", {}) or {}
    violation_events = raw.get("constraint_violation_events", []) or []

    blocked_targets = sorted(runtime_meta.get("blocked_targets", []))
    failed_targets = runtime_meta.get("failed_targets", {}) or {}
    failed_steps = runtime_meta.get("failed_steps", []) or []
    low_value_rounds = int(runtime_meta.get("rounds_without_progress", 0) or 0)
    current_attack_path = runtime_meta.get("current_attack_path")

    pending = [f for f in findings if f.get("verification_status", "pending") == "pending"]
    verified = [f for f in findings if f.get("verification_status") == "verified"]

    pending_sorted = sorted(
        pending,
        key=lambda finding: -_lookup_confidence(finding, finding_meta),
    )
    verified_sorted = sorted(
        verified,
        key=lambda finding: -_lookup_confidence(finding, finding_meta),
    )
    recon_priority_assets = _top_recon_assets(recon_meta)

    if pending_sorted:
        next_actions = [
            "优先复测高置信度待验证漏洞",
            "避免重新执行首页级目录枚举",
        ]
        if violation_events:
            next_actions.append("回避最近被约束策略阻断的动作与工具路径")
        if blocked_targets:
            next_actions.append("跳过已确认不可达目标，集中验证仍可访问的入口")
        if low_value_rounds >= 3:
            next_actions.append("连续低价值轮次较多，优先更换参数面或新入口")
        if recon_priority_assets:
            next_actions.append(f"优先回到高价值侦察资产：{recon_priority_assets[0]}")
        return {
            "strategy": "verify_pending_findings",
            "reason": _build_reason(
                f"存在 {len(pending_sorted)} 个待验证漏洞候选，应优先验证闭环",
                blocked_targets=blocked_targets,
                low_value_rounds=low_value_rounds,
            ),
            "recommended_phase": PentestPhase.VULN_DISCOVERY.value,
            "priority_findings": [_brief_finding(f, finding_meta) for f in pending_sorted[:5]],
            "priority_targets": _infer_priority_targets(pending_sorted)
            or recon_priority_assets[:5],
            "priority_recon_assets": recon_priority_assets[:5],
            "blocked_targets": blocked_targets[:5],
            "failed_targets": _top_failed_targets(failed_targets),
            "recent_failed_steps": failed_steps[:5],
            "low_value_rounds": low_value_rounds,
            "next_actions": next_actions,
        }

    if verified_sorted:
        next_actions = [
            "优先围绕已验证漏洞扩展利用链",
            "避免回退到低价值基础侦察",
        ]
        if violation_events:
            next_actions.append("扩展利用前先确认不会触发现有约束策略")
        if current_attack_path:
            next_actions.append(f"不要继续卡在旧路径 {current_attack_path}，优先扩展新后续利用")
        if recon_priority_assets:
            next_actions.append(f"结合高价值侦察资产扩展利用：{recon_priority_assets[0]}")
        return {
            "strategy": "exploit_expand",
            "reason": _build_reason(
                f"已有 {len(verified_sorted)} 个已验证漏洞，优先继续利用与扩展",
                blocked_targets=blocked_targets,
                low_value_rounds=low_value_rounds,
            ),
            "recommended_phase": PentestPhase.EXPLOITATION.value,
            "priority_findings": [_brief_finding(f, finding_meta) for f in verified_sorted[:5]],
            "priority_targets": _infer_priority_targets(verified_sorted)
            or recon_priority_assets[:5],
            "priority_recon_assets": recon_priority_assets[:5],
            "blocked_targets": blocked_targets[:5],
            "failed_targets": _top_failed_targets(failed_targets),
            "recent_failed_steps": failed_steps[:5],
            "low_value_rounds": low_value_rounds,
            "next_actions": next_actions,
        }

    active_dims = [key for key in ("server", "website", "domain", "personnel") if key in recon_dims]
    incomplete = [key for key in active_dims if not recon_dims.get(key, False)]
    if incomplete:
        next_actions = ["补齐侦察缺口后再进入漏洞验证"]
        if violation_events:
            next_actions.append("优先选择未被约束阻断的信息收集动作")
        if blocked_targets:
            next_actions.append("忽略不可达子目标，优先完成仍可访问资产的侦察维度")
        if recon_priority_assets:
            next_actions.append(f"优先继续这些高价值侦察资产：{recon_priority_assets[0]}")
        return {
            "strategy": "continue_recon",
            "reason": _build_reason(
                f"侦察维度未完成：{', '.join(incomplete)}",
                blocked_targets=blocked_targets,
                low_value_rounds=low_value_rounds,
            ),
            "recommended_phase": PentestPhase.RECON.value,
            "priority_findings": [],
            "priority_targets": recon_priority_assets[:5],
            "priority_recon_assets": recon_priority_assets[:5],
            "blocked_targets": blocked_targets[:5],
            "failed_targets": _top_failed_targets(failed_targets),
            "recent_failed_steps": failed_steps[:5],
            "low_value_rounds": low_value_rounds,
            "next_actions": next_actions,
        }

    next_actions = ["继续围绕已知入口点做候选验证"]
    if violation_events:
        next_actions.append("回避近期被约束阻断的高风险动作")
    if low_value_rounds >= 3:
        next_actions.append("避免最近失败的扫描路径，切换新的入口或不同参数面")
    if recon_priority_assets:
        next_actions.append(f"优先测试这些高价值侦察资产：{recon_priority_assets[0]}")
    return {
        "strategy": "continue_scan",
        "reason": _build_reason(
            "暂无已验证漏洞，继续从候选攻击面推进扫描",
            blocked_targets=blocked_targets,
            low_value_rounds=low_value_rounds,
        ),
        "recommended_phase": PentestPhase.VULN_DISCOVERY.value,
        "priority_findings": [],
        "priority_targets": recon_priority_assets[:5],
        "priority_recon_assets": recon_priority_assets[:5],
        "blocked_targets": blocked_targets[:5],
        "failed_targets": _top_failed_targets(failed_targets),
        "recent_failed_steps": failed_steps[:5],
        "low_value_rounds": low_value_rounds,
        "next_actions": next_actions,
    }


def compute_finding_confidence(meta: dict[str, Any]) -> float:
    """Compute effective confidence from stored finding metadata with time decay."""
    status = meta.get("verification_status", "pending")
    observation_count = int(meta.get("observation_count", 1))
    last_seen_at = meta.get("last_seen_at")
    last_verified_at = meta.get("last_verified_at")

    if status == "verified":
        base = 0.88
    elif status == "rejected":
        base = 0.08
    else:
        base = 0.55

    confidence = base + min(max(observation_count - 1, 0), 4) * 0.04

    age_days = _age_days(
        last_verified_at if status == "verified" and last_verified_at else last_seen_at
    )
    if status == "pending":
        confidence -= age_days * 0.02
    elif status == "verified":
        confidence -= age_days * 0.01

    return round(max(0.05, min(confidence, 0.99)), 3)


def compute_recon_asset_confidence(meta: dict[str, Any]) -> float:
    """Compute effective confidence for recon assets such as subdomains or paths."""
    category = str(meta.get("category", "asset"))
    value = str(meta.get("value", ""))
    observation_count = int(meta.get("observation_count", 1))
    last_seen_at = meta.get("last_seen_at")

    base = {
        "subdomains": 0.62,
        "paths": 0.68,
        "params": 0.58,
    }.get(category, 0.55)

    confidence = base + min(max(observation_count - 1, 0), 4) * 0.05
    value_lower = value.lower()

    if category == "subdomains" and any(
        token in value_lower for token in ("api", "admin", "vpn", "oa", "mail", "jw", "jwc", "zsw")
    ):
        confidence += 0.04
    elif category == "paths" and any(
        token in value_lower
        for token in ("admin", "api", "login", "upload", "download", "search", "news", "jwc", "vpn")
    ):
        confidence += 0.05
    elif category == "params" and any(
        token in value_lower
        for token in ("id", "file", "path", "q", "search", "wd", "keyword", "page", "cid")
    ):
        confidence += 0.04

    age_days = _age_days(last_seen_at)
    confidence -= age_days * 0.015

    return round(max(0.05, min(confidence, 0.99)), 3)


def _lookup_confidence(finding: dict[str, Any], finding_meta: dict[str, Any]) -> float:
    key = _finding_key(finding)
    meta = finding_meta.get(key, {})
    if not meta:
        return 0.5
    return float(meta.get("confidence", compute_finding_confidence(meta)))


def _finding_key(finding: dict[str, Any]) -> str:
    return (
        finding.get("finding_id") or f"{finding.get('title', '')}::{finding.get('vuln_type', '')}"
    )


def _brief_finding(finding: dict[str, Any], finding_meta: dict[str, Any]) -> str:
    confidence = _lookup_confidence(finding, finding_meta)
    title = finding.get("title", "unknown")
    status = finding.get("verification_status", "pending")
    return f"{title} ({status}, conf={confidence:.2f})"


def _age_days(timestamp: str | None) -> float:
    if not timestamp:
        return 0.0
    try:
        delta = datetime.now() - datetime.fromisoformat(timestamp)
        return max(delta.total_seconds() / 86400.0, 0.0)
    except Exception:
        return 0.0


def _infer_priority_targets(findings: list[dict[str, Any]]) -> list[str]:
    import re

    targets: list[str] = []
    for finding in findings:
        text = " ".join(
            str(part or "")
            for part in (
                finding.get("title"),
                finding.get("description"),
                finding.get("evidence"),
            )
        )
        url_match = re.search(r"https?://[^\s'\"<>()]+", text)
        path_match = re.search(r"/[A-Za-z0-9._/\-?=&%]+", text) if not url_match else None
        candidate = url_match.group(0) if url_match else path_match.group(0) if path_match else None
        if candidate and candidate not in targets:
            targets.append(candidate)
    return targets[:5]


def _top_recon_assets(recon_meta: dict[str, Any]) -> list[str]:
    assets: list[tuple[float, int, str]] = []
    for category, items in recon_meta.items():
        if not isinstance(items, dict):
            continue
        for value, meta in items.items():
            confidence = float(meta.get("confidence", compute_recon_asset_confidence(meta)))
            obs = int(meta.get("observation_count", 1))
            label = f"{category}:{value}"
            assets.append((confidence, obs, label))
    assets.sort(key=lambda item: (-item[0], -item[1], item[2]))
    return [label for _, _, label in assets[:5]]


def _top_failed_targets(failed_targets: dict[str, Any]) -> list[str]:
    items = sorted(
        ((str(host), int(count)) for host, count in failed_targets.items()),
        key=lambda item: (-item[1], item[0]),
    )
    return [f"{host} ({count})" for host, count in items[:5]]


def _build_reason(base: str, *, blocked_targets: list[str], low_value_rounds: int) -> str:
    suffix: list[str] = []
    if blocked_targets:
        suffix.append(f"已存在 {len(blocked_targets)} 个不可达目标")
    if low_value_rounds >= 3:
        suffix.append(f"连续 {low_value_rounds} 轮低价值推进")
    if not suffix:
        return base
    return f"{base}；{'；'.join(suffix)}"
