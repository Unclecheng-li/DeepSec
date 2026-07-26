"""Skill reference selection helpers for AgentCore.

Skills are reference material, not execution scripts.  This module keeps the
deterministic resolver and provenance trail, but prompt rendering deliberately
exposes only a compact reference index: selected skill names, descriptions,
resolver reason, and on-demand reference names.  The actual skill/reference body
is loaded only when the model chooses ``load_skill_reference``.

Resolving once per turn is deliberate: the recorded provenance attached to
findings names the same reference bundle that was offered to the model.
"""

from __future__ import annotations

from typing import Any, Optional

from deepsec.spear.skills.loader import load_skill_by_name
from deepsec.spear.skills.resolver import SkillQuery, SkillResolver, SkillSelection
from deepsec.spear.skills.routing import keyword_present, normalize_token

# Internal Chinese phase labels -> resolver's canonical phase tokens.  The IDLE
# label is intentionally absent so "not started" contributes no phase signal.
_PHASE_TOKEN: dict[str, str] = {
    "信息收集": "recon",
    "漏洞发现": "vuln_discovery",
    "漏洞利用": "exploitation",
    "后渗透": "post_exploitation",
    "报告生成": "reporting",
}

# Free-text vulnerability keywords (bilingual) -> canonical routing token.
_VULN_HINT_KEYWORDS: dict[str, str] = {
    "sql注入": "sqli",
    "sqli": "sqli",
    "xss": "xss",
    "rce": "rce",
    "命令注入": "rce",
    "远程代码执行": "rce",
    "ssrf": "ssrf",
    "ssti": "ssti",
    "xxe": "xxe",
    "csrf": "csrf",
    "反序列化": "deserialization",
    "越权": "idor",
    "idor": "idor",
    "文件上传": "file_upload",
    "路径遍历": "path_traversal",
    "目录穿越": "path_traversal",
    "lfi": "path_traversal",
    "rfi": "path_traversal",
    "jwt": "jwt",
    "oauth": "oauth",
    "认证绕过": "auth_bypass",
    "prompt注入": "prompt_injection",
    "prompt injection": "prompt_injection",
    "提权": "privilege_escalation",
    "横向": "lateral_movement",
}

# Technology keywords worth passing as routing signals.
_TECH_KEYWORDS = ("php", "java", "python", "nodejs", "node.js", "wordpress", "django", "spring")


def _infer_target_type(target: Optional[str], text: str) -> Optional[str]:
    """Conservatively infer a target type from the target string/request text."""

    blob = f"{target or ''} {text}".lower()
    if target:
        low = target.lower()
        if low.startswith(("http://", "https://")):
            return "web"
        if _looks_like_ip(low):
            return "network"
    if any(keyword in blob for keyword in ("apk", "安卓", "android")):
        return "android"
    if "http://" in blob or "https://" in blob:
        return "web"
    return None


def _looks_like_ip(value: str) -> bool:
    parts = value.split(":")[0].split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _extract_vuln_hints(text: str) -> list[str]:
    low = text.lower()
    hints: list[str] = []
    for keyword, token in _VULN_HINT_KEYWORDS.items():
        if token not in hints and keyword_present(keyword, low):
            hints.append(token)
    return hints


def _extract_technologies(text: str, recon_data: Optional[dict[str, Any]]) -> list[str]:
    low = text.lower()
    techs: list[str] = []
    for keyword in _TECH_KEYWORDS:
        if keyword_present(keyword, low):
            token = normalize_token(keyword)
            if token not in techs:
                techs.append(token)
    if isinstance(recon_data, dict):
        raw = recon_data.get("technologies")
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str):
                    token = normalize_token(item)
                    if token and token not in techs:
                        techs.append(token)
    return techs


def _build_query(
    user_input: Optional[str],
    *,
    phase_label: Optional[str] = None,
    target: Optional[str] = None,
    recon_data: Optional[dict[str, Any]] = None,
    task_summary: Optional[str] = None,
) -> SkillQuery:
    text = f"{user_input or ''} {task_summary or ''}"
    return SkillQuery.from_input(
        user_input,
        phase=_PHASE_TOKEN.get(phase_label or ""),
        target_type=_infer_target_type(target, text),
        vuln_hints=_extract_vuln_hints(text),
        technologies=_extract_technologies(text, recon_data),
        task_summary=task_summary,
    )


def resolve_active_skill_selection(
    user_input: Optional[str] = None,
    **kwargs: Any,
) -> Optional[SkillSelection]:
    """Resolve the optional reference bundle for a turn, or None."""

    task_summary = kwargs.get("task_summary")
    if not (user_input or task_summary):
        return None
    try:
        selection = SkillResolver().resolve(_build_query(user_input, **kwargs))
        return selection if not selection.is_empty() else None
    except Exception:
        return None


def apply_skill_selection(state: Any, user_input: Optional[str] = None) -> Optional[str]:
    """Resolve, record provenance on ``state``, and return a reference index.

    Skill bodies are never injected automatically.  A selected bundle only tells
    the model which reference files may be useful if it decides to load them.
    """

    phase_label = getattr(getattr(state, "phase", None), "value", None)
    selection = resolve_active_skill_selection(
        user_input,
        phase_label=phase_label,
        target=getattr(state, "target", None),
        recon_data=getattr(state, "recon_data", None),
    )
    try:
        state.set_active_skill_selection(selection.to_provenance() if selection else None)
    except Exception:
        pass

    if selection and selection.primary:
        return format_selection_context(selection)
    return None


def get_active_skill_context(user_input: Optional[str] = None, **kwargs: Any) -> Optional[str]:
    """Get the most relevant optional reference index without recording provenance."""

    if user_input or kwargs.get("task_summary"):
        selection = resolve_active_skill_selection(user_input, **kwargs)
        if selection and selection.primary:
            return format_selection_context(selection)
    return None


def format_selection_context(selection: SkillSelection) -> str:
    """Render a resolved bundle as optional reference material.

    The primary skill instructions are intentionally not injected here.  This
    keeps the model in control of strategy and makes ``load_skill_reference`` an
    explicit, model-chosen read action.
    """

    parts: list[str] = [
        "These skills are optional reference material only. They are not mandatory "
        "workflows, phases, checklists, or tool schedules. Use or ignore them based "
        "on the current evidence and your own reasoning."
    ]

    primary = load_skill_by_name(selection.primary) if selection.primary else None
    if primary:
        desc = primary.get("description", "").strip()
        summary = desc.splitlines()[0] if desc else "(no description)"
        parts.append(f"- primary reference: {selection.primary} — {summary}")

    for name in selection.supporting:
        skill = load_skill_by_name(name)
        if not skill:
            continue
        desc = skill.get("description", "").strip()
        summary = desc.splitlines()[0] if desc else "(no description)"
        parts.append(f"- supporting reference: {name} — {summary}")

    refs = primary.get("references", []) if primary else []
    if refs:
        ref_list = ", ".join(refs[:10])
        if len(refs) > 10:
            ref_list += f", ... ({len(refs)} total)"
        parts.append(
            "Available reference files, load only if useful with "
            f"`load_skill_reference`: {ref_list}"
        )

    if selection.reason:
        parts.append(
            f"<!-- reference routing: {selection.reason}; confidence={selection.confidence:.2f} -->"
        )

    return "\n\n".join(part for part in parts if part)
