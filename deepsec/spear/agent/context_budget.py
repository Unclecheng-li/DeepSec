"""Unified request budgeting and deterministic context compaction.

This module owns the model-facing context budget for the spear agent.  It
deliberately uses the existing structured AgentState/evidence records instead
of asking another LLM to summarize arbitrary history.  That keeps compaction
deterministic, avoids recursive context growth, and preserves evidence
references.

The configuration reads the ``context_*`` fields on
:class:`deepsec.config.schema.SessionConfig`; the older ``solve_auto_compact`` /
``solve_compact_trigger_ratio`` knobs are honoured as legacy aliases when the
new fields are left at their defaults.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any

from deepsec.spear.agent.token_counter import (
    estimate_message_group_tokens,
    estimate_tokens,
    estimate_tool_tokens,
    flatten_message_groups,
    group_messages,
    truncate_message_groups,
)
from deepsec.spear.agent.context_vault import (
    VaultBlock,
    VaultManager,
    _REF_RE,
    _content_text,
    _estimate_chars,
    assign_refs,
    ref_id,
)

_DIGEST_PREFIX = "[context digest v1]"
_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)(authorization|cookie|set-cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"secret|password)\s*[:=]\s*([^\s,;]+)"
)


@dataclass(frozen=True)
class ContextBudget:
    model_window_tokens: int
    usable_input_tokens: int
    output_reserve_tokens: int
    message_tokens: int
    tool_tokens: int
    total_input_tokens: int
    trigger_tokens: int
    target_tokens: int


@dataclass(frozen=True)
class ContextCompactionResult:
    messages: list[dict[str, Any]]
    compacted: bool
    before_tokens: int
    after_tokens: int
    tool_tokens: int
    removed_message_groups: int = 0
    retained_message_groups: int = 0
    reason: str = ""


def _number(value: Any, default: float, *, minimum: float | None = None) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        result = float(value)
    else:
        result = default
    return max(minimum, result) if minimum is not None else result


def _bool(value: Any, default: bool) -> bool:
    return value if isinstance(value, bool) else default


def _session_config(agent: Any) -> Any:
    return getattr(getattr(agent, "config", None), "session", None)


def _llm_config(agent: Any) -> Any:
    return getattr(getattr(agent, "config", None), "llm", None)


def _setting(session: Any, new_name: str, legacy_name: str, default: Any) -> Any:
    """Read a context_* setting, falling back to the legacy solve_* alias.

    The new field wins whenever it is present at all (its schema default is the
    canonical default); the legacy alias only kicks in when the new field is
    explicitly unset (None) on the model.
    """
    if session is None:
        return default
    new_value = getattr(session, new_name, None)
    if new_value is not None:
        return new_value
    legacy_value = getattr(session, legacy_name, None)
    if legacy_value is not None:
        return legacy_value
    return default


def build_context_budget(agent: Any, messages: list[dict[str, Any]], tools: list[dict] | None) -> ContextBudget | None:
    """Build a request budget, returning None when no model window is configured."""
    llm = _llm_config(agent)
    window = _number(getattr(llm, "max_context_tokens", None), 0, minimum=0)
    if window <= 0:
        return None

    session = _session_config(agent)
    configured_reserve = _number(
        getattr(session, "context_output_reserve_tokens", 0), 0, minimum=0
    )
    max_completion = _number(getattr(llm, "max_tokens", None), 4096, minimum=1)
    reserve = configured_reserve or min(max_completion, 8192)
    usable = max(1, int(window - reserve))

    # Legacy solve_* aliases are honoured when the new fields are defaulted.
    auto_compact = _bool(
        _setting(session, "context_auto_compact", "solve_auto_compact", True), True
    )
    trigger_ratio = min(
        0.95,
        max(
            0.1,
            _number(
                _setting(session, "context_compact_trigger_ratio", "solve_compact_trigger_ratio", 0.70),
                0.70,
            ),
        ),
    )
    target_ratio = min(
        trigger_ratio - 0.05,
        max(0.05, _number(getattr(session, "context_compact_target_ratio", 0.55), 0.55)),
    )
    message_tokens = estimate_tokens(messages)
    tool_tokens = estimate_tool_tokens(tools)
    return ContextBudget(
        model_window_tokens=int(window),
        usable_input_tokens=usable,
        output_reserve_tokens=int(reserve),
        message_tokens=message_tokens,
        tool_tokens=tool_tokens,
        total_input_tokens=message_tokens + tool_tokens,
        trigger_tokens=max(1, int(usable * trigger_ratio)),
        target_tokens=max(1, int(usable * target_ratio)),
    )


def _state_for(agent: Any) -> Any:
    return getattr(getattr(getattr(agent, "context", None), "state", None), "agent_state", None)


def _session_for(agent: Any) -> Any:
    return getattr(getattr(agent, "context", None), "state", None)


def _redact(value: str) -> str:
    return _SENSITIVE_VALUE_RE.sub(lambda match: f"{match.group(1)}=[redacted]", value)


def _clip(value: str, limit: int) -> str:
    text = str(value or "")
    if limit <= 0 or len(text) <= limit:
        return text
    marker = " ...[clipped]... "
    head = max(1, (limit - len(marker)) // 2)
    tail = max(1, limit - head - len(marker))
    return text[:head] + marker + text[-tail:]


def _one_line(value: Any, limit: int = 240) -> str:
    return _clip(re.sub(r"\s+", " ", str(value or "")).strip(), limit)


def _is_digest_message(message: dict[str, Any]) -> bool:
    return message.get("role") == "system" and str(message.get("content", "")).startswith(
        "[context digest"
    )


def _is_vault_pointer(message: dict[str, Any]) -> bool:
    """True for any vault-produced system message (pointer or distilled)."""
    return message.get("role") == "system" and str(message.get("content", "")).startswith(
        "[V]"
    )


def _vault_for(agent: Any) -> VaultManager | None:
    context = getattr(agent, "context", None)
    vault = getattr(context, "vault", None)
    return vault if isinstance(vault, VaultManager) else None


def _leading_system_groups(groups: list[list[dict[str, Any]]]) -> tuple[list[list[dict[str, Any]]], list[list[dict[str, Any]]]]:
    leading: list[list[dict[str, Any]]] = []
    remainder = list(groups)
    while remainder:
        group = remainder[0]
        if len(group) != 1 or not isinstance(group[0], dict) or group[0].get("role") != "system":
            break
        leading.append(remainder.pop(0))
    return leading, remainder


def _select_recent_groups(
    groups: list[list[dict[str, Any]]],
    *,
    base_tokens: int,
    target_tokens: int,
    min_recent_groups: int,
) -> tuple[list[list[dict[str, Any]]], list[list[dict[str, Any]]]]:
    """Keep the newest complete groups that fit, returning (kept, removed)."""
    kept_reversed: list[list[dict[str, Any]]] = []
    running = base_tokens
    required = max(1, min_recent_groups)
    for group in reversed(groups):
        cost = estimate_message_group_tokens(group)
        if running + cost <= target_tokens or len(kept_reversed) < required:
            kept_reversed.append(group)
            running += cost
        else:
            break
    kept = list(reversed(kept_reversed))
    return kept, groups[: len(groups) - len(kept)]


def _message_history_digest(groups: list[list[dict[str, Any]]], *, limit: int = 900) -> list[str]:
    """Extract small, explicitly-untrusted observations from removed history."""
    lines: list[str] = []
    for group in groups[-8:]:
        first = group[0] if group else {}
        role = str(first.get("role", "message")) if isinstance(first, dict) else "message"
        content = ""
        for message in group:
            if isinstance(message, dict) and message.get("content"):
                content = str(message["content"])
                break
        if content:
            lines.append(f"- Prior {role}: {_redact(_one_line(content, 180))}")
    rendered = "\n".join(lines)
    return rendered.splitlines() if len(rendered) <= limit else _clip(rendered, limit).splitlines()


def _build_digest(agent: Any, removed_groups: list[list[dict[str, Any]]], max_tokens: int) -> tuple[str, list[str]]:
    """Create deterministic memory from durable state plus removed history."""
    state = _state_for(agent)
    session = _session_for(agent)
    lines = [_DIGEST_PREFIX]
    evidence_ids: list[str] = []

    target = getattr(session, "target", "") if session is not None else ""
    if target:
        lines.append(f"Target: {_redact(_one_line(target, 240))}")

    constraints = getattr(session, "task_constraints", None) if session is not None else None
    if constraints is not None and hasattr(constraints, "to_prompt_block"):
        block = _redact(_one_line(constraints.to_prompt_block(), 600))
        if block:
            lines.append(f"Scope constraints: {block}")

    if state is not None:
        goal = getattr(state, "goal", "")
        origin = getattr(state, "origin", "")
        if goal:
            lines.append(f"Goal: {_redact(_one_line(goal, 320))}")
        if origin and origin != target:
            lines.append(f"Origin: {_redact(_one_line(origin, 240))}")

        verified = list(getattr(state, "verified_claims", []) or [])[-8:]
        if verified:
            lines.append("Verified facts:")
            for claim in verified:
                ids = list(getattr(claim, "evidence_ids", []) or [])
                evidence_ids.extend(ids)
                lines.append(
                    f"- {_redact(_one_line(getattr(claim, 'claim', ''), 260))}"
                    + (f" (evidence: {', '.join(ids)})" if ids else "")
                )

        facts = list(getattr(state, "pinned_facts", []) or [])[-12:]
        if facts:
            lines.append("Pinned facts:")
            for fact in facts:
                evidence_id = str(getattr(fact, "evidence_id", "") or "")
                if evidence_id:
                    evidence_ids.append(evidence_id)
                lines.append(
                    f"- {_redact(_one_line(getattr(fact, 'text', ''), 260))}"
                    + (f" ({evidence_id})" if evidence_id else "")
                )

        steps = list(getattr(state, "steps", []) or [])[-8:]
        if steps:
            lines.append("Recent outcomes and failed paths:")
            for step in steps:
                lines.append(
                    "- "
                    + _redact(
                        _one_line(
                            f"{getattr(step, 'reason', '')}; {getattr(step, 'observation', '')}",
                            320,
                        )
                    )
                )

        evidence = list(getattr(state, "evidence", []) or [])[-12:]
        if evidence:
            lines.append("Evidence references:")
            for item in evidence:
                evidence_id = str(getattr(item, "id", "") or "")
                if evidence_id:
                    evidence_ids.append(evidence_id)
                lines.append(
                    f"- {evidence_id} {getattr(item, 'tool', '')} status={getattr(item, 'status', 0)}: "
                    f"{_redact(_one_line(getattr(item, 'summary', ''), 220))}"
                )

        hints = list(getattr(state, "correction_hints", []) or [])[-6:]
        if hints:
            lines.append("Open hypotheses or safeguards:")
            lines.extend(f"- {_redact(_one_line(hint, 260))}" for hint in hints)

    historical = _message_history_digest(removed_groups)
    if historical:
        lines.append("Compressed conversational observations (unverified unless cited above):")
        lines.extend(historical)

    vault = _vault_for(agent)
    if vault is not None and vault.blocks:
        active = [block for block in vault.blocks if not block.restored]
        if active:
            lines.append("Vault archive index (search with vault_search):")
            for block in active[-8:]:
                lines.append(
                    f"- V{block.block_id:04d} tier{block.tier} "
                    f"{block.start_ref}–{block.end_ref} {len(block.summary or ''):,}c "
                    f"{_content_text({'content': block.topic})[:120]}"
                )

    rendered = _clip("\n".join(line for line in lines if line.strip()), max(800, max_tokens * 4))
    return rendered, list(dict.fromkeys(evidence_ids))[-32:]


def _compact_outbound_messages(
    messages: list[dict[str, Any]],
    *,
    digest_message: dict[str, Any],
    target_tokens: int,
    min_recent_groups: int,
) -> tuple[list[dict[str, Any]], list[list[dict[str, Any]]], list[list[dict[str, Any]]]]:
    groups = group_messages(messages)
    system_groups, body_groups = _leading_system_groups(groups)
    body_groups = [
        group
        for group in body_groups
        if not (
            len(group) == 1
            and isinstance(group[0], dict)
            and (_is_digest_message(group[0]) or _is_vault_pointer(group[0]))
        )
    ]
    base = flatten_message_groups(system_groups) + [digest_message]
    kept, removed = _select_recent_groups(
        body_groups,
        base_tokens=estimate_tokens(base),
        target_tokens=target_tokens,
        min_recent_groups=min_recent_groups,
    )
    return [*base, *flatten_message_groups(kept)], kept, removed


def _clip_to_budget(messages: list[dict[str, Any]], target_tokens: int) -> list[dict[str, Any]]:
    """Last-resort content clipping when one retained group exceeds the budget."""
    result = copy.deepcopy(messages)
    attempts = 0
    while estimate_tokens(result) > target_tokens and attempts < 8:
        candidates = [
            (index, message)
            for index, message in enumerate(result)
            if isinstance(message, dict) and isinstance(message.get("content"), str) and message["content"]
        ]
        if not candidates:
            break
        index, message = max(candidates, key=lambda item: len(item[1]["content"]))
        current = str(message["content"])
        excess_chars = max(64, (estimate_tokens(result) - target_tokens) * 4)
        next_limit = max(240, len(current) - excess_chars)
        if next_limit >= len(current):
            break
        result[index]["content"] = _clip(current, next_limit)
        attempts += 1
    return result


def _commit_history_compaction(
    agent: Any,
    digest_message: dict[str, Any],
    recent_groups: int,
) -> None:
    context = getattr(agent, "context", None)
    if context is None or not hasattr(context, "get_messages"):
        return
    history = context.get_messages()
    groups = [
        group
        for group in group_messages(history)
        if not (len(group) == 1 and isinstance(group[0], dict) and _is_digest_message(group[0]))
    ]
    recent = flatten_message_groups(groups[-max(1, recent_groups) :])
    replace = getattr(context, "replace_history_with_digest", None)
    if callable(replace):
        replace(digest_message, recent)


def prepare_context(
    agent: Any,
    messages: list[dict[str, Any]],
    tools: list[dict] | None = None,
    *,
    purpose: str = "agent",
) -> ContextCompactionResult:
    """Return a request that fits the configured model context budget.

    This is the only request-time context shaping entry point. Callers pass the
    exact messages and tools they intend to send, including transient prompts.
    """
    budget = build_context_budget(agent, messages, tools)
    if budget is None:
        return ContextCompactionResult(
            messages=list(messages),
            compacted=False,
            before_tokens=estimate_tokens(messages),
            after_tokens=estimate_tokens(messages),
            tool_tokens=estimate_tool_tokens(tools),
        )

    session = _session_config(agent)
    enabled = _bool(
        _setting(session, "context_auto_compact", "solve_auto_compact", True), True
    )
    before = budget.total_input_tokens
    should_compact = enabled and before > budget.trigger_tokens
    force_truncate = before > budget.usable_input_tokens
    if not should_compact and not force_truncate:
        return ContextCompactionResult(
            messages=list(messages),
            compacted=False,
            before_tokens=before,
            after_tokens=before,
            tool_tokens=budget.tool_tokens,
        )

    state = _state_for(agent)
    preliminary_digest = {"role": "system", "content": _DIGEST_PREFIX}
    _, _, preliminary_removed = _compact_outbound_messages(
        messages,
        digest_message=preliminary_digest,
        target_tokens=budget.target_tokens,
        min_recent_groups=int(_number(getattr(session, "context_recent_message_groups", 12), 12, minimum=1)),
    )
    summary_limit = int(_number(getattr(session, "context_summary_max_tokens", 3500), 3500, minimum=200))
    digest, evidence_ids = _build_digest(agent, preliminary_removed, summary_limit)
    digest_message = {"role": "system", "content": digest}
    recent_groups = int(_number(getattr(session, "context_recent_message_groups", 12), 12, minimum=1))

    # Vault-aware shaping: keep vault pointer/distill messages alongside the
    # deterministic digest so archived ranges stay addressable after compaction.
    vault = _vault_for(agent)
    if vault is not None:
        assign_refs(messages, vault.registry)
    vault_pins: list[dict[str, Any]] = []
    if vault is not None:
        for message in messages:
            if isinstance(message, dict) and _is_vault_pointer(message):
                vault_pins.append(message)

    if should_compact:
        compacted_messages, kept_groups, removed_groups = _compact_outbound_messages(
            messages,
            digest_message=digest_message,
            target_tokens=budget.target_tokens,
            min_recent_groups=recent_groups,
        )
        # Re-pin vault markers that live outside the retained recent groups.
        if vault_pins:
            existing = {str(m.get("content", "")) for m in compacted_messages}
            missing = [pin for pin in vault_pins if str(pin.get("content", "")) not in existing]
            if missing:
                compacted_messages = [*compacted_messages, *missing]
        reason = "threshold"
    else:
        compacted_messages = truncate_message_groups(
            messages,
            max(1, budget.usable_input_tokens - budget.tool_tokens),
            preserve_system=True,
            min_recent_groups=recent_groups,
            notice="[context truncated: automatic compaction disabled]",
        )
        kept_groups = group_messages(compacted_messages)
        removed_groups = preliminary_removed
        reason = "hard_limit"

    message_target = max(1, budget.usable_input_tokens - budget.tool_tokens)
    compacted_messages = _clip_to_budget(compacted_messages, message_target)
    after = estimate_tokens(compacted_messages) + budget.tool_tokens

    if should_compact:
        _commit_history_compaction(agent, digest_message, recent_groups)
        if state is not None:
            update = getattr(state, "update_context_digest", None)
            if callable(update):
                update(digest, evidence_ids)
        if vault is not None:
            vault.persist()

    if state is not None and _bool(getattr(session, "context_compaction_audit_enabled", True), True):
        record = getattr(state, "record_context_compaction", None)
        if callable(record):
            record(
                purpose=purpose,
                reason=reason,
                before_tokens=before,
                after_tokens=after,
                tool_tokens=budget.tool_tokens,
                removed_message_groups=len(removed_groups),
                retained_message_groups=len(kept_groups),
                evidence_ids=evidence_ids,
            )

    return ContextCompactionResult(
        messages=compacted_messages,
        compacted=should_compact,
        before_tokens=before,
        after_tokens=after,
        tool_tokens=budget.tool_tokens,
        removed_message_groups=len(removed_groups),
        retained_message_groups=len(kept_groups),
        reason=reason,
    )
