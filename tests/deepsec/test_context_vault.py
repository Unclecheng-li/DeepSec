"""Tests for the ported Context Vault (selective archiving) in DeepSec.

Covers the five design goals ported from the VulnClaw implementation:
ref tagging, tiered distillation, the protected tail, restore/search, and the
phantom-range guard — plus the deterministic budget integration.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from deepsec.spear.agent.context_vault import (
    VaultBlock,
    VaultConfig,
    VaultManager,
    _REF_RE,
    _content_text,
    _estimate_chars,
    _has_unarchived_message,
    _protected_range,
    assign_refs,
    ref_id,
)


def _history(count: int = 160) -> list[dict]:
    """A realistic conversation: system prompt + user/assistant tool rounds."""
    messages = [{"role": "system", "content": "You are the spear agent."}]
    for index in range(count):
        messages.append({"role": "user", "content": f"instruction {index} " + "x" * 60})
        messages.append(
            {
                "role": "assistant",
                "content": f"reply {index}",
                "tool_calls": [
                    {
                        "id": f"call_{index}",
                        "type": "function",
                        "function": {"name": "shell_command", "arguments": '{"cmd":"echo hi"}'},
                    }
                ],
            }
        )
        messages.append({"role": "tool", "tool_call_id": f"call_{index}", "content": f"output {index} " + "y" * 40})
    return messages


def _vault(tmp_path: Path) -> VaultManager:
    return VaultManager(output_dir=tmp_path)


# ── ref tagging ──────────────────────────────────────────────────────────────


def test_assign_refs_is_stable_and_incremental():
    registry: dict[str, int] = {}
    first = _history(3)
    assign_refs(first, registry)
    ids = [ref_id(m.get("_vault_ref", "")) for m in first]
    assert ids == list(range(1, len(first) + 1))
    # Re-running must not renumber existing messages.
    assign_refs(first, registry)
    assert [ref_id(m.get("_vault_ref", "")) for m in first] == ids
    # New messages continue after the highest id.
    second = [{"role": "user", "content": "next"}]
    assign_refs(second, registry)
    assert ref_id(second[0]["_vault_ref"]) == len(first) + 1


def test_ref_format_is_ascii_and_parseable():
    registry: dict[str, int] = {}
    messages = [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}]
    assign_refs(messages, registry)
    assert all(_REF_RE.fullmatch(m["_vault_ref"]) for m in messages)
    assert messages[0]["_vault_ref"] == "<v#00001>"


# ── protected tail ───────────────────────────────────────────────────────────


def test_protected_range_covers_recent_tail_and_last_user():
    messages = _history(40)
    start, end = _protected_range(
        messages,
        preserve_recent_messages=6,
        preserve_recent_tokens=1500,
    )
    assert end == len(messages) - 1
    assert start <= len(messages) - 6  # at least the last 6 messages
    # The very last message is a tool message; walk back to the user.
    assert messages[-1]["role"] == "tool"
    assert start > 0  # a 40-round history is not fully protected


def test_protected_range_never_archives_the_last_user_message():
    messages = _history(20)
    start, end = _protected_range(
        messages,
        preserve_recent_messages=2,
        preserve_recent_tokens=100,
    )
    protected = messages[start : end + 1]
    roles = [m["role"] for m in protected]
    assert "user" in roles


# ── phantom guard ────────────────────────────────────────────────────────────


def test_phantom_guard_rejects_ranges_without_new_messages():
    messages = _history(120)
    vault = _vault(Path("."))
    # Archive a mid-history range (tier 1), leaving a real block.
    ok, _, block = vault.archive_range(
        messages, start="<v#00010>", end="<v#00030>", tier=1, force=True
    )
    assert ok
    assert block is not None
    # Re-archiving the same range without force must fail as a phantom range.
    ok2, message2, _ = vault.archive_range(
        messages, start="<v#00010>", end="<v#00030>", tier=1
    )
    assert not ok2
    assert "no new messages" in message2
    # force=True still allows it (model explicitly asked).
    ok3, _, _ = vault.archive_range(
        messages, start="<v#00010>", end="<v#00030>", tier=1, force=True
    )
    assert ok3


def test_has_unarchived_message_is_range_scoped():
    messages = _history(10)
    blocks: list[VaultBlock] = [
        VaultBlock(
            block_id=1,
            tier=1,
            start_ref="<v#00002>",
            end_ref="<v#00005>",
            start_index=1,
            end_index=4,
        )
    ]
    assert not _has_unarchived_message(messages, blocks, 1, 4)
    assert _has_unarchived_message(messages, blocks, 5, 8)


# ── archive / restore / search ───────────────────────────────────────────────


def test_archive_range_rejects_protected_tail_without_force(tmp_path: Path):
    vault = _vault(tmp_path)
    messages = _history(30)
    ok, message, _ = vault.archive_range(
        messages, start="<v#00002>", end="<v#00100>", tier=2
    )
    assert not ok
    assert "protected" in message
    ok2, _, block = vault.archive_range(
        messages, start="<v#00002>", end="<v#00100>", tier=2, force=True
    )
    assert ok2
    assert block is not None and block.tier == 2


def test_archive_range_minimum_floor(tmp_path: Path):
    vault = _vault(tmp_path)
    messages = [{"role": "system", "content": "sys"}] + [
        {"role": "user", "content": f"tiny {i}"} for i in range(4)
    ]
    assign_refs(messages, vault.registry)
    ok, message, _ = vault.archive_range(
        messages, start="<v#00002>", end="<v#00003>", tier=1, force=True
    )
    # 2 messages < min_archive_messages=3 → rejected.
    assert not ok
    assert "minimum" in message


def test_archive_render_pointer_and_distill(tmp_path: Path):
    vault = _vault(tmp_path)
    messages = _history(20)
    ok, _, block = vault.archive_range(
        messages,
        start="<v#00002>",
        end="<v#00030>",
        tier=1,
        topic="early recon",
        force=True,
    )
    assert ok
    assert block is not None
    pointer = vault.render_pointer(block)
    assert pointer["role"] == "system"
    assert "[V]" in pointer["content"]
    assert "vault_search" in pointer["content"]

    distill = vault.render_distill(block, summary="Scanned subdomains, no hits.")
    assert "Scanned subdomains" in distill["content"]
    assert "tier" in distill["content"]


def test_restore_range_marks_blocks_restored(tmp_path: Path):
    vault = _vault(tmp_path)
    messages = _history(30)
    vault.archive_range(messages, start="<v#00002>", end="<v#00040>", tier=2, force=True)
    assert vault.stats(messages)["active_blocks"] == 1
    ok, message, _ = vault.restore_range(messages, start="<v#00002>", end="<v#00040>")
    assert ok
    assert "restored 1 block" in message
    assert vault.stats(messages)["active_blocks"] == 0
    assert vault.stats(messages)["restored_blocks"] == 1


def test_search_finds_block_by_topic_and_summary(tmp_path: Path):
    vault = _vault(tmp_path)
    messages = _history(30)
    vault.archive_range(
        messages,
        start="<v#00002>",
        end="<v#00040>",
        tier=2,
        topic="waf fingerprinting",
        summary="Detected ModSecurity; WAF rule bypass needs encoded payloads.",
        force=True,
    )
    hits = vault.search("ModSecurity")
    assert len(hits) == 1
    assert hits[0]["block"] == "V0001"
    assert "waf fingerprinting" in hits[0]["topic"]
    # Unrelated query → no hits.
    assert vault.search("unrelated-thing") == []


def test_persist_and_load_shard_roundtrip(tmp_path: Path):
    vault = _vault(tmp_path)
    messages = _history(20)
    vault.archive_range(
        messages, start="<v#00002>", end="<v#00025>", tier=2, topic="recon", force=True
    )
    vault.persist()
    fresh = _vault(tmp_path)
    restored = fresh.load_shard()
    assert restored == 1
    assert fresh.blocks[0].topic == "recon"
    assert fresh.registry["_next"] >= 25


# ── budget integration ───────────────────────────────────────────────────────


def _fake_agent(tmp_path: Path):
    """Minimal agent surface: config.session + context.state + context.vault."""
    from deepsec.config.schema import SessionConfig
    from deepsec.spear.agent.context import ContextManager

    class FakeConfig:
        session = SessionConfig(output_dir=tmp_path)
        llm = type(
            "LLM",
            (),
            {"max_context_tokens": 8000, "max_tokens": 2048},
        )()

    class FakeAgent:
        config = FakeConfig()
        context = ContextManager(vault_output_dir=tmp_path)

    return FakeAgent()


def test_prepare_context_returns_unchanged_when_under_budget(tmp_path: Path):
    from deepsec.spear.agent.context_budget import prepare_context

    agent = _fake_agent(tmp_path)
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}]
    result = prepare_context(agent, messages, [])
    assert not result.compacted
    assert result.messages == messages
    assert result.before_tokens == result.after_tokens


def test_prepare_context_compacts_oversized_history(tmp_path: Path):
    from deepsec.spear.agent.context_budget import prepare_context

    agent = _fake_agent(tmp_path)
    messages = _history(120)  # far above the 8000-token window with reserve
    result = prepare_context(agent, messages, [])
    # With the default trigger (0.70 * usable) the history must be compacted.
    assert result.compacted
    assert result.after_tokens < result.before_tokens
    assert any(
        str(m.get("content", "")).startswith("[context digest") for m in result.messages
    )
    # The digest keeps durable evidence: the goal is echoed into the digest.
    assert agent.context.state.agent_state is not None
    # Compaction is committed back to the context history.
    assert any(
        str(m.get("content", "")).startswith("[context digest")
        for m in agent.context.get_messages()
    )


def test_prepare_context_disabled_compaction_truncates_with_notice(tmp_path: Path):
    from deepsec.spear.agent.context_budget import prepare_context

    agent = _fake_agent(tmp_path)
    agent.config.session.context_auto_compact = False
    messages = _history(120)
    result = prepare_context(agent, messages, [])
    assert result.compacted is False  # disabled → hard-limit truncation only
    assert result.reason == "hard_limit"
    assert result.after_tokens < result.before_tokens


def test_build_context_budget_respects_legacy_solve_knobs(tmp_path: Path):
    from deepsec.spear.agent.context_budget import build_context_budget

    agent = _fake_agent(tmp_path)
    # Explicitly unset the new field to exercise the legacy alias path.
    del agent.config.session.context_auto_compact
    del agent.config.session.context_compact_trigger_ratio
    agent.config.session.solve_auto_compact = True
    agent.config.session.solve_compact_trigger_ratio = 0.8
    budget = build_context_budget(agent, [{"role": "user", "content": "x"}], [])
    assert budget is not None
    assert budget.trigger_tokens == int(
        budget.usable_input_tokens * 0.8
    )


def test_vault_survives_prepare_context_compaction(tmp_path: Path):
    from deepsec.spear.agent.context_budget import prepare_context

    agent = _fake_agent(tmp_path)
    messages = _history(60)
    # Archive an early range so the vault has an active block.
    assign_refs(messages, agent.context.vault.registry)
    ok, _, _ = agent.context.vault.archive_range(
        messages, start="<v#00002>", end="<v#00030>", tier=2, topic="early recon", force=True
    )
    assert ok
    result = prepare_context(agent, messages, [])
    assert result.compacted
    # Vault block survives and remains searchable.
    assert agent.context.vault.stats(messages)["active_blocks"] >= 1
    assert agent.context.vault.search("early recon")
