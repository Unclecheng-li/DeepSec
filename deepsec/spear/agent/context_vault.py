"""Selective conversation archiving for long spear sessions.

The deterministic compactor (:mod:`deepsec.spear.agent.context_budget`)
truncates *recent* history into a fixed structured digest.  This module adds a
second, complementary layer: a *selective* archive that lets the model ask for
older ranges to be replaced by a compact summary, while the full original text
is persisted to disk so it can be restored or searched later without ever
re-entering the model window.

Design goals:

* No LLM call is made inside the archive path — the summary is rendered from
  the same structured state the deterministic digest uses, so archiving never
  grows the request or triggers recursive LLM calls.
* Every archived message carries an invisible vault marker
  (``<v#NNNNN>`` / ``[V]``) so later turns can reference ranges by id without
  the marker ever being part of the model-visible text.
* Three retention tiers mirror how stale a range is:
    - Tier 1 ``archive``: original messages are preserved verbatim on disk
      (and in the hot ring), replaced in-context by a short pointer.
    - Tier 2 ``distill``: a mid-size structured summary replaces the range.
    - Tier 3 ``digest``: the range folds into the global deterministic digest.
* A protected zone (recent messages + the final user message + a token budget)
  can never be archived without an explicit ``force=True`` acknowledgement.
* Phantom-range protection: ranges that contain no *new* messages (everything
  already lives under an active archive block) are rejected — archiving them
  would only burn tokens on a summary nobody needs.

The Vault is deliberately *opt-in*: nothing is archived unless the model
explicitly calls ``vault_archive``.  Automatic overflow protection remains the
deterministic compactor's job.
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Marker format ────────────────────────────────────────────────────────────
# Invisible id reference: "<v#00042>" — never part of rendered content, but the
# model can cite it back ("vault_archive start=<v#00042>"). ASCII-safe so it
# round-trips through any console, terminal, or serialization layer.
_REF_RE = re.compile(r"<v#(\d{5,8})>")
_REF_TEMPLATE = "<v#{id:05d}>"
_BLOCK_MARKER = "[V]"
_BLOCK_RE = re.compile(r"\[V\]\s*(\d+)\s*[-–]\s*(\d+)")
_DIGEST_PREFIX = "[context digest v2 vault]"

# Persistent archive file name inside the run output directory.
_VAULT_FILENAME = "context_vault.jsonl"

# Conservative floor so tiny ranges never create a pointless archive entry.
_MIN_ARCHIVE_MESSAGES = 3
_MIN_ARCHIVE_CHARS = 200


@dataclass
class VaultConfig:
    """Tunables for the vault (code-level; not exposed in user config)."""

    preserve_recent_messages: int = 6      # last N messages never auto-archived
    preserve_recent_tokens: int = 1500     # approximate token floor for the tail
    min_archive_messages: int = _MIN_ARCHIVE_MESSAGES
    min_archive_chars: int = _MIN_ARCHIVE_CHARS
    summary_max_chars: int = 1600          # tier-2 distilled summary cap
    pointer_max_chars: int = 320           # tier-1 pointer cap
    hard_protected_tools: frozenset[str] = frozenset(
        {"vault_archive", "vault_restore", "vault_search", "vault_status"}
    )


@dataclass
class VaultBlock:
    """One archived range (mirrors the persisted JSONL record)."""

    block_id: int
    tier: int                      # 1 archive, 2 distill, 3 digest
    start_ref: str                 # "<v#00001>"
    end_ref: str
    start_index: int               # index into the message list at archive time
    end_index: int
    topic: str = ""
    summary: str = ""
    message_count: int = 0
    chars_saved: int = 0
    archived_at: float = field(default_factory=time.time)
    restored: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "block_id": self.block_id,
            "tier": self.tier,
            "start_ref": self.start_ref,
            "end_ref": self.end_ref,
            "start_index": self.start_index,
            "end_index": self.end_index,
            "topic": self.topic,
            "summary": self.summary,
            "message_count": self.message_count,
            "chars_saved": self.chars_saved,
            "archived_at": self.archived_at,
            "restored": self.restored,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VaultBlock":
        return cls(**{k: data.get(k) for k in cls.__dataclass_fields__})


def _estimate_chars(value: Any) -> int:
    if isinstance(value, str):
        return len(value)
    if isinstance(value, list):
        return sum(_estimate_chars(item) for item in value)
    if isinstance(value, dict):
        return sum(_estimate_chars(k) + _estimate_chars(v) for k, v in value.items())
    return len(str(value or ""))


def _content_text(message: dict[str, Any]) -> str:
    """Flatten a message's content to plain text for counting/rendering."""
    content = message.get("content", "")
    if isinstance(content, str):
        return content
    parts: list[str] = []
    if isinstance(content, list):
        for part in content:
            if isinstance(part, dict):
                text = part.get("text")
                if text:
                    parts.append(str(text))
            elif part:
                parts.append(str(part))
    return "\n".join(parts)


def _message_label(message: dict[str, Any], index: int) -> str:
    """Short one-line description of a message for pointers/summaries."""
    role = str(message.get("role", "message"))
    content = _content_text(message).strip()
    if message.get("tool_calls"):
        names = [tc.get("function", {}).get("name", "?") for tc in message["tool_calls"]]
        return f"assistant calls {', '.join(names)}"
    if role == "tool":
        tool = str(message.get("name", message.get("tool_name", "tool")))
        snippet = content[:140].replace("\n", " ")
        return f"tool {tool}: {snippet}"
    if content:
        return f"{role}: {content[:160].replace(chr(10), ' ')}"
    return f"{role} message"


def assign_refs(messages: list[dict[str, Any]], registry: dict[str, int]) -> list[dict[str, Any]]:
    """Stable-id every message with an invisible vault reference.

    Existing ids are reused (id → highest seen counter), new messages get the
    next id.  The ref is stored under ``message["_vault_ref"]`` and is *not*
    part of the serialized content; rendering is the caller's choice.
    """
    if not isinstance(registry, dict):
        registry = {}
    next_id = int(registry.get("_next", 0)) + 1
    for message in messages:
        if not isinstance(message, dict):
            continue
        existing = message.get("_vault_ref")
        if existing and _REF_RE.match(existing):
            continue
        message["_vault_ref"] = _REF_TEMPLATE.format(id=next_id)
        next_id += 1
    registry["_next"] = next_id - 1
    return messages


def ref_id(ref: str) -> int:
    """Parse a vault ref back into its numeric id (0 when malformed)."""
    match = _REF_RE.fullmatch(str(ref or "").strip())
    return int(match.group(1)) if match else 0


def _ref_for(message: dict[str, Any]) -> str:
    return str(message.get("_vault_ref") or "")


def _range_of(messages: list[dict[str, Any]], start: str, end: str) -> list[dict[str, Any]]:
    """Return the message slice between two refs (inclusive, stable order)."""
    ids = [ref_id(_ref_for(m)) for m in messages if isinstance(m, dict)]
    start_id = ref_id(start)
    end_id = ref_id(end)
    if start_id <= 0 or end_id <= 0:
        return []
    lo = min(start_id, end_id)
    hi = max(start_id, end_id)
    selected = [m for m in messages if isinstance(m, dict) and lo <= ref_id(_ref_for(m)) <= hi]
    return selected


def _has_unarchived_message(
    messages: list[dict[str, Any]],
    blocks: list[VaultBlock],
    lo: int | None = None,
    hi: int | None = None,
) -> bool:
    """True when at least one message in [lo, hi] is not covered by a block.

    With ``lo``/``hi`` omitted the whole list is scanned.  This is the
    phantom-range guard: archiving a span whose messages are all already
    covered by active blocks would only add pointer overhead with no token
    savings, so it must be rejected unless ``force`` is given.
    """
    covered: set[int] = set()
    for block in blocks:
        if block.restored:
            continue
        covered.update(range(block.start_index, block.end_index + 1))
    if lo is None:
        lo = 0
    if hi is None:
        hi = len(messages) - 1
    for index in range(lo, min(hi, len(messages) - 1) + 1):
        message = messages[index]
        if not isinstance(message, dict):
            continue
        if index in covered:
            continue
        if message.get("role") in {"system", "tool"} and not _content_text(message):
            continue
        return True
    return False


def _protected_range(
    messages: list[dict[str, Any]],
    *,
    preserve_recent_messages: int,
    preserve_recent_tokens: int,
) -> tuple[int, int]:
    """Return (start, end) indexes of the protected tail (inclusive).

    The protected zone covers the last ``preserve_recent_messages`` messages,
    the final user message, and at least ``preserve_recent_tokens`` worth of
    tail characters — whichever is largest.
    """
    size = len(messages)
    if size == 0:
        return 0, -1
    tail = max(1, preserve_recent_messages)
    start = max(0, size - tail)
    # Token floor: walk backwards until the tail is heavy enough.
    chars = 0
    cursor = size - 1
    while cursor >= 0 and chars < preserve_recent_tokens * 4:
        chars += _estimate_chars(messages[cursor])
        cursor -= 1
    token_start = max(0, cursor + 1)
    # The last user message is always in the protected zone
    # (it is the model's active instruction); older user turns are archivable.
    user_start = size - 1
    for index in range(size - 1, -1, -1):
        message = messages[index]
        if isinstance(message, dict) and message.get("role") == "user":
            user_start = index
            break
    return min(start, token_start, user_start), size - 1


class VaultManager:
    """Session-scoped vault: id registry, blocks, and on-disk archive.

    The manager is attached to :class:`~deepsec.spear.agent.context.ContextManager`
    as ``context.vault`` so every caller (compactor, tool dispatcher, status
    renderer) shares one registry per session.
    """

    def __init__(self, output_dir: Path | None = None, config: VaultConfig | None = None) -> None:
        self.config = config or VaultConfig()
        self.registry: dict[str, int] = {"_next": 0}
        self.blocks: list[VaultBlock] = []
        self._lock = threading.RLock()
        self._output_dir: Path | None = None
        if output_dir is not None:
            self.set_output_dir(output_dir)

    # ── persistence ────────────────────────────────────────────────────────
    def set_output_dir(self, output_dir: Path | None) -> None:
        self._output_dir = Path(output_dir) if output_dir else None

    def _archive_path(self) -> Path | None:
        if self._output_dir is None:
            return None
        return self._output_dir / _VAULT_FILENAME

    def persist(self) -> None:
        """Append a compact state snapshot to the vault JSONL shard."""
        path = self._archive_path()
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(
                        json.dumps(
                            {
                                "type": "snapshot",
                                "ts": time.time(),
                                "next": self.registry.get("_next", 0),
                                "blocks": [block.to_dict() for block in self.blocks],
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )
        except OSError:
            # Persistence is best-effort; never fail a request because of it.
            pass

    def load_shard(self, path: Path | None = None) -> int:
        """Rehydrate registry/block state from a previous vault shard.

        Returns the number of blocks restored (0 when the shard is absent).
        """
        target = path or self._archive_path()
        if target is None or not Path(target).exists():
            return 0
        try:
            with Path(target).open(encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if record.get("type") != "snapshot":
                        continue
                    self.registry["_next"] = int(record.get("next", 0))
                    restored = [
                        VaultBlock.from_dict(item)
                        for item in record.get("blocks", [])
                        if isinstance(item, dict)
                    ]
                    self.blocks = restored
                    return len(restored)
        except OSError:
            return 0
        return 0

    # ── range helpers ──────────────────────────────────────────────────────
    def next_block_id(self) -> int:
        with self._lock:
            return max([block.block_id for block in self.blocks] or [0]) + 1

    def active_block_for(self, ref: str) -> VaultBlock | None:
        rid = ref_id(ref)
        for block in self.blocks:
            if block.restored:
                continue
            if ref_id(block.start_ref) <= rid <= ref_id(block.end_ref):
                return block
        return None

    def stats(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        active = [block for block in self.blocks if not block.restored]
        return {
            "next_ref": self.registry.get("_next", 0),
            "active_blocks": len(active),
            "restored_blocks": sum(1 for block in self.blocks if block.restored),
            "archived_messages": sum(block.message_count for block in active),
            "chars_saved": sum(block.chars_saved for block in active),
        }

    # ── archiving ──────────────────────────────────────────────────────────
    def archive_range(
        self,
        messages: list[dict[str, Any]],
        *,
        start: str,
        end: str,
        tier: int,
        topic: str = "",
        summary: str = "",
        force: bool = False,
    ) -> tuple[bool, str, VaultBlock | None]:
        """Replace [start, end] with an archived block.

        Returns ``(ok, message, block)``.  When ``ok`` is False the ``message``
        explains why (protected zone, phantom range, malformed refs, …).
        """
        assign_refs(messages, self.registry)
        selected = _range_of(messages, start, end)
        if not selected:
            return False, "range matches no messages", None
        if len(selected) < self.config.min_archive_messages:
            return (
                False,
                f"range covers {len(selected)} message(s); minimum is {self.config.min_archive_messages}",
                None,
            )
        chars = sum(_estimate_chars(m) for m in selected)
        if chars < self.config.min_archive_chars:
            return False, f"range only saves ~{chars} chars; below the {self.config.min_archive_chars} floor", None

        indexes = [
            i
            for i, m in enumerate(messages)
            if isinstance(m, dict) and ref_id(_ref_for(m)) in {
                ref_id(_ref_for(s)) for s in selected
            }
        ]
        lo, hi = min(indexes), max(indexes)
        if not force:
            protected_start, protected_end = _protected_range(
                messages,
                preserve_recent_messages=self.config.preserve_recent_messages,
                preserve_recent_tokens=self.config.preserve_recent_tokens,
            )
            if lo <= protected_end and hi >= protected_start:
                return (
                    False,
                    "range overlaps the protected recent tail; pass force=true to override",
                    None,
                )
        if not force and not _has_unarchived_message(messages, self.blocks, lo, hi):
            return (
                False,
                "range contains no new messages (everything is already archived); "
                "pass force=true to re-archive",
                None,
            )

        tier = min(3, max(1, int(tier)))
        block = VaultBlock(
            block_id=self.next_block_id(),
            tier=tier,
            start_ref=_ref_for(selected[0]),
            end_ref=_ref_for(selected[-1]),
            start_index=lo,
            end_index=hi,
            topic=topic or "untitled",
            summary=summary,
            message_count=len(selected),
            chars_saved=chars,
        )
        with self._lock:
            self.blocks.append(block)
            self.persist()
        return True, f"archived {len(selected)} messages as block V{block.block_id:04d}", block

    # ── rendering ──────────────────────────────────────────────────────────
    def render_pointer(self, block: VaultBlock) -> dict[str, Any]:
        """Tier-1 pointer message replacing an archived range in context."""
        topic = block.topic or "archived range"
        body = (
            f"[V] block V{block.block_id:04d} - {block.start_ref}-{block.end_ref} - "
            f"{block.message_count} messages - tier {block.tier} ({topic})\n"
            f"Use vault_search to look inside, or vault_restore to bring it back."
        )
        return {"role": "system", "content": body}

    def render_distill(self, block: VaultBlock, summary: str = "") -> dict[str, Any]:
        """Tier-2 distilled summary message."""
        text = summary or block.summary or "(no summary provided)"
        body = (
            f"[V] distilled V{block.block_id:04d} - {block.start_ref}-{block.end_ref} - "
            f"{block.message_count} messages - tier {block.tier}\n{text}"
        )
        return {"role": "system", "content": body}

    def restore_range(
        self,
        messages: list[dict[str, Any]],
        *,
        start: str,
        end: str,
    ) -> tuple[bool, str, list[dict[str, Any]]]:
        """Mark a block as restored so its messages become archivable again.

        The original text lives on disk / in the hot ring, so restoring is a
        bookkeeping operation, not a re-read.
        """
        selected = _range_of(messages, start, end)
        if not selected:
            return False, "range matches no archived messages", []
        changed = 0
        start_rid = ref_id(_ref_for(selected[0]))
        end_rid = ref_id(_ref_for(selected[-1]))
        for block in self.blocks:
            if block.restored:
                continue
            if start_rid <= ref_id(block.start_ref) and ref_id(block.end_ref) <= end_rid:
                block.restored = True
                changed += 1
        if changed:
            self.persist()
        return True, f"restored {changed} block(s)", selected

    def search(
        self,
        query: str,
        *,
        limit: int = 8,
        max_chars: int = 6000,
    ) -> list[dict[str, Any]]:
        """Substring search across active block summaries/topics.

        Returns bounded hit records (block id, tier, refs, matched snippet).
        """
        query_lower = str(query or "").lower().strip()
        if not query_lower:
            return []
        hits: list[dict[str, Any]] = []
        for block in self.blocks:
            if block.restored:
                continue
            haystack = f"{block.topic}\n{block.summary}".lower()
            if query_lower not in haystack:
                continue
            idx = haystack.find(query_lower)
            snippet = (block.topic + "\n" + block.summary)[max(0, idx - 120) : idx + 240]
            hits.append(
                {
                    "block": f"V{block.block_id:04d}",
                    "tier": block.tier,
                    "refs": f"{block.start_ref}-{block.end_ref}",
                    "messages": block.message_count,
                    "topic": block.topic,
                    "snippet": snippet,
                }
            )
            if len(hits) >= limit:
                break
        return hits
