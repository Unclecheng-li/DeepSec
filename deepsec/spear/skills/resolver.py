"""Deterministic skill resolver.

Selects a small, task-fit skill *bundle* (one primary + up to two support,
references left on-demand) before prompt assembly, driven by typed routing
metadata first and keyword aliases second. Every decision is a pure function
of the :class:`SkillQuery`, so selection is testable and auditable — no LLM in
the loop.

Design contract:
- Explicit invocation (``/ctf-web`` or ``Use VulnClaw skill ctf-web``) always
  wins.
- Otherwise profiles are scored by metadata signals first, aliases second.
- ``pentest-flow`` is a fallback only for pentest-like input; unrelated,
  non-security text selects nothing.
- A broad knowledge base never eclipses a precise skill on a tie.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any, Optional

from pydantic import BaseModel, Field

from deepsec.spear.skills.loader import (
    list_core_skills,
    list_custom_skills,
    list_specialized_skills,
    load_skill_by_name,
)
from deepsec.spear.skills.routing import SkillRouting, keyword_present, normalize_token

# ── Scoring weights ─────────────────────────────────────────────────

TYPED_WEIGHT = 3.0
ALIAS_META_WEIGHT = 1.0
DIRECTORY_BOOST = 1.5
# A support skill must clear this fraction of the primary's score to ride along.
SUPPORT_RATIO = 0.35
SUPPORT_CAP = 2

_FALLBACK_SKILL = "pentest-flow"

# Signals that mark input as a pentest-like task worth the fallback skill.
_PENTEST_SIGNALS = (
    "pentest",
    "渗透",
    "测试",
    "扫描",
    "漏洞",
    "target",
    "目标",
    "recon",
    "侦察",
    "exploit",
    "攻击",
    "http://",
    "https://",
    "scan",
    "vulnerab",
    "security",
    "安全",
)

_EXPLICIT_USE_RE = re.compile(
    r"\buse\s+vulnclaw\s+skill\s+([A-Za-z0-9][A-Za-z0-9_-]*)\b",
    re.IGNORECASE,
)
_SLASH_RE = re.compile(r"(?:^|\s)/([A-Za-z0-9][A-Za-z0-9_-]*)")


# ── Typed objects ───────────────────────────────────────────────────


class SkillProfile(BaseModel):
    """Normalized catalog entry: frontmatter + optional routing metadata."""

    name: str
    description: str = ""
    format: str = "flat"
    is_core: bool = False
    requires_target: bool = True
    routing: SkillRouting = Field(default_factory=SkillRouting)
    references: list[str] = Field(default_factory=list)

    @property
    def specialized(self) -> bool:
        return self.format == "directory"


class SkillQuery(BaseModel):
    """Normalized request context handed to the resolver."""

    text: str = ""
    explicit_skill: Optional[str] = None
    phase: Optional[str] = None
    target_type: Optional[str] = None
    scan_mode: Optional[str] = None
    technologies: list[str] = Field(default_factory=list)
    vuln_hints: list[str] = Field(default_factory=list)
    task_types: list[str] = Field(default_factory=list)
    # Child-agent task summary; folded into the matched text so subtasks get
    # task-fit skills rather than inheriting the root context blindly.
    task_summary: Optional[str] = None

    @classmethod
    def from_input(cls, user_input: Optional[str] = None, **kwargs: Any) -> "SkillQuery":
        text = user_input or ""
        explicit = kwargs.pop("explicit_skill", None)
        if explicit is None:
            m = _EXPLICIT_USE_RE.search(text)
            if m:
                explicit = m.group(1)
        return cls(text=text, explicit_skill=explicit, **kwargs)

    def matched_text(self) -> str:
        return f"{self.text or ''} {self.task_summary or ''}".strip().lower()


class SkillSelection(BaseModel):
    """Resolver output: the chosen bundle plus an audit trail."""

    primary: Optional[str] = None
    supporting: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    reason: str = ""

    def all_skill_ids(self) -> list[str]:
        ids: list[str] = []
        if self.primary:
            ids.append(self.primary)
        ids.extend(self.supporting)
        return ids

    def is_empty(self) -> bool:
        return self.primary is None and not self.supporting

    def to_provenance(
        self, loaded_references: Optional[list[str]] = None
    ) -> dict[str, Any]:
        """Structured provenance for attaching to a finding or run event.

        Records the selected skill ids, which references were *actually* loaded
        (via ``load_skill_reference``, passed in by the caller), the resolver
        reason and confidence — never prose.
        """
        return {
            "primary": self.primary,
            "supporting": list(self.supporting),
            "references_loaded": list(loaded_references or []),
            "reason": self.reason,
            "confidence": self.confidence,
        }


class _ScoreDetail(BaseModel):
    score: float = 0.0
    signals: list[str] = Field(default_factory=list)
    typed_hits: int = 0


# ── Catalog ─────────────────────────────────────────────────────────


def _build_profile(name: str, is_core: bool) -> Optional[SkillProfile]:
    skill = load_skill_by_name(name)
    if not skill:
        return None
    routing = SkillRouting.model_validate(skill.get("routing") or {})
    return SkillProfile(
        name=skill.get("name", name),
        description=skill.get("description", ""),
        format=skill.get("format", "flat"),
        is_core=is_core,
        requires_target=skill.get("requires_target", True),
        routing=routing,
        references=list(skill.get("references", []) or []),
    )


def build_catalog() -> dict[str, SkillProfile]:
    """Load every available skill into a :class:`SkillProfile`.

    Not cached: custom skills (and tests' tmp skills) can change between calls,
    and the corpus is small enough that a fresh scan is cheap.
    """
    catalog: dict[str, SkillProfile] = {}
    for name in list_core_skills():
        profile = _build_profile(name, is_core=True)
        if profile:
            catalog[profile.name] = profile
    for name in list_specialized_skills():
        profile = _build_profile(name, is_core=False)
        if profile:
            catalog[profile.name] = profile
    for name in list_custom_skills():
        if name in catalog:
            continue
        profile = _build_profile(name, is_core=False)
        if profile:
            catalog[profile.name] = profile
    return catalog


class SkillResolver:
    """Resolve a :class:`SkillQuery` into a :class:`SkillSelection`."""

    def __init__(self, catalog: Optional[dict[str, SkillProfile]] = None) -> None:
        self._catalog = catalog if catalog is not None else build_catalog()

    @property
    def catalog(self) -> dict[str, SkillProfile]:
        return self._catalog

    # ── public API ──────────────────────────────────────────────────

    def resolve(self, query: SkillQuery) -> SkillSelection:
        combined = query.matched_text()

        explicit = self._detect_explicit(query, combined)
        if explicit:
            return self._explicit_selection(explicit, query, combined)

        scores: dict[str, _ScoreDetail] = {}
        for name, profile in self._catalog.items():
            if self._excluded(profile, combined):
                continue
            detail = self._score(profile, query, combined)
            if detail.score > 0:
                scores[name] = detail

        if not scores:
            return self._fallback(query, combined)

        primary = self._pick_primary(scores)
        detail = scores[primary]
        supporting = self._pick_supporting(primary, detail.score, scores)

        return SkillSelection(
            primary=primary,
            supporting=supporting,
            references=self._catalog[primary].references,
            signals=detail.signals,
            confidence=self._confidence(detail),
            reason=self._reason(primary, detail, supporting),
        )

    # ── explicit invocation ─────────────────────────────────────────

    def _detect_explicit(self, query: SkillQuery, combined: str) -> Optional[str]:
        if query.explicit_skill and query.explicit_skill in self._catalog:
            return query.explicit_skill
        for match in _SLASH_RE.finditer(query.text or ""):
            candidate = match.group(1).lower()
            if candidate in self._catalog:
                return candidate
        return None

    def _explicit_selection(
        self, name: str, query: SkillQuery, combined: str
    ) -> SkillSelection:
        # Attach only metadata-declared support skills whose signals match.
        supporting: list[str] = []
        for other, profile in self._catalog.items():
            if other == name or profile.routing.role != "support":
                continue
            detail = self._score(profile, query, combined)
            if detail.score > 0:
                supporting.append(other)
            if len(supporting) >= SUPPORT_CAP:
                break
        return SkillSelection(
            primary=name,
            supporting=supporting,
            references=self._catalog[name].references,
            signals=["explicit"],
            confidence=1.0,
            reason=f"explicit invocation → {name}",
        )

    # ── scoring ─────────────────────────────────────────────────────

    def _score(self, profile: SkillProfile, query: SkillQuery, combined: str) -> _ScoreDetail:
        signals: list[str] = []
        typed = 0.0
        typed_hits = 0
        r = profile.routing

        def _typed(value: Optional[str], vocab: set[str], label: str, weight: float) -> None:
            nonlocal typed, typed_hits
            if not value:
                return
            token = normalize_token(value)
            if token in vocab:
                typed += weight
                typed_hits += 1
                signals.append(f"{label}={token}")

        _typed(query.target_type, set(r.target_types), "target", TYPED_WEIGHT)
        _typed(query.phase, set(r.phases), "phase", TYPED_WEIGHT)
        _typed(query.scan_mode, set(r.scan_modes), "scan_mode", TYPED_WEIGHT * 0.5)
        tech_vocab = set(r.technologies) | set(r.frameworks) | set(r.protocols)
        for value in query.technologies:
            _typed(value, tech_vocab, "tech", TYPED_WEIGHT * 0.7)
        for value in query.vuln_hints:
            _typed(value, set(r.vulnerability_classes), "vuln", TYPED_WEIGHT)
        for value in query.task_types:
            _typed(value, set(r.task_types), "task", TYPED_WEIGHT * 0.6)

        # Routing free-text aliases matched as substrings.
        alias = 0.0
        for token in r.aliases:
            if keyword_present(token, combined):
                alias += ALIAS_META_WEIGHT
                signals.append(f"alias:{token}")

        # Legacy keyword map (bilingual) — reproduces historical winners.
        legacy = self._legacy_alias_score(profile, combined)
        if legacy > 0:
            signals.append(f"keywords:{round(legacy, 2)}")

        score = typed + alias + legacy
        if r.broad and score > 0:
            # Broad KBs stay in the running but never edge out a precise skill;
            # the tie-break in _pick_primary demotes them on equal scores.
            signals.append("broad")
        return _ScoreDetail(score=score, signals=signals, typed_hits=typed_hits)

    def _legacy_alias_score(self, profile: SkillProfile, combined: str) -> float:
        # The historical bilingual keyword map is the alias catalog: it lets the
        # resolver reproduce the old dispatcher's winners while typed metadata
        # layers on top.
        from deepsec.spear.skills.dispatcher import SKILL_INTENT_MAP

        score = 0.0
        boost = DIRECTORY_BOOST if profile.specialized else 1.0
        for pattern, skill_names in SKILL_INTENT_MAP.items():
            if profile.name not in skill_names:
                continue
            keywords = pattern.split("|")
            match_count = sum(1 for kw in keywords if keyword_present(kw, combined))
            if match_count:
                score += (match_count / len(keywords)) * boost
        return score

    def _excluded(self, profile: SkillProfile, combined: str) -> bool:
        for signal in profile.routing.exclude_signals:
            if signal and signal in combined:
                return True
        return False

    # ── bundle assembly ─────────────────────────────────────────────

    def _pick_primary(self, scores: dict[str, _ScoreDetail]) -> str:
        # Prefer non-support skills as primary; fall back to any if none.
        candidates = [
            n for n in scores if self._catalog[n].routing.role != "support"
        ] or list(scores)

        def key(name: str) -> tuple:
            detail = scores[name]
            profile = self._catalog[name]
            return (
                detail.score,
                0 if not profile.routing.broad else -1,  # narrow beats broad on tie
                detail.typed_hits,
                1 if profile.specialized else 0,
                # Stable, deterministic final tiebreak.
                -_alpha_rank(name),
            )

        return max(candidates, key=key)

    def _pick_supporting(
        self, primary: str, primary_score: float, scores: dict[str, _ScoreDetail]
    ) -> list[str]:
        threshold = max(SUPPORT_RATIO * primary_score, 0.5)
        pool = [
            (name, detail)
            for name, detail in scores.items()
            if name != primary and detail.score >= threshold
        ]

        def key(item: tuple[str, _ScoreDetail]) -> tuple:
            name, detail = item
            profile = self._catalog[name]
            return (
                1 if profile.routing.role == "support" else 0,
                detail.score,
                detail.typed_hits,
                -_alpha_rank(name),
            )

        pool.sort(key=key, reverse=True)
        return [name for name, _ in pool[:SUPPORT_CAP]]

    # ── fallback ────────────────────────────────────────────────────

    def _fallback(self, query: SkillQuery, combined: str) -> SkillSelection:
        if self._looks_pentest(query, combined) and _FALLBACK_SKILL in self._catalog:
            return SkillSelection(
                primary=_FALLBACK_SKILL,
                signals=["fallback"],
                confidence=0.2,
                reason="fallback: generic pentest task, no specific skill matched",
                references=self._catalog[_FALLBACK_SKILL].references,
            )
        return SkillSelection(
            primary=None,
            signals=[],
            confidence=0.0,
            reason="no matching skill; non-security input does not auto-inject a skill",
        )

    @staticmethod
    def _looks_pentest(query: SkillQuery, combined: str) -> bool:
        if query.phase or query.target_type or query.vuln_hints or query.task_types:
            return True
        return any(sig in combined for sig in _PENTEST_SIGNALS)

    # ── presentation ────────────────────────────────────────────────

    @staticmethod
    def _confidence(detail: _ScoreDetail) -> float:
        base = detail.score / (detail.score + 1.5)
        if detail.typed_hits:
            base = min(1.0, base + 0.15)
        return round(min(1.0, base), 2)

    def _reason(self, primary: str, detail: _ScoreDetail, supporting: list[str]) -> str:
        top_signals = ", ".join(detail.signals[:4]) or "keyword match"
        reason = f"{primary} selected via {top_signals}"
        if supporting:
            reason += f"; support: {', '.join(supporting)}"
        return reason


@lru_cache(maxsize=512)
def _alpha_rank(name: str) -> int:
    """Deterministic rank so tie-breaks never depend on dict ordering."""
    return sum((i + 1) * ord(c) for i, c in enumerate(name))

