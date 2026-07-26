"""Flag skills built from the public VulnClaw CLI manual."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Literal

# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: 消除 V5 违规 — skills/ 基础设施层不应反向依赖 cli/ 入口层，
#          改为从 config/cli_constants.py 导入共享数据常量。
from deepsec.config.cli_constants import COMMANDS, COMMON_TASK_FLAGS, ROOT_OPTIONS

TuiFlagAction = Literal[
    "target",
    "mode",
    "only_port",
    "only_host",
    "only_path",
    "blocked_host",
    "blocked_path",
    "allow_actions",
    "block_actions",
    "resume_true",
    "resume_false",
]

_OPTION_RE = re.compile(r"(?<!-)(--[A-Za-z0-9][A-Za-z0-9-]*|-{1}[A-Za-z])")
_CHECK_MODES = {"quick", "standard", "deep", "continuous"}

_TUI_ACTIONS: dict[str, TuiFlagAction] = {
    "--target": "target",
    "--mode": "mode",
    "--only-port": "only_port",
    "--only-host": "only_host",
    "--only-path": "only_path",
    "--blocked-host": "blocked_host",
    "--blocked-path": "blocked_path",
    "--allow-actions": "allow_actions",
    "--block-actions": "block_actions",
    "--resume": "resume_true",
    "--no-resume": "resume_false",
}


@dataclass(frozen=True)
class FlagSkill:
    """A compact help/apply skill for one documented CLI flag."""

    canonical: str
    value_hint: str = ""
    summary: str = ""
    availability: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    examples: tuple[str, ...] = ()
    descriptions: tuple[str, ...] = ()
    tui_action: TuiFlagAction | None = None

    @property
    def name(self) -> str:
        """Return the user-facing skill name without leading dashes."""
        return self.canonical.lstrip("-")


@dataclass(frozen=True)
class FlagSkillCommand:
    """Parsed `/.` command input."""

    query: str
    value: str = ""


@dataclass(frozen=True)
class ApplyResult:
    """Result of applying a flag skill to a TUI draft state."""

    applied: bool
    message: str
    error: bool = False


@dataclass
class _FlagSkillBuilder:
    canonical: str
    value_hint: str = ""
    summary: str = ""
    availability: list[str] = field(default_factory=list)
    aliases: set[str] = field(default_factory=set)
    examples: list[str] = field(default_factory=list)
    descriptions: list[str] = field(default_factory=list)

    def add_context(
        self,
        *,
        topic: str,
        description: str,
        value_hint: str,
        aliases: set[str],
        examples: tuple[str, ...],
    ) -> None:
        if topic not in self.availability:
            self.availability.append(topic)
        if description and description not in self.descriptions:
            self.descriptions.append(description)
        if not self.summary and description:
            self.summary = description
        if not self.value_hint and value_hint:
            self.value_hint = value_hint
        self.aliases.update(aliases)
        for example in examples:
            if example not in self.examples:
                self.examples.append(example)

    def build(self) -> FlagSkill:
        return FlagSkill(
            canonical=self.canonical,
            value_hint=self.value_hint,
            summary=self.summary,
            availability=tuple(self.availability),
            aliases=tuple(sorted(self.aliases)),
            examples=tuple(self.examples),
            descriptions=tuple(self.descriptions),
            tui_action=_TUI_ACTIONS.get(self.canonical),
        )


def parse_flag_skill_command(text: str) -> FlagSkillCommand:
    """Parse `/.flag [value]` text into a query and optional value."""
    stripped = text.strip()
    if stripped.startswith("/."):
        stripped = stripped[2:]
    elif stripped.startswith("."):
        stripped = stripped[1:]
    parts = stripped.split(maxsplit=1)
    if not parts:
        return FlagSkillCommand(query="")
    return FlagSkillCommand(query=parts[0], value=parts[1].strip() if len(parts) > 1 else "")


def normalize_flag_query(query: str) -> str:
    """Normalize a user-entered flag skill lookup key."""
    parsed = parse_flag_skill_command(query)
    raw = parsed.query or query.strip()
    if raw.startswith("/."):
        raw = raw[2:]
    if raw.startswith("."):
        raw = raw[1:]
    raw = raw.strip().lower().replace("_", "-")
    if raw.startswith("--"):
        return raw[2:]
    if raw.startswith("-"):
        return raw
    return raw


@lru_cache(maxsize=1)
def list_flag_skills() -> tuple[FlagSkill, ...]:
    """List all documented flag skills from the CLI manual."""
    builders: dict[str, _FlagSkillBuilder] = {}

    for option_spec, description in ROOT_OPTIONS:
        _add_option_spec(builders, "root", option_spec, description, ())

    for option_spec, description in COMMON_TASK_FLAGS:
        _add_option_spec(builders, "common task flags", option_spec, description, ())

    for topic in COMMANDS:
        for option_spec, description in topic.flags:
            _add_option_spec(builders, topic.name, option_spec, description, topic.examples)

    return tuple(sorted((builder.build() for builder in builders.values()), key=lambda item: item.name))


def find_flag_skill(query: str) -> FlagSkill | None:
    """Find a documented flag skill by slash-dot syntax, bare name, or alias."""
    key = normalize_flag_query(query)
    if not key:
        return None
    aliases = _flag_skill_aliases()
    return aliases.get(key)


def complete_flag_skills(prefix: str = "") -> tuple[FlagSkill, ...]:
    """Return flag skills whose canonical name or alias starts with *prefix*."""
    normalized = normalize_flag_query(prefix) if prefix else ""
    skills = list_flag_skills()
    if not normalized:
        return skills
    matches: list[FlagSkill] = []
    for skill in skills:
        keys = {normalize_flag_query(skill.canonical), normalize_flag_query(skill.name)}
        keys.update(normalize_flag_query(alias) for alias in skill.aliases)
        if any(key.startswith(normalized) for key in keys):
            matches.append(skill)
    return tuple(matches)


def render_flag_skill(skill: FlagSkill) -> str:
    """Render a user-facing flag skill help card."""
    lines = [
        f"{skill.canonical} ({'/.' + skill.name})",
        f"Available on: {', '.join(skill.availability)}",
    ]
    if skill.value_hint:
        lines.append(f"Usage: /.{skill.name} {skill.value_hint}")
    else:
        lines.append(f"Usage: /.{skill.name}")
    if skill.tui_action:
        lines.append("TUI: can apply to the current task draft.")
    else:
        lines.append("TUI: guidance only for this flag.")
    if skill.summary:
        lines.append(f"Summary: {skill.summary}")
    if skill.examples:
        lines.append(f"Example: {skill.examples[0]}")
    return "\n".join(lines)


def render_flag_skill_compact(skill: FlagSkill) -> str:
    """Render a one-line flag skill summary for compact TUI status surfaces."""
    usage = f"/.{skill.name} {skill.value_hint}".rstrip()
    availability = ", ".join(skill.availability)
    return f"{skill.canonical}: {skill.summary} | {availability} | {usage}"


def apply_flag_skill_to_tui_state(skill: FlagSkill, value: str, state: Any) -> ApplyResult:
    """Apply a supported flag skill to a TUI state object."""
    action = skill.tui_action
    if action is None:
        return ApplyResult(False, f"{skill.canonical} is guidance-only in the TUI.")

    value = value.strip()

    if action in {"resume_true", "resume_false"}:
        setattr(state, "resume", action == "resume_true")
        return ApplyResult(True, f"Set resume to {'on' if action == 'resume_true' else 'off'}.")

    if not value:
        return ApplyResult(False, f"{skill.canonical} needs a value before it can be applied.")

    if action == "target":
        state.target = value
    elif action == "mode":
        if value not in _CHECK_MODES:
            return ApplyResult(
                False,
                f"Unknown mode '{value}'. Expected one of: {', '.join(sorted(_CHECK_MODES))}.",
                error=True,
            )
        state.mode = value
    elif action == "only_port":
        try:
            _validate_port(value)
        except ValueError as exc:
            return ApplyResult(False, str(exc), error=True)
        state.only_port = value
    elif action == "only_host":
        state.only_host = value
    elif action == "only_path":
        state.only_path = value
    elif action == "blocked_host":
        state.blocked_host = value
    elif action == "blocked_path":
        state.blocked_path = value
    elif action == "allow_actions":
        state.allow_actions = _parse_csv(value)
    elif action == "block_actions":
        state.block_actions = _parse_csv(value)

    return ApplyResult(True, f"Applied {skill.canonical} to the current task draft.")


@lru_cache(maxsize=1)
def _flag_skill_aliases() -> dict[str, FlagSkill]:
    aliases: dict[str, FlagSkill] = {}
    for skill in list_flag_skills():
        keys = {skill.canonical, skill.name, f"/.{skill.name}", f"/.{skill.canonical}"}
        keys.update(skill.aliases)
        for key in keys:
            aliases[normalize_flag_query(key)] = skill
    return aliases


def _add_option_spec(
    builders: dict[str, _FlagSkillBuilder],
    topic: str,
    option_spec: str,
    description: str,
    examples: tuple[str, ...],
) -> None:
    options = _extract_options(option_spec)
    if not options:
        return

    long_options = [option for option in options if option.startswith("--")]
    if not long_options:
        return

    short_aliases = {option for option in options if option.startswith("-") and not option.startswith("--")}
    for canonical in long_options:
        builder = builders.setdefault(canonical, _FlagSkillBuilder(canonical=canonical))
        aliases = _aliases_for(canonical)
        if canonical == long_options[0]:
            aliases.update(short_aliases)
        builder.add_context(
            topic=topic,
            description=description,
            value_hint=_extract_value_hint(option_spec, canonical),
            aliases=aliases,
            examples=examples,
        )


def _extract_options(option_spec: str) -> list[str]:
    return [match.group(1) for match in _OPTION_RE.finditer(option_spec)]


def _extract_value_hint(option_spec: str, option: str) -> str:
    index = option_spec.find(option)
    if index < 0:
        return ""
    tail = option_spec[index + len(option) :]
    stop_positions = [pos for pos in [tail.find(","), tail.find("/")] if pos >= 0]
    if stop_positions:
        tail = tail[: min(stop_positions)]
    return tail.strip()


def _aliases_for(canonical: str) -> set[str]:
    bare = canonical.lstrip("-")
    return {canonical, bare, canonical.replace("-", "_"), bare.replace("-", "_")}


def _parse_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _validate_port(value: str) -> None:
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError("Invalid port. Expected an integer from 1 to 65535.") from exc
    if port < 1 or port > 65535:
        raise ValueError("Invalid port. Expected an integer from 1 to 65535.")
