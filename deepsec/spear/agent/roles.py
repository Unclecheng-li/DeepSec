"""Role registry and hard tool allow-list helpers for team runs."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any


@dataclass(frozen=True)
class AgentRole:
    """A specialist role definition used by the team supervisor."""

    name: str
    persona: str
    allowed_tool_globs: tuple[str, ...]
    goal_template: str


ROLE_REGISTRY: dict[str, AgentRole] = {
    "researcher": AgentRole(
        name="researcher",
        persona=(
            "You are the Researcher specialist. Focus on reconnaissance, OSINT, "
            "asset discovery, safe fetching, and evidence summaries. Do not attempt "
            "exploitation or payload execution."
        ),
        allowed_tool_globs=(
            "load_skill_reference",
            "evidence_*",
            "source_extract",
            "space_search",
            "subdomain_enum",
            "js_recon",
            "dir_enum",
            "unauth_test",
            "osint_recon",
            "cve_lookup",
            "topology_build",
            "fetch",
            "http_probe_batch",
            "search*",
            "*search*",
        ),
        goal_template=(
            "Research objective: {objective}\n"
            "Done when: {done_when}\n"
            "Return verified facts, sources, and follow-up surfaces only."
        ),
    ),
    "developer": AgentRole(
        name="developer",
        persona=(
            "You are the Developer specialist. Build payload candidates, parsers, "
            "decoders, and offline analysis helpers. Do not touch the target directly."
        ),
        allowed_tool_globs=(
            "load_skill_reference",
            "evidence_*",
            "source_extract",
            "runtime_diff_probe",
            "shell_command",
            "python_execute",
            "crypto_decode",
            "cve_lookup",
            "topology_build",
            "findings_*",
            "remediation_advice",
            "attack_map",
        ),
        goal_template=(
            "Development objective: {objective}\n"
            "Done when: {done_when}\n"
            "Return reusable payloads, parsers, and assumptions to verify."
        ),
    ),
    "executor": AgentRole(
        name="executor",
        persona=(
            "You are the Executor specialist. Run authorized checks against the "
            "target, capture concrete tool output, and avoid claims without evidence."
        ),
        allowed_tool_globs=(
            "load_skill_reference",
            "evidence_*",
            "source_extract",
            "runtime_diff_probe",
            "shell_command",
            "python_execute",
            "crypto_decode",
            "nmap_scan",
            "brute_force_login",
            "space_search",
            "subdomain_enum",
            "js_recon",
            "dir_enum",
            "unauth_test",
            "osint_recon",
            "fetch",
            "http*",
            "request*",
            "curl*",
            "browser*",
            "navigate",
            "click",
            "submit*",
            "*scan*",
            "*recon*",
        ),
        goal_template=(
            "Execution objective: {objective}\n"
            "Done when: {done_when}\n"
            "Use real tool output as evidence and record what was verified."
        ),
    ),
    "adviser": AgentRole(
        name="adviser",
        persona=(
            "You are the Adviser specialist. Plan, critique, and decide whether to "
            "continue, re-plan, or stop. You have no execution tools."
        ),
        allowed_tool_globs=(),
        goal_template=(
            "Advisory objective: {objective}\n"
            "Done when: {done_when}\n"
            "Return a decision and rationale without executing tools."
        ),
    ),
}


def normalize_role_name(role: str | None) -> str | None:
    """Return a canonical role name, or ``None`` when no role is active."""
    normalized = str(role or "").strip().lower()
    return normalized or None


def get_role(role: str | None) -> AgentRole | None:
    """Look up a role definition by name."""
    normalized = normalize_role_name(role)
    if normalized is None:
        return None
    return ROLE_REGISTRY.get(normalized)


def require_role(role: str) -> AgentRole:
    """Return a role or raise a stable ValueError."""
    definition = get_role(role)
    if definition is None:
        raise ValueError(f"Unknown team role: {role}")
    return definition


def tool_allowed_for_role(tool_name: str, role: str | None) -> bool:
    """Return whether ``tool_name`` is allowed for ``role``.

    A missing role preserves today's behavior: all tools are available.
    """
    normalized = normalize_role_name(role)
    if normalized is None:
        return True
    definition = get_role(normalized)
    if definition is None:
        return False
    return any(fnmatchcase(tool_name, pattern) for pattern in definition.allowed_tool_globs)


def filter_tools_for_role(
    tools: list[dict[str, Any]],
    role: str | None,
) -> list[dict[str, Any]]:
    """Filter OpenAI tool schemas to the active role's allow-list."""
    if normalize_role_name(role) is None:
        return tools

    filtered: list[dict[str, Any]] = []
    for tool in tools:
        function = tool.get("function", {}) if isinstance(tool, dict) else {}
        tool_name = str(function.get("name", "") or "")
        if tool_name and tool_allowed_for_role(tool_name, role):
            filtered.append(tool)
    return filtered


def role_tool_violation(role: str | None, tool_name: str) -> str | None:
    """Return a structured rejection message for out-of-role calls."""
    normalized = normalize_role_name(role)
    if normalized is None or tool_allowed_for_role(tool_name, normalized):
        return None
    if get_role(normalized) is None:
        return f"[role_tool_violation] unknown active role {normalized!r}; blocked tool {tool_name!r}"
    return (
        f"[role_tool_violation] role {normalized!r} is not allowed to call tool "
        f"{tool_name!r}; the call was blocked before execution"
    )


def role_prompt_block(role: str | None) -> str:
    """Render the role persona block for an active worker."""
    definition = get_role(role)
    if definition is None:
        return ""
    allowed = ", ".join(definition.allowed_tool_globs) or "none"
    return (
        "## Active Specialist Role\n"
        f"Role: {definition.name}\n"
        f"{definition.persona}\n"
        f"Allowed tool patterns: {allowed}\n"
        "Stay inside this role. If a task needs a different role, report that need."
    )
