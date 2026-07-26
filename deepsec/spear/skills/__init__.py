"""Typed routing metadata for skills.

Skills may declare an optional ``routing:`` block in their ``SKILL.md``
frontmatter. It is parsed into :class:`SkillRouting`, a Pydantic model that
normalizes every token to a canonical lowercase form and records any value
outside the known vocabulary in :attr:`SkillRouting.warnings`.

The vocabularies here are intentionally the single source of truth for the
resolver's typed signals. Tests assert that shipped skills produce no
warnings, so an unknown enum token fails CI rather than silently mis-routing.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from pydantic import BaseModel, Field, model_validator

# ── Canonical vocabularies ──────────────────────────────────────────
# Every set is lowercase, underscore-separated. ``normalize_token`` maps free
# text ("SQL Injection", "sql-injection") onto these forms.

TARGET_TYPES = frozenset(
    {
        "web",
        "api",
        "android",
        "ios",
        "mobile",
        "client",
        "desktop",
        "network",
        "intranet",
        "host",
        "cloud",
        "wireless",
        "ai_agent",
        "mcp",
        "crypto",
        "binary",
        "ctf",
    }
)

PHASES = frozenset(
    {
        "recon",
        "vuln_discovery",
        "exploitation",
        "post_exploitation",
        "reporting",
    }
)

SCAN_MODES = frozenset(
    {
        "passive",
        "safe",
        "active",
        "aggressive",
        "headless",
    }
)

VULNERABILITY_CLASSES = frozenset(
    {
        "sqli",
        "xss",
        "ssrf",
        "ssti",
        "xxe",
        "rce",
        "deserialization",
        "idor",
        "csrf",
        "cors",
        "file_upload",
        "path_traversal",
        "auth_bypass",
        "privilege_escalation",
        "jwt",
        "oauth",
        "graphql",
        "websocket",
        "request_smuggling",
        "prototype_pollution",
        "prompt_injection",
        "tool_abuse",
        "info_disclosure",
        "business_logic",
        "type_juggling",
        "sandbox_escape",
        "lateral_movement",
        "credential_theft",
    }
)

FRAMEWORKS = frozenset(
    {
        "django",
        "flask",
        "spring",
        "laravel",
        "thinkphp",
        "wordpress",
        "express",
        "rails",
        "struts",
        "fastapi",
        "vue",
        "react",
        "langchain",
    }
)

TECHNOLOGIES = frozenset(
    {
        "php",
        "python",
        "java",
        "nodejs",
        "javascript",
        "dotnet",
        "golang",
        "ruby",
        "c",
        "cpp",
        "sql",
        "llm",
        "rag",
        "memory",
        "plugin",
    }
)

PROTOCOLS = frozenset(
    {
        "http",
        "https",
        "websocket",
        "tcp",
        "udp",
        "dns",
        "smb",
        "ldap",
        "kerberos",
        "rdp",
        "ssh",
        "ftp",
        "tls",
    }
)

TOOLING = frozenset(
    {
        "nmap",
        "sqlmap",
        "burp",
        "nuclei",
        "ffuf",
        "frida",
        "jadx",
        "bloodhound",
        "impacket",
        "crackmapexec",
        "hashcat",
        "metasploit",
        "mimikatz",
        "chisel",
        "ligolo",
        "frp",
        "scrcpy",
    }
)

TASK_TYPES = frozenset(
    {
        "pentest",
        "ctf",
        "osint",
        "reverse",
        "crypto",
        "report",
        "triage",
        "recon",
        "audit",
        "bugbounty",
    }
)

# role: how the skill participates in a bundle.
ROLES = frozenset({"primary", "support", "fallback"})

# Common alias corrections applied before matching against a vocabulary.
_ALIASES: dict[str, str] = {
    "sql_injection": "sqli",
    "sql注入": "sqli",
    "cross_site_scripting": "xss",
    "remote_code_execution": "rce",
    "命令注入": "rce",
    "command_injection": "rce",
    "lfi": "path_traversal",
    "rfi": "path_traversal",
    "文件上传": "file_upload",
    "越权": "idor",
    "反序列化": "deserialization",
    "提权": "privilege_escalation",
    "横向移动": "lateral_movement",
    "凭据窃取": "credential_theft",
    "prompt注入": "prompt_injection",
    "工具滥用": "tool_abuse",
    "js": "javascript",
    "node": "nodejs",
    "node.js": "nodejs",
    "net": "dotnet",
    ".net": "dotnet",
    "go": "golang",
    "c++": "cpp",
    "ai": "ai_agent",
    "agent": "ai_agent",
    "post-exploitation": "post_exploitation",
    "vuln-discovery": "vuln_discovery",
    "type_confusion": "type_juggling",
    "弱类型": "type_juggling",
}


def keyword_present(keyword: str, text: str) -> bool:
    """Whether ``keyword`` occurs in already-lowercased ``text``.

    ASCII abbreviations (``rce``, ``xss``, ``php`` …) require alphanumeric
    boundaries so ``rce`` doesn't fire inside ``source`` nor ``java`` inside
    ``javascript``. Non-ASCII phrases (Chinese) keep plain substring matching,
    where word boundaries do not apply.
    """
    if not keyword:
        return False
    if keyword.isascii():
        return re.search(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])", text) is not None
    return keyword in text


def normalize_token(value: str) -> str:
    """Normalize a free-text token to a canonical lowercase form.

    Lowercases, trims, collapses spaces / hyphens / dots to underscores, then
    applies the small alias table. Non-ASCII tokens (Chinese) are preserved so
    the alias table can still map them (e.g. ``sql注入`` → ``sqli``).
    """
    token = value.strip().lower()
    if token in _ALIASES:
        return _ALIASES[token]
    normalized = token.replace(" ", "_").replace("-", "_").replace(".", "_")
    normalized = normalized.strip("_")
    return _ALIASES.get(normalized, normalized)


def _normalize_field(
    raw: Any, vocab: frozenset[str], field: str, warnings: list[str]
) -> list[str]:
    """Normalize a list-valued routing field, recording unknown tokens."""
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, Iterable):
        warnings.append(f"{field}: expected a list, got {type(raw).__name__}")
        return []

    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            warnings.append(f"{field}: non-string token {item!r}")
            continue
        token = normalize_token(item)
        if not token:
            continue
        if token not in vocab:
            warnings.append(f"{field}: unknown token {token!r}")
            continue
        if token not in seen:
            seen.add(token)
            out.append(token)
    return out


class SkillRouting(BaseModel):
    """Typed, normalized routing metadata for one skill.

    All list fields hold canonical tokens (see the vocabularies above). Free
    text lives only in :attr:`aliases` and :attr:`exclude_signals`, which are
    matched as substrings against the request text.
    """

    target_types: list[str] = Field(default_factory=list)
    phases: list[str] = Field(default_factory=list)
    scan_modes: list[str] = Field(default_factory=list)
    vulnerability_classes: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    tooling: list[str] = Field(default_factory=list)
    task_types: list[str] = Field(default_factory=list)
    # Free-text, bilingual keyword aliases matched as lowercase substrings.
    aliases: list[str] = Field(default_factory=list)
    # Free-text signals that, when present in the request, disqualify this skill.
    exclude_signals: list[str] = Field(default_factory=list)
    # How the skill participates in a bundle.
    role: str = Field(default="primary")
    # A broad knowledge base wins only on strong signals; a narrow skill beats
    # it on a tie (see the resolver's broad penalty).
    broad: bool = Field(default=False)
    # Collected during normalization; empty for well-formed metadata.
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        warnings: list[str] = list(data.get("warnings", []) or [])
        result: dict[str, Any] = {}
        for field, vocab in (
            ("target_types", TARGET_TYPES),
            ("phases", PHASES),
            ("scan_modes", SCAN_MODES),
            ("vulnerability_classes", VULNERABILITY_CLASSES),
            ("frameworks", FRAMEWORKS),
            ("technologies", TECHNOLOGIES),
            ("protocols", PROTOCOLS),
            ("tooling", TOOLING),
            ("task_types", TASK_TYPES),
        ):
            result[field] = _normalize_field(data.get(field), vocab, field, warnings)

        # Aliases / exclude_signals: lowercase free text, deduped, no vocab.
        for field in ("aliases", "exclude_signals"):
            raw = data.get(field) or []
            if isinstance(raw, str):
                raw = [raw]
            tokens: list[str] = []
            seen: set[str] = set()
            for item in raw:
                if not isinstance(item, str):
                    warnings.append(f"{field}: non-string token {item!r}")
                    continue
                low = item.strip().lower()
                if low and low not in seen:
                    seen.add(low)
                    tokens.append(low)
            result[field] = tokens

        role = str(data.get("role", "primary")).strip().lower()
        if role not in ROLES:
            warnings.append(f"role: unknown value {role!r}")
            role = "primary"
        result["role"] = role
        result["broad"] = bool(data.get("broad", False))
        result["warnings"] = warnings
        return result

    def typed_tokens(self) -> set[str]:
        """All canonical typed tokens, for quick membership tests."""
        return {
            *self.target_types,
            *self.phases,
            *self.scan_modes,
            *self.vulnerability_classes,
            *self.frameworks,
            *self.technologies,
            *self.protocols,
            *self.tooling,
            *self.task_types,
        }

    def is_empty(self) -> bool:
        return not (self.typed_tokens() or self.aliases or self.exclude_signals)
