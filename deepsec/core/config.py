"""DeepSec configuration surface.

Historically this module owned a standalone TOML config (``config.toml``) that
diverged from the runtime configuration in ``deepsec.config.settings`` (which
reads ``config.yaml`` and backs every LLM / Spear call). That split meant
``deepsec config set`` wrote a file the runtime never read — the API key you
set was silently ignored.

This module is now a thin compatibility layer over ``deepsec.config.settings``:
the single source of truth is ``~/.deepsec/config.yaml``. ``load_config`` still
returns an object that exposes the legacy attribute surface
(``config.llm.*``, ``config.shield.*``, ``config.storage.*`` …) so the existing
Shield scanner, ``DeepSecLLM`` client, and CLI keep working unchanged, but the
underlying data always comes from the unified YAML config.
"""

from __future__ import annotations

import copy
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml


# ── Legacy dataclasses (kept for type hints + ProviderConfig reuse) ──────
# These are no longer the storage format, but ``core.llm`` and ``scanner``
# import them for annotations / instantiation, so they must remain importable.

@dataclass(slots=True)
class LLMModeConfig:
    chat_model: str = "deepseek-chat"
    reason_model: str = "deepseek-reasoner"
    explore_model: str = "deepseek-chat"


@dataclass(slots=True)
class ProviderConfig:
    """Per-provider credentials and optional model overrides."""

    api_key: str = ""
    base_url: str = ""
    chat_model: str = ""
    reason_model: str = ""


@dataclass(slots=True)
class LLMConfig:
    provider: str = "deepseek"
    api_key: str = ""
    base_url: str = "https://api.deepseek.com/v1"
    fallbacks: list[str] = field(default_factory=lambda: ["claude", "openai", "local"])
    providers: dict[str, ProviderConfig] = field(default_factory=dict)
    shield: LLMModeConfig = field(default_factory=LLMModeConfig)
    spear: LLMModeConfig = field(default_factory=LLMModeConfig)


@dataclass(slots=True)
class ShieldConfig:
    l1: bool = True
    l2: bool = True
    l3: bool = False
    package_verification: str = "seed"
    dedup: bool = True


@dataclass(slots=True)
class SpearConfig:
    scan_mode: str = "standard"
    fail_on: str = "verified"
    scope: str = "full"
    max_parallel: int = 3
    max_rounds: int = 20


@dataclass(slots=True)
class ReportConfig:
    format: list[str] = field(default_factory=lambda: ["markdown", "sarif"])
    output_dir: str = "~/.deepsec/reports"
    attack_chain: bool = True


@dataclass(slots=True)
class StorageConfig:
    findings_db: str = "~/.deepsec/findings.db"
    runs_dir: str = "~/.deepsec/runs"
    snapshots_dir: str = "~/.deepsec/snapshots"


@dataclass(slots=True)
class TuiConfig:
    theme: str = "dark"
    thinking_display: bool = True
    model_auto: bool = True
    sidebar_width: int = 30
    output_width: int = 45


@dataclass(slots=True)
class RoleConfig:
    default: str = "pentester"


@dataclass(slots=True)
class DeepSecConfig:
    """Legacy aggregate config — retained only for type annotations."""

    llm: LLMConfig = field(default_factory=LLMConfig)
    shield: ShieldConfig = field(default_factory=ShieldConfig)
    spear: SpearConfig = field(default_factory=SpearConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    tui: TuiConfig = field(default_factory=TuiConfig)
    role: RoleConfig = field(default_factory=RoleConfig)


# ── Unified config path (delegates to settings) ──────────────────────────

def config_path() -> Path:
    """The single config file: ``~/.deepsec/config.yaml``.

    Resolution honours ``DEEPSEC_CONFIG_DIR`` (used by
    ``deepsec.config.settings``); the historical ``DEEPSEC_CONFIG`` toml
    override is intentionally dropped so we never read the stale toml again.
    """
    from deepsec.config.settings import CONFIG_FILE

    return Path(str(CONFIG_FILE)).expanduser()


def ensure_config_file(path: Path | None = None) -> Path:
    """Ensure ``config.yaml`` exists, writing defaults on first run."""
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        from deepsec.config.settings import load_config as _load_settings, save_config

        save_config(_load_settings())
    return path


def load_config(path: Path | None = None) -> "LegacyConfig":
    """Load the unified YAML config and wrap it in a legacy-compatible adapter.

    When *path* is given and points to an existing file, the unified settings
    are loaded from that file (useful for tests). Otherwise the global
    ``config.yaml`` resolved via ``settings`` is used.
    """
    from deepsec.config.settings import load_config as _load_settings

    if path is not None and path.exists():
        # Load from an explicit file path (test / custom config support).
        import yaml as _yaml
        from deepsec.config.settings import _merge_config, _overlay_env, _apply_provider_defaults
        from deepsec.config.schema import VulnClawConfig, MCPServersConfig, MCPServerConfig
        from deepsec.config.schema import BUILTIN_MCP_SERVERS

        servers: dict[str, MCPServerConfig] = {}
        for name, cfg in BUILTIN_MCP_SERVERS.items():
            from deepsec.config.settings import _parse_mcp_server
            servers[name] = _parse_mcp_server(name, cfg)
        base = VulnClawConfig(mcp=MCPServersConfig(servers=servers))
        with path.open("r", encoding="utf-8") as f:
            raw = _yaml.safe_load(f) or {}
        merged = _merge_config(base, raw)
        merged = _overlay_env(merged)
        _apply_provider_defaults(merged)
        return LegacyConfig(merged, raw)

    return LegacyConfig(_load_settings())


def update_config_value(key: str, value: str, path: Path | None = None) -> Path:
    """Persist a dotted config key in ``config.yaml``, preserving other keys.

    Unlike the old TOML implementation this writes the *unified* YAML file, so
    values set here are actually read at runtime. Unknown keys (e.g. legacy
    ``role.default``) are preserved too.
    """
    path = ensure_config_file(path)
    raw: dict[str, Any] = {}
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
    if not isinstance(raw, dict):
        raw = {}

    cursor: dict[str, Any] = raw
    parts = key.split(".")
    if not all(parts):
        raise ValueError("Configuration key must be a dotted path")
    for part in parts[:-1]:
        current = cursor.get(part)
        if current is None or not isinstance(current, dict):
            current = {}
            cursor[part] = current
        cursor = current
    cursor[parts[-1]] = _parse_scalar(value)

    with path.open("w", encoding="utf-8") as handle:
        yaml.dump(raw, handle, default_flow_style=False, allow_unicode=True, sort_keys=False)
    return path


# ── Legacy compatibility adapter ─────────────────────────────────────────

class LegacyLLMModeConfig:
    """Exposes the old ``llm.shield`` / ``llm.spear`` model selectors."""

    def __init__(self, model: str) -> None:
        self.chat_model = model or "deepseek-chat"
        self.reason_model = model or "deepseek-reasoner"
        self.explore_model = model or "deepseek-chat"


class LegacyLLMConfig:
    """Bridges ``settings.LLMConfig`` to the legacy ``llm`` attribute surface."""

    def __init__(self, llm: Any, raw: dict[str, Any] | None = None) -> None:
        self._llm = llm
        self._raw = raw or {}

    @property
    def provider(self) -> str:
        return str(self._llm.provider or "deepseek")

    @property
    def api_key(self) -> str:
        pool = getattr(self._llm, "api_keys", None) or []
        if pool:
            return str(pool[0])
        return str(getattr(self._llm, "api_key", "") or "")

    @property
    def base_url(self) -> str:
        return str(getattr(self._llm, "base_url", "") or "")

    @property
    def fallbacks(self) -> list[str]:
        raw_llm = self._raw.get("llm", {}) if isinstance(self._raw, dict) else {}
        if isinstance(raw_llm, dict) and "fallbacks" in raw_llm:
            return list(raw_llm["fallbacks"])
        return ["claude", "openai", "local"]

    @property
    def providers(self) -> dict[str, ProviderConfig]:
        # Per-provider overrides from the raw config (if present).
        raw_llm = self._raw.get("llm", {}) if isinstance(self._raw, dict) else {}
        raw_providers = raw_llm.get("providers", {}) if isinstance(raw_llm, dict) else {}
        if isinstance(raw_providers, dict) and raw_providers:
            return {
                name: ProviderConfig(
                    api_key=str(p.get("api_key", "")),
                    base_url=str(p.get("base_url", "")),
                    chat_model=str(p.get("chat_model", "")),
                    reason_model=str(p.get("reason_model", "")),
                )
                for name, p in raw_providers.items()
                if isinstance(p, dict)
            }
        return {}

    @property
    def shield(self) -> LegacyLLMModeConfig:
        return LegacyLLMModeConfig(self._llm.model)

    @property
    def spear(self) -> LegacyLLMModeConfig:
        return LegacyLLMModeConfig(self._llm.model)


class LegacyStorageConfig:
    """Bridges ``settings.session`` to the legacy ``storage`` attribute surface."""

    def __init__(self, cfg: Any) -> None:
        self._cfg = cfg

    @property
    def runs_dir(self) -> str:
        runs = getattr(self._cfg.session, "runs_dir", None)
        if runs:
            return str(Path(runs).expanduser())
        from deepsec.config.settings import RUNS_DIR

        return str(RUNS_DIR)

    findings_db: str = "~/.deepsec/findings.db"
    snapshots_dir: str = "~/.deepsec/snapshots"


class LegacyConfig:
    """Wraps the unified ``VulnClawConfig`` and exposes the legacy surface."""

    def __init__(self, cfg: Any, raw: dict[str, Any] | None = None) -> None:
        self._cfg = cfg
        self._raw = raw or {}

    @property
    def llm(self) -> LegacyLLMConfig:
        return LegacyLLMConfig(self._cfg.llm, self._raw)

    @property
    def shield(self) -> ShieldConfig:
        # L1/L2/L3 are driven by CLI options; dedup defaults to True.
        # But if shield.l3 was explicitly set in the config file, honour it.
        raw_shield = self._raw.get("shield", {}) if isinstance(self._raw, dict) else {}
        if isinstance(raw_shield, dict):
            return ShieldConfig(
                l1=raw_shield.get("l1", True),
                l2=raw_shield.get("l2", True),
                l3=raw_shield.get("l3", False),
                package_verification=raw_shield.get("package_verification", "seed"),
                dedup=raw_shield.get("dedup", True),
            )
        return ShieldConfig()

    @property
    def spear(self) -> SpearConfig:
        return SpearConfig()

    @property
    def report(self) -> ReportConfig:
        return ReportConfig()

    @property
    def storage(self) -> LegacyStorageConfig:
        return LegacyStorageConfig(self._cfg)

    @property
    def tui(self) -> TuiConfig:
        return TuiConfig()

    @property
    def role(self) -> RoleConfig:
        raw_role = self._raw.get("role", {}) if isinstance(self._raw, dict) else {}
        if isinstance(raw_role, dict):
            return RoleConfig(default=raw_role.get("default", "pentester"))
        return RoleConfig()


# ── Helpers (retained for completeness / external callers) ───────────────

def _parse_scalar(value: str) -> Any:
    lowered = value.strip().lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    try:
        return int(value)
    except ValueError:
        return value
