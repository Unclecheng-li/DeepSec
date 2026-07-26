"""Validated hot-loaded role and external-tool catalogs."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

logger = logging.getLogger(__name__)

ROLE_NAMES = frozenset({"pentester", "auditor", "redteam", "blueteam", "ctf_player"})
TOOL_CATEGORIES = frozenset({"recon", "exploit", "verify", "report"})
INSTALL_METHODS = frozenset({"pip", "apt", "cargo", "go_install", "binary_download", "scoop", "brew", "manual"})


class Role(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    mode: Literal["shield", "spear"]
    tools: list[str] = Field(default_factory=list)
    skills: list[str] = Field(default_factory=list)
    llm: dict[str, Any] = Field(default_factory=dict)
    prompt_prefix: str = ""
    max_rounds: int = Field(default=5, ge=1, le=100)
    max_parallel: int = Field(default=1, ge=1, le=32)


class ToolInstall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check: str = Field(min_length=1)
    command: str = Field(min_length=1)
    method: str = "manual"

    @field_validator("method")
    @classmethod
    def known_install_method(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in INSTALL_METHODS:
            raise ValueError(f"unsupported install method {value!r}; expected one of {sorted(INSTALL_METHODS)}")
        return normalized


class ToolDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    category: str
    install: ToolInstall
    parameters: dict[str, Any] = Field(default_factory=dict)
    output: dict[str, Any] = Field(default_factory=dict)
    skills: list[str] = Field(default_factory=list)
    min_role: list[str] = Field(default_factory=lambda: ["pentester", "redteam", "ctf_player"])

    @field_validator("category")
    @classmethod
    def known_category(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in TOOL_CATEGORIES:
            raise ValueError(f"unsupported category {value!r}; expected one of {sorted(TOOL_CATEGORIES)}")
        return normalized

    @field_validator("min_role", mode="before")
    @classmethod
    def normalize_roles(cls, value: Any) -> list[str]:
        values = [value] if isinstance(value, str) else value
        if not isinstance(values, list) or not values:
            raise ValueError("min_role must be a non-empty role name or list of role names")
        normalized = [str(role).strip().lower() for role in values]
        unknown = set(normalized) - ROLE_NAMES - {"*"}
        if unknown:
            raise ValueError(f"unknown min_role values: {sorted(unknown)}")
        return normalized


def catalog_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_role(name: str, root: Path | None = None) -> Role:
    root = root or catalog_root() / "roles"
    return _load_model(root / f"{name}.yaml", Role)


def list_roles(root: Path | None = None) -> list[Role]:
    root = root or catalog_root() / "roles"
    return _load_all(root, Role)


def load_tools(root: Path | None = None) -> list[ToolDefinition]:
    root = root or catalog_root() / "tools"
    return _load_all(root, ToolDefinition)


def tools_for_role(role: str, root: Path | None = None) -> list[ToolDefinition]:
    normalized = role.strip().lower()
    if normalized not in ROLE_NAMES:
        raise ValueError(f"Unknown DeepSec role: {role}")
    return [tool for tool in load_tools(root) if "*" in tool.min_role or normalized in tool.min_role]


def _load_all(root: Path, model: type[BaseModel]) -> list[Any]:
    if not root.exists():
        logger.warning("DeepSec catalog directory does not exist: %s", root)
        return []
    loaded: list[Any] = []
    for path in sorted(root.glob("*.yaml")):
        try:
            loaded.append(_load_model(path, model))
        except (OSError, yaml.YAMLError, ValidationError, ValueError) as error:
            logger.warning("Skipping invalid DeepSec catalog entry %s: %s", path.name, error)
    return loaded


def _load_model(path: Path, model: type[BaseModel]) -> Any:
    if not path.exists():
        raise ValueError(f"Configuration does not exist: {path}")
    content = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(content, dict):
        raise ValueError(f"Configuration must be a mapping: {path}")
    return model.model_validate(content)
