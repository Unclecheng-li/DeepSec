"""Structured target modeling for run-backed persistence."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Sequence
from urllib.parse import urlsplit, urlunsplit

TargetKind = Literal["local_repo", "repo_url", "web_url", "domain", "ip"]
IngressMode = Literal["copy", "mount"]
ScopeMode = Literal["auto", "diff", "full"]

TARGET_KINDS: set[str] = {"local_repo", "repo_url", "web_url", "domain", "ip"}
_REPO_HOSTS = {
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "gitee.com",
    "codeberg.org",
}


@dataclass(frozen=True)
class Target:
    """A normalized target that can be persisted independently inside a run."""

    kind: TargetKind
    raw: str
    canonical: str
    label: str | None = None
    ingress_mode: IngressMode = "copy"
    scope_mode: ScopeMode = "auto"
    diff_base: str | None = None

    @property
    def state_key(self) -> str:
        return target_state_key(self.canonical)

    @property
    def target_id(self) -> str:
        return self.state_key

    def to_manifest(self, *, state_path: str | None = None) -> dict[str, str | None]:
        data: dict[str, str | None] = {
            "target_id": self.target_id,
            "state_key": self.state_key,
            "input": self.raw,
            "type": self.kind,
            "canonical": self.canonical,
            "label": self.label,
            "ingress_mode": self.ingress_mode,
            "scope_mode": self.scope_mode,
            "diff_base": self.diff_base,
        }
        if state_path is not None:
            data["state_path"] = state_path
        return data


def target_state_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def legacy_target_state_key(raw: str) -> str:
    return target_state_key(raw)


def build_targets(
    primary: str | None,
    additional: Sequence[str] | None = None,
    *,
    target_type: str | None = None,
    mount: bool = False,
    scope_mode: ScopeMode = "auto",
    diff_base: str | None = None,
) -> list[Target]:
    """Build normalized targets from CLI/Web inputs, preserving input order."""
    raw_values = [item for item in [primary, *(additional or [])] if item]
    targets: list[Target] = []
    seen: set[str] = set()
    for raw in raw_values:
        target = parse_target(
            raw,
            target_type=target_type,
            ingress_mode="mount" if mount else "copy",
            scope_mode=scope_mode,
            diff_base=diff_base,
        )
        if target.state_key in seen:
            continue
        seen.add(target.state_key)
        targets.append(target)
    if not targets:
        raise ValueError("at least one target is required")
    return targets


def parse_target(
    raw: str,
    *,
    target_type: str | None = None,
    ingress_mode: IngressMode = "copy",
    scope_mode: ScopeMode = "auto",
    diff_base: str | None = None,
    label: str | None = None,
) -> Target:
    value = raw.strip()
    if not value:
        raise ValueError("target cannot be empty")

    kind = _resolve_kind(value, target_type)
    return Target(
        kind=kind,
        raw=value,
        canonical=_canonicalize(value, kind),
        label=label,
        ingress_mode=ingress_mode,
        scope_mode=scope_mode,
        diff_base=diff_base,
    )


def _resolve_kind(raw: str, target_type: str | None) -> TargetKind:
    if target_type:
        normalized = target_type.strip().lower().replace("-", "_")
        if normalized not in TARGET_KINDS:
            allowed = ", ".join(sorted(TARGET_KINDS))
            raise ValueError(f"target-type must be one of: {allowed}")
        return normalized  # type: ignore[return-value]
    return infer_target_kind(raw)


def infer_target_kind(raw: str) -> TargetKind:
    value = raw.strip()
    path = Path(value).expanduser()
    if path.exists():
        return "local_repo"

    parsed = urlsplit(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        if _looks_like_repo_url(parsed.hostname or "", parsed.path):
            return "repo_url"
        return "web_url"

    try:
        ipaddress.ip_address(value.strip("[]"))
        return "ip"
    except ValueError:
        pass

    return "domain"


def _looks_like_repo_url(host: str, path: str) -> bool:
    normalized_host = host.lower()
    parts = [part for part in path.strip("/").split("/") if part]
    if normalized_host in _REPO_HOSTS and len(parts) >= 2:
        return True
    if normalized_host.endswith(".github.com") and len(parts) >= 2:
        return True
    return False


def _canonicalize(raw: str, kind: TargetKind) -> str:
    if kind == "local_repo":
        return str(Path(raw).expanduser().resolve())
    if kind in {"repo_url", "web_url"}:
        return _canonicalize_url(raw)
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(raw.strip("[]")))
        except ValueError:
            return raw.strip().lower()
    return _canonicalize_domain(raw)


def _canonicalize_url(raw: str) -> str:
    parsed = urlsplit(raw.strip())
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower().rstrip(".")
    netloc = hostname
    if parsed.port:
        default_port = (scheme == "http" and parsed.port == 80) or (
            scheme == "https" and parsed.port == 443
        )
        if not default_port:
            netloc = f"{hostname}:{parsed.port}"
    path = re.sub(r"/+", "/", parsed.path or "/").rstrip("/") or "/"
    return urlunsplit((scheme, netloc, path, "", ""))


def _canonicalize_domain(raw: str) -> str:
    value = raw.strip().lower().rstrip(".")
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlsplit(value)
        return (parsed.hostname or value).lower().rstrip(".")
    return value
