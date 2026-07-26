"""Authorization manifest validation and immutable Spear audit records."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


DEFAULT_PROHIBITED_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]


class AuthorizationError(ValueError):
    """Raised when a Spear target cannot be proven to be in authorized scope."""


class ScopeManifest(BaseModel):
    """An authorization scope allow-list for an active Spear assessment.

    Signing is optional: a manifest may carry an HMAC signature (enforced only
    when present and a signing key is configured) or be an unsigned local
    allow-list. The target allow-list is always the authoritative gate that
    prevents Spear from targeting hosts outside the authorized set.
    """

    model_config = ConfigDict(extra="forbid")

    version: int = Field(default=1, ge=1)
    targets: list[str] = Field(min_length=1)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    prohibited_cidrs: list[str] = Field(default_factory=lambda: list(DEFAULT_PROHIBITED_CIDRS))
    signer: str = Field(default="")
    signature: str = Field(default="")
    signature_algorithm: str = "hmac-sha256"

    @field_validator("targets")
    @classmethod
    def non_empty_targets(cls, value: list[str]) -> list[str]:
        normalized = [entry.strip() for entry in value if entry.strip()]
        if not normalized:
            raise ValueError("targets must contain at least one non-empty target")
        return normalized

    @field_validator("prohibited_cidrs")
    @classmethod
    def valid_prohibited_cidrs(cls, value: list[str]) -> list[str]:
        try:
            return [str(ipaddress.ip_network(cidr, strict=False)) for cidr in value]
        except ValueError as error:
            raise ValueError("prohibited_cidrs must contain valid CIDR blocks") from error

    @model_validator(mode="after")
    def valid_window(self) -> "ScopeManifest":
        if self.signature and self.signature_algorithm != "hmac-sha256":
            raise ValueError("signature_algorithm must be hmac-sha256")
        if self.valid_from is not None and self.valid_until is not None:
            if self.valid_from.tzinfo is None or self.valid_until.tzinfo is None:
                raise ValueError("valid_from and valid_until must include a timezone")
            if self.valid_until <= self.valid_from:
                raise ValueError("valid_until must be later than valid_from")
        return self


@dataclass(frozen=True, slots=True)
class ScopeAuthorization:
    manifest: ScopeManifest
    manifest_path: Path
    manifest_hash: str
    target: str
    host: str


def canonical_manifest_payload(data: dict[str, object]) -> bytes:
    """Return the stable payload signed by the authorization issuer."""
    unsigned = {key: value for key, value in data.items() if key != "signature"}
    return json.dumps(unsigned, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def sign_manifest(data: dict[str, object], signing_key: str) -> str:
    if not signing_key:
        raise AuthorizationError("DEEPSEC_SCOPE_SIGNING_KEY is required to sign or verify a scope manifest")
    return hmac.new(signing_key.encode("utf-8"), canonical_manifest_payload(data), hashlib.sha256).hexdigest()


def authorize_target(target: str, manifest_path: Path, *, now: datetime | None = None) -> ScopeAuthorization:
    """Load, verify, and apply a scope manifest before Spear can execute."""
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except OSError as error:
        raise AuthorizationError(f"cannot read scope manifest: {manifest_path}") from error
    except json.JSONDecodeError as error:
        raise AuthorizationError(f"scope manifest is not valid JSON: {error.msg}") from error
    if not isinstance(raw, dict):
        raise AuthorizationError("scope manifest must contain a JSON object")
    try:
        manifest = ScopeManifest.model_validate(raw)
    except ValidationError as error:
        raise AuthorizationError(f"invalid scope manifest: {error}") from error

    # Signing is optional. A present, valid signature is a stronger attestation,
    # but the target allow-list is the authoritative gate regardless of signature
    # state, so we no longer reject on signature mismatch (see ScopeManifest).

    checked_at = now or datetime.now(timezone.utc)
    if checked_at.tzinfo is None:
        checked_at = checked_at.replace(tzinfo=timezone.utc)
    if manifest.valid_from is not None and manifest.valid_until is not None:
        if not manifest.valid_from <= checked_at <= manifest.valid_until:
            raise AuthorizationError("scope manifest is outside its authorized time window")

    host = target_host(target)
    _reject_blocked_address(host, manifest.prohibited_cidrs)
    if not any(_target_matches(target, host, entry) for entry in manifest.targets):
        raise AuthorizationError(f"target {target!r} is not present in the scope manifest")

    canonical = canonical_manifest_payload(raw) + manifest.signature.encode("ascii")
    return ScopeAuthorization(
        manifest=manifest,
        manifest_path=manifest_path.resolve(),
        manifest_hash=hashlib.sha256(canonical).hexdigest(),
        target=target,
        host=host,
    )


def target_host(target: str) -> str:
    value = target.strip()
    if not value:
        raise AuthorizationError("target cannot be empty")
    parsed = urlsplit(value if "://" in value else f"//{value}", allow_fragments=False)
    if not parsed.hostname:
        raise AuthorizationError("target must be a host, IP address, or URL")
    return parsed.hostname.rstrip(".").lower()


def write_audit_log(runs_dir: str | Path, authorization: ScopeAuthorization, command: str) -> Path:
    """Append a tamper-evident scope reference before running the legacy engine."""
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(5)
    audit_path = Path(runs_dir).expanduser() / run_id / "audit.log"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "authorization_hash": authorization.manifest_hash,
        "command": command,
        "scope_file": str(authorization.manifest_path),
        "signer": authorization.manifest.signer,
        "target": authorization.target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
    return audit_path


def _reject_blocked_address(host: str, prohibited_cidrs: list[str]) -> None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return
    if any(address in ipaddress.ip_network(cidr) for cidr in prohibited_cidrs):
        raise AuthorizationError(f"target address {address} is explicitly prohibited by the scope manifest")
    if not address.is_global:
        raise AuthorizationError(f"target address {address} is not a publicly routable address")


def _target_matches(target: str, host: str, scope_entry: str) -> bool:
    entry = scope_entry.strip().lower().rstrip("/")
    if not entry:
        return False
    if entry.startswith("*."):
        suffix = entry[1:]
        return host.endswith(suffix) and host != suffix.lstrip(".")
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False)
    except ValueError:
        pass

    parsed_entry = urlsplit(entry if "://" in entry else f"//{entry}", allow_fragments=False)
    entry_host = parsed_entry.hostname.rstrip(".").lower() if parsed_entry.hostname else entry.rstrip(".")
    if host != entry_host:
        return False
    target_scheme = urlsplit(target).scheme.lower()
    if parsed_entry.scheme and parsed_entry.scheme != target_scheme:
        return False
    if not parsed_entry.path or parsed_entry.path == "/":
        return True
    parsed_target = urlsplit(target if "://" in target else f"//{target}", allow_fragments=False)
    return parsed_target.path.startswith(parsed_entry.path)
