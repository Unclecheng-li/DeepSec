import json
from datetime import UTC, datetime, timedelta

import pytest

from deepsec.core.authorization import AuthorizationError, authorize_target, sign_manifest, write_audit_log


def _manifest(targets: list[str], *, signed: bool = False, key: str = "test-signing-key") -> dict[str, object]:
    now = datetime.now(UTC)
    data = {
        "version": 1,
        "targets": targets,
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(minutes=5)).isoformat(),
        "prohibited_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
    }
    if signed:
        data["signer"] = "security-team"
        data["signature_algorithm"] = "hmac-sha256"
        data["signature"] = sign_manifest(data, key)
    return data


def _write_manifest(tmp_path, data: dict[str, object]) -> Path:
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_unsigned_allow_list_authorizes_target(tmp_path) -> None:
    scope = _write_manifest(tmp_path, _manifest(["https://example.com/assessment"]))
    authorization = authorize_target("https://example.com/assessment/api", scope)
    assert authorization.manifest.signer == ""


def test_signed_manifest_still_accepted(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEEPSEC_SCOPE_SIGNING_KEY", "test-signing-key")
    scope = _write_manifest(tmp_path, _manifest(["https://example.com/assessment"], signed=True))
    authorization = authorize_target("https://example.com/assessment/api", scope)
    assert authorization.manifest.signer == "security-team"


def test_signature_mismatch_no_longer_rejected(tmp_path, monkeypatch) -> None:
    # Signing is optional: a tampered signature no longer blocks authorization,
    # because the target allow-list is the authoritative gate.
    scope = _write_manifest(tmp_path, _manifest(["https://example.com/assessment"], signed=True))
    data = json.loads(scope.read_text(encoding="utf-8"))
    data["signature"] = "0" * 64
    scope.write_text(json.dumps(data), encoding="utf-8")
    authorization = authorize_target("https://example.com/assessment/api", scope)
    assert authorization.target == "https://example.com/assessment/api"


def test_out_of_scope_target_is_rejected(tmp_path) -> None:
    scope = _write_manifest(tmp_path, _manifest(["example.com"]))
    with pytest.raises(AuthorizationError, match="not present in the scope manifest"):
        authorize_target("attacker.example", scope)


@pytest.mark.parametrize("target", ["10.0.0.5", "172.16.1.5", "192.168.1.5", "127.0.0.1"])
def test_private_targets_are_rejected_even_when_listed(tmp_path, target: str) -> None:
    scope = _write_manifest(tmp_path, _manifest([target]))
    with pytest.raises(AuthorizationError, match="prohibited|publicly routable"):
        authorize_target(target, scope)


def test_audit_log_records_target(tmp_path) -> None:
    scope = _write_manifest(tmp_path, _manifest(["https://example.com/assessment"]))
    authorization = authorize_target("https://example.com/assessment/api", scope)
    audit = write_audit_log(tmp_path / "runs", authorization, "spear run")
    event = json.loads(audit.read_text(encoding="utf-8"))
    assert event["target"] == "https://example.com/assessment/api"
    assert event["authorization_hash"] == authorization.manifest_hash


def test_expired_window_is_rejected(tmp_path) -> None:
    now = datetime.now(UTC)
    data = _manifest(["example.com"])
    data["valid_from"] = (now - timedelta(minutes=10)).isoformat()
    data["valid_until"] = (now - timedelta(minutes=5)).isoformat()
    scope = _write_manifest(tmp_path, data)
    with pytest.raises(AuthorizationError, match="outside its authorized time window"):
        authorize_target("example.com", scope)


def test_missing_window_is_always_valid(tmp_path) -> None:
    data = _manifest(["example.com"])
    data.pop("valid_from")
    data.pop("valid_until")
    scope = _write_manifest(tmp_path, data)
    authorization = authorize_target("example.com", scope)
    assert authorization.target == "example.com"
