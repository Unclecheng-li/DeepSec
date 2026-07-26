from __future__ import annotations

import base64
import json
from typing import Any

from deepsec.plugins.base import PluginContext, VulnPlugin
from deepsec.plugins.result import PluginFinding, PluginResult, PluginStage, RiskLevel


class JWTClaimsPlugin(VulnPlugin):
    plugin_id = "builtin.web.jwt"
    name = "JWT Claims"
    version = "0.1.0"
    description = "Analyze a supplied JWT without verifying signatures or making network calls."
    stages = (PluginStage.DISCOVERY, PluginStage.VERIFICATION)
    default_risk = RiskLevel.LOW

    def run(self, context: PluginContext) -> PluginResult:
        token = str(context.options.get("token") or "").strip()
        if not token:
            return PluginResult(
                plugin_id=self.plugin_id,
                stage=context.stage,
                messages=["No token was supplied."],
            )

        decoded = _decode_jwt(token)
        if decoded is None:
            return PluginResult(
                plugin_id=self.plugin_id,
                stage=context.stage,
                ok=False,
                error="Invalid JWT format.",
            )

        header, payload = decoded
        findings: list[PluginFinding] = []
        algorithm = str(header.get("alg", "")).lower()
        if algorithm in {"", "none"}:
            findings.append(
                PluginFinding(
                    title="JWT uses an unsigned or missing algorithm",
                    risk=RiskLevel.LOW,
                    target=context.target,
                    vuln_type="jwt",
                    description="The supplied token header does not require a signing algorithm.",
                    evidence={"alg": header.get("alg")},
                    remediation="Reject unsigned tokens and enforce an expected signing algorithm.",
                    confidence=0.9,
                )
            )

        missing_claims = [claim for claim in ("exp", "iat", "iss", "aud") if claim not in payload]
        if missing_claims:
            findings.append(
                PluginFinding(
                    title="JWT is missing common validation claims",
                    risk=RiskLevel.LOW,
                    target=context.target,
                    vuln_type="jwt",
                    description="The supplied token payload lacks claims commonly used during validation.",
                    evidence={"missing_claims": missing_claims},
                    remediation="Require appropriate issuer, audience, issued-at, and expiration validation.",
                    confidence=0.75,
                )
            )

        return PluginResult(
            plugin_id=self.plugin_id,
            stage=context.stage,
            findings=findings,
            metadata={
                "header_keys": sorted(str(key) for key in header),
                "payload_keys": sorted(str(key) for key in payload),
            },
        )


def _decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        header = _decode_segment(parts[0])
        payload = _decode_segment(parts[1])
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


def _decode_segment(segment: str) -> Any:
    padding = "=" * (-len(segment) % 4)
    raw = base64.urlsafe_b64decode(f"{segment}{padding}")
    return json.loads(raw.decode("utf-8"))
