from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from deepsec.plugins.base import PluginContext, VulnPlugin
from deepsec.plugins.result import PluginFinding, PluginResult, PluginStage, RiskLevel

IMPORTANT_HEADERS: dict[str, str] = {
    "content-security-policy": "Define a restrictive Content-Security-Policy.",
    "x-frame-options": "Set X-Frame-Options or use CSP frame-ancestors.",
    "x-content-type-options": "Set X-Content-Type-Options to nosniff.",
    "referrer-policy": "Set a privacy-aware Referrer-Policy.",
    "strict-transport-security": "Set Strict-Transport-Security on HTTPS responses.",
}


class SecurityHeadersPlugin(VulnPlugin):
    plugin_id = "builtin.web.headers"
    name = "Security Headers"
    version = "0.1.0"
    description = "Analyze supplied HTTP response headers for common low-risk hardening gaps."
    stages = (PluginStage.DISCOVERY, PluginStage.VERIFICATION)
    default_risk = RiskLevel.LOW

    def run(self, context: PluginContext) -> PluginResult:
        headers = _normalize_headers(context.options.get("headers"))
        if not headers:
            return PluginResult(
                plugin_id=self.plugin_id,
                stage=context.stage,
                messages=["No headers were supplied."],
            )

        findings: list[PluginFinding] = []
        missing = [name for name in IMPORTANT_HEADERS if name not in headers]
        if missing:
            findings.append(
                PluginFinding(
                    title="Missing common security headers",
                    risk=RiskLevel.LOW,
                    target=context.target,
                    vuln_type="security_headers",
                    description="One or more common browser hardening headers were not present in the supplied headers.",
                    evidence={"missing_headers": missing},
                    remediation="Add the missing headers where they match the application's deployment model.",
                    confidence=0.75,
                )
            )

        weak_csp = _weak_csp_reason(headers.get("content-security-policy", ""))
        if weak_csp:
            findings.append(
                PluginFinding(
                    title="Weak Content-Security-Policy",
                    risk=RiskLevel.LOW,
                    target=context.target,
                    vuln_type="security_headers",
                    description=weak_csp,
                    evidence={"content_security_policy": headers["content-security-policy"]},
                    remediation=IMPORTANT_HEADERS["content-security-policy"],
                    confidence=0.7,
                )
            )

        hsts = headers.get("strict-transport-security", "")
        if hsts and "max-age=0" in hsts.lower():
            findings.append(
                PluginFinding(
                    title="Strict-Transport-Security disables HSTS",
                    risk=RiskLevel.LOW,
                    target=context.target,
                    vuln_type="security_headers",
                    description="The supplied Strict-Transport-Security header disables HSTS.",
                    evidence={"strict_transport_security": hsts},
                    remediation=IMPORTANT_HEADERS["strict-transport-security"],
                    confidence=0.85,
                )
            )

        return PluginResult(
            plugin_id=self.plugin_id,
            stage=context.stage,
            findings=findings,
            metadata={"checked_headers": sorted(headers)},
        )


def _normalize_headers(value: Any) -> dict[str, str]:
    if isinstance(value, Mapping):
        return {str(key).strip().lower(): str(item).strip() for key, item in value.items() if key}
    return {}


def _weak_csp_reason(value: str) -> str:
    normalized = value.lower()
    if not normalized:
        return ""
    if "'unsafe-inline'" in normalized or "'unsafe-eval'" in normalized:
        return "The supplied Content-Security-Policy allows unsafe script execution patterns."
    if "default-src" not in normalized and "script-src" not in normalized:
        return "The supplied Content-Security-Policy does not define default-src or script-src."
    return ""
