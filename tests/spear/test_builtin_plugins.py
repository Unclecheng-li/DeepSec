from __future__ import annotations

import base64
import json

from deepsec.plugins import PluginContext, PluginStage, RiskLevel
from deepsec.plugins.web import (
    BUILTIN_WEB_PLUGINS,
    JavaScriptEndpointsPlugin,
    JWTClaimsPlugin,
    SecurityHeadersPlugin,
)


def test_builtin_web_plugins_are_exported() -> None:
    plugin_ids = {plugin_cls.plugin_id for plugin_cls in BUILTIN_WEB_PLUGINS}

    assert plugin_ids == {
        "builtin.web.headers",
        "builtin.web.jwt",
        "builtin.web.js_endpoints",
    }


def test_security_headers_plugin_reports_missing_headers_from_options_only() -> None:
    context = PluginContext(
        target="https://example.com",
        stage=PluginStage.DISCOVERY,
        options={"headers": {"Content-Security-Policy": "default-src 'self'"}},
    )

    result = SecurityHeadersPlugin().run(context)

    assert result.plugin_id == "builtin.web.headers"
    assert result.ok is True
    assert result.findings
    assert result.findings[0].risk == RiskLevel.LOW
    assert "x-frame-options" in result.findings[0].evidence["missing_headers"]


def test_security_headers_plugin_handles_missing_input_without_findings() -> None:
    result = SecurityHeadersPlugin().run(PluginContext(options={}))

    assert result.ok is True
    assert result.findings == []
    assert result.messages == ["No headers were supplied."]


def test_jwt_plugin_reports_unsigned_and_missing_claims() -> None:
    token = _jwt({"alg": "none", "typ": "JWT"}, {"sub": "user-1"})
    context = PluginContext(
        target="https://example.com",
        stage=PluginStage.VERIFICATION,
        options={"token": token},
    )

    result = JWTClaimsPlugin().run(context)

    titles = {finding.title for finding in result.findings}
    assert "JWT uses an unsigned or missing algorithm" in titles
    assert "JWT is missing common validation claims" in titles
    assert result.metadata["payload_keys"] == ["sub"]


def test_jwt_plugin_rejects_invalid_format() -> None:
    result = JWTClaimsPlugin().run(PluginContext(options={"token": "not-a-jwt"}))

    assert result.ok is False
    assert result.error == "Invalid JWT format."


def test_js_endpoints_plugin_extracts_endpoints_from_content() -> None:
    context = PluginContext(
        target="https://example.com",
        stage=PluginStage.RECON,
        options={
            "content": """
                fetch("/api/users");
                const admin = '/admin/debug';
                const cdn = "https://cdn.example.com/assets/app.js";
            """,
        },
    )

    result = JavaScriptEndpointsPlugin().run(context)

    assert result.findings[0].risk == RiskLevel.INFO
    evidence = result.findings[0].evidence
    assert evidence["endpoints"] == [
        "/admin/debug",
        "/api/users",
        "https://cdn.example.com/assets/app.js",
    ]
    assert evidence["interesting_endpoints"] == ["/admin/debug"]


def _jwt(header: dict[str, object], payload: dict[str, object]) -> str:
    return f"{_segment(header)}.{_segment(payload)}."


def _segment(value: dict[str, object]) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")
