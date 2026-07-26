from __future__ import annotations

import re

from deepsec.plugins.base import PluginContext, VulnPlugin
from deepsec.plugins.result import PluginFinding, PluginResult, PluginStage, RiskLevel

ENDPOINT_PATTERN = re.compile(
    r"""(?P<quote>["'`])(?P<value>(?:https?://[^"'`\s<>()]+|/(?:api|admin|auth|graphql|v\d|static|assets|internal)[^"'`\s<>()]*))(?P=quote)""",
    re.IGNORECASE,
)
SENSITIVE_WORDS = ("admin", "debug", "internal", "graphql", "token", "secret")


class JavaScriptEndpointsPlugin(VulnPlugin):
    plugin_id = "builtin.web.js_endpoints"
    name = "JavaScript Endpoints"
    version = "0.1.0"
    description = "Extract interesting endpoints from supplied JavaScript content."
    stages = (PluginStage.RECON, PluginStage.DISCOVERY)
    default_risk = RiskLevel.INFO

    def run(self, context: PluginContext) -> PluginResult:
        content = str(context.options.get("content") or "")
        if not content:
            return PluginResult(
                plugin_id=self.plugin_id,
                stage=context.stage,
                messages=["No content was supplied."],
            )

        endpoints = sorted({match.group("value").rstrip(".,;") for match in ENDPOINT_PATTERN.finditer(content)})
        if not endpoints:
            return PluginResult(
                plugin_id=self.plugin_id,
                stage=context.stage,
                messages=["No endpoints were found."],
            )

        interesting = [
            endpoint
            for endpoint in endpoints
            if any(word in endpoint.lower() for word in SENSITIVE_WORDS)
        ]
        finding = PluginFinding(
            title="JavaScript endpoints discovered",
            risk=RiskLevel.INFO,
            target=context.target,
            vuln_type="javascript_endpoint_discovery",
            description="The supplied JavaScript content contains endpoints useful for manual review.",
            evidence={"endpoints": endpoints, "interesting_endpoints": interesting},
            remediation="Review discovered endpoints for exposure, authorization, and environment leakage.",
            confidence=0.8,
        )
        return PluginResult(
            plugin_id=self.plugin_id,
            stage=context.stage,
            findings=[finding],
            metadata={"endpoint_count": len(endpoints)},
        )
