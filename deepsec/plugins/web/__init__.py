from __future__ import annotations

from deepsec.plugins.web.headers import SecurityHeadersPlugin
from deepsec.plugins.web.js_endpoints import JavaScriptEndpointsPlugin
from deepsec.plugins.web.jwt import JWTClaimsPlugin

BUILTIN_WEB_PLUGINS = (
    SecurityHeadersPlugin,
    JWTClaimsPlugin,
    JavaScriptEndpointsPlugin,
)


__all__ = [
    "BUILTIN_WEB_PLUGINS",
    "JWTClaimsPlugin",
    "JavaScriptEndpointsPlugin",
    "SecurityHeadersPlugin",
]
