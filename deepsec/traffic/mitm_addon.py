"""mitmproxy addon: route all in-scope proxy traffic through the capture layer.

This is the Tier-A HTTP capture backend. It runs inside the per-run Docker
sandbox as a VulnClaw-maintained mitmproxy addon; every request/response flow is
normalized into a :class:`CapturedExchange` and handed to a
:class:`TrafficCapture`, which applies scope filtering before storing. Burp MCP
stays an optional interactive overlay (see ``normalize``); headless/CI never
depends on it.

``mitmproxy`` is an optional dependency — importing this module never requires
it. :func:`mitmproxy_available` gates the real runtime; the addon logic itself
is transport-agnostic and unit-testable against a stub flow.
"""

from __future__ import annotations

from typing import Any

from deepsec.traffic.capture import TrafficCapture
from deepsec.traffic.models import (
    SOURCE_PROXY,
    CapturedExchange,
    CapturedRequest,
    CapturedResponse,
    coerce_headers,
)


def mitmproxy_available() -> bool:
    """Whether the mitmproxy runtime is importable in this environment."""
    try:
        import mitmproxy  # noqa: F401
    except Exception:
        return False
    return True


def exchange_from_flow(flow: Any) -> CapturedExchange:
    """Build a :class:`CapturedExchange` from a mitmproxy ``HTTPFlow``.

    Kept free of any ``mitmproxy`` import so it can be exercised with a stub flow
    that duck-types ``flow.request`` / ``flow.response``.
    """
    req = flow.request
    request = CapturedRequest(
        method=str(getattr(req, "method", "GET")),
        url=str(getattr(req, "url", "")),
        headers=coerce_headers(getattr(req, "headers", {})),
        body=bytes(getattr(req, "raw_content", b"") or getattr(req, "content", b"") or b""),
        http_version=str(getattr(req, "http_version", "HTTP/1.1")),
    )
    response = None
    resp = getattr(flow, "response", None)
    if resp is not None:
        response = CapturedResponse(
            status=int(getattr(resp, "status_code", 0) or 0),
            headers=coerce_headers(getattr(resp, "headers", {})),
            body=bytes(getattr(resp, "raw_content", b"") or getattr(resp, "content", b"") or b""),
            reason=str(getattr(resp, "reason", "")),
            http_version=str(getattr(resp, "http_version", "HTTP/1.1")),
        )
    return CapturedExchange(request=request, response=response)


class TrafficCaptureAddon:
    """mitmproxy addon that captures each completed flow into the store."""

    def __init__(self, capture: TrafficCapture) -> None:
        self.capture = capture

    def capture_flow(self, flow: Any) -> str | None:
        """Normalize + capture a flow; returns the ``request_id`` or ``None``."""
        exchange = exchange_from_flow(flow)
        return self.capture.capture(exchange, source=SOURCE_PROXY, tags=["proxy"])

    # mitmproxy event hook (called once the response is available).
    def response(self, flow: Any) -> None:  # pragma: no cover - requires runtime
        self.capture_flow(flow)
