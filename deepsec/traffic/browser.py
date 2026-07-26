"""Headless Playwright browser routed through the shared capture layer.

The browser is a VulnClaw-maintained headless Playwright instance inside the
sandbox, launched with the run's mitmproxy as its upstream proxy so that
browser-driven and direct-HTTP traffic land in one store. chrome-devtools MCP
stays an optional overlay (normalized via ``normalize``).

``playwright`` is an optional dependency — importing this module never requires
it. The request/response mapping (:func:`exchange_from_playwright`) is
transport-agnostic and unit-testable against stub objects; the launch helper is
gated behind :func:`playwright_available`.
"""

from __future__ import annotations

from typing import Any

from deepsec.traffic.capture import TrafficCapture
from deepsec.traffic.models import (
    SOURCE_BROWSER,
    CapturedExchange,
    CapturedRequest,
    CapturedResponse,
    coerce_headers,
)


def playwright_available() -> bool:
    """Whether the Playwright runtime is importable in this environment."""
    try:
        import playwright  # noqa: F401
    except Exception:
        return False
    return True


def exchange_from_playwright(request: Any, response: Any | None = None) -> CapturedExchange:
    """Build a :class:`CapturedExchange` from Playwright request/response objects.

    Accepts either live Playwright objects (whose ``headers`` / ``post_data`` are
    attributes or callables) or plain stubs exposing the same names.
    """

    def _call_or_attr(obj: Any, name: str, default: Any = None) -> Any:
        attr = getattr(obj, name, default)
        if callable(attr):
            try:
                return attr()
            except Exception:
                return default
        return attr

    body = _call_or_attr(request, "post_data", "") or ""
    captured_request = CapturedRequest(
        method=str(_call_or_attr(request, "method", "GET") or "GET"),
        url=str(_call_or_attr(request, "url", "") or ""),
        headers=coerce_headers(_call_or_attr(request, "headers", {})),
        body=body if isinstance(body, bytes) else str(body).encode("utf-8", "replace"),
    )
    captured_response = None
    if response is not None:
        resp_body = _call_or_attr(response, "body", b"") or b""
        captured_response = CapturedResponse(
            status=int(_call_or_attr(response, "status", 0) or 0),
            headers=coerce_headers(_call_or_attr(response, "headers", {})),
            body=resp_body if isinstance(resp_body, bytes) else str(resp_body).encode("utf-8", "replace"),
            reason=str(_call_or_attr(response, "status_text", "") or ""),
        )
    return CapturedExchange(request=captured_request, response=captured_response)


class BrowserCaptureBridge:
    """Wire Playwright request/response events into the shared capture layer."""

    def __init__(self, capture: TrafficCapture) -> None:
        self.capture = capture

    def on_response(self, request: Any, response: Any) -> str | None:
        exchange = exchange_from_playwright(request, response)
        return self.capture.capture(exchange, source=SOURCE_BROWSER, tags=["browser"])
