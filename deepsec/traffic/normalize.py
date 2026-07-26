"""Normalize overlay captures into the shared store schema.

Burp (`get_proxy_http_history`) and chrome-devtools MCP servers stay optional
interactive overlays, but when attached their captures are normalized into the
same :class:`CapturedExchange` shape and land in the same store with a coherent
``source`` — Burp is a proxy (``source=proxy``), chrome-devtools is a browser
(``source=browser``). The mappers are tolerant of the differing field names
these tools use.
"""

from __future__ import annotations

from typing import Any

from deepsec.traffic.capture import TrafficCapture
from deepsec.traffic.models import (
    SOURCE_BROWSER,
    SOURCE_PROXY,
    CapturedExchange,
    CapturedRequest,
    CapturedResponse,
    coerce_headers,
)


def _as_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8", "replace")


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_burp_entry(entry: dict[str, Any]) -> CapturedExchange:
    """Map one Burp proxy-history entry into a :class:`CapturedExchange`."""
    req = entry.get("request", entry) if isinstance(entry.get("request"), dict) else entry
    resp = entry.get("response") if isinstance(entry.get("response"), dict) else None

    request = CapturedRequest(
        method=str(req.get("method", entry.get("method", "GET")) or "GET"),
        url=str(req.get("url", entry.get("url", "")) or ""),
        headers=coerce_headers(req.get("headers", entry.get("headers"))),
        body=_as_bytes(req.get("body", req.get("data"))),
    )
    response = None
    if resp is not None or "status" in entry or "status_code" in entry:
        source = resp or entry
        response = CapturedResponse(
            status=_int(source.get("status", source.get("status_code", 0))),
            headers=coerce_headers(source.get("headers")),
            body=_as_bytes(source.get("body", source.get("data"))),
            reason=str(source.get("reason", "")),
        )
    return CapturedExchange(request=request, response=response)


def normalize_chrome_devtools_entry(entry: dict[str, Any]) -> CapturedExchange:
    """Map one chrome-devtools network entry into a :class:`CapturedExchange`."""
    req = entry.get("request", {}) if isinstance(entry.get("request"), dict) else entry
    resp = entry.get("response") if isinstance(entry.get("response"), dict) else None

    request = CapturedRequest(
        method=str(req.get("method", "GET") or "GET"),
        url=str(req.get("url", entry.get("url", "")) or ""),
        headers=coerce_headers(req.get("headers")),
        body=_as_bytes(req.get("postData", req.get("body"))),
    )
    response = None
    if resp is not None:
        response = CapturedResponse(
            status=_int(resp.get("status", resp.get("statusCode", 0))),
            headers=coerce_headers(resp.get("headers")),
            body=_as_bytes(resp.get("body", entry.get("body"))),
            reason=str(resp.get("statusText", resp.get("reason", ""))),
        )
    return CapturedExchange(request=request, response=response)


def ingest_burp_history(
    capture: TrafficCapture, entries: list[dict[str, Any]]
) -> list[str]:
    """Normalize + capture a batch of Burp history entries; return kept ids."""
    kept: list[str] = []
    for entry in entries:
        exchange = normalize_burp_entry(entry)
        request_id = capture.capture(
            exchange, source=SOURCE_PROXY, tags=["burp", "overlay"]
        )
        if request_id:
            kept.append(request_id)
    return kept


def ingest_chrome_devtools(
    capture: TrafficCapture, entries: list[dict[str, Any]]
) -> list[str]:
    """Normalize + capture a batch of chrome-devtools entries; return kept ids."""
    kept: list[str] = []
    for entry in entries:
        exchange = normalize_chrome_devtools_entry(entry)
        request_id = capture.capture(
            exchange, source=SOURCE_BROWSER, tags=["chrome-devtools", "overlay"]
        )
        if request_id:
            kept.append(request_id)
    return kept
