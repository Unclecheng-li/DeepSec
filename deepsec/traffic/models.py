"""Data model for the VulnClaw-owned traffic evidence store.

These dataclasses describe HTTP exchanges independently of *how* they were
captured (mitmproxy proxy, headless Playwright, or an overlay MCP server such as
Burp / chrome-devtools). The capture layer normalizes every backend into a
:class:`CapturedExchange`, so the store and the agent-facing tools only ever
speak this one shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Recognized capture sources, mirrored in the JSONL index ``source`` field.
SOURCE_PROXY = "proxy"
SOURCE_BROWSER = "browser"
SOURCE_MANUAL_REPLAY = "manual-replay"
VALID_SOURCES = frozenset({SOURCE_PROXY, SOURCE_BROWSER, SOURCE_MANUAL_REPLAY})


def coerce_headers(value: Any) -> dict[str, str]:
    """Coerce a backend's headers into a ``{str: str}`` dict.

    Accepts a mapping (mitmproxy / Burp), a list of ``{name, value}`` pairs
    (chrome-devtools / HAR), or anything else (→ empty). Shared by every capture
    backend so header normalization lives in one place.
    """
    if isinstance(value, list):
        headers: dict[str, str] = {}
        for item in value:
            if isinstance(item, dict) and "name" in item:
                headers[str(item["name"])] = str(item.get("value", ""))
        return headers
    # dict, or any mapping-like object exposing .items() (e.g. mitmproxy Headers).
    if hasattr(value, "items"):
        try:
            return {str(k): str(v) for k, v in value.items()}
        except Exception:
            return {}
    return {}


class ScopeMode(str, Enum):
    """How strictly a request host must match the run's Target list.

    ``strict``    — host must equal a target host exactly.
    ``subdomain`` — host may equal a target host or be a subdomain of it.
    ``open``      — no host filtering (everything is in scope).
    """

    STRICT = "strict"
    SUBDOMAIN = "subdomain"
    OPEN = "open"


@dataclass
class Target:
    """A single in-scope target used for capture-time scope filtering.

    This is a deliberately small stand-in for the richer ``Target`` model owned
    by the scope PRD; it carries only the fields the traffic scope filter needs
    and is forward-compatible with a superset model.
    """

    host: str
    port: int | None = None
    path_prefix: str | None = None

    def __post_init__(self) -> None:
        self.host = (self.host or "").strip().lower()
        if self.path_prefix and not self.path_prefix.startswith("/"):
            self.path_prefix = "/" + self.path_prefix


@dataclass
class CapturedRequest:
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    http_version: str = "HTTP/1.1"


@dataclass
class CapturedResponse:
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    reason: str = ""
    http_version: str = "HTTP/1.1"


@dataclass
class CapturedExchange:
    """A request paired with its response (response may be absent)."""

    request: CapturedRequest
    response: CapturedResponse | None = None


@dataclass
class TrafficRecord:
    """The stored index entry for one captured exchange."""

    request_id: str
    seq: int
    timestamp: str
    method: str
    url: str
    host: str
    path: str
    status: int
    content_length: int
    source: str
    tags: list[str] = field(default_factory=list)

    def to_index(self) -> dict:
        return {
            "request_id": self.request_id,
            "seq": self.seq,
            "timestamp": self.timestamp,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "status": self.status,
            "content_length": self.content_length,
            "source": self.source,
            "tags": list(self.tags),
        }
