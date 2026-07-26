"""VulnClaw-owned, sandbox-native HTTP traffic evidence store.

A single capture layer (mitmproxy addon + headless Playwright, plus optional
Burp / chrome-devtools overlays) writes every in-scope request/response to an
append-only JSONL index plus raw blob files under ``evidence/traffic/``.
Findings reference a captured pair by ``request_id``; the report generator
inlines the raw request/response that proved each verified finding.
"""

from __future__ import annotations

from deepsec.traffic.capture import TrafficCapture
from deepsec.traffic.models import (
    SOURCE_BROWSER,
    SOURCE_MANUAL_REPLAY,
    SOURCE_PROXY,
    CapturedExchange,
    CapturedRequest,
    CapturedResponse,
    ScopeMode,
    Target,
    TrafficRecord,
)
from deepsec.traffic.scope import ScopeChecker
from deepsec.traffic.store import TrafficStore, compute_request_id

__all__ = [
    "TrafficCapture",
    "TrafficStore",
    "ScopeChecker",
    "ScopeMode",
    "Target",
    "CapturedExchange",
    "CapturedRequest",
    "CapturedResponse",
    "TrafficRecord",
    "compute_request_id",
    "SOURCE_PROXY",
    "SOURCE_BROWSER",
    "SOURCE_MANUAL_REPLAY",
]
