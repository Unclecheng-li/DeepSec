"""The one capture seam every backend routes through.

Proxy (mitmproxy), browser (Playwright), and overlay (Burp / chrome-devtools)
captures all call :meth:`TrafficCapture.capture`. It applies scope filtering
*before* writing, so out-of-scope traffic is dropped rather than stored, then
records the exchange in the shared :class:`TrafficStore`.
"""

from __future__ import annotations

from deepsec.traffic.models import CapturedExchange
from deepsec.traffic.scope import ScopeChecker
from deepsec.traffic.store import TrafficStore


class TrafficCapture:
    def __init__(self, store: TrafficStore, scope: ScopeChecker | None = None) -> None:
        self.store = store
        self.scope = scope or ScopeChecker()

    def capture(
        self,
        exchange: CapturedExchange,
        *,
        source: str,
        tags: list[str] | None = None,
        timestamp: str | None = None,
    ) -> str | None:
        """Record ``exchange`` if in scope; return its ``request_id`` or ``None``.

        A ``None`` return means the request was out of scope and dropped (no
        JSONL line, no blob files written).
        """
        if not self.scope.in_scope(exchange.request.url):
            return None
        record = self.store.record(
            exchange, source=source, tags=tags, timestamp=timestamp
        )
        return record.request_id
