"""Capture-time scope filtering.

The proxy addon and browser layer check every request against the run's active
:class:`Target` list *before* logging, so out-of-scope traffic (CDNs, ads,
unrelated third-party calls) is dropped rather than stored.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from deepsec.traffic.models import ScopeMode, Target


def _host_port(url: str) -> tuple[str, int | None, str]:
    """Return ``(host, port, path)`` for ``url`` (host lower-cased)."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    port = parts.port
    if port is None:
        if parts.scheme == "https":
            port = 443
        elif parts.scheme == "http":
            port = 80
    path = parts.path or "/"
    return host, port, path


def _host_matches(host: str, target: Target, mode: ScopeMode) -> bool:
    if not target.host:
        return False
    if host == target.host:
        return True
    if mode is ScopeMode.SUBDOMAIN:
        return host.endswith("." + target.host)
    return False


class ScopeChecker:
    """Decide whether a URL is in scope for the current run."""

    def __init__(
        self, targets: list[Target] | None = None, mode: ScopeMode | str = ScopeMode.STRICT
    ) -> None:
        self.targets = list(targets or [])
        self.mode = mode if isinstance(mode, ScopeMode) else ScopeMode(str(mode))

    def in_scope(self, url: str) -> bool:
        if self.mode is ScopeMode.OPEN:
            return True
        if not self.targets:
            # No targets declared: nothing is in scope under strict/subdomain.
            return False

        host, port, path = _host_port(url)
        if not host:
            return False

        for target in self.targets:
            if not _host_matches(host, target, self.mode):
                continue
            if target.port is not None and port is not None and target.port != port:
                continue
            if target.path_prefix and not path.startswith(target.path_prefix):
                continue
            return True
        return False
