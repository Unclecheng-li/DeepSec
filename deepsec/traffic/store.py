"""Append-only traffic evidence store.

Mirrors the run directory's ``events.jsonl`` append-only pattern (no DB): every
captured exchange appends one line to ``requests.jsonl`` and writes raw blob
files under ``<request_id>/{request,response}``. ``request_id`` is a
content+sequence hash, so it is deterministic and stable across a resume — an
already-recorded id is read back unchanged, and the sequence counter resumes
from the existing line count so new captures never collide.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from deepsec.traffic.models import (
    VALID_SOURCES,
    CapturedExchange,
    CapturedRequest,
    TrafficRecord,
)
from deepsec.traffic.serialization import (
    parse_raw_request,
    raw_request_bytes,
    raw_response_bytes,
)

INDEX_FILENAME = "requests.jsonl"
REQUEST_BLOB = "request"
RESPONSE_BLOB = "response"


def compute_request_id(seq: int, request: CapturedRequest) -> str:
    """Content+sequence hash: deterministic given the sequence index + request."""
    hasher = hashlib.sha256()
    hasher.update(f"{seq:08d}\n{request.method} {request.url}\n".encode("utf-8", "replace"))
    hasher.update(request.body or b"")
    return hasher.hexdigest()[:16]


class TrafficStore:
    """Read/write access to one run's ``evidence/traffic/`` directory."""

    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)
        self.index_path = self.base_dir / INDEX_FILENAME

    # ── writing ──────────────────────────────────────────────────────────
    def _next_seq(self) -> int:
        if not self.index_path.exists():
            return 0
        count = 0
        with self.index_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    count += 1
        return count

    def record(
        self,
        exchange: CapturedExchange,
        *,
        source: str,
        tags: list[str] | None = None,
        timestamp: str | None = None,
    ) -> TrafficRecord:
        """Append one exchange to the store and return its index record."""
        if source not in VALID_SOURCES:
            raise ValueError(f"unknown traffic source: {source!r}")

        self.base_dir.mkdir(parents=True, exist_ok=True)
        seq = self._next_seq()
        request = exchange.request
        response = exchange.response
        request_id = compute_request_id(seq, request)

        blob_dir = self.base_dir / request_id
        blob_dir.mkdir(parents=True, exist_ok=True)
        (blob_dir / REQUEST_BLOB).write_bytes(raw_request_bytes(request))
        if response is not None:
            (blob_dir / RESPONSE_BLOB).write_bytes(raw_response_bytes(response))

        split = urlsplit(request.url)
        record = TrafficRecord(
            request_id=request_id,
            seq=seq,
            timestamp=timestamp or datetime.now().isoformat(),
            method=request.method,
            url=request.url,
            host=(split.hostname or "").lower(),
            path=split.path or "/",
            status=response.status if response is not None else 0,
            content_length=len(response.body) if response is not None else 0,
            source=source,
            tags=list(tags or []),
        )
        with self.index_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.to_index(), ensure_ascii=False) + "\n")
        return record

    # ── reading ──────────────────────────────────────────────────────────
    def entries(self) -> list[dict]:
        """Return every index record in capture order."""
        if not self.index_path.exists():
            return []
        rows: list[dict] = []
        with self.index_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows

    def find(self, request_id: str) -> dict | None:
        for row in self.entries():
            if row.get("request_id") == request_id:
                return row
        return None

    def _blob_dir(self, request_id: str) -> Path:
        return self.base_dir / request_id

    def request_blob(self, request_id: str) -> bytes | None:
        path = self._blob_dir(request_id) / REQUEST_BLOB
        return path.read_bytes() if path.exists() else None

    def response_blob(self, request_id: str) -> bytes | None:
        path = self._blob_dir(request_id) / RESPONSE_BLOB
        return path.read_bytes() if path.exists() else None

    def view(self, request_id: str) -> dict | None:
        """Return the index record plus decoded raw request/response text."""
        entry = self.find(request_id)
        if entry is None:
            return None
        request_blob = self.request_blob(request_id)
        response_blob = self.response_blob(request_id)
        view = dict(entry)
        view["request_text"] = request_blob.decode("utf-8", "replace") if request_blob else ""
        view["response_text"] = response_blob.decode("utf-8", "replace") if response_blob else ""
        return view

    def load_request(self, request_id: str) -> CapturedRequest | None:
        """Reconstruct the original request (for replay)."""
        entry = self.find(request_id)
        blob = self.request_blob(request_id)
        if entry is None or blob is None:
            return None
        return parse_raw_request(blob, url=str(entry.get("url", "")))

    def sitemap(self) -> dict[str, list[dict]]:
        """Aggregate captured hosts → paths (methods + hit counts)."""
        hosts: dict[str, dict[str, dict]] = {}
        for row in self.entries():
            host = str(row.get("host", "")) or "(unknown)"
            path = str(row.get("path", "/")) or "/"
            method = str(row.get("method", "GET"))
            bucket = hosts.setdefault(host, {})
            leaf = bucket.setdefault(path, {"methods": set(), "count": 0})
            leaf["methods"].add(method)
            leaf["count"] += 1
        result: dict[str, list[dict]] = {}
        for host, paths in sorted(hosts.items()):
            result[host] = [
                {
                    "path": path,
                    "methods": sorted(leaf["methods"]),
                    "count": leaf["count"],
                }
                for path, leaf in sorted(paths.items())
            ]
        return result
