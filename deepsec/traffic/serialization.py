"""Raw HTTP (de)serialization for traffic blob files.

Request/response blobs are stored as raw HTTP text so a finding's report can
inline exactly what proved it, and so ``traffic_repeat`` can reconstruct a
request's headers and body from disk. The request line uses the URL path (plus
query) — the full absolute URL is kept in the JSONL index.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from deepsec.traffic.models import CapturedRequest, CapturedResponse


def _path_with_query(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return path


def raw_request_bytes(request: CapturedRequest) -> bytes:
    line = f"{request.method} {_path_with_query(request.url)} {request.http_version}"
    header_lines = [f"{name}: {value}" for name, value in request.headers.items()]
    head = "\r\n".join([line, *header_lines]) + "\r\n\r\n"
    return head.encode("utf-8", "replace") + (request.body or b"")


def raw_response_bytes(response: CapturedResponse) -> bytes:
    reason = f" {response.reason}" if response.reason else ""
    line = f"{response.http_version} {response.status}{reason}"
    header_lines = [f"{name}: {value}" for name, value in response.headers.items()]
    head = "\r\n".join([line, *header_lines]) + "\r\n\r\n"
    return head.encode("utf-8", "replace") + (response.body or b"")


def parse_raw_request(blob: bytes, *, url: str = "") -> CapturedRequest:
    """Reconstruct a :class:`CapturedRequest` from a stored request blob.

    ``url`` (the absolute URL from the index) is used verbatim when supplied,
    since the raw request line only carries the path.
    """
    head, _, body = blob.partition(b"\r\n\r\n")
    if not head and not body:
        head, _, body = blob.partition(b"\n\n")
    lines = head.decode("utf-8", "replace").splitlines()
    method = "GET"
    request_target = url
    http_version = "HTTP/1.1"
    if lines:
        parts = lines[0].split(" ")
        if len(parts) >= 1 and parts[0]:
            method = parts[0]
        if not url and len(parts) >= 2:
            request_target = parts[1]
        if len(parts) >= 3:
            http_version = parts[2]

    headers: dict[str, str] = {}
    for raw in lines[1:]:
        if ":" not in raw:
            continue
        name, _, value = raw.partition(":")
        headers[name.strip()] = value.strip()

    return CapturedRequest(
        method=method,
        url=request_target,
        headers=headers,
        body=body,
        http_version=http_version,
    )
