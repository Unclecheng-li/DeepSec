"""Store + capture: JSONL/blob writes, scope filtering, resume-stable ids."""

from __future__ import annotations

import json

from deepsec.traffic import (
    CapturedExchange,
    CapturedRequest,
    CapturedResponse,
    ScopeChecker,
    ScopeMode,
    Target,
    TrafficCapture,
    TrafficStore,
)
from deepsec.traffic.store import compute_request_id


def _exchange(url: str, method: str = "GET", body: bytes = b"") -> CapturedExchange:
    return CapturedExchange(
        request=CapturedRequest(method=method, url=url, headers={"Host": "app.test"}, body=body),
        response=CapturedResponse(status=200, headers={"Server": "x"}, body=b"OK"),
    )


def _capture(tmp_path, mode=ScopeMode.STRICT) -> TrafficCapture:
    store = TrafficStore(tmp_path / "evidence" / "traffic")
    scope = ScopeChecker([Target(host="app.test")], mode=mode)
    return TrafficCapture(store, scope)


def test_in_scope_request_writes_one_line_and_blobs(tmp_path):
    capture = _capture(tmp_path)
    request_id = capture.capture(_exchange("http://app.test/login"), source="proxy")

    assert request_id
    store = capture.store
    entries = store.entries()
    assert len(entries) == 1
    row = entries[0]
    assert row["method"] == "GET"
    assert row["url"] == "http://app.test/login"
    assert row["status"] == 200
    assert row["source"] == "proxy"
    assert row["content_length"] == len(b"OK")

    # Raw blob files exist and are addressable by request_id.
    blob_dir = store.base_dir / request_id
    assert (blob_dir / "request").exists()
    assert (blob_dir / "response").exists()
    assert b"GET /login HTTP/1.1" in (blob_dir / "request").read_bytes()
    assert b"200" in (blob_dir / "response").read_bytes()

    # One physical JSONL line.
    lines = [ln for ln in store.index_path.read_text().splitlines() if ln.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0])["request_id"] == request_id


def test_request_id_stable_across_resume(tmp_path):
    capture = _capture(tmp_path)
    first = capture.capture(_exchange("http://app.test/a"), source="proxy")

    # Simulate a resume: rebuild the store from the on-disk directory.
    resumed = TrafficStore(capture.store.base_dir)
    assert resumed.find(first) is not None
    assert resumed.find(first)["request_id"] == first
    assert resumed.request_blob(first) is not None

    # The sequence counter resumes so a new capture gets a distinct id.
    resumed_capture = TrafficCapture(resumed, capture.scope)
    second = resumed_capture.capture(_exchange("http://app.test/b"), source="proxy")
    assert second != first
    assert len(resumed.entries()) == 2

    # request_id is a pure content+sequence hash.
    assert first == compute_request_id(0, _exchange("http://app.test/a").request)


def test_out_of_scope_host_is_dropped(tmp_path):
    capture = _capture(tmp_path)
    kept = capture.capture(_exchange("http://cdn.example.com/ads.js"), source="proxy")
    assert kept is None
    assert capture.store.entries() == []
    assert not capture.store.index_path.exists()


def test_subdomain_scope_mode(tmp_path):
    capture = _capture(tmp_path, mode=ScopeMode.SUBDOMAIN)
    assert capture.capture(_exchange("http://api.app.test/v1"), source="proxy")
    # A different apex is still dropped.
    assert capture.capture(_exchange("http://evil.test/x"), source="proxy") is None
    assert len(capture.store.entries()) == 1


def test_sitemap_reflects_hosts_and_paths(tmp_path):
    capture = _capture(tmp_path, mode=ScopeMode.SUBDOMAIN)
    capture.capture(_exchange("http://app.test/login", method="POST"), source="proxy")
    capture.capture(_exchange("http://app.test/login", method="GET"), source="proxy")
    capture.capture(_exchange("http://api.app.test/health"), source="browser")

    sitemap = capture.store.sitemap()
    assert set(sitemap.keys()) == {"app.test", "api.app.test"}
    login = next(p for p in sitemap["app.test"] if p["path"] == "/login")
    assert login["methods"] == ["GET", "POST"]
    assert login["count"] == 2
