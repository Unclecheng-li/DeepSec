"""Overlay normalization + manual replay."""

from __future__ import annotations

import httpx

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
from deepsec.traffic.normalize import ingest_burp_history, ingest_chrome_devtools
from deepsec.traffic.replay import replay_request


def _capture(tmp_path) -> TrafficCapture:
    store = TrafficStore(tmp_path / "evidence" / "traffic")
    scope = ScopeChecker([Target(host="app.test")], mode=ScopeMode.SUBDOMAIN)
    return TrafficCapture(store, scope)


def test_burp_history_normalizes_with_proxy_source(tmp_path):
    capture = _capture(tmp_path)
    entries = [
        {
            "request": {
                "method": "POST",
                "url": "http://app.test/login",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "user=admin",
            },
            "response": {"status": 302, "headers": {"Location": "/home"}, "body": ""},
        },
        # Out-of-scope third-party call is dropped even from the overlay path.
        {"request": {"method": "GET", "url": "http://cdn.other/x.js"}},
    ]
    kept = ingest_burp_history(capture, entries)
    assert len(kept) == 1
    row = capture.store.find(kept[0])
    assert row["source"] == "proxy"
    assert "burp" in row["tags"]
    assert row["method"] == "POST"
    assert row["status"] == 302


def test_chrome_devtools_normalizes_with_browser_source(tmp_path):
    capture = _capture(tmp_path)
    entries = [
        {
            "request": {
                "method": "GET",
                "url": "http://api.app.test/v1/users",
                "headers": [{"name": "Accept", "value": "application/json"}],
            },
            "response": {"status": 200, "headers": {"Content-Type": "application/json"}, "body": "[]"},
        }
    ]
    kept = ingest_chrome_devtools(capture, entries)
    assert len(kept) == 1
    view = capture.store.view(kept[0])
    assert view["source"] == "browser"
    assert "chrome-devtools" in view["tags"]
    assert "GET /v1/users HTTP/1.1" in view["request_text"]
    assert "Accept: application/json" in view["request_text"]


def test_replay_issues_with_overrides_and_records_manual_replay(tmp_path):
    store = TrafficStore(tmp_path / "evidence" / "traffic")
    capture = TrafficCapture(
        store, ScopeChecker([Target(host="app.test")], mode=ScopeMode.STRICT)
    )
    original = capture.capture(
        CapturedExchange(
            request=CapturedRequest(
                method="GET",
                url="http://app.test/item?id=1",
                headers={"Host": "app.test", "Cookie": "s=abc"},
            ),
            response=CapturedResponse(status=200, body=b"one"),
        ),
        source="proxy",
    )

    seen: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["req"] = request
        return httpx.Response(500, text="boom")

    record = replay_request(
        store,
        original,
        overrides={"url": "http://app.test/item?id=2", "headers": {"Cookie": "s=xyz"}},
        transport=httpx.MockTransport(handler),
    )

    assert record.source == "manual-replay"
    assert f"from:{original}" in record.tags
    assert record.status == 500
    # The override reached the wire.
    assert str(seen["req"].url) == "http://app.test/item?id=2"
    assert seen["req"].headers["cookie"] == "s=xyz"
    # And a second store line now exists, addressable and viewable.
    assert len(store.entries()) == 2
    replayed = store.view(record.request_id)
    assert "boom" in replayed["response_text"]
