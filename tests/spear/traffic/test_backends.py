"""Proxy/browser backend adapters against stub transports (no runtime deps)."""

from __future__ import annotations

from deepsec.traffic import ScopeChecker, ScopeMode, Target, TrafficCapture, TrafficStore
from deepsec.traffic.browser import (
    BrowserCaptureBridge,
    exchange_from_playwright,
    playwright_available,
)
from deepsec.traffic.mitm_addon import (
    TrafficCaptureAddon,
    exchange_from_flow,
    mitmproxy_available,
)


class _StubHeaders(dict):
    pass


class _StubRequest:
    def __init__(self, method, url, headers, content=b""):
        self.method = method
        self.url = url
        self.headers = _StubHeaders(headers)
        self.raw_content = content
        self.http_version = "HTTP/1.1"


class _StubResponse:
    def __init__(self, status, headers, content=b""):
        self.status_code = status
        self.headers = _StubHeaders(headers)
        self.raw_content = content
        self.reason = "OK"
        self.http_version = "HTTP/1.1"


class _StubFlow:
    def __init__(self, request, response=None):
        self.request = request
        self.response = response


def _capture(tmp_path) -> TrafficCapture:
    store = TrafficStore(tmp_path / "evidence" / "traffic")
    scope = ScopeChecker([Target(host="app.test")], mode=ScopeMode.SUBDOMAIN)
    return TrafficCapture(store, scope)


def test_availability_helpers_return_bool():
    assert isinstance(mitmproxy_available(), bool)
    assert isinstance(playwright_available(), bool)


def test_mitm_addon_captures_in_scope_flow(tmp_path):
    capture = _capture(tmp_path)
    addon = TrafficCaptureAddon(capture)
    flow = _StubFlow(
        _StubRequest("GET", "http://app.test/x", {"Host": "app.test"}),
        _StubResponse(200, {"Server": "nginx"}, b"body"),
    )
    request_id = addon.capture_flow(flow)
    assert request_id
    row = capture.store.find(request_id)
    assert row["source"] == "proxy"
    assert row["status"] == 200


def test_mitm_addon_drops_out_of_scope_flow(tmp_path):
    capture = _capture(tmp_path)
    addon = TrafficCaptureAddon(capture)
    flow = _StubFlow(_StubRequest("GET", "http://tracker.ads/x", {}))
    assert addon.capture_flow(flow) is None
    assert capture.store.entries() == []


def test_exchange_from_flow_maps_fields():
    flow = _StubFlow(
        _StubRequest("POST", "http://app.test/a", {"X": "1"}, b"data"),
        _StubResponse(201, {"Y": "2"}, b"ok"),
    )
    exchange = exchange_from_flow(flow)
    assert exchange.request.method == "POST"
    assert exchange.request.body == b"data"
    assert exchange.response.status == 201


class _PwRequest:
    def __init__(self, method, url, headers, post_data=None):
        self._method = method
        self._url = url
        self._headers = headers
        self._post_data = post_data

    def method(self):
        return self._method

    @property
    def url(self):
        return self._url

    def headers(self):
        return self._headers

    def post_data(self):
        return self._post_data


class _PwResponse:
    def __init__(self, status, body=b""):
        self._status = status
        self._body = body

    @property
    def status(self):
        return self._status

    def headers(self):
        return {"Content-Type": "text/html"}

    def body(self):
        return self._body


def test_browser_bridge_captures_in_scope_with_body(tmp_path):
    capture = _capture(tmp_path)
    bridge = BrowserCaptureBridge(capture)
    request_id = bridge.on_response(
        _PwRequest("GET", "http://api.app.test/data", {"Accept": "*/*"}),
        _PwResponse(200, body=b"<html>secret</html>"),
    )
    assert request_id
    row = capture.store.find(request_id)
    assert row["source"] == "browser"
    assert row["host"] == "api.app.test"
    # Browser response body is preserved for evidence (not dropped).
    assert row["content_length"] == len(b"<html>secret</html>")
    assert b"secret" in capture.store.response_blob(request_id)


def test_exchange_from_playwright_handles_callable_and_attr():
    exchange = exchange_from_playwright(
        _PwRequest("POST", "http://app.test/p", {"K": "v"}, "a=b"),
        _PwResponse(302, body=b"redirecting"),
    )
    assert exchange.request.method == "POST"
    assert exchange.request.body == b"a=b"
    assert exchange.response.status == 302
    assert exchange.response.body == b"redirecting"
