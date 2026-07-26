"""Tests for the built-in ChatGPT-backend bridge proxy."""

from __future__ import annotations

import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from deepsec.spear.agent import chatgpt_proxy as cp

# ── Pure translation functions ───────────────────────────────────────


def test_chat_to_responses_maps_roles_tools_and_params():
    req = {
        "model": "gpt-5",
        "messages": [
            {"role": "system", "content": "be terse"},
            {"role": "user", "content": "hello"},
            {
                "role": "assistant",
                "content": "hi",
                "tool_calls": [
                    {"id": "c1", "type": "function", "function": {"name": "f", "arguments": "{}"}}
                ],
            },
            {"role": "tool", "tool_call_id": "c1", "content": "result"},
        ],
        "tools": [{"type": "function", "function": {"name": "f", "description": "d", "parameters": {}}}],
        "temperature": 0.3,
        "max_tokens": 128,
        "reasoning_effort": "high",
    }
    r = cp.chat_to_responses(req)
    assert r["instructions"] == "be terse"
    assert [i["type"] for i in r["input"]] == [
        "message",
        "message",
        "function_call",
        "function_call_output",
    ]
    assert r["input"][3]["call_id"] == "c1"
    assert r["tools"][0] == {"type": "function", "name": "f", "description": "d", "parameters": {}}
    # The ChatGPT backend rejects sampling/limit params — they must NOT be sent.
    assert "temperature" not in r
    assert "max_output_tokens" not in r
    assert "top_p" not in r
    # reasoning_effort is mapped onto the accepted `reasoning` object.
    assert r["reasoning"] == {"effort": "high"}
    # The ChatGPT backend requires streaming + store=false.
    assert r["stream"] is True
    assert r["store"] is False


def test_responses_to_chat_content_and_tool_calls():
    resp = {
        "id": "resp_1",
        "output": [
            {"type": "message", "content": [{"type": "output_text", "text": "hello "}]},
            {"type": "message", "content": [{"type": "output_text", "text": "world"}]},
            {"type": "function_call", "call_id": "c9", "name": "do", "arguments": '{"x":1}'},
        ],
        "usage": {"input_tokens": 5, "output_tokens": 7, "total_tokens": 12},
    }
    chat = cp.responses_to_chat(resp, "gpt-5")
    msg = chat["choices"][0]["message"]
    assert msg["content"] == "hello world"
    assert msg["tool_calls"][0]["id"] == "c9"
    assert msg["tool_calls"][0]["function"] == {"name": "do", "arguments": '{"x":1}'}
    assert chat["choices"][0]["finish_reason"] == "tool_calls"
    assert chat["usage"]["total_tokens"] == 12


def test_responses_to_chat_output_text_fallback():
    chat = cp.responses_to_chat({"output": [], "output_text": "flat"}, "m")
    assert chat["choices"][0]["message"]["content"] == "flat"
    assert chat["choices"][0]["finish_reason"] == "stop"


def test_aggregate_sse_text_and_tool_call():
    events = [
        {"type": "response.created", "response": {"id": "r1"}},
        {"type": "response.output_text.delta", "delta": "Hel"},
        {"type": "response.output_text.delta", "delta": "lo"},
        {
            "type": "response.output_item.done",
            "item": {"type": "function_call", "call_id": "c7", "name": "go", "arguments": '{"a":1}'},
        },
        {
            "type": "response.completed",
            "response": {"id": "r1", "usage": {"input_tokens": 2, "output_tokens": 3, "total_tokens": 5}},
        },
    ]
    raw = [f"data: {json.dumps(e)}\n".encode() for e in events]
    resp = cp._aggregate_sse(raw)
    chat = cp.responses_to_chat(resp, "gpt-5.5")
    msg = chat["choices"][0]["message"]
    assert msg["content"] == "Hello"
    assert msg["tool_calls"][0]["id"] == "c7"
    assert msg["tool_calls"][0]["function"]["name"] == "go"
    assert chat["usage"]["total_tokens"] == 5


def test_aggregate_sse_surfaces_error():
    raw = [
        b'data: {"type": "response.failed", "response": {"error": {"message": "boom"}}}\n'
    ]
    with pytest.raises(cp._UpstreamError):
        cp._aggregate_sse(raw)


def test_chat_to_stream_chunks():
    chat = {
        "id": "x",
        "model": "gpt-5",
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "hi",
                    "tool_calls": [
                        {"id": "c1", "type": "function", "function": {"name": "f", "arguments": "{}"}}
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
    }
    chunks = cp.chat_to_stream_chunks(chat)
    assert chunks[0]["choices"][0]["delta"]["content"] == "hi"
    assert chunks[0]["choices"][0]["delta"]["tool_calls"][0]["index"] == 0
    assert chunks[1]["choices"][0]["finish_reason"] == "tool_calls"


# ── Integration: proxy server ↔ mock ChatGPT backend ─────────────────


@pytest.fixture
def mock_backend(monkeypatch):
    received: dict = {}

    def _sse(event: dict) -> bytes:
        return f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()

    class Backend(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 — emulates the streaming Responses backend
            received["auth"] = self.headers.get("Authorization")
            received["account"] = self.headers.get("chatgpt-account-id")
            n = int(self.headers.get("Content-Length", 0))
            received["body"] = json.loads(self.rfile.read(n).decode())
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(_sse({"type": "response.created", "response": {"id": "resp_x"}}))
            self.wfile.write(
                _sse({"type": "response.output_text.delta", "delta": "po"})
            )
            self.wfile.write(
                _sse({"type": "response.output_text.delta", "delta": "ng"})
            )
            self.wfile.write(
                _sse(
                    {
                        "type": "response.completed",
                        "response": {
                            "id": "resp_x",
                            "usage": {
                                "input_tokens": 1,
                                "output_tokens": 1,
                                "total_tokens": 2,
                            },
                        },
                    }
                )
            )

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Backend)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("DEEPSEC_CHATGPT_BACKEND_URL", f"http://127.0.0.1:{port}/responses")
    monkeypatch.setattr(cp, "_resolve_credentials", lambda: ("tok-123", "acct-9"))
    monkeypatch.setattr(cp, "list_backend_models", lambda token, account_id: ["gpt-5.5"])
    yield received
    srv.shutdown()


def _post(url, payload):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode()


def test_proxy_non_stream(mock_backend):
    base = cp.ensure_proxy_running()
    body = _post(
        base + "/chat/completions",
        {"model": "gpt-5", "messages": [{"role": "user", "content": "ping"}]},
    )
    chat = json.loads(body)
    assert chat["choices"][0]["message"]["content"] == "pong"
    assert mock_backend["auth"] == "Bearer tok-123"
    assert mock_backend["account"] == "acct-9"
    # request was translated into Responses shape (streaming + store=false)
    assert mock_backend["body"]["input"][0]["type"] == "message"
    assert mock_backend["body"]["stream"] is True
    assert mock_backend["body"]["store"] is False


def test_proxy_stream(mock_backend):
    base = cp.ensure_proxy_running()
    body = _post(
        base + "/chat/completions",
        {"model": "gpt-5", "messages": [{"role": "user", "content": "ping"}], "stream": True},
    )
    assert "data: " in body
    assert "[DONE]" in body
    first = json.loads(body.split("data: ", 1)[1].split("\n", 1)[0])
    assert first["choices"][0]["delta"]["content"] == "pong"


def test_proxy_models_endpoint(mock_backend):
    base = cp.ensure_proxy_running()
    with urllib.request.urlopen(base + "/models", timeout=10) as r:
        data = json.loads(r.read().decode())
    assert data["object"] == "list"
    assert any(m["id"] for m in data["data"])
