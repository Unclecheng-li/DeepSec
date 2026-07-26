"""Built-in OpenAI-compatible proxy for the ChatGPT backend (Responses API).

When a user signs in with their ChatGPT subscription (``vulnclaw login --chatgpt``),
the resulting token only works against OpenAI's ChatGPT backend (the Responses
API at ``chatgpt.com/backend-api/codex``), **not** the public
``/v1/chat/completions`` endpoint that VulnClaw speaks.

This module runs a tiny local HTTP server that:

* accepts standard OpenAI ``/v1/chat/completions`` (and ``/v1/models``) requests
  from VulnClaw's OpenAI client,
* translates them into Responses-API requests,
* forwards them to the ChatGPT backend with the stored (auto-refreshed) bearer
  token + ``chatgpt-account-id`` header,
* translates the answer back into chat-completions shape (including tool calls).

It is started automatically (in-process, background thread) by
``AgentCore._get_client`` when ``llm.chatgpt_auto_proxy`` is enabled — so users
do not have to install or launch any external proxy.

⚠️ The ChatGPT backend protocol is undocumented and may change. The endpoint and
headers are overridable via env vars (``DEEPSEC_CHATGPT_BACKEND_URL`` etc.) so
breakage can be fixed without code changes. This is a best-effort bridge.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

# ── Upstream (ChatGPT backend) configuration — all overridable via env ───
DEFAULT_BACKEND_URL = "https://chatgpt.com/backend-api/codex/responses"
DEFAULT_MODELS_URL = "https://chatgpt.com/backend-api/codex/models"
DEFAULT_CLIENT_VERSION = "1.0.0"


def _backend_url() -> str:
    return os.environ.get("DEEPSEC_CHATGPT_BACKEND_URL", DEFAULT_BACKEND_URL)


def _models_url() -> str:
    return os.environ.get("DEEPSEC_CHATGPT_MODELS_URL", DEFAULT_MODELS_URL)


def _client_version() -> str:
    return os.environ.get("DEEPSEC_CHATGPT_CLIENT_VERSION", DEFAULT_CLIENT_VERSION)


def _extra_headers() -> dict[str, str]:
    """Headers Codex sends to the backend. Overridable via env."""
    headers = {
        "OpenAI-Beta": os.environ.get("DEEPSEC_CHATGPT_OPENAI_BETA", "responses=experimental"),
        "originator": os.environ.get("DEEPSEC_CHATGPT_ORIGINATOR", "codex_cli_rs"),
        "User-Agent": os.environ.get("DEEPSEC_CHATGPT_USER_AGENT", "vulnclaw-codex-proxy"),
    }
    return headers


# ═════════════════════════════════════════════════════════════════════
# Translation: OpenAI chat.completions  <->  Responses API
# (pure functions — unit-testable without any network)
# ═════════════════════════════════════════════════════════════════════


def chat_to_responses(payload: dict[str, Any]) -> dict[str, Any]:
    """Translate an OpenAI chat.completions request into a Responses request."""
    messages = payload.get("messages") or []
    instructions_parts: list[str] = []
    input_items: list[dict[str, Any]] = []

    for msg in messages:
        role = msg.get("role")
        content = msg.get("content")

        if role == "system":
            if content:
                instructions_parts.append(content if isinstance(content, str) else str(content))
            continue

        if role == "tool":
            input_items.append(
                {
                    "type": "function_call_output",
                    "call_id": msg.get("tool_call_id", ""),
                    "output": content if isinstance(content, str) else json.dumps(content),
                }
            )
            continue

        if role == "assistant":
            if content:
                input_items.append(
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": content}],
                    }
                )
            for tc in msg.get("tool_calls") or []:
                fn = tc.get("function", {})
                input_items.append(
                    {
                        "type": "function_call",
                        "call_id": tc.get("id", ""),
                        "name": fn.get("name", ""),
                        "arguments": fn.get("arguments", "") or "{}",
                    }
                )
            continue

        # user (and any other) role → input_text
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            text = "".join(
                part.get("text", "") for part in content if isinstance(part, dict)
            )
        else:
            text = str(content) if content is not None else ""
        input_items.append(
            {
                "type": "message",
                "role": role or "user",
                "content": [{"type": "input_text", "text": text}],
            }
        )

    responses: dict[str, Any] = {
        "model": payload.get("model"),
        "input": input_items,
        # The ChatGPT backend REQUIRES streaming and store=false.
        "stream": True,
        "store": False,
    }
    if instructions_parts:
        responses["instructions"] = "\n\n".join(instructions_parts)

    # Tools: chat.completions nests under .function; Responses flattens them.
    tools = payload.get("tools")
    if tools:
        conv_tools = []
        for t in tools:
            if t.get("type") == "function" and "function" in t:
                fn = t["function"]
                conv_tools.append(
                    {
                        "type": "function",
                        "name": fn.get("name"),
                        "description": fn.get("description", ""),
                        "parameters": fn.get("parameters", {}),
                    }
                )
            else:
                conv_tools.append(t)
        responses["tools"] = conv_tools

    # The ChatGPT backend rejects sampling / limit params with HTTP 400
    # ("Unsupported parameter: temperature / top_p / max_output_tokens"), so we
    # do NOT forward them. It does accept a `reasoning` object — map the chat
    # `reasoning_effort` onto it.
    if isinstance(payload.get("reasoning"), dict):
        responses["reasoning"] = payload["reasoning"]
    elif payload.get("reasoning_effort"):
        responses["reasoning"] = {"effort": payload["reasoning_effort"]}
    return responses


def responses_to_chat(resp: dict[str, Any], model: str) -> dict[str, Any]:
    """Translate a Responses-API answer into a chat.completions answer."""
    content_text = ""
    tool_calls: list[dict[str, Any]] = []

    for item in resp.get("output") or []:
        itype = item.get("type")
        if itype == "message":
            for c in item.get("content") or []:
                if c.get("type") in ("output_text", "text"):
                    content_text += c.get("text", "")
        elif itype in ("function_call", "tool_call"):
            tool_calls.append(
                {
                    "id": item.get("call_id") or item.get("id") or f"call_{uuid.uuid4().hex[:8]}",
                    "type": "function",
                    "function": {
                        "name": item.get("name", ""),
                        "arguments": item.get("arguments", "") or "{}",
                    },
                }
            )
        elif itype == "reasoning":
            # Optional: surface reasoning summary if present (kept out of content).
            continue

    # Fallback: some responses expose a flattened output_text field.
    if not content_text and isinstance(resp.get("output_text"), str):
        content_text = resp["output_text"]

    message: dict[str, Any] = {"role": "assistant", "content": content_text or None}
    if tool_calls:
        message["tool_calls"] = tool_calls

    usage = resp.get("usage") or {}
    return {
        "id": resp.get("id") or f"chatcmpl-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": "tool_calls" if tool_calls else "stop",
            }
        ],
        "usage": {
            "prompt_tokens": usage.get("input_tokens", 0),
            "completion_tokens": usage.get("output_tokens", 0),
            "total_tokens": usage.get("total_tokens", 0),
        },
    }


def chat_to_stream_chunks(chat: dict[str, Any]) -> list[dict[str, Any]]:
    """Split a chat.completions answer into SSE chunk dicts (single content chunk).

    We buffer upstream then synthesize a minimal stream: one chunk carrying the
    full content + any tool_calls, then a finish chunk. VulnClaw's streaming
    parser accumulates these correctly.
    """
    choice = chat["choices"][0]
    msg = choice["message"]
    model = chat.get("model", "")
    base = {"id": chat["id"], "object": "chat.completion.chunk", "model": model}

    delta: dict[str, Any] = {"role": "assistant"}
    if msg.get("content"):
        delta["content"] = msg["content"]
    if msg.get("tool_calls"):
        delta["tool_calls"] = [
            {
                "index": i,
                "id": tc["id"],
                "type": "function",
                "function": tc["function"],
            }
            for i, tc in enumerate(msg["tool_calls"])
        ]

    return [
        {**base, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
        {
            **base,
            "choices": [{"index": 0, "delta": {}, "finish_reason": choice["finish_reason"]}],
        },
    ]


# ═════════════════════════════════════════════════════════════════════
# Upstream call
# ═════════════════════════════════════════════════════════════════════


class _UpstreamError(Exception):
    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        super().__init__(f"upstream {status}: {body[:200]}")


def _backend_headers(token: str, account_id: str) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        "session_id": str(uuid.uuid4()),
        **_extra_headers(),
    }
    if account_id:
        headers["chatgpt-account-id"] = account_id
    return headers


def _aggregate_sse(resp_stream: Any) -> dict[str, Any]:
    """Consume the backend's Responses SSE stream into a single responses dict.

    The ChatGPT backend only streams. We accumulate text deltas and completed
    function-call items, then hand a synthesized {"output": [...]} object to
    ``responses_to_chat`` so the rest of the pipeline is unchanged.
    """
    content = ""
    tool_calls: list[dict[str, Any]] = []
    usage: dict[str, Any] = {}
    resp_id = ""
    error_detail = ""

    for raw in resp_stream:
        line = raw.decode("utf-8", "replace").strip()
        if not line.startswith("data:"):
            continue
        data_str = line[len("data:"):].strip()
        if not data_str or data_str == "[DONE]":
            continue
        try:
            ev = json.loads(data_str)
        except json.JSONDecodeError:
            continue
        etype = ev.get("type", "")

        if etype == "response.output_text.delta":
            content += ev.get("delta", "")
        elif etype == "response.output_item.done":
            item = ev.get("item", {})
            if item.get("type") == "function_call":
                tool_calls.append(
                    {
                        "type": "function_call",
                        "call_id": item.get("call_id") or item.get("id") or "",
                        "name": item.get("name", ""),
                        "arguments": item.get("arguments", "") or "{}",
                    }
                )
        elif etype in ("response.completed", "response.incomplete"):
            r = ev.get("response", {})
            resp_id = r.get("id", resp_id)
            usage = r.get("usage", usage) or usage
        elif etype in ("response.failed", "error", "response.error"):
            r = ev.get("response", {}) or ev
            err = r.get("error") or ev.get("error") or {}
            error_detail = err.get("message") if isinstance(err, dict) else str(err)

    if error_detail:
        raise _UpstreamError(502, f"backend stream error: {error_detail}")

    output: list[dict[str, Any]] = []
    if content:
        output.append(
            {"type": "message", "content": [{"type": "output_text", "text": content}]}
        )
    output.extend(tool_calls)
    return {"id": resp_id, "output": output, "usage": usage}


def _call_backend(responses_payload: dict[str, Any], token: str, account_id: str) -> dict[str, Any]:
    """Stream the request to the ChatGPT backend and aggregate the SSE answer."""
    data = json.dumps(responses_payload).encode("utf-8")
    req = urllib.request.Request(
        _backend_url(), data=data, headers=_backend_headers(token, account_id), method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:  # noqa: S310
            return _aggregate_sse(resp)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace") if hasattr(exc, "read") else str(exc)
        raise _UpstreamError(exc.code, detail) from exc
    except urllib.error.URLError as exc:
        raise _UpstreamError(502, f"cannot reach ChatGPT backend: {exc}") from exc


def list_backend_models(token: str, account_id: str) -> list[str]:
    """Return the model slugs the ChatGPT backend allows for this account."""
    url = f"{_models_url()}?client_version={urllib.parse.quote(_client_version())}"
    headers = _backend_headers(token, account_id)
    headers["Accept"] = "application/json"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError):
        return []
    return [m.get("slug", "") for m in data.get("models", []) if m.get("slug")]


# ═════════════════════════════════════════════════════════════════════
# Local OpenAI-compatible HTTP server
# ═════════════════════════════════════════════════════════════════════


def _resolve_credentials() -> tuple[str, str]:
    """Fetch a fresh ChatGPT token (auto-refreshing) + account id from the store."""
    from deepsec.config.settings import load_config
    from deepsec.config.token_provider import load_oauth_tokens, resolve_llm_token

    token = resolve_llm_token(load_config().llm)
    account_id = str(load_oauth_tokens().get("account_id") or "")
    return token, account_id


class _ProxyHandler(BaseHTTPRequestHandler):
    def _send_json(self, obj: dict[str, Any], status: int = 200) -> None:
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_error_json(self, status: int, message: str) -> None:
        self._send_json(
            {"error": {"message": message, "type": "vulnclaw_chatgpt_proxy"}}, status=status
        )

    def do_GET(self):  # noqa: N802
        if self.path.rstrip("/").endswith("/models"):
            slugs: list[str] = []
            try:
                token, account_id = _resolve_credentials()
                slugs = list_backend_models(token, account_id)
            except Exception:  # noqa: BLE001 - models listing is best-effort
                slugs = []
            if not slugs:
                slugs = ["gpt-5.5"]
            self._send_json(
                {
                    "object": "list",
                    "data": [
                        {"id": s, "object": "model", "owned_by": "openai"} for s in slugs
                    ],
                }
            )
        else:
            self._send_error_json(404, f"not found: {self.path}")

    def do_POST(self):  # noqa: N802
        if not self.path.rstrip("/").endswith("/chat/completions"):
            self._send_error_json(404, f"not found: {self.path}")
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(n).decode("utf-8"))
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_error_json(400, f"bad request body: {exc}")
            return

        want_stream = bool(payload.get("stream"))
        model = payload.get("model", "")

        try:
            token, account_id = _resolve_credentials()
            responses_payload = chat_to_responses(payload)
            upstream = _call_backend(responses_payload, token, account_id)
            chat = responses_to_chat(upstream, model)
        except _UpstreamError as exc:
            self._send_error_json(exc.status, exc.body)
            return
        except Exception as exc:  # noqa: BLE001 - surface anything as an API error
            self._send_error_json(500, f"proxy error: {exc}")
            return

        if not want_stream:
            self._send_json(chat)
            return

        # Synthesize an SSE stream from the buffered answer.
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        for chunk in chat_to_stream_chunks(chat):
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")

    def log_message(self, *args):  # silence default logging
        pass


_PROXY_LOCK = threading.Lock()
_PROXY_BASE_URL: str | None = None


def ensure_proxy_running() -> str:
    """Start the in-process proxy (once) and return its OpenAI base_url."""
    global _PROXY_BASE_URL
    with _PROXY_LOCK:
        if _PROXY_BASE_URL is not None:
            return _PROXY_BASE_URL
        server = ThreadingHTTPServer(("127.0.0.1", 0), _ProxyHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        _PROXY_BASE_URL = f"http://127.0.0.1:{port}/v1"
        return _PROXY_BASE_URL
