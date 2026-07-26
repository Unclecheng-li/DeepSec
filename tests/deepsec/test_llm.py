import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from deepsec.core.config import DeepSecConfig, LLMConfig, LLMModeConfig, ProviderConfig, StorageConfig
from deepsec.core.llm import DeepSecLLM


class FakeCompletions:
    def __init__(self, outcomes, calls):
        self.outcomes = list(outcomes)
        self.calls = calls

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeClient:
    def __init__(self, outcomes, calls):
        self.chat = SimpleNamespace(completions=FakeCompletions(outcomes, calls))


class FakeStream:
    def __init__(self, chunks):
        self.chunks = chunks

    def __aiter__(self):
        self._iterator = iter(self.chunks)
        return self

    async def __anext__(self):
        try:
            return next(self._iterator)
        except StopIteration as error:
            raise StopAsyncIteration from error


def response(content: str, prompt_tokens: int = 10, completion_tokens: int = 5):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
        usage=SimpleNamespace(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens),
    )


def chunk(value: str):
    return SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content=value))])


@pytest.mark.asyncio
async def test_fallback_uses_a_provider_specific_client_and_model(tmp_path: Path) -> None:
    config = DeepSecConfig(
        llm=LLMConfig(
            provider="deepseek",
            api_key="deepseek-key",
            fallbacks=["openai"],
            shield=LLMModeConfig(chat_model="deepseek-chat", reason_model="deepseek-reasoner"),
            spear=LLMModeConfig(chat_model="deepseek-chat", reason_model="deepseek-reasoner"),
            providers={"openai": ProviderConfig(api_key="openai-key", base_url="https://openai.example/v1", reason_model="openai-reason")},
        ),
        storage=StorageConfig(runs_dir=str(tmp_path / "runs")),
    )
    calls = {"deepseek": [], "openai": []}
    client_requests = []

    def factory(provider: str, api_key: str, base_url: str):
        client_requests.append((provider, api_key, base_url))
        outcomes = [RuntimeError("gateway timeout")] if provider == "deepseek" else [response('{"findings": []}')]
        return FakeClient(outcomes, calls[provider])

    llm = DeepSecLLM(config, client_factory=factory, usage_path=tmp_path / "usage.jsonl", max_retries=1)
    result, usage = await llm.spear_reason("https://authorized.example", "")

    assert result == {"findings": []}
    assert usage.provider == "openai"
    assert llm.last_provider == "openai"
    assert client_requests == [
        ("deepseek", "deepseek-key", "https://api.deepseek.com/v1"),
        ("openai", "openai-key", "https://openai.example/v1"),
    ]
    assert calls["deepseek"][0]["model"] == "deepseek-reasoner"
    assert calls["openai"][0]["model"] == "openai-reason"
    assert calls["deepseek"][0]["extra_body"] == {"prompt_cache": {"enable": True}}
    assert "extra_body" not in calls["openai"][0]
    assert json.loads((tmp_path / "usage.jsonl").read_text(encoding="utf-8")) ["provider"] == "openai"


@pytest.mark.asyncio
async def test_stream_falls_back_before_any_delta(tmp_path: Path) -> None:
    config = DeepSecConfig(
        llm=LLMConfig(provider="deepseek", api_key="key", fallbacks=["local"]),
        storage=StorageConfig(runs_dir=str(tmp_path / "runs")),
    )
    calls = {"deepseek": [], "local": []}

    def factory(provider: str, _api_key: str, _base_url: str):
        outcome = RuntimeError("unavailable") if provider == "deepseek" else FakeStream([chunk("hello "), chunk("world")])
        return FakeClient([outcome], calls[provider])

    llm = DeepSecLLM(config, client_factory=factory, usage_path=tmp_path / "usage.jsonl")
    chunks = [part async for part in llm.stream(task="shield", system="system", user="user")]

    assert chunks == ["hello ", "world"]
    assert llm.last_provider == "local"
    assert len(calls["deepseek"]) == 1
    assert len(calls["local"]) == 1


@pytest.mark.asyncio
async def test_claude_uses_its_cache_control_payload(tmp_path: Path) -> None:
    config = DeepSecConfig(
        llm=LLMConfig(provider="claude", api_key="claude-key"),
        storage=StorageConfig(runs_dir=str(tmp_path / "runs")),
    )
    calls = []

    def factory(_provider: str, _api_key: str, _base_url: str):
        return FakeClient([response('{"findings": []}')], calls)

    llm = DeepSecLLM(config, client_factory=factory, usage_path=tmp_path / "usage.jsonl")
    await llm.shield_review("print('ok')")

    assert calls[0]["extra_body"] == {"cache_control": {"type": "ephemeral"}}


def test_load_config_supports_provider_overrides_and_fallbacks(tmp_path: Path) -> None:
    from deepsec.core.config import load_config

    path = tmp_path / "config.yaml"
    path.write_text(
        """llm:
  provider: deepseek
  api_key: primary
  fallbacks:
    - openai
    - local
  providers:
    openai:
      api_key: openai-key
      base_url: https://openai.example/v1
      chat_model: gpt-custom
""",
        encoding="utf-8",
    )

    config = load_config(path)

    assert config.llm.fallbacks == ["openai", "local"]
    assert config.llm.providers["openai"].chat_model == "gpt-custom"
