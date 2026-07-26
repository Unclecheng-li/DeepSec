"""Provider-neutral LLM routing with DeepSeek-first fallback and streaming."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import DeepSecConfig, ProviderConfig

logger = logging.getLogger(__name__)


SHIELD_SYSTEM_PROMPT = """You are DeepSec Shield's code-security auditor.
Review only the supplied code. Return a JSON object with a `findings` array.
Each finding needs: severity, title, description, line, evidence, suggestion,
and confidence. Focus on authentication, authorization, validation, output
encoding, rate limits, secret handling, SSRF defenses, and error disclosure.
Do not invent files, runtime behavior, or findings without code evidence."""

SPEAR_REASON_SYSTEM_PROMPT = """You are DeepSec Spear's planning assistant.
Work only within explicitly authorized scope. Return a JSON object describing a
cautious evidence-driven assessment plan; never claim execution or findings
without tool evidence."""

SPEAR_EXPLORE_SYSTEM_PROMPT = """You are DeepSec Spear's authorized task assistant.
Use only explicitly authorized tools and scope. Return structured JSON with
actions and evidence requirements; do not invent tool results."""


@dataclass(frozen=True, slots=True)
class ProviderDefaults:
    base_url: str
    chat_model: str
    reason_model: str
    prompt_cost_per_million: float
    completion_cost_per_million: float
    supports_prompt_cache: bool = False


_PROVIDER_DEFAULTS: dict[str, ProviderDefaults] = {
    "deepseek": ProviderDefaults("https://api.deepseek.com/v1", "deepseek-chat", "deepseek-reasoner", 0.28, 0.42, True),
    "openai": ProviderDefaults("https://api.openai.com/v1", "gpt-4o", "gpt-4o", 2.50, 10.00),
    "claude": ProviderDefaults("https://api.anthropic.com/v1", "claude-sonnet-4-20250514", "claude-sonnet-4-20250514", 3.00, 15.00),
    "local": ProviderDefaults("http://localhost:11434/v1", "qwen2.5-coder:7b", "qwen2.5-coder:7b", 0.0, 0.0),
}


@dataclass(slots=True)
class LLMUsage:
    provider: str
    model: str
    task: str
    input_tokens: int | None = None
    output_tokens: int | None = None
    estimated_cost_usd: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


ClientFactory = Callable[[str, str, str], Any]


class DeepSecLLM:
    """OpenAI-compatible multi-provider LLM client.

    Clients are created lazily and are always keyed by provider, preventing a
    fallback request from retaining the failed provider's base URL. The class
    writes usage-only metadata to the run artifact directory; prompts and API
    keys are never recorded.
    """

    def __init__(
        self,
        config: DeepSecConfig,
        *,
        client_factory: ClientFactory | None = None,
        usage_path: Path | None = None,
        max_retries: int = 2,
    ):
        self.config = config
        self._client_factory = client_factory or self._openai_client
        self._clients: dict[str, Any] = {}
        self._usage_path = usage_path or Path(config.storage.runs_dir) / "llm-usage.jsonl"
        self._max_retries = max(1, max_retries)
        self.usage_history: list[LLMUsage] = []
        self.last_provider: str | None = None
        self.failures: list[tuple[str, str]] = []

    @property
    def configured(self) -> bool:
        return bool(self._provider_chain())

    @property
    def provider_chain(self) -> list[str]:
        """Expose the effective configured provider chain for status UIs."""
        return self._provider_chain()

    async def shield_review(self, code: str, context: str = "") -> tuple[dict[str, Any], LLMUsage]:
        return await self.call(
            task="shield",
            system=SHIELD_SYSTEM_PROMPT,
            user=f"File context: {context}\n\n```\n{code}\n```",
        )

    async def spear_reason(self, target_info: str, history: str) -> tuple[dict[str, Any], LLMUsage]:
        return await self.call(
            task="reason",
            system=SPEAR_REASON_SYSTEM_PROMPT,
            user=f"Target: {target_info}\n\nHistory: {history}",
        )

    async def spear_explore(self, task: str, tools: list[dict[str, Any]] | list[str]) -> tuple[dict[str, Any], LLMUsage]:
        return await self.call(
            task="explore",
            system=SPEAR_EXPLORE_SYSTEM_PROMPT,
            user=f"Task: {task}\n\nAvailable tools: {json.dumps(tools, ensure_ascii=False)}",
        )

    async def call(self, *, task: str, system: str, user: str) -> tuple[dict[str, Any], LLMUsage]:
        """Return a JSON response, retrying a provider before deterministic fallback."""
        errors: list[str] = []
        for provider in self._provider_chain():
            client = self._client(provider)
            model = self._model_for(provider, task)
            for attempt in range(self._max_retries):
                try:
                    response = await client.chat.completions.create(
                        model=model,
                        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                        temperature=0.1,
                        response_format={"type": "json_object"},
                        timeout=120,
                        **self._cache_extra(provider),
                    )
                    parsed = _parse_json(response.choices[0].message.content or "{}")
                    usage = self._usage(provider, model, task, getattr(response, "usage", None))
                    self._record_usage(usage)
                    self.last_provider = provider
                    return parsed, usage
                except Exception as error:  # Provider exceptions are intentionally fail-open to the next provider.
                    message = f"{type(error).__name__}: {error}"
                    errors.append(f"{provider} attempt {attempt + 1}: {message}")
                    self.failures.append((provider, message))
                    logger.warning("DeepSec LLM provider %s failed (attempt %s/%s): %s", provider, attempt + 1, self._max_retries, message)
                    if attempt + 1 < self._max_retries:
                        await asyncio.sleep(0)
            logger.info("DeepSec LLM falling back from %s", provider)
        raise RuntimeError("All configured LLM providers failed: " + " | ".join(errors))

    async def stream(self, *, task: str, system: str, user: str) -> AsyncIterator[str]:
        """Yield text deltas without blocking a TUI event loop.

        Fallback remains safe until a provider has emitted a delta. Once a
        provider has produced user-visible text, replaying another provider
        would duplicate output, so the original error is surfaced instead.
        """
        errors: list[str] = []
        for provider in self._provider_chain():
            model = self._model_for(provider, task)
            emitted = False
            try:
                stream = await self._client(provider).chat.completions.create(
                    model=model,
                    messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                    temperature=0.1,
                    stream=True,
                    timeout=120,
                    **self._cache_extra(provider),
                )
                async for chunk in stream:
                    delta = _chunk_text(chunk)
                    if delta:
                        emitted = True
                        yield delta
                usage = self._usage(provider, model, task, getattr(stream, "usage", None))
                self._record_usage(usage)
                self.last_provider = provider
                return
            except Exception as error:
                message = f"{type(error).__name__}: {error}"
                self.failures.append((provider, message))
                errors.append(f"{provider}: {message}")
                logger.warning("DeepSec LLM streaming provider %s failed: %s", provider, message)
                if emitted:
                    raise RuntimeError(f"Streaming provider {provider} failed after emitting output: {message}") from error
        raise RuntimeError("All configured LLM providers failed for streaming: " + " | ".join(errors))

    def _provider_chain(self) -> list[str]:
        ordered = [self.config.llm.provider.lower(), *self.config.llm.fallbacks]
        seen: set[str] = set()
        return [
            provider
            for provider in ordered
            if provider in _PROVIDER_DEFAULTS
            and provider not in seen
            and not seen.add(provider)
            and self._has_credentials(provider)
        ]

    def _has_credentials(self, provider: str) -> bool:
        if provider == "local":
            return True
        return bool(self._api_key_for(provider))

    def _api_key_for(self, provider: str) -> str:
        environment_key = f"DEEPSEC_{provider.upper()}_API_KEY"
        if value := __import__("os").environ.get(environment_key):
            return value
        override = self._provider_config(provider).api_key
        if override:
            return override
        return self.config.llm.api_key if provider == self.config.llm.provider.lower() else ""

    def _provider_config(self, provider: str) -> ProviderConfig:
        return self.config.llm.providers.get(provider, ProviderConfig())

    def _client(self, provider: str) -> Any:
        if provider not in self._clients:
            defaults = _PROVIDER_DEFAULTS[provider]
            override = self._provider_config(provider)
            self._clients[provider] = self._client_factory(
                provider,
                self._api_key_for(provider) or "local",
                override.base_url or (self.config.llm.base_url if provider == self.config.llm.provider.lower() else "") or defaults.base_url,
            )
        return self._clients[provider]

    def _model_for(self, provider: str, task: str) -> str:
        defaults = _PROVIDER_DEFAULTS[provider]
        override = self._provider_config(provider)
        if task == "reason":
            if override.reason_model:
                return override.reason_model
            if provider == self.config.llm.provider.lower() and self.config.llm.spear.reason_model:
                return self.config.llm.spear.reason_model
            return defaults.reason_model
        if override.chat_model:
            return override.chat_model
        if provider == self.config.llm.provider.lower():
            if task == "explore" and self.config.llm.spear.explore_model:
                return self.config.llm.spear.explore_model
            if self.config.llm.shield.chat_model:
                return self.config.llm.shield.chat_model
        return defaults.chat_model

    def _cache_extra(self, provider: str) -> dict[str, Any]:
        if provider == "deepseek":
            return {"extra_body": {"prompt_cache": {"enable": True}}}
        if provider == "claude":
            return {"extra_body": {"cache_control": {"type": "ephemeral"}}}
        return {}

    def _usage(self, provider: str, model: str, task: str, raw: Any) -> LLMUsage:
        input_tokens = _as_int(getattr(raw, "prompt_tokens", None))
        output_tokens = _as_int(getattr(raw, "completion_tokens", None))
        defaults = _PROVIDER_DEFAULTS[provider]
        cost = ((input_tokens or 0) * defaults.prompt_cost_per_million + (output_tokens or 0) * defaults.completion_cost_per_million) / 1_000_000
        return LLMUsage(provider=provider, model=model, task=task, input_tokens=input_tokens, output_tokens=output_tokens, estimated_cost_usd=round(cost, 8))

    def _record_usage(self, usage: LLMUsage) -> None:
        self.usage_history.append(usage)
        try:
            self._usage_path.parent.mkdir(parents=True, exist_ok=True)
            with self._usage_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(usage.to_dict(), ensure_ascii=False) + "\n")
        except OSError as error:
            logger.warning("DeepSec could not write LLM usage metadata: %s", error)

    @staticmethod
    def _openai_client(_provider: str, api_key: str, base_url: str) -> Any:
        try:
            from openai import AsyncOpenAI
        except ImportError as error:  # pragma: no cover - declared project dependency
            raise RuntimeError("Install DeepSec LLM dependencies first") from error
        return AsyncOpenAI(api_key=api_key, base_url=base_url)


def _as_int(value: Any) -> int | None:
    return value if isinstance(value, int) else None


def _chunk_text(chunk: Any) -> str:
    choices = getattr(chunk, "choices", None) or []
    if not choices:
        return ""
    delta = getattr(choices[0], "delta", None)
    return str(getattr(delta, "content", "") or "")


def _parse_json(content: str) -> dict[str, Any]:
    cleaned = content.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
    parsed = json.loads(cleaned)
    if not isinstance(parsed, dict):
        raise ValueError("The LLM response must be a JSON object")
    return parsed
