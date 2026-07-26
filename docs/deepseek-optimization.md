# DeepSeek And LLM Configuration

`DeepSecLLM` routes Shield reviews to the chat model and Spear reasoning to the reasoning model. Providers are independent clients with a deterministic fallback chain, so a failed DeepSeek request cannot reuse the wrong endpoint for OpenAI, Claude, or a local server.

```toml
[llm]
provider = "deepseek"
fallbacks = ["claude", "openai", "local"]

[llm.providers.deepseek]
api_key = ""
base_url = ""

[llm.providers.openai]
api_key = ""
base_url = ""

[llm.shield]
chat_model = "deepseek-chat"

[llm.spear]
reason_model = "deepseek-reasoner"
explore_model = "deepseek-chat"
```

Use `DEEPSEC_DEEPSEEK_API_KEY` for a provider-specific secret or `DEEPSEC_LLM_API_KEY` for the primary provider. DeepSeek requests enable prompt caching through `extra_body.prompt_cache`; usage-only metadata containing provider, model, token counts, and estimated cost is appended to `~/.deepsec/runs/llm-usage.jsonl`. Prompts and credentials are never written there.
