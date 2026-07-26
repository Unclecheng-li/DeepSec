"""Knowledge-base prompt context helpers for AgentCore."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from deepsec.spear.agent.agent_context import AgentContext


from deepsec.kb.retriever import KnowledgeRetriever, RetrieverStatus

logger = logging.getLogger(__name__)


def _retriever_for(agent: AgentContext) -> Optional[KnowledgeRetriever]:
    """Return the agent's KB retriever, lazily initializing it once.

    Returns None when the retriever cannot be constructed at all, so callers
    can degrade silently without raising into the main loop.
    """
    if KnowledgeRetriever is None:
        return None
    if getattr(agent, "_kb_retriever", None) is None:
        try:
            agent._kb_retriever = KnowledgeRetriever()
        except Exception as exc:  # defensive — never break the agent loop
            logger.warning("KB retriever initialization failed: %s", exc)
            agent._kb_retriever = None
    return agent._kb_retriever


def build_kb_context(agent: AgentContext, user_input: Optional[str] = None) -> str:
    """Build knowledge-base context for prompt injection.

    Results are cached per agent for identical queries within a session so the
    same lookup is not repeated. Any retrieval failure degrades silently to an
    empty context (logged, not raised).
    """
    retriever = _retriever_for(agent)
    if retriever is None or retriever.get_status() is RetrieverStatus.DISABLED:
        return ""

    # ── Session-level cache (keyed by the query signature) ───────────
    cache = getattr(agent, "_kb_context_cache", None)
    if cache is None:
        cache = {}
        agent._kb_context_cache = cache

    services = []
    recon = getattr(agent.context.state, "recon_data", {})
    if isinstance(recon, dict):
        services = recon.get("services", [])
    finding_types = [
        (f.vuln_type or "").lower() for f in agent.context.state.findings if (f.vuln_type or "")
    ]
    cache_key = (
        (user_input or "").lower(),
        tuple(str(s).lower() for s in services[:3]),
        tuple(finding_types[:3]),
    )
    if cache_key in cache:
        return cache[cache_key]

    try:
        context = _collect_kb_context(agent, retriever, user_input, services, finding_types)
    except Exception as exc:  # defensive — retrieval must never break the loop
        logger.warning("KB context build failed: %s", exc)
        context = ""

    cache[cache_key] = context
    return context


def _collect_kb_context(
    agent,
    retriever: KnowledgeRetriever,
    user_input: Optional[str],
    services: list,
    finding_types: list[str],
) -> str:
    """Gather and format relevant KB entries (backend-agnostic)."""
    entries: list[dict[str, Any]] = []

    for svc in services[:3]:
        parts = str(svc).lower().split("/")
        name = parts[0]
        version = parts[1] if len(parts) > 1 else ""
        entries.extend(retriever.search_by_service(name, version))

    for vuln_type in finding_types[:3]:
        if vuln_type:
            entries.extend(retriever.search_technique(vuln_type))

    if user_input and "waf" in user_input.lower():
        entries.extend(retriever.get_waf_bypass())

    if user_input:
        for keyword in ("sqli", "xss", "rce", "lfi", "ssrf", "csrf", "deserialization"):
            if keyword in user_input.lower():
                entries.extend(retriever.search_technique(keyword))

    # Generic semantic/keyword retrieval over the free-form user input.
    if user_input:
        entries.extend(retriever.retrieve(user_input, top_k=3))

    seen_ids: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for entry in entries:
        eid = entry.get("id", entry.get("title", ""))
        if eid and eid not in seen_ids:
            seen_ids.add(eid)
            deduped.append(entry)

    if not deduped:
        return ""

    formatted = retriever.format_for_prompt(deduped, max_entries=5)
    return (
        "## 知识库参考（相关 CVE / 利用技巧 / 绕过方法）\n"
        "以下信息来自本地安全知识库，供参考使用：\n\n"
        f"{formatted}\n"
    )
