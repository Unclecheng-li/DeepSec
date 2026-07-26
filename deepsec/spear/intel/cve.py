"""CVE / exploit intelligence for VulnClaw.

Ported from HackBot (``hackbot/core/cve.py``) and rewritten for VulnClaw's
async, httpx-based stack. Queries NVD (keyless, or with an API key for higher
rate limits) and optionally discovers exploit PoC repositories on GitHub.

Exposed to the agent as the read-only ``cve_lookup`` tool.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Optional

import httpx

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_EXPLOIT_SEARCH = "https://api.github.com/search/repositories"

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# NVD allows ~5 req/30s without an API key, ~50 req/30s with one.
_NVD_RATE_LIMIT_NO_KEY = 6.5
_NVD_RATE_LIMIT_WITH_KEY = 0.6
_rate_lock = asyncio.Lock()
_last_nvd_request = 0.0


# ── Data model ───────────────────────────────────────────────────────────────


@dataclass
class CVEEntry:
    """Single CVE record."""

    cve_id: str
    description: str
    severity: str = "Unknown"
    cvss_score: float = 0.0
    cvss_vector: str = ""
    published: str = ""
    modified: str = ""
    references: list[str] = field(default_factory=list)
    cpe_matches: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)
    exploits: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "published": self.published,
            "modified": self.modified,
            "references": self.references,
            "cpe_matches": self.cpe_matches,
            "weaknesses": self.weaknesses,
            "exploits": list(self.exploits),
        }

    @property
    def severity_label(self) -> str:
        if self.cvss_score >= 9.0:
            return "Critical"
        if self.cvss_score >= 7.0:
            return "High"
        if self.cvss_score >= 4.0:
            return "Medium"
        if self.cvss_score > 0:
            return "Low"
        return "Info"


# ── NVD parsing ──────────────────────────────────────────────────────────────


def _parse_nvd_item(item: dict[str, Any]) -> CVEEntry:
    """Parse a single NVD CVE item into a CVEEntry."""
    cve_data = item.get("cve", {})
    cve_id = cve_data.get("id", "")

    descriptions = cve_data.get("descriptions", [])
    desc = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    if not desc and descriptions:
        desc = descriptions[0].get("value", "")

    metrics = cve_data.get("metrics", {})
    cvss_score = 0.0
    cvss_vector = ""
    severity = "Unknown"
    for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(version, [])
        if metric_list:
            primary = metric_list[0]
            cvss_data = primary.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_vector = cvss_data.get("vectorString", "")
            severity = primary.get("baseSeverity", cvss_data.get("baseSeverity", "Unknown"))
            break

    published = (cve_data.get("published", "") or "")[:10]
    modified = (cve_data.get("lastModified", "") or "")[:10]

    refs = [ref.get("url", "") for ref in cve_data.get("references", []) if ref.get("url")]

    cpe_matches = []
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if criteria:
                    cpe_matches.append(criteria)

    weaknesses = []
    for w in cve_data.get("weaknesses", []):
        for wd in w.get("description", []):
            val = wd.get("value", "")
            if val and val not in ("NVD-CWE-Other", "NVD-CWE-noinfo"):
                weaknesses.append(val)

    return CVEEntry(
        cve_id=cve_id,
        description=desc,
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        published=published,
        modified=modified,
        references=refs[:10],
        cpe_matches=cpe_matches[:20],
        weaknesses=weaknesses,
    )


# ── HTTP helpers ─────────────────────────────────────────────────────────────


def _headers(api_key: str) -> dict[str, str]:
    headers = {
        "User-Agent": "VulnClaw/0.3 CVE-Lookup",
        "Accept": "application/json",
    }
    if api_key:
        headers["apiKey"] = api_key
    return headers


@contextlib.asynccontextmanager
async def _client_ctx(
    client: Optional[httpx.AsyncClient], timeout: float, api_key: str
) -> AsyncIterator[httpx.AsyncClient]:
    """Yield the caller's client, or a short-lived one closed on exit."""
    if client is not None:
        yield client
        return
    async with httpx.AsyncClient(timeout=timeout, headers=_headers(api_key)) as owned:
        yield owned


async def _nvd_rate_limit(has_key: bool) -> None:
    global _last_nvd_request
    async with _rate_lock:
        limit = _NVD_RATE_LIMIT_WITH_KEY if has_key else _NVD_RATE_LIMIT_NO_KEY
        elapsed = time.monotonic() - _last_nvd_request
        if 0 < elapsed < limit:
            await asyncio.sleep(limit - elapsed)
        _last_nvd_request = time.monotonic()


# ── Queries ──────────────────────────────────────────────────────────────────


async def search_cve(
    keyword: str,
    *,
    max_results: int = 20,
    severity: str = "",
    api_key: str = "",
    timeout: float = 20.0,
    client: Optional[httpx.AsyncClient] = None,
    rate_limit: bool = True,
) -> list[CVEEntry]:
    """Search NVD for CVEs matching a keyword, sorted by CVSS descending."""
    keyword = keyword.strip()
    if not keyword:
        return []
    max_results = min(max_results, 50)

    params: dict[str, Any] = {"keywordSearch": keyword, "resultsPerPage": max_results}
    sev = severity.upper()
    if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        params["cvssV3Severity"] = sev

    if rate_limit:
        await _nvd_rate_limit(bool(api_key))

    try:
        async with _client_ctx(client, timeout, api_key) as c:
            resp = await c.get(NVD_API_BASE, params=params)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return []

    results = [_parse_nvd_item(item) for item in data.get("vulnerabilities", [])]
    results.sort(key=lambda e: e.cvss_score, reverse=True)
    return results


async def lookup_cve_id(
    cve_id: str,
    *,
    api_key: str = "",
    timeout: float = 20.0,
    client: Optional[httpx.AsyncClient] = None,
    rate_limit: bool = True,
    with_exploits: bool = True,
) -> Optional[CVEEntry]:
    """Look up a specific CVE by ID (e.g. CVE-2021-44228)."""
    cve_id = cve_id.strip().upper()
    if not _CVE_ID_RE.match(cve_id):
        return None

    if rate_limit:
        await _nvd_rate_limit(bool(api_key))

    try:
        async with _client_ctx(client, timeout, api_key) as c:
            resp = await c.get(NVD_API_BASE, params={"cveId": cve_id})
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None
            entry = _parse_nvd_item(vulns[0])
            if with_exploits:
                entry.exploits = await search_exploits(cve_id, client=c, timeout=timeout)
            return entry
    except (httpx.HTTPError, ValueError):
        return None


async def search_exploits(
    query: str,
    *,
    max_results: int = 5,
    timeout: float = 20.0,
    client: Optional[httpx.AsyncClient] = None,
) -> list[dict[str, str]]:
    """Best-effort GitHub search for exploit / PoC repositories."""
    exploits: list[dict[str, str]] = []
    try:
        async with _client_ctx(client, timeout, "") as c:
            resp = await c.get(
                GITHUB_EXPLOIT_SEARCH,
                params={
                    "q": f"{query} exploit OR poc OR vulnerability",
                    "sort": "stars",
                    "order": "desc",
                    "per_page": min(max_results, 20),
                },
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            for repo in data.get("items", [])[:max_results]:
                exploits.append(
                    {
                        "title": repo.get("full_name", ""),
                        "source": "GitHub",
                        "url": repo.get("html_url", ""),
                        "description": (repo.get("description") or "")[:200],
                        "stars": str(repo.get("stargazers_count", 0)),
                        "language": repo.get("language") or "",
                    }
                )
    except (httpx.HTTPError, ValueError):
        return []
    return exploits


# ── Formatting ───────────────────────────────────────────────────────────────


def format_cve_report(cves: list[CVEEntry], title: str = "CVE Results") -> str:
    """Format CVEs as a markdown report (table + detail for top entries)."""
    if not cves:
        return f"## {title}\n\nNo CVEs found."

    lines = [f"## {title}\n", f"**{len(cves)} vulnerabilities found**\n"]
    lines.append("| CVE ID | CVSS | Severity | Description |")
    lines.append("|--------|------|----------|-------------|")
    for cve in cves:
        desc = cve.description[:100] + "..." if len(cve.description) > 100 else cve.description
        desc = desc.replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {cve.cve_id} | {cve.cvss_score} | {cve.severity_label} | {desc} |")
    lines.append("")

    for cve in cves[:5]:
        lines.append(f"### {cve.cve_id} — CVSS {cve.cvss_score} ({cve.severity_label})")
        lines.append(f"\n{cve.description}\n")
        if cve.weaknesses:
            lines.append(f"**Weaknesses:** {', '.join(cve.weaknesses)}")
        if cve.published:
            lines.append(f"**Published:** {cve.published}")
        if cve.references:
            lines.append("\n**References:**")
            for ref in cve.references[:5]:
                lines.append(f"- {ref}")
        if cve.exploits:
            lines.append("\n**Known exploit / PoC repositories:**")
            for exp in cve.exploits:
                stars = f" ⭐ {exp['stars']}" if exp.get("stars") else ""
                lines.append(f"- [{exp['title']}]({exp['url']}){stars}")
        lines.append("")

    return "\n".join(lines)


# ── Tool handler ─────────────────────────────────────────────────────────────


def _resolve_nvd_key(agent: Any) -> str:
    """Resolve an NVD API key from agent config, else the NVD_API_KEY env var."""
    cfg = getattr(agent, "config", None)
    intel = getattr(cfg, "intel", None)
    key = getattr(intel, "nvd_api_key", "") if intel is not None else ""
    return (key or os.environ.get("NVD_API_KEY", "") or "").strip()


async def cve_lookup_tool(agent: Any, args: dict[str, Any]) -> str:
    """Agent tool: look up CVEs by keyword or CVE-ID against NVD."""
    query = str(args.get("query", "") or "").strip()
    if not query:
        return "[cve_lookup] error: 'query' is required (a keyword or a CVE-ID)."
    try:
        limit = int(args.get("limit", 5) or 5)
    except (TypeError, ValueError):
        limit = 5
    limit = max(1, min(limit, 50))

    api_key = _resolve_nvd_key(agent)

    if _CVE_ID_RE.match(query.upper()):
        entry = await lookup_cve_id(query, api_key=api_key)
        if entry is None:
            return f"[cve_lookup] No NVD record found for {query.upper()}."
        return format_cve_report([entry], title=f"CVE detail: {query.upper()}")

    entries = await search_cve(query, max_results=limit, api_key=api_key)
    if not entries:
        return f"[cve_lookup] No CVEs found for '{query}'."
    return format_cve_report(entries, title=f"CVE search: {query}")
