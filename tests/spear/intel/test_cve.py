import httpx
import pytest

from deepsec.spear.intel import cve
from deepsec.spear.intel.cve import (
    CVEEntry,
    cve_lookup_tool,
    format_cve_report,
    lookup_cve_id,
    search_cve,
)

# Minimal NVD 2.0 response shaped like the real API.
NVD_SAMPLE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [
                    {"lang": "en", "value": "Apache Log4j2 JNDI features allow RCE."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "vectorString": "CVSS:3.1/AV:N/AC:L",
                                "baseSeverity": "CRITICAL",
                            },
                            "baseSeverity": "CRITICAL",
                        }
                    ]
                },
                "published": "2021-12-10T00:00:00.000",
                "lastModified": "2023-04-03T00:00:00.000",
                "references": [{"url": "https://logging.apache.org/log4j/"}],
                "weaknesses": [{"description": [{"value": "CWE-502"}]}],
                "configurations": [
                    {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:log4j:2.0"}]}]}
                ],
            }
        }
    ]
}

GITHUB_SAMPLE = {
    "items": [
        {
            "full_name": "owner/log4shell-poc",
            "html_url": "https://github.com/owner/log4shell-poc",
            "description": "PoC",
            "stargazers_count": 1234,
            "language": "Java",
        }
    ]
}


def _mock_client() -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "services.nvd.nist.gov" in url:
            return httpx.Response(200, json=NVD_SAMPLE)
        if "api.github.com" in url:
            return httpx.Response(200, json=GITHUB_SAMPLE)
        return httpx.Response(404, json={})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_parse_nvd_item_extracts_fields():
    entry = cve._parse_nvd_item(NVD_SAMPLE["vulnerabilities"][0])
    assert entry.cve_id == "CVE-2021-44228"
    assert entry.cvss_score == 10.0
    assert entry.severity_label == "Critical"
    assert "CWE-502" in entry.weaknesses
    assert entry.references and entry.cpe_matches


@pytest.mark.asyncio
async def test_search_cve_returns_sorted_entries():
    async with _mock_client() as client:
        results = await search_cve(
            "log4j", max_results=5, client=client, rate_limit=False
        )
    assert len(results) == 1
    assert isinstance(results[0], CVEEntry)
    assert results[0].cve_id == "CVE-2021-44228"


@pytest.mark.asyncio
async def test_lookup_cve_id_attaches_exploits():
    async with _mock_client() as client:
        entry = await lookup_cve_id(
            "CVE-2021-44228", client=client, rate_limit=False, with_exploits=True
        )
    assert entry is not None
    assert entry.exploits and entry.exploits[0]["source"] == "GitHub"


@pytest.mark.asyncio
async def test_lookup_cve_id_rejects_malformed_id():
    async with _mock_client() as client:
        entry = await lookup_cve_id("not-a-cve", client=client, rate_limit=False)
    assert entry is None


def test_format_cve_report_renders_table_and_detail():
    entry = cve._parse_nvd_item(NVD_SAMPLE["vulnerabilities"][0])
    out = format_cve_report([entry], title="CVE search: log4j")
    assert "CVE search: log4j" in out
    assert "CVE-2021-44228" in out
    assert "| CVE ID | CVSS | Severity |" in out


def test_format_cve_report_empty():
    assert "No CVEs found" in format_cve_report([], title="x")


@pytest.mark.asyncio
async def test_tool_empty_query_is_structured_error():
    out = await cve_lookup_tool(agent=None, args={"query": "  "})
    assert out.startswith("[cve_lookup]") and "query" in out


@pytest.mark.asyncio
async def test_tool_routes_cve_id_vs_keyword(monkeypatch):
    calls = {}

    async def fake_lookup(cve_id, **kw):
        calls["id"] = cve_id
        return cve._parse_nvd_item(NVD_SAMPLE["vulnerabilities"][0])

    async def fake_search(keyword, **kw):
        calls["kw"] = keyword
        return [cve._parse_nvd_item(NVD_SAMPLE["vulnerabilities"][0])]

    monkeypatch.setattr(cve, "lookup_cve_id", fake_lookup)
    monkeypatch.setattr(cve, "search_cve", fake_search)

    out_id = await cve_lookup_tool(agent=None, args={"query": "CVE-2021-44228"})
    out_kw = await cve_lookup_tool(agent=None, args={"query": "log4j"})

    assert calls.get("id") == "CVE-2021-44228"
    assert calls.get("kw") == "log4j"
    assert "CVE-2021-44228" in out_id and "CVE-2021-44228" in out_kw
