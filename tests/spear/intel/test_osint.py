import socket

import httpx
import pytest

from deepsec.spear.intel import osint
from deepsec.spear.intel.osint import (
    DNSRecord,
    OSINTReport,
    SubdomainResult,
    WHOISResult,
    clean_domain,
    crtsh_subdomains,
    enumerate_subdomains,
    fingerprint_tech,
    format_report,
    get_dns_records,
    is_valid_subdomain,
    normalize_url,
    osint_recon_tool,
    rdap_whois,
)

CRTSH_SAMPLE = [
    {"name_value": "www.example.com\nadmin.example.com"},
    {"name_value": "*.example.com"},
    {"name_value": "mail.example.com"},
]

RDAP_SAMPLE = {
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar Inc"]]],
        }
    ],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
    ],
    "nameservers": [{"ldhName": "a.iana-servers.net"}, {"ldhName": "b.iana-servers.net"}],
    "status": ["client delete prohibited"],
}

TECH_HTML = (
    "<html><head>"
    '<meta name="generator" content="WordPress 6.4">'
    '<script src="/wp-includes/js/jquery.js"></script>'
    "</head><body>wp-content theme</body></html>"
)


# ── pure helpers ─────────────────────────────────────────────────────────────


def test_clean_domain_strips_scheme_path_port_www():
    assert clean_domain("https://www.Example.com:443/path?x=1") == "example.com"


def test_normalize_url_adds_scheme():
    assert normalize_url("example.com") == "https://example.com"
    assert normalize_url("http://x.io") == "http://x.io"


def test_is_valid_subdomain():
    assert is_valid_subdomain("a.example.com")
    assert not is_valid_subdomain("bad_underscore.example.com")
    assert not is_valid_subdomain("")


# ── HTTP features via MockTransport ──────────────────────────────────────────


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_crtsh_subdomains_parses_ct_log():
    def handler(req):
        assert "crt.sh" in str(req.url)
        return httpx.Response(200, json=CRTSH_SAMPLE)

    async with _client(handler) as c:
        subs = await crtsh_subdomains("example.com", client=c)
    assert subs == {"www.example.com", "admin.example.com", "mail.example.com", "example.com"}


@pytest.mark.asyncio
async def test_enumerate_subdomains_no_resolve():
    def handler(req):
        return httpx.Response(200, json=CRTSH_SAMPLE)

    async with _client(handler) as c:
        results = await enumerate_subdomains("example.com", resolve=False, client=c)
    names = [r.subdomain for r in results]
    assert names == sorted(names)
    assert "www.example.com" in names
    assert all(isinstance(r, SubdomainResult) for r in results)


@pytest.mark.asyncio
async def test_rdap_whois_parses_fields():
    def handler(req):
        assert "rdap.org" in str(req.url)
        return httpx.Response(200, json=RDAP_SAMPLE)

    async with _client(handler) as c:
        w = await rdap_whois("example.com", client=c)
    assert isinstance(w, WHOISResult)
    assert w.registrar == "Example Registrar Inc"
    assert w.creation_date == "1995-08-14"
    assert w.expiration_date == "2026-08-13"
    assert "a.iana-servers.net" in w.name_servers


@pytest.mark.asyncio
async def test_rdap_whois_returns_none_on_404():
    async with _client(lambda req: httpx.Response(404, json={})) as c:
        assert await rdap_whois("nope.example", client=c) is None


@pytest.mark.asyncio
async def test_fingerprint_tech_detects_stack():
    def handler(req):
        return httpx.Response(
            200,
            headers={
                "Server": "nginx/1.18.0",
                "X-Powered-By": "PHP/8.1",
                "Set-Cookie": "PHPSESSID=abc123; Path=/",
            },
            text=TECH_HTML,
        )

    async with _client(handler) as c:
        result = await fingerprint_tech("example.com", client=c, check_ssl=False)

    names = {t["name"] for t in result.technologies}
    assert "Nginx" in names
    assert "PHP" in names  # from header and/or cookie
    assert "WordPress" in names  # from html "wp-content"
    assert result.server.startswith("nginx")
    assert "PHPSESSID" in result.cookies
    assert any("jquery" in s for s in result.scripts)
    assert "WordPress 6.4" in result.frameworks


# ── DNS fallback ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_dns_records_socket_fallback(monkeypatch):
    monkeypatch.setattr(osint, "_dnspython_records", lambda d, t: None)

    def fake_getaddrinfo(host, port):
        return [(socket.AF_INET, None, None, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    records = await get_dns_records("example.com")
    assert any(r.record_type == "A" and r.value == "93.184.216.34" for r in records)


# ── formatting ───────────────────────────────────────────────────────────────


def test_format_report_sections():
    report = OSINTReport(
        domain="example.com",
        subdomains=[SubdomainResult(subdomain="www.example.com", ip="1.2.3.4", source="crt.sh")],
        dns_records=[DNSRecord(record_type="A", value="1.2.3.4", ttl=300)],
        whois=WHOISResult(domain="example.com", registrar="Example Registrar Inc"),
        emails=["info@example.com"],
    )
    out = format_report(report)
    assert "# OSINT Report: example.com" in out
    assert "## Subdomains" in out
    assert "## DNS Records" in out
    assert "Example Registrar Inc" in out
    assert "info@example.com" in out


# ── tool ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tool_rejects_invalid_domain():
    out = await osint_recon_tool(agent=None, args={"domain": "not a domain"})
    assert out.startswith("[osint_recon]") and "domain" in out


@pytest.mark.asyncio
async def test_tool_orchestrates_without_network(monkeypatch):
    async def fake_subs(domain, **kw):
        return [SubdomainResult(subdomain="www.example.com", ip="1.2.3.4", source="crt.sh")]

    async def fake_dns(domain, **kw):
        return [DNSRecord(record_type="A", value="1.2.3.4", ttl=300)]

    async def fake_whois(domain, **kw):
        return WHOISResult(domain="example.com", registrar="Example Registrar Inc")

    async def fake_tech(domain, **kw):
        return osint.TechStackResult(url="https://example.com", server="nginx")

    async def fake_emails(domain, **kw):
        return ["info@example.com"]

    monkeypatch.setattr(osint, "enumerate_subdomains", fake_subs)
    monkeypatch.setattr(osint, "get_dns_records", fake_dns)
    monkeypatch.setattr(osint, "whois_lookup", fake_whois)
    monkeypatch.setattr(osint, "fingerprint_tech", fake_tech)
    monkeypatch.setattr(osint, "common_emails", fake_emails)

    out = await osint_recon_tool(agent=None, args={"domain": "example.com"})
    assert "# OSINT Report: example.com" in out
    assert "www.example.com" in out
    assert "Example Registrar Inc" in out
    assert "info@example.com" in out
