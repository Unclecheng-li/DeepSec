"""OSINT reconnaissance for VulnClaw.

Ported from HackBot (``hackbot/core/osint.py``) and rewritten for VulnClaw's
async stack: HTTP features (Certificate Transparency via crt.sh, RDAP WHOIS,
tech-stack fingerprinting) use httpx; blocking DNS / socket-WHOIS / TLS calls run
in worker threads. ``dnspython`` is an optional enhancement (``vulnclaw[osint]``);
without it DNS resolution falls back to the stdlib socket resolver.

Exposed to the agent as the ``osint_recon`` tool. This is *active* recon (it
contacts the target and third-party services), so it is classified as ``recon``
rather than read-only.
"""

from __future__ import annotations

import contextlib
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Optional
from urllib.parse import urlparse

import httpx

_BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

DEFAULT_MODULES = ("subdomains", "dns", "whois", "tech", "emails")


# ── Data models ──────────────────────────────────────────────────────────────


@dataclass
class SubdomainResult:
    subdomain: str
    ip: str = ""
    source: str = ""
    status: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "subdomain": self.subdomain,
            "ip": self.ip,
            "source": self.source,
            "status": self.status,
        }


@dataclass
class WHOISResult:
    domain: str
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    name_servers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    org: str = ""
    country: str = ""
    raw: str = ""


@dataclass
class DNSRecord:
    record_type: str
    value: str
    ttl: int = 0


@dataclass
class TechStackResult:
    url: str
    server: str = ""
    powered_by: str = ""
    technologies: list[dict[str, str]] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    meta_tags: dict[str, str] = field(default_factory=dict)
    scripts: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)


@dataclass
class OSINTReport:
    domain: str
    subdomains: list[SubdomainResult] = field(default_factory=list)
    dns_records: list[DNSRecord] = field(default_factory=list)
    whois: Optional[WHOISResult] = None
    tech_stack: Optional[TechStackResult] = None
    emails: list[str] = field(default_factory=list)


# ── Fingerprints / wordlists ─────────────────────────────────────────────────

TECH_FINGERPRINTS: dict[str, Any] = {
    "headers": {
        "X-Powered-By": {
            "Express": {"name": "Express.js", "category": "Web Framework"},
            "PHP": {"name": "PHP", "category": "Language"},
            "ASP.NET": {"name": "ASP.NET", "category": "Web Framework"},
            "Next.js": {"name": "Next.js", "category": "Web Framework"},
            "Servlet": {"name": "Java Servlet", "category": "Web Framework"},
        },
        "Server": {
            "nginx": {"name": "Nginx", "category": "Web Server"},
            "Apache": {"name": "Apache", "category": "Web Server"},
            "Microsoft-IIS": {"name": "IIS", "category": "Web Server"},
            "LiteSpeed": {"name": "LiteSpeed", "category": "Web Server"},
            "cloudflare": {"name": "Cloudflare", "category": "CDN"},
            "AmazonS3": {"name": "Amazon S3", "category": "Cloud Storage"},
            "gunicorn": {"name": "Gunicorn", "category": "Web Server"},
            "Caddy": {"name": "Caddy", "category": "Web Server"},
        },
        "X-AspNet-Version": {"": {"name": "ASP.NET", "category": "Web Framework"}},
        "X-Drupal-Cache": {"": {"name": "Drupal", "category": "CMS"}},
    },
    "cookies": {
        "PHPSESSID": {"name": "PHP", "category": "Language"},
        "JSESSIONID": {"name": "Java", "category": "Language"},
        "ASP.NET_SessionId": {"name": "ASP.NET", "category": "Web Framework"},
        "csrftoken": {"name": "Django", "category": "Web Framework"},
        "laravel_session": {"name": "Laravel", "category": "Web Framework"},
        "wp-settings": {"name": "WordPress", "category": "CMS"},
        "_rails_": {"name": "Ruby on Rails", "category": "Web Framework"},
        "connect.sid": {"name": "Express.js", "category": "Web Framework"},
    },
    "html": {
        "wp-content": {"name": "WordPress", "category": "CMS"},
        "wp-includes": {"name": "WordPress", "category": "CMS"},
        "Joomla": {"name": "Joomla", "category": "CMS"},
        "Drupal.settings": {"name": "Drupal", "category": "CMS"},
        "react": {"name": "React", "category": "JS Framework"},
        "vue": {"name": "Vue.js", "category": "JS Framework"},
        "angular": {"name": "Angular", "category": "JS Framework"},
        "__next": {"name": "Next.js", "category": "Web Framework"},
        "__nuxt": {"name": "Nuxt.js", "category": "Web Framework"},
        "gatsby": {"name": "Gatsby", "category": "Static Site Generator"},
        "shopify": {"name": "Shopify", "category": "E-Commerce"},
        "jquery": {"name": "jQuery", "category": "JS Library"},
        "bootstrap": {"name": "Bootstrap", "category": "CSS Framework"},
        "tailwindcss": {"name": "Tailwind CSS", "category": "CSS Framework"},
    },
}

SUBDOMAIN_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "test", "portal", "ns",
    "support", "dev", "web", "mx", "email", "cloud", "forum", "admin",
    "store", "cdn", "api", "exchange", "app", "vps", "news", "intranet",
    "staging", "beta", "demo", "internal", "lab", "stg", "sandbox", "git",
    "jenkins", "ci", "jira", "confluence", "wiki", "monitor", "grafana",
    "kibana", "status", "docs", "assets", "static", "media", "img", "files",
    "backup", "old", "legacy", "proxy", "gateway", "auth", "sso", "login",
]

COMMON_EMAIL_PREFIXES = [
    "info", "admin", "contact", "support", "hello", "sales",
    "security", "abuse", "webmaster", "postmaster", "hr",
]

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_SUBDOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$"
)
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)', re.IGNORECASE)
_META_RE = re.compile(
    r'<meta\s+(?:name|property)=["\']([^"\']+)["\']\s+content=["\']([^"\']+)',
    re.IGNORECASE,
)


# ── Utilities ────────────────────────────────────────────────────────────────


def clean_domain(domain: str) -> str:
    domain = domain.strip().lower()
    for prefix in ("https://", "http://", "www."):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    return domain


def normalize_url(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    return target


def is_valid_subdomain(name: str) -> bool:
    if not name or len(name) > 253:
        return False
    return bool(_SUBDOMAIN_RE.match(name))


@contextlib.asynccontextmanager
async def _client_ctx(
    client: Optional[httpx.AsyncClient], timeout: float, *, verify: bool = True
) -> AsyncIterator[httpx.AsyncClient]:
    if client is not None:
        yield client
        return
    async with httpx.AsyncClient(
        timeout=timeout,
        headers={"User-Agent": _BROWSER_UA},
        follow_redirects=True,
        verify=verify,
    ) as owned:
        yield owned


def _resolve_host(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except (socket.gaierror, OSError):
        return ""


# ── Subdomain enumeration ────────────────────────────────────────────────────


async def crtsh_subdomains(
    domain: str, *, client: Optional[httpx.AsyncClient] = None, timeout: float = 15.0
) -> set[str]:
    """Fetch subdomains from Certificate Transparency logs via crt.sh."""
    subs: set[str] = set()
    try:
        async with _client_ctx(client, timeout) as c:
            resp = await c.get(f"https://crt.sh/?q=%25.{domain}&output=json")
            if resp.status_code != 200:
                return subs
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return subs

    for entry in data:
        name = entry.get("name_value", "")
        for line in name.split("\n"):
            line = line.strip().lower().lstrip("*.")
            if (line.endswith(f".{domain}") or line == domain) and is_valid_subdomain(line):
                subs.add(line)
    return subs


async def enumerate_subdomains(
    domain: str,
    *,
    bruteforce: bool = False,
    resolve: bool = True,
    client: Optional[httpx.AsyncClient] = None,
    timeout: float = 15.0,
) -> list[SubdomainResult]:
    """Enumerate subdomains via Certificate Transparency + optional brute force."""
    domain = clean_domain(domain)
    found: dict[str, SubdomainResult] = {}

    for sub in await crtsh_subdomains(domain, client=client, timeout=timeout):
        found.setdefault(sub, SubdomainResult(subdomain=sub, source="crt.sh"))

    if bruteforce:
        for word in SUBDOMAIN_WORDLIST:
            sub = f"{word}.{domain}"
            if sub in found:
                continue
            ip = _resolve_host(sub)
            if ip:
                found[sub] = SubdomainResult(subdomain=sub, ip=ip, source="brute")

    if resolve:
        for result in found.values():
            if not result.ip:
                result.ip = _resolve_host(result.subdomain)

    return sorted(found.values(), key=lambda s: s.subdomain)


# ── DNS records ──────────────────────────────────────────────────────────────


def _dnspython_records(domain: str, timeout: float) -> Optional[list[DNSRecord]]:
    """Resolve records via dnspython, or None if dnspython is unavailable."""
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        return None

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    records: list[DNSRecord] = []
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV"):
        try:
            answers = resolver.resolve(domain, rtype)
        except Exception:
            continue
        ttl = answers.rrset.ttl if answers.rrset else 0
        for rdata in answers:
            records.append(DNSRecord(record_type=rtype, value=str(rdata), ttl=ttl))
    return records


def _socket_records(domain: str) -> list[DNSRecord]:
    records: list[DNSRecord] = []
    try:
        infos = socket.getaddrinfo(domain, None)
    except (socket.gaierror, OSError):
        return records
    seen: set[tuple[str, str]] = set()
    for family, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        rtype = "A" if family == socket.AF_INET else "AAAA"
        if (rtype, ip) not in seen:
            records.append(DNSRecord(record_type=rtype, value=ip))
            seen.add((rtype, ip))
    return records


def _dns_records_blocking(domain: str, timeout: float) -> list[DNSRecord]:
    records = _dnspython_records(domain, timeout)
    if records is not None:
        return records
    return _socket_records(domain)


async def get_dns_records(domain: str, *, timeout: float = 15.0) -> list[DNSRecord]:
    """Retrieve DNS records (dnspython if installed, socket fallback otherwise)."""
    return _dns_records_blocking(clean_domain(domain), timeout)


def _mx_exists_blocking(domain: str) -> bool:
    try:
        import dns.resolver

        return len(list(dns.resolver.resolve(domain, "MX"))) > 0
    except ImportError:
        pass
    except Exception:
        return False
    try:
        socket.getaddrinfo(f"mail.{domain}", 25)
        return True
    except (socket.gaierror, OSError):
        return False


# ── WHOIS ────────────────────────────────────────────────────────────────────


async def rdap_whois(
    domain: str, *, client: Optional[httpx.AsyncClient] = None, timeout: float = 15.0
) -> Optional[WHOISResult]:
    """RDAP lookup (IETF replacement for WHOIS)."""
    try:
        async with _client_ctx(client, timeout) as c:
            resp = await c.get(
                f"https://rdap.org/domain/{domain}",
                headers={"Accept": "application/rdap+json"},
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return None

    result = WHOISResult(domain=domain)
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray", [None, []])
            for item in vcard[1] if len(vcard) > 1 else []:
                if item and item[0] == "fn":
                    result.registrar = item[3]
                    break
    for event in data.get("events", []):
        date = (event.get("eventDate", "") or "")[:10]
        action = event.get("eventAction", "")
        if action == "registration":
            result.creation_date = date
        elif action == "expiration":
            result.expiration_date = date
        elif action == "last changed":
            result.updated_date = date
    for ns in data.get("nameservers", []):
        name = ns.get("ldhName", "")
        if name:
            result.name_servers.append(name)
    result.status = data.get("status", [])
    return result


def _socket_whois_blocking(domain: str, timeout: float) -> Optional[WHOISResult]:
    tld = domain.rsplit(".", 1)[-1]
    whois_servers = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "io": "whois.nic.io",
        "dev": "whois.nic.google",
        "app": "whois.nic.google",
    }
    server = whois_servers.get(tld, f"whois.nic.{tld}")
    try:
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.sendall(f"{domain}\r\n".encode())
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        text = b"".join(chunks).decode("utf-8", errors="replace")
    except (OSError, socket.error):
        return None

    result = WHOISResult(domain=domain, raw=text)
    for raw_line in text.splitlines():
        line = raw_line.strip()
        lower = line.lower()
        if "registrar:" in lower:
            result.registrar = line.split(":", 1)[1].strip()
        elif "creation date:" in lower or "created:" in lower:
            result.creation_date = line.split(":", 1)[1].strip()[:10]
        elif "expir" in lower and "date:" in lower:
            result.expiration_date = line.split(":", 1)[1].strip()[:10]
        elif "updated date:" in lower:
            result.updated_date = line.split(":", 1)[1].strip()[:10]
        elif "name server:" in lower:
            result.name_servers.append(line.split(":", 1)[1].strip())
        elif "registrant organization:" in lower:
            result.org = line.split(":", 1)[1].strip()
        elif "registrant country:" in lower:
            result.country = line.split(":", 1)[1].strip()
    result.emails = sorted(set(_EMAIL_RE.findall(text)))
    return result


async def whois_lookup(
    domain: str, *, client: Optional[httpx.AsyncClient] = None, timeout: float = 15.0
) -> Optional[WHOISResult]:
    """WHOIS via RDAP, falling back to socket WHOIS."""
    domain = clean_domain(domain)
    result = await rdap_whois(domain, client=client, timeout=timeout)
    if result:
        return result
    return _socket_whois_blocking(domain, timeout)


# ── Email harvesting ─────────────────────────────────────────────────────────


async def common_emails(domain: str) -> list[str]:
    """Generate common-prefix emails when the domain has MX records.

    Note: HackBot's search-engine scraping is intentionally dropped — it was
    unreliable and ToS-fragile. This yields deterministic, low-noise candidates.
    """
    domain = clean_domain(domain)
    if not _mx_exists_blocking(domain):
        return []
    return sorted(f"{prefix}@{domain}" for prefix in COMMON_EMAIL_PREFIXES)


# ── Tech stack fingerprinting ────────────────────────────────────────────────


def _ssl_issuer_org(hostname: str, timeout: float) -> str:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as s:
                cert = s.getpeercert()
        if cert:
            issuer = dict(x[0] for x in cert.get("issuer", []))
            return issuer.get("organizationName", "")
    except (OSError, ssl.SSLError):
        return ""
    return ""


async def fingerprint_tech(
    target: str,
    *,
    client: Optional[httpx.AsyncClient] = None,
    timeout: float = 15.0,
    check_ssl: bool = True,
) -> TechStackResult:
    """Detect technologies from HTTP headers, cookies, HTML, and TLS issuer."""
    url = normalize_url(target)
    result = TechStackResult(url=url)
    try:
        async with _client_ctx(client, timeout, verify=False) as c:
            resp = await c.get(url)
    except httpx.HTTPError:
        return result

    result.headers = dict(resp.headers)
    result.server = resp.headers.get("Server", "")
    result.powered_by = resp.headers.get("X-Powered-By", "")

    for header_name, patterns in TECH_FINGERPRINTS["headers"].items():
        header_val = resp.headers.get(header_name, "")
        if not header_val:
            continue
        for pattern, tech in patterns.items():
            if not pattern or pattern.lower() in header_val.lower():
                result.technologies.append(
                    {
                        "name": tech["name"],
                        "category": tech["category"],
                        "evidence": f"Header: {header_name}: {header_val[:100]}",
                    }
                )

    for cookie in resp.cookies.jar:
        name = cookie.name
        result.cookies.append(name)
        for pattern, tech in TECH_FINGERPRINTS["cookies"].items():
            if pattern.lower() in name.lower():
                result.technologies.append(
                    {
                        "name": tech["name"],
                        "category": tech["category"],
                        "evidence": f"Cookie: {name}",
                    }
                )

    html = resp.text
    for pattern, tech in TECH_FINGERPRINTS["html"].items():
        if pattern.lower() in html.lower():
            result.technologies.append(
                {
                    "name": tech["name"],
                    "category": tech["category"],
                    "evidence": f"HTML content match: {pattern}",
                }
            )

    result.scripts = _SCRIPT_SRC_RE.findall(html)[:20]
    for name, content in _META_RE.findall(html):
        result.meta_tags[name] = content[:200]
        if "generator" in name.lower():
            result.frameworks.append(content)

    if check_ssl:
        parsed = urlparse(url)
        if parsed.scheme == "https" and parsed.hostname:
            org = _ssl_issuer_org(parsed.hostname, timeout)
            if org:
                result.technologies.append(
                    {
                        "name": f"SSL: {org}",
                        "category": "Certificate Authority",
                        "evidence": f"Certificate issuer: {org}",
                    }
                )

    seen: set[str] = set()
    unique = []
    for tech in result.technologies:
        if tech["name"] not in seen:
            seen.add(tech["name"])
            unique.append(tech)
    result.technologies = unique
    return result


# ── Orchestration ────────────────────────────────────────────────────────────


async def full_scan(
    domain: str,
    *,
    modules: tuple[str, ...] = DEFAULT_MODULES,
    bruteforce: bool = False,
    client: Optional[httpx.AsyncClient] = None,
    timeout: float = 15.0,
) -> OSINTReport:
    """Run a configurable OSINT scan against a domain."""
    domain = clean_domain(domain)
    report = OSINTReport(domain=domain)
    if "subdomains" in modules:
        report.subdomains = await enumerate_subdomains(
            domain, bruteforce=bruteforce, client=client, timeout=timeout
        )
    if "dns" in modules:
        report.dns_records = await get_dns_records(domain, timeout=timeout)
    if "whois" in modules:
        report.whois = await whois_lookup(domain, client=client, timeout=timeout)
    if "tech" in modules:
        report.tech_stack = await fingerprint_tech(domain, client=client, timeout=timeout)
    if "emails" in modules:
        report.emails = await common_emails(domain)
    return report


# ── Formatting ───────────────────────────────────────────────────────────────


def format_report(report: OSINTReport) -> str:
    lines = [f"# OSINT Report: {report.domain}\n"]

    lines.append("## Summary\n")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Subdomains | {len(report.subdomains)} |")
    lines.append(f"| DNS Records | {len(report.dns_records)} |")
    lines.append(f"| Emails | {len(report.emails)} |")
    tech_count = len(report.tech_stack.technologies) if report.tech_stack else 0
    lines.append(f"| Technologies | {tech_count} |")
    lines.append("")

    if report.subdomains:
        lines.append("## Subdomains\n")
        lines.append("| Subdomain | IP | Source |")
        lines.append("|-----------|-----|--------|")
        for s in report.subdomains[:50]:
            lines.append(f"| {s.subdomain} | {s.ip or '—'} | {s.source} |")
        if len(report.subdomains) > 50:
            lines.append(f"\n_...and {len(report.subdomains) - 50} more_")
        lines.append("")

    if report.dns_records:
        lines.append("## DNS Records\n")
        lines.append("| Type | Value | TTL |")
        lines.append("|------|-------|-----|")
        for r in report.dns_records:
            val = r.value[:80] + "..." if len(r.value) > 80 else r.value
            lines.append(f"| {r.record_type} | {val} | {r.ttl} |")
        lines.append("")

    if report.whois:
        w = report.whois
        lines.append("## WHOIS\n")
        if w.registrar:
            lines.append(f"- **Registrar:** {w.registrar}")
        if w.org:
            lines.append(f"- **Organization:** {w.org}")
        if w.country:
            lines.append(f"- **Country:** {w.country}")
        if w.creation_date:
            lines.append(f"- **Created:** {w.creation_date}")
        if w.expiration_date:
            lines.append(f"- **Expires:** {w.expiration_date}")
        if w.name_servers:
            lines.append(f"- **Name Servers:** {', '.join(w.name_servers)}")
        if w.emails:
            lines.append(f"- **Contacts:** {', '.join(w.emails)}")
        lines.append("")

    if report.tech_stack and report.tech_stack.technologies:
        ts = report.tech_stack
        lines.append("## Technology Stack\n")
        if ts.server:
            lines.append(f"- **Server:** {ts.server}")
        if ts.powered_by:
            lines.append(f"- **Powered By:** {ts.powered_by}")
        lines.append("")
        by_category: dict[str, list[dict[str, str]]] = {}
        for tech in ts.technologies:
            by_category.setdefault(tech.get("category", "Other"), []).append(tech)
        for cat, techs in by_category.items():
            lines.append(f"**{cat}:**")
            for t in techs:
                lines.append(f"- {t['name']} _{t.get('evidence', '')}_")
            lines.append("")

    if report.emails:
        lines.append("## Email Addresses\n")
        for email in report.emails:
            lines.append(f"- {email}")
        lines.append("")

    return "\n".join(lines)


# ── Tool handler ─────────────────────────────────────────────────────────────


async def osint_recon_tool(agent: Any, args: dict[str, Any]) -> str:
    """Agent tool: run OSINT recon (subdomains/DNS/WHOIS/tech/emails) on a domain."""
    domain = clean_domain(str(args.get("domain", "") or ""))
    if not domain or "." not in domain:
        return "[osint_recon] error: a valid 'domain' is required (e.g. example.com)."

    requested = args.get("modules")
    if isinstance(requested, list) and requested:
        modules = tuple(m for m in requested if m in DEFAULT_MODULES)
        if not modules:
            modules = DEFAULT_MODULES
    else:
        modules = DEFAULT_MODULES

    bruteforce = bool(args.get("bruteforce", False))
    try:
        report = await full_scan(domain, modules=modules, bruteforce=bruteforce)
    except Exception as exc:  # never raise into the agent loop
        return f"[osint_recon] error during scan of {domain}: {exc}"
    return format_report(report)
