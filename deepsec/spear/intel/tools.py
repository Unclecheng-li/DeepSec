"""Intel tool schemas (OpenAI format) and name->dispatcher routing.

Each real module (cve/osint/topology/compliance/remediation) registers its
async handler in ``_HANDLERS`` as its port lands. Until then, a tool's handler
is a structured stub so the dispatch path is testable end-to-end.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

# Read-only tools the constraint policy may treat as passive: no egress to the
# target, no host-changing action.
READ_ONLY_INTEL_TOOLS: set[str] = {
    "cve_lookup",
    "compliance_map",
    "remediation_advice",
    "topology_build",
    "findings_report",
    "findings_diff",
    "attack_map",
}

# Active-recon tools: they contact the target / third-party services but are
# low-impact reconnaissance. The constraint policy classifies them as "recon".
RECON_INTEL_TOOLS: set[str] = {"osint_recon"}


def intel_tool_schemas() -> list[dict[str, Any]]:
    """OpenAI tool schemas for all intel tools."""
    return [
        {
            "type": "function",
            "function": {
                "name": "cve_lookup",
                "description": (
                    "Look up CVEs by keyword or CVE-ID against NVD, with optional "
                    "exploit-PoC discovery. Read-only; safe to call during recon."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": (
                                "Keyword (e.g. 'openssl 3.0') or a CVE-ID "
                                "(e.g. CVE-2024-3094)."
                            ),
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results.",
                            "default": 5,
                        },
                    },
                    "required": ["query"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "osint_recon",
                "description": (
                    "Run OSINT reconnaissance on a domain: subdomain enumeration "
                    "(Certificate Transparency), DNS records, WHOIS/RDAP, web "
                    "technology fingerprinting, and common-email candidates. "
                    "Active recon — contacts the target and third-party services."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Target domain, e.g. example.com.",
                        },
                        "modules": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": ["subdomains", "dns", "whois", "tech", "emails"],
                            },
                            "description": "Subset of modules to run (default: all).",
                        },
                        "bruteforce": {
                            "type": "boolean",
                            "description": "DNS-brute-force a built-in subdomain wordlist.",
                            "default": False,
                        },
                    },
                    "required": ["domain"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "topology_build",
                "description": (
                    "Build a network topology (hosts, ports, services, subnets) "
                    "from nmap (text or XML) or masscan scan output. Offline/read-only "
                    "— parses scan text you already have. Returns markdown, ascii, or json."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "scan_output": {
                            "type": "string",
                            "description": "Raw nmap/masscan output (text or nmap XML).",
                        },
                        "format": {
                            "type": "string",
                            "enum": ["markdown", "ascii", "json"],
                            "description": "Output format (default: markdown).",
                            "default": "markdown",
                        },
                    },
                    "required": ["scan_output"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "compliance_map",
                "description": (
                    "Map security findings to compliance controls (PCI DSS v4.0, "
                    "NIST 800-53, OWASP Top 10, ISO 27001) with gap analysis. "
                    "Read-only. Uses the provided findings, or the current session's "
                    "findings if none are passed."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "findings": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "title": {"type": "string"},
                                    "severity": {"type": "string"},
                                    "description": {"type": "string"},
                                    "evidence": {"type": "string"},
                                },
                            },
                            "description": "Findings to map (optional; defaults to session findings).",
                        },
                        "frameworks": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": ["pci", "nist", "owasp", "iso"],
                            },
                            "description": "Subset of frameworks (default: all four).",
                        },
                        "target": {
                            "type": "string",
                            "description": "Assessment target for the report header.",
                        },
                    },
                    "required": [],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "findings_report",
                "description": (
                    "Risk-score findings: severity breakdown, total risk, top "
                    "risks, and optional compliance-control coverage. Read-only. "
                    "Uses provided findings or the current session's findings."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "findings": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "Findings to score (optional; defaults to session findings).",
                        },
                        "with_compliance": {
                            "type": "boolean",
                            "description": "Include compliance-control coverage.",
                            "default": False,
                        },
                    },
                    "required": [],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "findings_diff",
                "description": (
                    "Diff two assessments: report new / fixed / persistent findings "
                    "(and severity regressions) between a baseline and the current "
                    "set. Read-only/offline."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "baseline": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "Baseline (older) findings.",
                        },
                        "current": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "Current (newer) findings (optional; defaults to session findings).",
                        },
                        "target": {"type": "string", "description": "Target label for the report."},
                    },
                    "required": ["baseline"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "remediation_advice",
                "description": (
                    "Generate actionable remediation guidance (fix commands, config "
                    "patches, code snippets) for findings from a built-in rule "
                    "knowledge base. Read-only. Accepts findings, a vuln 'query' "
                    "string, or the current session's findings."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "findings": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "Findings to remediate (optional).",
                        },
                        "query": {
                            "type": "string",
                            "description": "A vulnerability type/title to remediate, e.g. 'SQL injection'.",
                        },
                        "severity": {
                            "type": "string",
                            "description": "Severity for a 'query' finding (default Medium).",
                        },
                    },
                    "required": [],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "attack_map",
                "description": (
                    "Map findings (and optional tool usage) to MITRE ATT&CK "
                    "techniques/tactics. Read-only. Returns a markdown report, or "
                    "an ATT&CK Navigator layer JSON when format='navigator'."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "findings": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "Findings to map (optional; defaults to session findings).",
                        },
                        "tool_history": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "Optional tool-execution records to map to techniques.",
                        },
                        "target": {"type": "string", "description": "Assessment target label."},
                        "format": {
                            "type": "string",
                            "enum": ["markdown", "navigator"],
                            "description": "Output format (default: markdown).",
                        },
                    },
                    "required": [],
                },
            },
        },
    ]


INTEL_TOOL_NAMES: list[str] = [s["function"]["name"] for s in intel_tool_schemas()]


async def _stub(tool_name: str, args: dict[str, Any]) -> str:
    return f"[intel_pending] {tool_name} is not yet implemented in this build."


def _build_handlers() -> dict[str, Callable[[Any, dict[str, Any]], Awaitable[str]]]:
    """Map tool name -> async handler. Each ported module registers here."""
    from deepsec.spear.intel.attack import attack_map_tool
    from deepsec.spear.intel.compliance import compliance_map_tool
    from deepsec.spear.intel.cve import cve_lookup_tool
    from deepsec.spear.intel.findings import findings_diff_tool, findings_report_tool
    from deepsec.spear.intel.osint import osint_recon_tool
    from deepsec.spear.intel.remediation import remediation_advice_tool
    from deepsec.spear.intel.topology import topology_build_tool

    return {
        "cve_lookup": cve_lookup_tool,
        "osint_recon": osint_recon_tool,
        "topology_build": topology_build_tool,
        "compliance_map": compliance_map_tool,
        "findings_report": findings_report_tool,
        "findings_diff": findings_diff_tool,
        "remediation_advice": remediation_advice_tool,
        "attack_map": attack_map_tool,
    }


# Handlers are filled in by each module's port. Tools in the schema list without
# a handler fall back to a structured stub so dispatch stays testable.
_HANDLERS: dict[str, Callable[[Any, dict[str, Any]], Awaitable[str]]] = _build_handlers()


# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: V7 修复 — 将 agent 参数类型从 AgentContext 改为 Any，
#          消除 intel/ 基础设施层对 agent/ 领域层协议的依赖。
async def dispatch_intel_tool(agent: Any, tool_name: str, args: dict[str, Any]) -> str:
    """Route an intel tool call to its handler; structured error on unknown name."""
    if tool_name not in INTEL_TOOL_NAMES:
        return f"[intel_error] unknown intel tool: {tool_name}"
    handler = _HANDLERS.get(tool_name)
    if handler is None:
        return await _stub(tool_name, args)
    return await handler(agent, args)
