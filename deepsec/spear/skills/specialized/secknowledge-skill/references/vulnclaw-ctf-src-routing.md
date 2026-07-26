# VulnClaw CTF/SRC Routing Guide

This reference connects `secknowledge-skill` to VulnClaw's CTF and SRC workflows.

## When To Use This Skill

Use `secknowledge-skill` when the user is doing authorized practical testing with a concrete target, especially:

- SRC/bug bounty/vulnerability research with Web or AI attack surface.
- CTF tasks that look like real Web, AI, MCP, Agent, sandbox, SSRF, upload, deserialization, XXE, logic, or auth vulnerabilities.
- Mixed CTF/SRC questions where the user needs both exploit ideas and a checklist for evidence, risk, and reportability.
- AI/LLM security tasks that need GAARM, OWASP LLM/ASI, prompt injection, MCP, Agent, RAG, or sandbox escape mapping.

Keep VulnClaw's existing specialist skills in the loop:

- Use `ctf-web` for short CTF Web tricks such as PHP weak comparison, preg_match bypass, eval/RCE, SSTI, and file upload chains.
- Use `ctf-crypto` for pure crypto problems.
- Use `ctf-misc` for pyjail, bash jail, encoding chains, stego, and platform tasks.
- Use `web-security-advanced` when the user asks for a focused Web playbook without SRC/bug-bounty context.
- Use `ai-mcp-security` when the wording is a general AI/MCP assessment and does not need the broader secknowledge knowledge base.

## Fast Reference Map

| Scenario | Load These References First |
| --- | --- |
| SRC initial triage | `testing-methodology.md`, `web-deployment-security.md` |
| SQL injection | `web-sqli.md`, `web-sqli-fushuling-one-pass.md`, `testing-methodology.md` |
| XSS or DOM sink testing | `web-xss.md`, `testing-methodology.md` |
| RCE or command injection | `web-rce.md`, `web-upload.md` |
| File upload / traversal / leak | `web-upload.md`, `web-traversal.md`, `web-leak.md` |
| SSRF, XXE, deserialization | `web-ssrf-misc.md`, `web-xxe.md`, `web-deser.md` |
| Auth, logic, IDOR, payment risk | `web-logic-auth.md`, `testing-methodology.md` |
| GraphQL, WebSocket, OAuth, protocol edge cases | `web-modern-protocols.md` |
| AI prompt injection or jailbreak | `ai-app-prompt.md`, `ai-model-jailbreak.md` |
| MCP / Agent / tool abuse | `ai-app-mcp.md`, `ai-app-agent-cot.md`, `ai-app-frontier.md` |
| RAG / data poisoning / leakage | `ai-data-app.md`, `ai-data-deploy.md`, `ai-model-extraction.md` |
| AI risk rating | `gaarm-risk-matrix.md`, `testing-methodology.md` |

## CTF Workflow

1. Classify the challenge into Web, AI/MCP/Agent, sandbox, crypto, or misc.
2. If it is a narrow CTF trick, route to the matching VulnClaw CTF skill and use this skill only for broader vulnerability families or evidence discipline.
3. If it resembles a real vulnerability, load the matching `web-*` or `ai-*` reference and keep each exploit hypothesis separate from confirmed behavior.
4. Keep payload output small and cite the specific reference file when possible.

## SRC Workflow

1. Confirm authorization scope, target, and test objective.
2. Start with `testing-methodology.md` for coverage and `web-deployment-security.md` for exposure checks.
3. Load the most relevant vulnerability-family reference only after an observable clue appears.
4. Track each item as `hypothesis`, `needs validation`, or `confirmed`, with evidence such as request/response, impact boundary, affected user role, and reproducibility.
5. For AI targets, map observed behavior to `gaarm-risk-matrix.md` before writing severity or report language.

## Output Discipline

- Do not present a payload, CVE, OWASP ID, or GAARM ID as verified unless it is supported by a reference file or live evidence.
- For SRC reports, separate impact from exploitation steps, and avoid expanding beyond authorized scope.
- For CTF writeups, keep solution steps reproducible but do not overstate real-world impact unless the reference supports it.

## Upstream Attribution

Integrated from `Pa55w0rd/secknowledge-skill`: https://github.com/Pa55w0rd/secknowledge-skill

Upstream author: Pa55w0rd

Upstream version noted in README at integration time: v2.0, 2026-05-18

Upstream license declaration: MIT License
