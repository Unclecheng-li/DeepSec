"""
VulnClaw Remediation Engine
================================
Ported from HackBot (``hackbot/core/remediation.py``). For each finding,
auto-generate actionable fix commands, configuration patches, and code
snippets from a built-in rule knowledge base. Works in two modes:

1. **Rule-based** — instant remediation from a built-in knowledge base of
   vulnerability patterns (no API key required). This is the path used by the
   ``remediation_advice`` tool.
2. **AI-enhanced** — optional; uses a passed-in engine to generate tailored
   fixes. Not used by the agent tool (the agent itself is the LLM).

Each remediation contains:
  • One-liner summary of the fix
  • Shell commands (apt, systemctl, sysctl, iptables, etc.)
  • Config file patches (nginx, apache, sshd, etc.)
  • Code snippets (Python, PHP, JS, Java, etc.)
  • References (CVE links, CIS benchmarks, OWASP pages)

Usage (CLI)::

    /remediate              Remediate all current findings
    /remediate 2            Remediate finding #2 only
    /remediate --ai         Force AI-enhanced remediation

Usage (Agent)::

    The agent can call the remediation engine automatically after
    discovering findings to provide immediate fix guidance.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Enums ────────────────────────────────────────────────────────────────────

class RemediationType(str, Enum):
    """Category of remediation action."""
    COMMAND = "command"
    CONFIG = "config"
    CODE = "code"
    REFERENCE = "reference"


class RemediationPriority(str, Enum):
    """How urgently the fix should be applied."""
    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# ── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class RemediationStep:
    """A single actionable fix step."""
    type: RemediationType
    title: str
    content: str
    language: str = ""  # bash, python, nginx, apache, yaml, etc.
    filename: str = ""  # target file path when applicable
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "title": self.title,
            "content": self.content,
            "language": self.language,
            "filename": self.filename,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RemediationStep":
        return cls(
            type=RemediationType(data.get("type", "reference")),
            title=data.get("title", ""),
            content=data.get("content", ""),
            language=data.get("language", ""),
            filename=data.get("filename", ""),
            description=data.get("description", ""),
        )


@dataclass
class Remediation:
    """Complete remediation guidance for a single finding."""
    finding_title: str
    finding_severity: str
    summary: str
    priority: RemediationPriority
    steps: List[RemediationStep] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    generated_at: float = field(default_factory=time.time)
    source: str = "rule"  # "rule" or "ai"
    confidence: float = 1.0  # 0.0-1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_title": self.finding_title,
            "finding_severity": self.finding_severity,
            "summary": self.summary,
            "priority": self.priority.value,
            "steps": [s.to_dict() for s in self.steps],
            "references": self.references,
            "generated_at": self.generated_at,
            "source": self.source,
            "confidence": self.confidence,
            "step_count": len(self.steps),
            "has_commands": any(s.type == RemediationType.COMMAND for s in self.steps),
            "has_config": any(s.type == RemediationType.CONFIG for s in self.steps),
            "has_code": any(s.type == RemediationType.CODE for s in self.steps),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Remediation":
        return cls(
            finding_title=data.get("finding_title", ""),
            finding_severity=data.get("finding_severity", ""),
            summary=data.get("summary", ""),
            priority=RemediationPriority(data.get("priority", "medium")),
            steps=[RemediationStep.from_dict(s) for s in data.get("steps", [])],
            references=data.get("references", []),
            generated_at=data.get("generated_at", time.time()),
            source=data.get("source", "rule"),
            confidence=data.get("confidence", 1.0),
        )

    def get_markdown(self) -> str:
        """Render remediation as markdown."""
        lines = [f"## 🔧 Remediation: {self.finding_title}\n"]
        lines.append(f"**Priority:** {self.priority.value.upper()} | "
                      f"**Severity:** {self.finding_severity} | "
                      f"**Source:** {self.source}\n")
        lines.append(f"{self.summary}\n")

        for i, step in enumerate(self.steps, 1):
            icon = {"command": "💻", "config": "⚙️", "code": "📝", "reference": "📖"}.get(step.type.value, "•")
            lines.append(f"### {icon} Step {i}: {step.title}\n")
            if step.description:
                lines.append(f"{step.description}\n")
            if step.filename:
                lines.append(f"**File:** `{step.filename}`\n")
            lang = step.language or ("bash" if step.type == RemediationType.COMMAND else "")
            if step.content:
                lines.append(f"```{lang}\n{step.content}\n```\n")

        if self.references:
            lines.append("### 📚 References\n")
            for ref in self.references:
                lines.append(f"- {ref}")
            lines.append("")

        return "\n".join(lines)


# ── Severity → Priority Mapping ─────────────────────────────────────────────

_SEVERITY_PRIORITY = {
    "Critical": RemediationPriority.IMMEDIATE,
    "High": RemediationPriority.HIGH,
    "Medium": RemediationPriority.MEDIUM,
    "Low": RemediationPriority.LOW,
    "Info": RemediationPriority.INFORMATIONAL,
}


def _severity_to_priority(severity: str) -> RemediationPriority:
    return _SEVERITY_PRIORITY.get(severity, RemediationPriority.MEDIUM)


# ── Rule-Based Remediation Knowledge Base ────────────────────────────────────
#
# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: S4 修复 — 规则定义已提取到 intel/remediation_rules.py，
#          此处导入 _RULES 以触发规则注册。

_RULES: List[Tuple[str, Callable]] = []


def _rule(pattern: str):
    """Decorator to register a remediation rule."""
    def decorator(fn: Callable):
        _RULES.append((pattern, fn))
        return fn
    return decorator


# 导入规则定义模块（触发 @_rule 装饰器注册）
from deepsec.spear.intel import remediation_rules  # noqa: E402, F401

# ── Compile Rules ────────────────────────────────────────────────────────────

_COMPILED_RULES: List[Tuple[re.Pattern, Callable]] = []


def _compile_rules() -> None:
    """Compile all rule patterns (lazy, on first use)."""
    if _COMPILED_RULES:
        return
    _COMPILED_RULES.extend(
        (re.compile(pattern, re.IGNORECASE), fn)
        for pattern, fn in _RULES
    )


# ── Remediation Engine ───────────────────────────────────────────────────────

class RemediationEngine:
    """
    Generates remediation guidance for security findings.

    Two strategies:
    1. Rule-based (instant, no API) — matches finding title/description
       against built-in vulnerability patterns.
    2. AI-enhanced (optional) — Falls back to an LLM for tailored fixes
       when no rule matches or when --ai flag is used.
    """

    def __init__(self, ai_engine: Optional[Any] = None):
        """
        Args:
            ai_engine: Optional AIEngine instance for AI-enhanced remediation.
        """
        _compile_rules()
        self.ai_engine = ai_engine

    # ── Rule-Based Remediation ───────────────────────────────────────────

    def remediate_finding(self, finding: Dict[str, Any], use_ai: bool = False) -> Remediation:
        """
        Generate remediation for a single finding.

        Args:
            finding: Finding dict with title, severity, description, etc.
            use_ai: Force AI-enhanced remediation even if rules match.

        Returns:
            Remediation object with fix steps.
        """
        title = finding.get("title", "")
        desc = finding.get("description", "")
        search_text = f"{title} {desc}"

        # Try rule-based first
        if not use_ai:
            for pattern, builder in _COMPILED_RULES:
                m = pattern.search(search_text)
                if m:
                    try:
                        return builder(finding, m)
                    except Exception as e:
                        logger.warning(f"Rule failed for '{title}': {e}")

        # AI-enhanced fallback
        if self.ai_engine:
            return self._ai_remediate(finding)

        # Generic fallback
        return self._generic_remediation(finding)

    def remediate_findings(
        self,
        findings: List[Dict[str, Any]],
        use_ai: bool = False,
    ) -> List[Remediation]:
        """Remediate a list of findings."""
        return [self.remediate_finding(f, use_ai=use_ai) for f in findings]

    # ── AI-Enhanced Remediation ──────────────────────────────────────────

    def _ai_remediate(self, finding: Dict[str, Any]) -> Remediation:
        """Use AI to generate tailored remediation."""
        prompt = self._build_ai_prompt(finding)
        try:
            response = self.ai_engine.chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
            )
            return self._parse_ai_response(finding, response)
        except Exception as e:
            logger.error(f"AI remediation failed: {e}")
            return self._generic_remediation(finding)

    @staticmethod
    def _build_ai_prompt(finding: Dict[str, Any]) -> str:
        """Build a prompt for AI-enhanced remediation."""
        return f"""You are a cybersecurity remediation expert. Generate specific, actionable fix guidance for this security finding.

**Finding:** {finding.get('title', 'Unknown')}
**Severity:** {finding.get('severity', 'Unknown')}
**Description:** {finding.get('description', 'No description')}
**Evidence:** {finding.get('evidence', 'None')}
**Tool:** {finding.get('tool', 'Unknown')}

Provide your response in this exact format:

SUMMARY: <one-sentence fix description>

COMMAND:
<title>: <title of the command step>
<description>: <brief description>
<language>: bash
```
<shell commands to fix the issue>
```

CONFIG:
<title>: <title of the config step>
<filename>: <config file path>
<language>: <config type>
```
<config patch content>
```

CODE:
<title>: <title of the code step>
<language>: <programming language>
```
<code snippet to fix>
```

REFERENCES:
- <relevant URL 1>
- <relevant URL 2>

Include at least one COMMAND and one CODE or CONFIG section. Be specific to the actual finding — don't give generic advice. Use real file paths and real commands."""

    @staticmethod
    def _parse_ai_response(finding: Dict[str, Any], response: str) -> Remediation:
        """Parse AI response into structured Remediation."""
        steps = []
        references = []
        summary = ""

        # Extract summary
        summary_match = re.search(r'SUMMARY:\s*(.+?)(?:\n\n|\nCOMMAND|\nCONFIG|\nCODE|\nREFERENCES)', response, re.DOTALL)
        if summary_match:
            summary = summary_match.group(1).strip()

        # Extract code blocks with their section context
        sections = re.split(r'\n(COMMAND|CONFIG|CODE|REFERENCES):', response)

        current_type = None
        for i, section in enumerate(sections):
            section_stripped = section.strip()
            if section_stripped in ('COMMAND', 'CONFIG', 'CODE'):
                current_type = section_stripped
                continue
            if section_stripped == 'REFERENCES':
                # Extract reference URLs
                ref_matches = re.findall(r'-\s*(https?://\S+)', section if i + 1 < len(sections) else "")
                if not ref_matches and i + 1 < len(sections):
                    ref_matches = re.findall(r'-\s*(https?://\S+)', sections[i + 1])
                references.extend(ref_matches)
                continue

            if current_type and section_stripped:
                rtype = {
                    'COMMAND': RemediationType.COMMAND,
                    'CONFIG': RemediationType.CONFIG,
                    'CODE': RemediationType.CODE,
                }.get(current_type, RemediationType.COMMAND)

                # Extract title
                title_match = re.search(r'<title>:\s*(.+)', section)
                title = title_match.group(1).strip() if title_match else f"{current_type.title()} Fix"

                # Extract description
                desc_match = re.search(r'<description>:\s*(.+)', section)
                desc = desc_match.group(1).strip() if desc_match else ""

                # Extract language
                lang_match = re.search(r'<language>:\s*(.+)', section)
                lang = lang_match.group(1).strip() if lang_match else ("bash" if rtype == RemediationType.COMMAND else "")

                # Extract filename
                file_match = re.search(r'<filename>:\s*(.+)', section)
                filename = file_match.group(1).strip() if file_match else ""

                # Extract code block
                code_match = re.search(r'```\w*\n(.*?)```', section, re.DOTALL)
                content = code_match.group(1).strip() if code_match else section_stripped[:500]

                steps.append(RemediationStep(
                    type=rtype,
                    title=title,
                    content=content,
                    language=lang,
                    filename=filename,
                    description=desc,
                ))

        # Extract references from the end if not found yet
        if not references:
            ref_matches = re.findall(r'-\s*(https?://\S+)', response)
            references = ref_matches[:5]

        if not summary:
            summary = f"AI-generated remediation for: {finding.get('title', 'Unknown')}"

        return Remediation(
            finding_title=finding.get("title", "Unknown"),
            finding_severity=finding.get("severity", "Unknown"),
            summary=summary,
            priority=_severity_to_priority(finding.get("severity", "Medium")),
            steps=steps or [RemediationStep(
                type=RemediationType.REFERENCE,
                title="AI Guidance",
                content=response[:2000],
                description="Full AI-generated remediation guidance.",
            )],
            references=references,
            source="ai",
            confidence=0.8,
        )

    # ── Generic Fallback ─────────────────────────────────────────────────

    @staticmethod
    def _generic_remediation(finding: Dict[str, Any]) -> Remediation:
        """Fallback remediation when no rule matches and AI is unavailable."""
        severity = finding.get("severity", "Medium")
        title = finding.get("title", "Security Finding")
        recommendation = finding.get("recommendation", "")

        steps = []
        if recommendation:
            steps.append(RemediationStep(
                type=RemediationType.REFERENCE,
                title="Original Recommendation",
                content=recommendation,
                description="Recommendation from the assessment tool.",
            ))

        steps.append(RemediationStep(
            type=RemediationType.REFERENCE,
            title="General Guidance",
            content=f"""1. Research "{title}" in the OWASP Testing Guide and NVD
2. Apply vendor-recommended patches or workarounds
3. Implement defense-in-depth controls:
   - Network segmentation and firewall rules
   - Input validation and output encoding
   - Least-privilege access controls
   - Monitoring and alerting
4. Verify the fix with a targeted re-test
5. Document the remediation in your risk register""",
            description="Follow these steps when a specific remediation is not available.",
        ))

        return Remediation(
            finding_title=title,
            finding_severity=severity,
            summary=f"Review and apply vendor-recommended fixes for: {title}",
            priority=_severity_to_priority(severity),
            steps=steps,
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/",
                "https://nvd.nist.gov/",
            ],
            source="generic",
            confidence=0.3,
        )

    # ── Batch Summary ────────────────────────────────────────────────────

    @staticmethod
    def get_summary_markdown(remediations: List[Remediation]) -> str:
        """Generate a combined markdown report for all remediations."""
        if not remediations:
            return "No remediations generated.\n"

        lines = ["# 🔧 Remediation Report\n"]

        # Priority summary
        by_priority: Dict[str, int] = {}
        for r in remediations:
            by_priority[r.priority.value] = by_priority.get(r.priority.value, 0) + 1
        lines.append("## Priority Summary\n")
        for p in ["immediate", "high", "medium", "low", "informational"]:
            if p in by_priority:
                icon = {"immediate": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "informational": "⚪"}.get(p, "•")
                lines.append(f"- {icon} **{p.upper()}:** {by_priority[p]} findings")
        lines.append("")

        # Stats
        total_steps = sum(len(r.steps) for r in remediations)
        cmd_count = sum(1 for r in remediations for s in r.steps if s.type == RemediationType.COMMAND)
        cfg_count = sum(1 for r in remediations for s in r.steps if s.type == RemediationType.CONFIG)
        code_count = sum(1 for r in remediations for s in r.steps if s.type == RemediationType.CODE)
        lines.append(f"**Total:** {len(remediations)} findings → {total_steps} fix steps "
                      f"({cmd_count} commands, {cfg_count} configs, {code_count} code snippets)\n")
        lines.append("---\n")

        # Individual remediations
        for r in remediations:
            lines.append(r.get_markdown())
            lines.append("---\n")

        return "\n".join(lines)

    # ── Utilities ────────────────────────────────────────────────────────

    @staticmethod
    def get_rule_count() -> int:
        """Return the number of built-in remediation rules."""
        return len(_RULES)

    @staticmethod
    def get_rule_patterns() -> List[str]:
        """Return all rule patterns (for debugging/testing)."""
        return [p for p, _ in _RULES]


# ── Agent tool ───────────────────────────────────────────────────────────────


def _findings_from_agent(agent: Any) -> List[Dict[str, Any]]:
    session = getattr(agent, "session_state", None)
    findings = getattr(session, "findings", None) or []
    out: List[Dict[str, Any]] = []
    for f in findings:
        if isinstance(f, dict):
            out.append(f)
        elif hasattr(f, "model_dump"):
            out.append(f.model_dump())
    return out


async def remediation_advice_tool(agent: Any, args: Dict[str, Any]) -> str:
    """Agent tool: generate rule-based remediation guidance for findings.

    Accepts a ``findings`` array, a single ``query`` string (vuln type/title),
    or falls back to the current session's findings. Returns markdown with fix
    commands, config patches, and code snippets.
    """
    findings = args.get("findings")
    if not isinstance(findings, list) or not findings:
        query = str(args.get("query", "") or "").strip()
        if query:
            findings = [{"title": query, "severity": str(args.get("severity", "Medium") or "Medium"),
                         "description": query}]
        else:
            findings = _findings_from_agent(agent)
    if not findings:
        return (
            "[remediation_advice] No findings to remediate. Pass a 'findings' array, "
            "a 'query' string (e.g. 'SQL injection'), or run after findings exist."
        )

    engine = RemediationEngine()
    remediations = engine.remediate_findings(findings, use_ai=False)
    return RemediationEngine.get_summary_markdown(remediations)
