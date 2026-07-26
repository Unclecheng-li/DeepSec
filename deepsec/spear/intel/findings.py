"""Findings risk scoring & assessment diff for VulnClaw.

Ports the *logic* of HackBot's ``vulndb.py`` (risk scoring) and ``diff_report.py``
(assessment diff) — but with no second database. Everything operates on plain
VulnClaw finding dicts and ``target_state`` snapshot dicts, so the canonical
store stays the single source of truth (spec §5.2).

Exposes two read-only tools:
  * ``findings_report`` — risk score, severity breakdown, top risks, optional
    compliance-control coverage for the current/given findings.
  * ``findings_diff`` — new / fixed / persistent findings between two finding
    sets (e.g. a baseline snapshot vs the current assessment).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from deepsec.spear.intel.compliance import map_findings

SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}
_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
_REJECTED_STATES = {"rejected", "fixed", "closed"}
MATCH_THRESHOLD = 0.65


# ── Severity / risk ──────────────────────────────────────────────────────────


def _norm_sev(severity: str) -> str:
    return (severity or "info").strip().lower()


def _canonical_sev(severity: str) -> str:
    norm = _norm_sev(severity)
    for s in _SEVERITY_ORDER:
        if s.lower() == norm:
            return s
    return "Info"


def _is_open(finding: dict[str, Any]) -> bool:
    status = str(finding.get("lifecycle_status", finding.get("status", "")) or "").lower()
    return status not in _REJECTED_STATES


def finding_risk(finding: dict[str, Any]) -> float:
    """Risk weight for one finding: CVSS base score if present (>0), else the
    severity weight."""
    cvss = finding.get("cvss_score")
    try:
        if cvss is not None and float(cvss) > 0:
            return float(cvss)
    except (TypeError, ValueError):
        pass
    return SEVERITY_WEIGHTS.get(_norm_sev(str(finding.get("severity", "Info"))), 0.5)


@dataclass
class RiskScore:
    total: float = 0.0
    open_count: int = 0
    counts: dict[str, int] = field(default_factory=lambda: {s: 0 for s in _SEVERITY_ORDER})

    @property
    def band(self) -> str:
        for s in _SEVERITY_ORDER:
            if self.counts.get(s, 0) > 0:
                return s
        return "Info"


def score_findings(findings: list[dict[str, Any]], *, open_only: bool = True) -> RiskScore:
    """Aggregate a risk score + severity breakdown over findings."""
    score = RiskScore()
    for f in findings:
        if open_only and not _is_open(f):
            continue
        score.counts[_canonical_sev(str(f.get("severity", "Info")))] += 1
        score.open_count += 1
        score.total += finding_risk(f)
    score.total = round(score.total, 1)
    return score


# ── Compliance annotation ────────────────────────────────────────────────────


def annotate_compliance(
    finding: dict[str, Any], *, frameworks: Optional[list[str]] = None
) -> dict[str, Any]:
    """Return a copy of the finding with a 'compliance' list of matched controls
    (framework + control_id). Reuses the compliance keyword-rule engine."""
    report = map_findings([finding], frameworks=frameworks)
    controls = [
        {"framework": m.control.framework, "control_id": m.control.control_id, "status": m.status}
        for m in report.mappings
    ]
    annotated = dict(finding)
    annotated["compliance"] = controls
    return annotated


# ── Diff engine ──────────────────────────────────────────────────────────────


def _normalize(text: str) -> str:
    return (text or "").strip().lower()


def _finding_fingerprint(finding: dict[str, Any]) -> str:
    title = _normalize(str(finding.get("title", "")))
    desc = _normalize(str(finding.get("description", "")))[:80]
    tool = _normalize(str(finding.get("tool", finding.get("vuln_type", ""))))
    return f"{title}|{desc}|{tool}"


def _similarity(fp1: str, fp2: str) -> float:
    p1, p2 = fp1.split("|"), fp2.split("|")
    if p1[0] and p1[0] == p2[0]:
        return 1.0
    t1, t2 = set(p1[0].split()), set(p2[0].split())
    if not t1 or not t2:
        return 0.0
    union = t1 | t2
    jaccard = len(t1 & t2) / len(union) if union else 0.0
    if p1[2] and p1[2] == p2[2]:
        jaccard = min(1.0, jaccard + 0.15)
    return jaccard


def _match_findings(
    old: list[dict[str, Any]], new: list[dict[str, Any]]
) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
    old_fps = [(_finding_fingerprint(f), f) for f in old]
    new_fps = [(_finding_fingerprint(f), f) for f in new]
    scores: list[tuple[float, int, int]] = []
    for i, (fp_old, _) in enumerate(old_fps):
        for j, (fp_new, _) in enumerate(new_fps):
            sim = _similarity(fp_old, fp_new)
            if sim >= MATCH_THRESHOLD:
                scores.append((sim, i, j))
    scores.sort(key=lambda x: x[0], reverse=True)
    used_old: set[int] = set()
    used_new: set[int] = set()
    pairs: list[tuple[dict, dict]] = []
    for _sim, i, j in scores:
        if i in used_old or j in used_new:
            continue
        pairs.append((old_fps[i][1], new_fps[j][1]))
        used_old.add(i)
        used_new.add(j)
    unmatched_old = [old_fps[i][1] for i in range(len(old_fps)) if i not in used_old]
    unmatched_new = [new_fps[j][1] for j in range(len(new_fps)) if j not in used_new]
    return pairs, unmatched_old, unmatched_new


@dataclass
class DiffEntry:
    title: str
    severity: str
    status: str  # new | fixed | persistent
    old_severity: str = ""


@dataclass
class DiffReport:
    target: str = ""
    new: list[DiffEntry] = field(default_factory=list)
    fixed: list[DiffEntry] = field(default_factory=list)
    persistent: list[DiffEntry] = field(default_factory=list)

    @property
    def regressions(self) -> list[DiffEntry]:
        """Persistent findings whose severity increased."""
        out = []
        for e in self.persistent:
            if e.old_severity and _SEVERITY_ORDER.index(
                _canonical_sev(e.severity)
            ) < _SEVERITY_ORDER.index(_canonical_sev(e.old_severity)):
                out.append(e)
        return out


def _as_findings(state: Any) -> list[dict[str, Any]]:
    if isinstance(state, dict):
        return state.get("findings", []) or []
    if isinstance(state, list):
        return state
    return []


def diff_assessments(old_state: Any, new_state: Any, *, target: str = "") -> DiffReport:
    """Compare two assessments (target_state snapshot dicts or finding lists)."""
    old = _as_findings(old_state)
    new = _as_findings(new_state)
    pairs, unmatched_old, unmatched_new = _match_findings(old, new)

    if not target and isinstance(new_state, dict):
        target = new_state.get("target", "")
    report = DiffReport(target=target)

    for old_f, new_f in pairs:
        old_sev = str(old_f.get("severity", "Info"))
        new_sev = str(new_f.get("severity", "Info"))
        report.persistent.append(
            DiffEntry(
                title=str(new_f.get("title", "")),
                severity=new_sev,
                status="persistent",
                old_severity=old_sev if old_sev != new_sev else "",
            )
        )
    for f in unmatched_old:
        report.fixed.append(
            DiffEntry(title=str(f.get("title", "")), severity=str(f.get("severity", "Info")), status="fixed")
        )
    for f in unmatched_new:
        report.new.append(
            DiffEntry(title=str(f.get("title", "")), severity=str(f.get("severity", "Info")), status="new")
        )
    return report


# ── Formatting ───────────────────────────────────────────────────────────────


def format_risk_report(
    findings: list[dict[str, Any]], score: RiskScore, *, with_compliance: bool = False
) -> str:
    lines = ["# Findings Risk Summary\n"]
    lines.append(f"**Open findings:** {score.open_count}  ·  **Risk score:** {score.total}  ·  **Top band:** {score.band}\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for s in _SEVERITY_ORDER:
        lines.append(f"| {s} | {score.counts.get(s, 0)} |")
    lines.append("")

    ranked = sorted(findings, key=finding_risk, reverse=True)
    open_ranked = [f for f in ranked if _is_open(f)]
    if open_ranked:
        lines.append("## Top Risks\n")
        lines.append("| Risk | Severity | Title |")
        lines.append("|------|----------|-------|")
        for f in open_ranked[:10]:
            lines.append(
                f"| {finding_risk(f):.1f} | {_canonical_sev(str(f.get('severity', 'Info')))} "
                f"| {str(f.get('title', ''))[:80]} |"
            )
        lines.append("")

    if with_compliance:
        report = map_findings(findings)
        if report.mappings:
            by_fw: dict[str, int] = {}
            for m in report.mappings:
                by_fw[m.control.framework] = by_fw.get(m.control.framework, 0) + 1
            lines.append("## Compliance Control Coverage\n")
            lines.append("| Framework | Mapped controls |")
            lines.append("|-----------|-----------------|")
            for fw, n in by_fw.items():
                lines.append(f"| {fw} | {n} |")
            lines.append("")
    return "\n".join(lines)


def format_diff(report: DiffReport) -> str:
    lines = [f"# Assessment Diff: {report.target or 'N/A'}\n"]
    lines.append(
        f"**+{len(report.new)} new**  ·  **-{len(report.fixed)} fixed**  ·  "
        f"**{len(report.persistent)} persistent**"
    )
    regs = report.regressions
    if regs:
        lines.append(f"  ·  **⚠ {len(regs)} regressions** (severity increased)")
    lines.append("")

    def _section(title: str, entries: list[DiffEntry], show_change: bool = False) -> None:
        if not entries:
            return
        lines.append(f"## {title} ({len(entries)})\n")
        lines.append("| Severity | Title |" + (" Change |" if show_change else ""))
        lines.append("|----------|-------|" + ("--------|" if show_change else ""))
        for e in entries:
            row = f"| {e.severity} | {e.title[:80]} |"
            if show_change:
                row += f" {e.old_severity + ' → ' + e.severity if e.old_severity else '—'} |"
            lines.append(row)
        lines.append("")

    _section("New", report.new)
    _section("Fixed", report.fixed)
    _section("Persistent", report.persistent, show_change=True)
    return "\n".join(lines)


# ── Tool handlers ────────────────────────────────────────────────────────────


def _findings_from_agent(agent: Any) -> list[dict[str, Any]]:
    session = getattr(agent, "session_state", None)
    findings = getattr(session, "findings", None) or []
    out: list[dict[str, Any]] = []
    for f in findings:
        if isinstance(f, dict):
            out.append(f)
        elif hasattr(f, "model_dump"):
            out.append(f.model_dump())
    return out


async def findings_report_tool(agent: Any, args: dict[str, Any]) -> str:
    """Agent tool: risk-score and summarize findings (session or provided)."""
    findings = args.get("findings")
    if not isinstance(findings, list) or not findings:
        findings = _findings_from_agent(agent)
    if not findings:
        return "[findings_report] No findings to score. Pass a 'findings' array or run after findings exist."
    with_compliance = bool(args.get("with_compliance", False))
    score = score_findings(findings)
    return format_risk_report(findings, score, with_compliance=with_compliance)


async def findings_diff_tool(agent: Any, args: dict[str, Any]) -> str:
    """Agent tool: diff a baseline finding set against the current/new one."""
    baseline = args.get("baseline")
    current = args.get("current")
    if not isinstance(current, list) or not current:
        current = _findings_from_agent(agent)
    if not isinstance(baseline, list):
        baseline = []
    if not baseline and not current:
        return "[findings_diff] Provide 'baseline' and 'current' finding arrays to diff."
    report = diff_assessments(baseline, current, target=str(args.get("target", "") or ""))
    return format_diff(report)
