"""L3 endpoint-oriented semantic checks with optional remote AI augmentation."""

from __future__ import annotations

import re
from typing import Awaitable, Callable

from deepsec.core.finding import DeepSecFinding, DeepSecMode, FindingType, Severity


def audit_semantics(text: str, target: str, language: str | None = None) -> list[DeepSecFinding]:
    findings: list[DeepSecFinding] = []
    for method, path, start, snippet in _endpoints(text, language):
        lower = snippet.lower()
        if _sensitive(path) and not _has_auth(lower):
            findings.append(_finding(target, text, start, FindingType.MISSING_SECURITY_MEASURE, Severity.HIGH, "l3_missing_authentication", f"Endpoint {method.upper()} {path} appears to access sensitive functionality without obvious authentication.", "Add authentication and authorization before exposing this endpoint."))
        if _needs_rate_limit(method, path) and not _has_rate_limit(lower):
            findings.append(_finding(target, text, start, FindingType.MISSING_SECURITY_MEASURE, Severity.MEDIUM, "l3_missing_rate_limiting", f"Endpoint {method.upper()} {path} looks abuse-prone and has no obvious rate limiting.", "Add a rate limiter appropriate for the endpoint and identity."))
        if _uses_input(lower) and not _has_validation(lower):
            findings.append(_finding(target, text, start, FindingType.MISSING_SECURITY_MEASURE, Severity.MEDIUM, "l3_missing_input_validation", f"Endpoint {method.upper()} {path} uses request input without obvious validation.", "Validate request fields with an explicit schema before use."))
        if _uses_input(lower) and _performs_io(lower) and not _has_error_handling(lower):
            findings.append(_finding(target, text, start, FindingType.MISSING_SECURITY_MEASURE, Severity.LOW, "l3_missing_error_handling", f"Endpoint {method.upper()} {path} performs IO without obvious error handling.", "Handle failures and return a safe client error response."))
    return findings


async def audit_with_llm(text: str, target: str, review: Callable[[str, str], Awaitable[tuple[dict, object]]]) -> list[DeepSecFinding]:
    response, _usage = await review(text, target)
    result: list[DeepSecFinding] = []
    for raw in response.get("findings", []):
        if not isinstance(raw, dict):
            continue
        severity_text = str(raw.get("severity", "medium")).lower()
        severity = Severity(severity_text) if severity_text in Severity._value2member_map_ else Severity.MEDIUM
        line = raw.get("line") if isinstance(raw.get("line"), int) else None
        result.append(DeepSecFinding.create(mode=DeepSecMode.SHIELD, type=FindingType.MISSING_SECURITY_MEASURE, severity=severity, target=target, description=str(raw.get("description") or raw.get("title") or "AI security concern"), title=str(raw.get("title") or "AI security concern"), rule="l3_llm_semantic_review", layer="L3", evidence=str(raw.get("evidence") or ""), suggestion=str(raw.get("suggestion") or ""), line=line, confidence=_coerce_confidence(raw.get("confidence"))))
    return result


def _coerce_confidence(value: object) -> float:
    """Normalize an LLM-provided confidence to a 0-1 float.

    Models may return a number (0.8), a numeric string ("0.8"/"80"/"80%"), or a
    qualitative word ("high"/"medium"/"low"). float("high") would crash, so map
    everything to a float and fall back to 0.6 when unparseable.
    """
    if isinstance(value, bool) or value is None:
        return 0.6
    if isinstance(value, (int, float)):
        return max(0.0, min(1.0, float(value)))
    if isinstance(value, str):
        text = value.strip().lower()
        words = {
            "critical": 0.95, "very high": 0.9, "high": 0.85, "medium": 0.6,
            "moderate": 0.6, "low": 0.35, "very low": 0.2, "info": 0.2,
            "informational": 0.2, "unknown": 0.6,
        }
        if text in words:
            return words[text]
        try:
            parsed = float(text.rstrip("%"))
        except ValueError:
            return 0.6
        if parsed > 1.0:  # "80" or "80%" -> 0.8
            parsed /= 100.0
        return max(0.0, min(1.0, parsed))
    return 0.6


def _endpoints(text: str, language: str | None) -> list[tuple[str, str, int, str]]:
    endpoints: list[tuple[str, str, int, str]] = []
    if (language or "").lower() in {"python", "py"}:
        pattern = re.compile(r"@(?:app|router|blueprint)\.(?:(get|post|put|patch|delete)|route)\s*\(\s*['\"]([^'\"]+)['\"][^\n]*\)\s*\n(?:@[^^\n]+\n)*\s*(?:async\s+)?def\b[\s\S]{0,1800}", re.I)
    else:
        pattern = re.compile(r"\b(?:app|router)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['\"`]([^'\"`]+)['\"`][\s\S]{0,1800}?\n\s*}\s*\)?\s*;?", re.I)
    for match in pattern.finditer(text):
        method = (match.group(1) or "request").lower()
        endpoints.append((method, match.group(2), match.start(), match.group(0)))
    return endpoints


def _finding(target: str, text: str, offset: int, type: FindingType, severity: Severity, rule: str, message: str, suggestion: str) -> DeepSecFinding:
    line = text.count("\n", 0, offset) + 1
    column = offset - text.rfind("\n", 0, offset)
    return DeepSecFinding.create(mode=DeepSecMode.SHIELD, type=type, severity=severity, target=target, description=message, rule=rule, layer="L3", evidence="", suggestion=suggestion, line=line, column=column, confidence=0.65)


def _sensitive(path: str) -> bool:
    return bool(re.search(r"admin|account|billing|payment|profile|settings|user|token|secret|private", path, re.I))


def _needs_rate_limit(method: str, path: str) -> bool:
    return method != "get" or bool(re.search(r"login|register|signup|password|reset|token|upload|invite", path, re.I))


def _uses_input(text: str) -> bool:
    return bool(re.search(r"\b(?:req\.(?:body|query|params)|request\.(?:json|form|args|GET|POST|body|FILES|headers)|body|query|params)\b", text, re.I))


def _has_auth(text: str) -> bool:
    return bool(re.search(r"authenticate|authorize|requireauth|isauthenticated|verifytoken|jwt|session|current_user|login_required|permission_required|bearer|preauthorize|secured", text, re.I))


def _has_rate_limit(text: str) -> bool:
    return bool(re.search(r"ratelimit|rate_limit|limiter|throttle|slowapi|express-rate-limit|@limit", text, re.I))


def _has_validation(text: str) -> bool:
    return bool(re.search(r"validate|validated|validator|schema|zod|joi|yup|pydantic|sanitize|escape|safeparse|basemodel|is_valid", text, re.I))


def _performs_io(text: str) -> bool:
    return bool(re.search(r"\b(?:fetch|axios|requests|httpx|query|execute|readfile|writefile|open|send_file|subprocess)\b", text, re.I))


def _has_error_handling(text: str) -> bool:
    return bool(re.search(r"\btry\s*(?:\{|:)|\bcatch\s*\(|\.catch\s*\(|\bexcept\b|error_?handler", text, re.I))
