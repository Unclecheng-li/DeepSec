"""L1 secret, unsafe configuration, and AI-code pattern detectors."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Iterable

from deepsec.core.finding import DeepSecFinding, DeepSecMode, FindingType, Severity


@dataclass(frozen=True, slots=True)
class PatternRule:
    id: str
    type: FindingType
    severity: Severity
    message: str
    suggestion: str
    pattern: str
    flags: int = 0
    languages: tuple[str, ...] = ()


def _rule(id: str, type: FindingType, severity: Severity, message: str, suggestion: str, pattern: str, flags: int = 0, languages: tuple[str, ...] = ()) -> PatternRule:
    return PatternRule(id, type, severity, message, suggestion, pattern, flags, languages)


SECRET_RULES = (
    _rule("hardcoded_secret_aws_access_key", FindingType.HARDCODED_SECRET, Severity.CRITICAL, "AWS access key appears to be hardcoded.", "Move the value to a secret manager and rotate it.", r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b"),
    _rule("hardcoded_secret_github_token", FindingType.HARDCODED_SECRET, Severity.CRITICAL, "GitHub token appears to be hardcoded.", "Move the value to a secret manager and rotate it.", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,255}\b"),
    _rule("hardcoded_secret_slack_token", FindingType.HARDCODED_SECRET, Severity.CRITICAL, "Slack token appears to be hardcoded.", "Move the value to a secret manager and rotate it.", r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    _rule("hardcoded_secret_stripe_key", FindingType.HARDCODED_SECRET, Severity.CRITICAL, "Stripe API key appears to be hardcoded.", "Move the value to a secret manager and rotate it.", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    _rule("hardcoded_secret_google_api_key", FindingType.HARDCODED_SECRET, Severity.CRITICAL, "Google API key appears to be hardcoded.", "Move the value to a secret manager and rotate it.", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    _rule("hardcoded_secret_npm_token", FindingType.HARDCODED_SECRET, Severity.CRITICAL, "npm access token appears to be hardcoded.", "Move the value to a secret manager and rotate it.", r"\bnpm_[A-Za-z0-9]{36}\b"),
    _rule("hardcoded_secret_anthropic_key", FindingType.HARDCODED_SECRET, Severity.CRITICAL, "Anthropic API key appears to be hardcoded.", "Move the value to a secret manager and rotate it.", r"\bsk-ant-[A-Za-z0-9_-]{32,}\b"),
    _rule("hardcoded_secret_openai_key", FindingType.HARDCODED_SECRET, Severity.CRITICAL, "OpenAI API key appears to be hardcoded.", "Move the value to a secret manager and rotate it.", r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
    _rule("hardcoded_secret_jwt", FindingType.HARDCODED_SECRET, Severity.CRITICAL, "JWT token appears to be hardcoded.", "Move the value to a secret manager and rotate it.", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    _rule("hardcoded_secret_private_key", FindingType.HARDCODED_SECRET, Severity.CRITICAL, "Private key material appears to be committed.", "Remove it from source control, rotate it, and use secure runtime storage.", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ED25519 )?PRIVATE KEY-----"),
    _rule("hardcoded_secret_database_url", FindingType.HARDCODED_SECRET, Severity.CRITICAL, "Database URL includes a password.", "Move the connection string to a secret manager and rotate the password.", r"\b(?:postgres|postgresql|mysql|mongodb|redis)://[^:\s/@]+:[^@\s]+@[^)\s'\"]+", re.I),
)

CONFIG_RULES = (
    _rule("insecure_config_debug_true", FindingType.INSECURE_CONFIG, Severity.HIGH, "Django or Flask debug mode is enabled.", "Disable debug mode in production.", r"\bDEBUG\s*=\s*True\b", 0, ("python",)),
    _rule("insecure_config_app_debug_true", FindingType.INSECURE_CONFIG, Severity.HIGH, "Application debug mode is enabled.", "Disable debug mode outside local development.", r"\bapp\.debug\s*=\s*(?:True|true)\b"),
    _rule("insecure_config_allowed_hosts_wildcard", FindingType.INSECURE_CONFIG, Severity.HIGH, "Django ALLOWED_HOSTS allows every host.", "Use the exact production host names.", r"\bALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]\s*\]", 0, ("python",)),
    _rule("insecure_config_cors_allow_all", FindingType.INSECURE_CONFIG, Severity.HIGH, "CORS is configured to allow every origin.", "Restrict CORS to trusted origins.", r"\b(?:CORS_ALLOW_ALL|CORS_ALLOW_ALL_ORIGINS)\s*=\s*True\b", 0, ("python",)),
    _rule("insecure_config_acao_wildcard", FindingType.INSECURE_CONFIG, Severity.MEDIUM, "Access-Control-Allow-Origin is set to a wildcard.", "Return a specific allowlisted origin.", r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]", re.I),
    _rule("insecure_config_disable_host_check", FindingType.INSECURE_CONFIG, Severity.HIGH, "Host header checks are disabled.", "Configure explicit trusted hosts.", r"\bDANGEROUSLY_DISABLE_HOST_CHECK\s*=\s*(?:true|1)\b", re.I),
    _rule("insecure_config_csrf_exempt", FindingType.INSECURE_CONFIG, Severity.HIGH, "CSRF protection is disabled for this endpoint.", "Keep CSRF protection enabled or add a narrowly reviewed control.", r"@csrf_exempt\b|\bcsrf_exempt\s*\(", 0, ("python",)),
    _rule("insecure_config_spring_permit_all", FindingType.INSECURE_CONFIG, Severity.MEDIUM, "Spring Security permitAll() may expose an endpoint.", "Verify the endpoint is intentionally public.", r"\.permitAll\s*\(", 0, ("java",)),
    _rule("insecure_config_cross_origin_wildcard", FindingType.INSECURE_CONFIG, Severity.HIGH, "Spring @CrossOrigin allows every origin.", "Restrict origins to trusted domains.", r"@CrossOrigin\s*\([^)]*(?:origins\s*=\s*)?['\"]\*['\"][^)]*\)", 0, ("java",)),
    _rule("insecure_config_eval", FindingType.INSECURE_CONFIG, Severity.HIGH, "eval() executes arbitrary code.", "Use a structured parser or explicit dispatch table.", r"(?<![.\w])eval\s*\("),
    # exec( is Python's arbitrary-code sink. In JavaScript the same spelling is
    # RegExp.prototype.exec / String.prototype.match -- an extremely common and
    # entirely benign call -- so running this rule language-blind produced the
    # single largest source of false positives in the whole ruleset.
    _rule("insecure_config_python_exec", FindingType.INSECURE_CONFIG, Severity.HIGH, "exec() executes arbitrary Python code.", "Avoid exec() and use explicit functions.", r"(?<![.\w])exec\s*\(", 0, ("python",)),
    _rule("insecure_config_pickle_loads", FindingType.INSECURE_CONFIG, Severity.HIGH, "pickle deserialization can execute arbitrary code.", "Use JSON or a safe serialization format.", r"\bpickle\.loads?\s*\(", 0, ("python",)),
    _rule("insecure_config_yaml_load_without_loader", FindingType.INSECURE_CONFIG, Severity.HIGH, "yaml.load() is used without a safe loader.", "Use yaml.safe_load() or SafeLoader explicitly.", r"\byaml\.load\s*\(\s*[^,\n)]+?\s*\)", 0, ("python",)),
)

AI_PATTERN_RULES = (
    _rule("ai_pattern_default_password", FindingType.AI_PATTERN_ERROR, Severity.CRITICAL, "Default password is hardcoded.", "Generate a unique secret per environment and require setup.", r"\b(?:password|passwd|pwd)\s*[:=]\s*['\"](?:admin|password|123456|12345678|changeme)['\"]", re.I),
    _rule("ai_pattern_admin_admin_credentials", FindingType.AI_PATTERN_ERROR, Severity.CRITICAL, "Default admin/admin credentials are present.", "Remove default credentials and provision initial users securely.", r"\b(?:username|user|login)\s*[:=]\s*['\"]admin['\"][\s\S]{0,120}\b(?:password|passwd|pwd)\s*[:=]\s*['\"]admin['\"]", re.I),
    _rule("ai_pattern_hardcoded_jwt_secret", FindingType.AI_PATTERN_ERROR, Severity.CRITICAL, "JWT secret is hardcoded.", "Load JWT_SECRET from secure runtime configuration and rotate it.", r"\bJWT_SECRET\b\s*[:=]\s*['\"`](?!process\.env|import\.meta\.env|os\.getenv)[^'\"`]{8,}['\"`]"),
    _rule("ai_pattern_sql_f_string", FindingType.AI_PATTERN_ERROR, Severity.HIGH, "SQL query appears to interpolate a variable directly.", "Use parameterized queries.", r"\bf['\"`][^'\"`]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^'\"`]*\{[^}]+}[^'\"`]*['\"`]", re.I, ("python",)),
    _rule("ai_pattern_dangerously_set_inner_html", FindingType.AI_PATTERN_ERROR, Severity.HIGH, "dangerouslySetInnerHTML is used without an obvious sanitizer.", "Sanitize HTML before rendering it.", r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!DOMPurify|sanitizeHtml|sanitize)[^}]+}\s*}", 0, ("javascript", "typescript", "jsx", "tsx")),
    _rule("ai_pattern_frontend_secret_name", FindingType.AI_PATTERN_ERROR, Severity.CRITICAL, "Secret-like value is exposed through a frontend environment variable.", "Move secrets to server-side configuration.", r"\b(?:VITE|NEXT_PUBLIC|REACT_APP)_[A-Z0-9_]*(?:SECRET|PRIVATE|TOKEN|API_KEY)[A-Z0-9_]*\s*[:=]\s*['\"`][^'\"`]{8,}['\"`]", 0, ("javascript", "typescript", "jsx", "tsx")),
    _rule("ai_pattern_jwt_none_algorithm", FindingType.AI_PATTERN_ERROR, Severity.CRITICAL, "JWT accepts the none algorithm.", "Require a signed JWT algorithm.", r"\bjwt\.(?:sign|verify)\s*\([\s\S]{0,240}\balgorithms?\s*:\s*(?:\[\s*)?['\"]none['\"]", re.I),
    _rule("ai_pattern_jwt_ignore_expiration", FindingType.AI_PATTERN_ERROR, Severity.HIGH, "JWT expiration validation is disabled.", "Require token expiration checks.", r"\bjwt\.verify\s*\([\s\S]{0,240}\bignoreExpiration\s*:\s*true\b", re.I),
    _rule("ai_pattern_tls_verification_disabled", FindingType.AI_PATTERN_ERROR, Severity.HIGH, "TLS certificate verification is disabled.", "Keep certificate verification enabled.", r"\bNODE_TLS_REJECT_UNAUTHORIZED\b\s*=\s*['\"]?0['\"]?|\brejectUnauthorized\s*:\s*false\b", re.I),
    _rule("ai_pattern_requests_verify_false", FindingType.AI_PATTERN_ERROR, Severity.HIGH, "Python HTTP request disables TLS verification.", "Remove verify=False and configure trusted CAs.", r"\brequests\.(?:get|post|put|patch|delete|request)\s*\([^\)\n]*\bverify\s*=\s*False\b", 0, ("python",)),
    _rule("ai_pattern_bcrypt_low_rounds", FindingType.AI_PATTERN_ERROR, Severity.HIGH, "bcrypt uses an extremely low work factor.", "Use a modern bcrypt cost factor.", r"\bbcrypt(?:js)?\.(?:hash|genSalt)\s*\([^\)\n]*,\s*[0-4]\s*\)", re.I),
    _rule("ai_pattern_math_random_token", FindingType.AI_PATTERN_ERROR, Severity.HIGH, "Security token is generated with Math.random().", "Use crypto.randomBytes or Web Crypto.", r"\b(?:token|secret|apiKey|resetToken|sessionId)\b\s*[:=]\s*Math\.random\s*\("),
    _rule("ai_pattern_flask_secret_key_placeholder", FindingType.AI_PATTERN_ERROR, Severity.CRITICAL, "Flask or Django secret key uses a placeholder.", "Generate a high-entropy secret outside source control.", r"\b(?:app\.config\s*\[\s*['\"]SECRET_KEY['\"]\s*\]\s*=|SECRET_KEY\s*=)\s*['\"](?:secret|dev|development|changeme|password|123456)['\"]", re.I, ("python",)),
    _rule("ai_pattern_fastapi_cors_credentials_wildcard", FindingType.AI_PATTERN_ERROR, Severity.HIGH, "CORS allows wildcard origins with credentials.", "Set explicit trusted origins.", r"\bCORSMiddleware\b[\s\S]{0,300}\ballow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\][\s\S]{0,300}\ballow_credentials\s*=\s*True\b", 0, ("python",)),
    _rule("ai_pattern_cookie_secure_false", FindingType.AI_PATTERN_ERROR, Severity.HIGH, "Session cookie is allowed over insecure HTTP.", "Set secure: true outside local development.", r"\b(?:res|response)\.cookie\s*\([^,\n]+,\s*[^,\n]+,\s*\{[\s\S]{0,240}\bsecure\s*:\s*false\b", re.I),
    _rule("ai_pattern_cookie_httponly_false", FindingType.AI_PATTERN_ERROR, Severity.HIGH, "Session cookie is readable by client-side scripts.", "Set httpOnly: true for sensitive cookies.", r"\b(?:res|response)\.cookie\s*\([^,\n]+,\s*[^,\n]+,\s*\{[\s\S]{0,240}\bhttpOnly\s*:\s*false\b", re.I),
    _rule("ai_pattern_spring_csrf_disabled", FindingType.AI_PATTERN_ERROR, Severity.HIGH, "Spring Security CSRF protection is disabled.", "Keep CSRF enabled for browser-authenticated flows.", r"\.csrf\s*\(\s*\)\s*\.disable\s*\(\s*\)|\.csrf\s*\(\s*(?:csrf\s*->\s*)?csrf\.disable\s*\(\s*\)\s*\)", 0, ("java",)),
    _rule("ai_pattern_jinja_autoescape_disabled", FindingType.AI_PATTERN_ERROR, Severity.HIGH, "Jinja template autoescaping is disabled.", "Keep autoescape enabled for HTML templates.", r"\bEnvironment\s*\([^\)\n]*\bautoescape\s*=\s*False\b", 0, ("python",)),
    _rule("ai_pattern_paramiko_auto_add_host_key", FindingType.AI_PATTERN_ERROR, Severity.HIGH, "SSH host key verification accepts unknown hosts.", "Verify and pin expected SSH host keys.", r"\bset_missing_host_key_policy\s*\(\s*paramiko\.AutoAddPolicy\s*\(\s*\)\s*\)", 0, ("python",)),
    _rule("ai_pattern_object_storage_public_write_acl", FindingType.AI_PATTERN_ERROR, Severity.CRITICAL, "Object storage ACL grants public write access.", "Remove public-write access immediately.", r"\b(?:ACL|acl)\s*[:=]\s*['\"]public-read-write['\"]|\.putObjectAcl\s*\([\s\S]{0,160}public-read-write", re.I),
)


def scan_patterns(text: str, target: str, language: str | None = None) -> list[DeepSecFinding]:
    findings: list[DeepSecFinding] = []
    seen_ranges: list[tuple[int, int]] = []
    for rule in SECRET_RULES:
        findings.extend(_matches(rule, text, target, language, seen_ranges, redact=True))
    findings.extend(_sensitive_assignments(text, target, seen_ranges))
    for rule in (*CONFIG_RULES, *AI_PATTERN_RULES):
        findings.extend(_matches(rule, text, target, language, None))
    return findings


def _matches(rule: PatternRule, text: str, target: str, language: str | None, seen_ranges: list[tuple[int, int]] | None, redact: bool = False) -> list[DeepSecFinding]:
    if rule.languages and (language or "").lower() not in rule.languages:
        return []
    findings: list[DeepSecFinding] = []
    for match in re.finditer(rule.pattern, text, rule.flags):
        if seen_ranges is not None and any(match.start() < end and start < match.end() for start, end in seen_ranges):
            continue
        evidence = _redact(match.group(0)) if redact else match.group(0)
        findings.append(_finding(rule, target, text, match.start(), match.end(), evidence))
        if seen_ranges is not None:
            seen_ranges.append((match.start(), match.end()))
    return findings


def _sensitive_assignments(text: str, target: str, seen_ranges: list[tuple[int, int]]) -> list[DeepSecFinding]:
    pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:api[_-]?key|secret|password|passwd|pwd|token|private[_-]?key|jwt[_-]?secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|credential)[A-Za-z0-9_]*)\b\s*[:=]\s*(['\"`])((?:\\.|(?!\2).){6,})\2", re.I)
    rule = _rule("hardcoded_secret_assignment", FindingType.HARDCODED_SECRET, Severity.CRITICAL, "Sensitive value is assigned a literal.", "Read this value from a secret manager or environment variable.", "")
    findings: list[DeepSecFinding] = []
    for match in pattern.finditer(text):
        value = match.group(3).strip()
        line = _line_text(text, match.start())
        if _placeholder(value) or _environment_reference(line) or any(match.start(3) < end and start < match.end(3) for start, end in seen_ranges):
            continue
        identifier = "hardcoded_secret_high_entropy_assignment" if _high_entropy(value, True) else rule.id
        finding_rule = PatternRule(identifier, rule.type, rule.severity, rule.message, rule.suggestion, "")
        findings.append(_finding(finding_rule, target, text, match.start(), match.end(), f"{match.group(1)} = {_redact(value)}"))
        seen_ranges.append((match.start(3), match.end(3)))
    return findings


def _finding(rule: PatternRule, target: str, text: str, start: int, end: int, evidence: str) -> DeepSecFinding:
    line, column = _position(text, start)
    end_line, end_column = _position(text, end)
    return DeepSecFinding.create(mode=DeepSecMode.SHIELD, type=rule.type, severity=rule.severity, target=target, description=rule.message, rule=rule.id, layer="L1", evidence=evidence, suggestion=rule.suggestion, line=line, column=column, end_line=end_line, end_column=end_column)


def _position(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last_newline = text.rfind("\n", 0, offset)
    return line, offset - last_newline


def _line_text(text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    return text[start:] if end == -1 else text[start:end]


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"


def _placeholder(value: str) -> bool:
    return value.strip().lower().replace(" ", "-") in {"changeme", "change-me", "example", "sample", "placeholder", "your-key", "your-api-key", "your-secret", "your-token", "test", "test-key", "dummy", "fake", "todo"}


def _environment_reference(line: str) -> bool:
    return bool(re.search(r"(?:process\.env|os\.getenv|os\.environ|import\.meta\.env|ENV\[)", line))


def _high_entropy(value: str, contextual: bool) -> bool:
    if len(value) < (16 if contextual else 24) or len(value) > 180 or re.search(r"\s", value):
        return False
    if not re.search(r"[A-Za-z]", value) or not re.search(r"\d", value):
        return False
    entropy = -sum((count / len(value)) * math.log2(count / len(value)) for count in (value.count(character) for character in set(value)))
    return entropy >= (3.8 if contextual else 4.5)
