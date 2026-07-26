"""L2 SAST checks with Python AST enrichment and language-neutral sinks."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from deepsec.core.finding import DeepSecFinding, DeepSecMode, FindingType, Severity


@dataclass(frozen=True, slots=True)
class SastRule:
    id: str
    type: FindingType
    severity: Severity
    message: str
    suggestion: str
    pattern: str
    flags: int = re.I


RULES = (
    SastRule("sast_sql_template_interpolation", FindingType.SQL_INJECTION, Severity.HIGH, "SQL query uses template interpolation.", "Use parameterized queries or a query builder that binds variables.", r"\b(?:query|sql|statement)\b\s*=\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{[^}]+}[^`]*`"),
    SastRule("sast_sql_string_concat", FindingType.SQL_INJECTION, Severity.HIGH, "SQL query is built with string concatenation.", "Use parameterized queries instead of concatenating user input.", r"\b(?:query|sql|statement)\b\s*=\s*['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^'\"]*['\"]\s*\+"),
    SastRule("sast_sql_python_f_string_execute", FindingType.SQL_INJECTION, Severity.HIGH, "Database execute() receives an interpolated SQL f-string.", "Use placeholders and a separate tuple or object for parameters.", r"\bexecute\s*\(\s*f['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^'\"]*\{[^}]+}[^'\"]*['\"]"),
    SastRule("sast_sql_user_input_execute", FindingType.SQL_INJECTION, Severity.HIGH, "Database execution receives a user-controlled SQL value.", "Use placeholders and pass request values separately.", r"\b(?:(?:db|database|pool|connection|conn|client|cursor|session)\.(?:query|execute|executemany)|(?:statement|preparedStatement)\.(?:execute|executeQuery))\s*\([^\)\n]*(?:req\.(?:query|body|params)|request\.(?:args|form|json)|request\s*\.\s*getParameter\s*\()"),
    SastRule("sast_xss_inner_html", FindingType.XSS, Severity.HIGH, "HTML is assigned directly to the DOM.", "Use textContent or sanitize trusted HTML.", r"\.(?:innerHTML|outerHTML)\s*=\s*(?!DOMPurify|sanitizeHtml|sanitize)[^;\n]+", 0),
    SastRule("sast_xss_document_write", FindingType.XSS, Severity.HIGH, "document.write() can introduce XSS.", "Create DOM nodes safely or sanitize first.", r"\bdocument\.write\s*\("),
    SastRule("sast_xss_dangerously_set_inner_html", FindingType.XSS, Severity.HIGH, "dangerouslySetInnerHTML receives user-controlled HTML.", "Use text rendering or sanitize untrusted HTML.", r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!DOMPurify|sanitizeHtml|sanitize)[^}]*\breq\.(?:query|body|params)\b[^}]*}\s*}", re.I),
    SastRule("sast_ssrf_fetch_user_url", FindingType.SSRF, Severity.MEDIUM, "HTTP request appears to use a user-controlled URL.", "Allowlist outbound hosts and validate URL schemes.", r"\b(?:fetch|axios\.(?:get|post|put|patch|delete)|got(?:\.(?:get|post|put|patch|delete))?|requests\.(?:get|post|put|patch|delete)|httpx\.(?:get|post|put|patch|delete)|urllib\.request\.urlopen)\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:args|form|json))"),
    SastRule("sast_path_traversal_fs_user_input", FindingType.PATH_TRAVERSAL, Severity.HIGH, "File path appears to include user-controlled input.", "Resolve paths against a fixed base and reject traversal outside it.", r"\b(?:fs(?:\.promises)?\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|rm)|open|Path\(|send_file)\s*\([^\)\n]*(?:req\.(?:query|body|params)|request\.(?:args|form|json)|params?\[)"),
    SastRule("sast_insecure_deserialization_pickle", FindingType.INSECURE_DESERIALIZATION, Severity.HIGH, "pickle deserializes data that may be user-controlled.", "Use JSON or another safe format for untrusted data.", r"\bpickle\.loads?\s*\([^\)\n]*(?:request|req\.|input|body|data)"),
    SastRule("sast_insecure_deserialization_yaml", FindingType.INSECURE_DESERIALIZATION, Severity.HIGH, "yaml.load() may deserialize untrusted data without SafeLoader.", "Use yaml.safe_load() for untrusted YAML.", r"\byaml\.load\s*\([^\)\n]*(?:request|req\.|input|body|data)(?![^)]*SafeLoader)"),
    SastRule("sast_command_injection_os_system", FindingType.COMMAND_INJECTION, Severity.HIGH, "Command execution appears to include user-controlled input.", "Use argument arrays, strict allowlists, and avoid shell=True.", r"\b(?:os\.system|subprocess\.(?:call|run|Popen|check_call|check_output)|child_process\.exec(?:Sync)?)\s*\([^\)\n]*(?:request|req\.|input|body|params|\$\{)"),
    SastRule("sast_open_redirect_user_input", FindingType.OPEN_REDIRECT, Severity.MEDIUM, "Redirect target appears to come from user-controlled input.", "Redirect only to relative paths or allowlisted hosts.", r"\b(?:res|response)\.redirect\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:query|body|params))|\bredirect\s*\(\s*(?:request\.(?:args|GET|POST)|req\.(?:query|body|params))"),
    SastRule("sast_information_leakage_error_details", FindingType.INFORMATION_LEAKAGE, Severity.MEDIUM, "Raw error details are returned to a client.", "Log detailed errors internally and return a generic client message.", r"\b(?:res|response)\.(?:send|json)\s*\([^;\n]*(?:err(?:or)?|exception|stack)\b"),
)


def scan_sast(text: str, target: str, language: str | None = None) -> list[DeepSecFinding]:
    findings = _regex_findings(text, target)
    if (language or "").lower() in {"python", "py"}:
        findings.extend(_python_ast_findings(text, target))
    return _deduplicate(findings)


def _regex_findings(text: str, target: str) -> list[DeepSecFinding]:
    findings: list[DeepSecFinding] = []
    for rule in RULES:
        for match in re.finditer(rule.pattern, text, rule.flags):
            findings.append(_finding(rule, text, target, match.start(), match.end(), match.group(0)))
    return findings


def _python_ast_findings(text: str, target: str) -> list[DeepSecFinding]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    findings: list[DeepSecFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        arguments = " ".join(ast.unparse(arg) for arg in node.args) if node.args else ""
        if name in {"os.system", "subprocess.run", "subprocess.call", "subprocess.Popen"} and _looks_user_controlled(arguments):
            rule = next(rule for rule in RULES if rule.id == "sast_command_injection_os_system")
            findings.append(_node_finding(rule, text, target, node))
        elif name in {"requests.get", "requests.post", "httpx.get", "httpx.post", "urllib.request.urlopen"} and _looks_user_controlled(arguments):
            rule = next(rule for rule in RULES if rule.id == "sast_ssrf_fetch_user_url")
            findings.append(_node_finding(rule, text, target, node))
        elif name in {"open", "send_file"} and _looks_user_controlled(arguments):
            rule = next(rule for rule in RULES if rule.id == "sast_path_traversal_fs_user_input")
            findings.append(_node_finding(rule, text, target, node))
    return findings


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _looks_user_controlled(arguments: str) -> bool:
    return bool(re.search(r"\b(?:request|req|input|params|query|body|form|args)\b", arguments, re.I))


def _node_finding(rule: SastRule, text: str, target: str, node: ast.Call) -> DeepSecFinding:
    start = _offset(text, node.lineno, node.col_offset)
    end = _offset(text, getattr(node, "end_lineno", node.lineno), getattr(node, "end_col_offset", node.col_offset))
    return _finding(rule, text, target, start, end, text[start:end])


def _finding(rule: SastRule, text: str, target: str, start: int, end: int, evidence: str) -> DeepSecFinding:
    line, column = _position(text, start)
    end_line, end_column = _position(text, end)
    return DeepSecFinding.create(mode=DeepSecMode.SHIELD, type=rule.type, severity=rule.severity, target=target, description=rule.message, rule=rule.id, layer="L2", evidence=evidence, suggestion=rule.suggestion, line=line, column=column, end_line=end_line, end_column=end_column)


def _position(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    return line, offset - text.rfind("\n", 0, offset)


def _offset(text: str, line: int, column: int) -> int:
    lines = text.splitlines(keepends=True)
    return sum(len(item) for item in lines[: line - 1]) + column


def _deduplicate(findings: list[DeepSecFinding]) -> list[DeepSecFinding]:
    unique: dict[tuple[str, int | None, str], DeepSecFinding] = {}
    for item in findings:
        unique.setdefault((item.detection_rule, item.line, item.evidence), item)
    return list(unique.values())
