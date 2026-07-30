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


# A quoted string literal that may embed the *other* quote character. SQL built by
# concatenation almost always wraps a value in inner quotes ("... id = '" + x + "'"),
# so a naive [^'"]* body never matches the very case this rule exists to catch.
_STRING_LITERAL = r"""(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')"""
_SQL_KEYWORD = r"(?:SELECT|INSERT|UPDATE|DELETE)"
_SQL_STRING = rf"""(?:"(?:[^"\\]|\\.)*\b{_SQL_KEYWORD}\b(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*\b{_SQL_KEYWORD}\b(?:[^'\\]|\\.)*')"""

RULES = (
    SastRule("sast_sql_template_interpolation", FindingType.SQL_INJECTION, Severity.HIGH, "SQL query uses template interpolation.", "Use parameterized queries or a query builder that binds variables.", rf"\b\w*\s*=\s*`[^`]*{_SQL_KEYWORD}\b[^`]*\$\{{[^}}]+}}[^`]*`"),
    SastRule("sast_sql_string_concat", FindingType.SQL_INJECTION, Severity.HIGH, "SQL query is built with string concatenation.", "Use parameterized queries instead of concatenating user input.", rf"\b[A-Za-z_]\w*\s*=\s*{_SQL_STRING}\s*\+"),
    SastRule("sast_sql_python_f_string_execute", FindingType.SQL_INJECTION, Severity.HIGH, "Database execute() receives an interpolated SQL f-string.", "Use placeholders and a separate tuple or object for parameters.", rf"\bexecute\s*\(\s*f['\"][^'\"]*{_SQL_KEYWORD}\b[^'\"]*\{{[^}}]+}}[^'\"]*['\"]"),
    SastRule("sast_sql_user_input_execute", FindingType.SQL_INJECTION, Severity.HIGH, "Database execution receives a user-controlled SQL value.", "Use placeholders and pass request values separately.", r"\b(?:(?:db|database|pool|connection|conn|client|cursor|session)\.(?:query|execute|executemany)|(?:statement|preparedStatement)\.(?:execute|executeQuery))\s*\([^\)\n]*(?:req\.(?:query|body|params)|request\.(?:args|form|json)|request\s*\.\s*getParameter\s*\()"),
    SastRule("sast_sql_concat_execute", FindingType.SQL_INJECTION, Severity.HIGH, "Database execution receives a concatenated SQL string.", "Use placeholders and pass values separately.", rf"\b(?:execute|executemany|query|executeQuery)\s*\(\s*{_SQL_STRING}\s*\+"),
    SastRule("sast_xss_inner_html", FindingType.XSS, Severity.HIGH, "HTML is assigned directly to the DOM.", "Use textContent or sanitize trusted HTML.", r"\.(?:innerHTML|outerHTML)\s*=\s*(?!DOMPurify|sanitizeHtml|sanitize|['\"`]\s*['\"`])[^;\n]+", 0),
    SastRule("sast_xss_document_write", FindingType.XSS, Severity.HIGH, "document.write() can introduce XSS.", "Create DOM nodes safely or sanitize first.", r"\bdocument\.write\s*\("),
    SastRule("sast_xss_dangerously_set_inner_html", FindingType.XSS, Severity.HIGH, "dangerouslySetInnerHTML receives user-controlled HTML.", "Use text rendering or sanitize untrusted HTML.", r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!DOMPurify|sanitizeHtml|sanitize)[^}]*\breq\.(?:query|body|params)\b[^}]*}\s*}", re.I),
    SastRule("sast_ssrf_fetch_user_url", FindingType.SSRF, Severity.MEDIUM, "HTTP request appears to use a user-controlled URL.", "Allowlist outbound hosts and validate URL schemes.", r"\b(?:fetch|axios\.(?:get|post|put|patch|delete)|got(?:\.(?:get|post|put|patch|delete))?|requests\.(?:get|post|put|patch|delete)|httpx\.(?:get|post|put|patch|delete)|urllib\.request\.urlopen)\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:args|form|json))"),
    SastRule("sast_path_traversal_fs_user_input", FindingType.PATH_TRAVERSAL, Severity.HIGH, "File path appears to include user-controlled input.", "Resolve paths against a fixed base and reject traversal outside it.", r"\b(?:fs(?:\.promises)?\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|rm)|open|Path\(|send_file)\s*\([^\)\n]*(?:req\.(?:query|body|params)|request\.(?:args|form|json)|params?\[)"),
    SastRule("sast_insecure_deserialization_pickle", FindingType.INSECURE_DESERIALIZATION, Severity.HIGH, "pickle deserializes data that may be user-controlled.", "Use JSON or another safe format for untrusted data.", r"\bpickle\.loads?\s*\([^\)\n]*(?:request|req\.|input|body|data)"),
    SastRule("sast_insecure_deserialization_yaml", FindingType.INSECURE_DESERIALIZATION, Severity.HIGH, "yaml.load() may deserialize untrusted data without SafeLoader.", "Use yaml.safe_load() for untrusted YAML.", r"\byaml\.load\s*\([^\)\n]*(?:request|req\.|input|body|data)(?![^)]*SafeLoader)"),
    SastRule("sast_command_injection_os_system", FindingType.COMMAND_INJECTION, Severity.HIGH, "Command execution appears to include user-controlled input.", "Use argument arrays, strict allowlists, and avoid shell=True.", r"\b(?:os\.system|subprocess\.(?:call|run|Popen|check_call|check_output)|child_process\.exec(?:Sync)?)\s*\([^\)\n]*(?:request|req\.|input|body|params|\$\{)"),
    SastRule("sast_command_injection_shell_true", FindingType.COMMAND_INJECTION, Severity.HIGH, "Command runs through a shell with a dynamically built command line.", "Pass an argument list and drop shell=True.", r"\bsubprocess\.(?:call|run|Popen|check_call|check_output)\s*\([^\)]*\bshell\s*=\s*True\b"),
    SastRule("sast_open_redirect_user_input", FindingType.OPEN_REDIRECT, Severity.MEDIUM, "Redirect target appears to come from user-controlled input.", "Redirect only to relative paths or allowlisted hosts.", r"\b(?:res|response)\.redirect\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:query|body|params))|\bredirect\s*\(\s*(?:request\.(?:args|GET|POST)|req\.(?:query|body|params))"),
    SastRule("sast_information_leakage_error_details", FindingType.INFORMATION_LEAKAGE, Severity.MEDIUM, "Raw error details are returned to a client.", "Log detailed errors internally and return a generic client message.", r"\b(?:res|response)\.(?:send|json)\s*\([^;\n]*(?:err(?:or)?|exception|stack)\b"),
)

_RULES_BY_ID = {rule.id: rule for rule in RULES}

# Names that mark a value as attacker-reachable regardless of enclosing scope.
_REQUEST_SOURCES = re.compile(r"\b(?:request|req|flask\.request|self\.request)\b")
_SQL_IN_TEXT = re.compile(rf"\b{_SQL_KEYWORD}\b", re.I)

_COMMAND_SINKS = {"os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput"}
_SSRF_SINKS = {"requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete", "requests.request", "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete", "urllib.request.urlopen"}
_PATH_SINKS = {"open", "send_file"}
_SQL_SINKS = {"execute", "executemany", "executescript", "query"}


def scan_sast(text: str, target: str, language: str | None = None) -> list[DeepSecFinding]:
    findings: list[DeepSecFinding] = []
    if (language or "").lower() in {"python", "py"}:
        findings.extend(_python_ast_findings(text, target))
    findings.extend(_regex_findings(text, target))
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
    for scope_node, tainted in _scopes(tree):
        for node in ast.walk(scope_node):
            if not isinstance(node, ast.Call) or _encloses_nested_scope(scope_node, node):
                continue
            findings.extend(_call_findings(node, tainted, text, target))
    return findings


def _scopes(tree: ast.AST) -> list[tuple[ast.AST, set[str]]]:
    """Pair every function body with the parameter names it can be attacked through.

    Module level code gets an empty taint set, so only explicit request objects
    flag there. Inside a function, each parameter is a potential attacker input:
    a helper like ``def ping(host)`` is just as reachable as ``request.args``,
    and keying taint on parameter *names* alone (host, uid, filename, ...) is
    what made the previous implementation blind to most real code.
    """
    scopes: list[tuple[ast.AST, set[str]]] = [(tree, set())]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = node.args
            names = {item.arg for item in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)}
            for optional in (arguments.vararg, arguments.kwarg):
                if optional is not None:
                    names.add(optional.arg)
            names.discard("self")
            names.discard("cls")
            scopes.append((node, names))
    return scopes


def _encloses_nested_scope(scope_node: ast.AST, node: ast.Call) -> bool:
    """True when node belongs to a nested function that owns its own taint set."""
    for child in ast.walk(scope_node):
        if child is scope_node or not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(inner is node for inner in ast.walk(child)):
            return True
    return False


def _call_findings(node: ast.Call, tainted: set[str], text: str, target: str) -> list[DeepSecFinding]:
    findings: list[DeepSecFinding] = []
    name = _call_name(node.func)
    short_name = name.rsplit(".", 1)[-1]
    positional = node.args

    if name in _COMMAND_SINKS:
        shell = _keyword(node, "shell")
        uses_shell = shell is not None and isinstance(shell, ast.Constant) and shell.value is True
        first = positional[0] if positional else None
        # An argv list without shell=True is the recommended fix, not a defect:
        # the OS never parses a shell metacharacter, so interpolating a variable
        # into an element is safe. Only flag it when a shell is explicitly asked for.
        argv_form = isinstance(first, (ast.List, ast.Tuple)) and not uses_shell
        dynamic = first is not None and not _is_literal(first)
        if dynamic and not argv_form and (_is_tainted(first, tainted) or uses_shell):
            rule_id = "sast_command_injection_shell_true" if uses_shell else "sast_command_injection_os_system"
            findings.append(_node_finding(_RULES_BY_ID[rule_id], text, target, node))
    elif name in _SSRF_SINKS and positional and _is_tainted(positional[0], tainted):
        findings.append(_node_finding(_RULES_BY_ID["sast_ssrf_fetch_user_url"], text, target, node))
    elif name in _PATH_SINKS and positional and _traversable_path(positional[0], tainted):
        findings.append(_node_finding(_RULES_BY_ID["sast_path_traversal_fs_user_input"], text, target, node))
    elif short_name in _SQL_SINKS and positional:
        findings.extend(_sql_findings(node, positional[0], tainted, text, target))
    return findings


def _sql_findings(node: ast.Call, first: ast.expr, tainted: set[str], text: str, target: str) -> list[DeepSecFinding]:
    interpolated = _sql_interpolation(first)
    if interpolated is None:
        return []
    rule = _RULES_BY_ID["sast_sql_python_f_string_execute" if isinstance(first, ast.JoinedStr) else "sast_sql_concat_execute"]
    # Interpolating a value that traces back to a parameter or request object is a
    # real injection. Interpolating something the code already controls -- a table
    # name read from sqlite_master, a constant picked from a dict -- is an
    # identifier splice: worth a look to confirm the allowlist, not a high finding.
    if not _is_tainted(interpolated, tainted):
        rule = SastRule(rule.id, rule.type, Severity.MEDIUM, "SQL identifier is interpolated rather than bound.", "Confirm the interpolated identifier comes from a fixed allowlist, not from caller input.", rule.pattern, rule.flags)
    return [_node_finding(rule, text, target, node)]


def _sql_interpolation(node: ast.expr) -> ast.expr | None:
    """Return the interpolated sub-expression when node is a dynamically built SQL string."""
    if isinstance(node, ast.JoinedStr):
        literal = "".join(part.value for part in node.values if isinstance(part, ast.Constant) and isinstance(part.value, str))
        if not _SQL_IN_TEXT.search(literal):
            return None
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                return part.value
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        if not _SQL_IN_TEXT.search(_literal_text(node)):
            return None
        for side in (node.left, node.right):
            if not _is_literal(side):
                return side
        return None
    if isinstance(node, ast.Call) and _call_name(node.func).endswith(".format"):
        target_node = node.func.value if isinstance(node.func, ast.Attribute) else None
        if isinstance(target_node, ast.Constant) and isinstance(target_node.value, str) and _SQL_IN_TEXT.search(target_node.value):
            return node.args[0] if node.args else target_node
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str) and _SQL_IN_TEXT.search(node.left.value):
            return node.right
    return None


def _literal_text(node: ast.expr) -> str:
    return " ".join(part.value for part in ast.walk(node) if isinstance(part, ast.Constant) and isinstance(part.value, str))


def _is_literal(node: ast.expr) -> bool:
    """True when the expression is fully static (no names, calls, or attributes)."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(part, ast.Constant) for part in node.values)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_literal(item) for item in node.elts)
    if isinstance(node, ast.BinOp):
        return _is_literal(node.left) and _is_literal(node.right)
    return False


def _traversable_path(node: ast.expr, tainted: set[str]) -> bool:
    """True when a tainted value is appended to a path the code otherwise controls.

    ``open(path)`` where path is the function's own parameter is an ordinary
    internal helper: the caller supplied the whole path and is responsible for it.
    Traversal is about a *segment* an attacker can steer -- ``open(BASE + name)``
    or ``os.path.join(UPLOAD_DIR, filename)`` -- where "../.." escapes the base.
    Flagging every open(param) buries the real cases in helper functions.
    """
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_tainted(node.right, tainted)
    if isinstance(node, ast.JoinedStr):
        parts = node.values
        return any(isinstance(part, ast.FormattedValue) and index > 0 and _is_tainted(part.value, tainted) for index, part in enumerate(parts))
    if isinstance(node, ast.Call):
        name = _call_name(node.func)
        if name in {"os.path.join", "posixpath.join", "ntpath.join"} or name.endswith(".joinpath"):
            return any(_is_tainted(argument, tainted) for argument in node.args[1:])
    return False


def _is_tainted(node: ast.expr, tainted: set[str]) -> bool:
    if _is_literal(node):
        return False
    if _REQUEST_SOURCES.search(ast.unparse(node)):
        return True
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in tainted:
            return True
    return False


def _keyword(node: ast.Call, name: str) -> ast.expr | None:
    for item in node.keywords:
        if item.arg == name:
            return item.value
    return None


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


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
    """Collapse regex and AST reports of the same defect.

    Both engines legitimately match the same construct, and several rules overlap
    by design (a shell=True call is also a command-injection sink), so keying on
    evidence let one defect surface two or three times. One vulnerability class
    per line is the identity that matters. AST findings are appended first so the
    precise span wins over the regex approximation.
    """
    unique: dict[tuple[FindingType, int | None], DeepSecFinding] = {}
    for item in findings:
        unique.setdefault((item.type, item.line), item)
    return list(unique.values())
