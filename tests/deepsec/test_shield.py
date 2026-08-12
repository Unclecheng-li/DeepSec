from pathlib import Path

from deepsec.shield.scanner import ScanOptions, scan_path, scan_text


def test_l1_redacts_provider_secret() -> None:
    result = scan_text('OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"', "demo.py", "python", ScanOptions(l2=False))

    finding = next(item for item in result.findings if item.detection_rule == "hardcoded_secret_openai_key")
    assert finding.severity.value == "critical"
    assert finding.evidence.startswith("sk-")
    assert "abcdefghijklmnopqrstuvwxyz" not in finding.evidence


def test_l2_detects_python_sql_f_string() -> None:
    result = scan_text('cursor.execute(f"SELECT * FROM users WHERE id = {request.args[\'id\']}")', "app.py", "python", ScanOptions(l1=False))

    assert {item.detection_rule for item in result.findings} >= {"sast_sql_python_f_string_execute"}


def test_l3_finds_missing_authentication() -> None:
    source = '''@app.get("/admin/users")
def users():
    return db.query("SELECT * FROM users")
'''
    result = scan_text(source, "app.py", "python", ScanOptions(l1=False, l2=False, l3=True))

    assert "l3_missing_authentication" in {item.detection_rule for item in result.findings}


def test_project_scan_skips_node_modules(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text('SECRET_KEY = "not-a-placeholder-secret-1234"', encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.js").write_text('const key = "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"', encoding="utf-8")

    result = scan_path(tmp_path, ScanOptions(l2=False))

    assert result.files_scanned == 1
    assert all("node_modules" not in item.target for item in result.findings)


def test_project_scan_calls_stream_callback_as_findings_are_discovered(tmp_path: Path) -> None:
    first = tmp_path / "first.py"
    second = tmp_path / "second.py"
    first.write_text("DEBUG = True\n", encoding="utf-8")
    second.write_text('SECRET_KEY = "not-a-placeholder-secret-1234"\n', encoding="utf-8")
    emitted = []

    result = scan_path(tmp_path, ScanOptions(l2=False), on_finding=emitted.append)

    assert emitted
    assert {finding.id for finding in emitted} >= {finding.id for finding in result.findings}


def test_l2_detects_injection_through_plain_parameter_names() -> None:
    """Taint must follow function parameters, not just framework-idiomatic names.

    Real code names its parameters uid, host, and name. Keying taint on a fixed
    vocabulary of request/params/body left every such helper undetected.
    """
    source = '''import subprocess

def get_user(conn, uid):
    conn.cursor().execute("SELECT * FROM users WHERE id = '" + uid + "'")

def ping(host):
    return subprocess.check_output("ping -c1 " + host, shell=True)

def read(name):
    return open("/var/data/" + name).read()
'''
    result = scan_text(source, "app.py", "python", ScanOptions(l1=False))
    rules = {item.detection_rule for item in result.findings}

    assert "sast_sql_concat_execute" in rules
    assert "sast_command_injection_shell_true" in rules
    assert "sast_path_traversal_fs_user_input" in rules
    assert all(item.severity.value == "high" for item in result.findings)


def test_l2_sql_rule_survives_quotes_inside_the_query() -> None:
    """Concatenated SQL almost always wraps the value in inner quotes."""
    source = 'query = "SELECT * FROM t WHERE id = \'" + supplied + "\'"\n'

    result = scan_text(source, "app.js", "javascript", ScanOptions(l1=False))

    assert "sast_sql_string_concat" in {item.detection_rule for item in result.findings}


def test_l2_accepts_argv_list_without_shell() -> None:
    """An argument list without shell=True is the recommended fix, not a finding."""
    source = '''import subprocess

def run(binary, args):
    return subprocess.run([binary, *args], capture_output=True)
'''
    result = scan_text(source, "app.py", "python", ScanOptions(l1=False))

    assert not [item for item in result.findings if item.type.value == "command_injection"]


def test_l2_downgrades_identifier_interpolation_to_medium() -> None:
    """A table name the code itself controls is an allowlist question, not an injection."""
    source = '''def counts(conn):
    for (table,) in conn.execute("SELECT name FROM sqlite_master").fetchall():
        conn.execute(f"SELECT count(*) FROM [{table}]")
'''
    result = scan_text(source, "app.py", "python", ScanOptions(l1=False))
    sql = [item for item in result.findings if item.type.value == "sql_injection"]

    assert sql
    assert all(item.severity.value == "medium" for item in sql)


def test_l2_reports_one_finding_per_defect() -> None:
    """Regex and AST both match a shell=True call; the user should see it once."""
    source = '''import subprocess

def ping(host):
    subprocess.run("ping " + host, shell=True)
'''
    result = scan_text(source, "app.py", "python", ScanOptions(l1=False))
    injections = [item for item in result.findings if item.type.value == "command_injection"]

    assert len(injections) == 1


def test_l1_exec_rule_does_not_fire_on_javascript_regex_exec() -> None:
    """RegExp.prototype.exec is not Python's exec()."""
    source = 'const parts = /(\\d+)/.exec(input); while (re.exec(line)) {}\n'

    result = scan_text(source, "app.js", "javascript", ScanOptions(l2=False))

    assert "insecure_config_python_exec" not in {item.detection_rule for item in result.findings}


def test_l2_path_traversal_needs_a_tainted_segment_not_just_a_path_parameter() -> None:
    """open(path) is a helper contract; open(base + name) is traversal.

    Treating every open() of a parameter as traversal turns the rule into noise:
    almost every file helper in every codebase takes the path from its caller.
    """
    source = '''import os

def load(path):
    return open(path, "r").read()

def save(folder, data):
    with open(os.path.join(folder, "out.txt"), "w") as handle:
        handle.write(data)

def fetch(base, name):
    return open(os.path.join(base, name)).read()
'''
    result = scan_text(source, "app.py", "python", ScanOptions(l1=False))
    traversal = [item for item in result.findings if item.detection_rule == "sast_path_traversal_fs_user_input"]

    assert [item.line for item in traversal] == [11]


def test_project_scan_skips_tests_and_generated_files_by_default(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text('SECRET_KEY = "not-a-placeholder-secret-1234"', encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "conftest.py").write_text('TOKEN = "not-a-placeholder-secret-5678"', encoding="utf-8")
    (tmp_path / "app.test.js").write_text('const key = "not-a-placeholder-secret-9012"', encoding="utf-8")
    (tmp_path / "app.min.js").write_text('const key = "not-a-placeholder-secret-3456"', encoding="utf-8")

    result = scan_path(tmp_path, ScanOptions(l2=False))

    assert result.files_scanned == 1
    assert all("tests" not in item.target and ".min." not in item.target for item in result.findings)


def test_project_scan_includes_tests_when_requested(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text('SECRET_KEY = "not-a-placeholder-secret-1234"', encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "conftest.py").write_text('TOKEN = "not-a-placeholder-secret-5678"', encoding="utf-8")

    result = scan_path(tmp_path, ScanOptions(l2=False, include_tests=True))

    assert result.files_scanned == 2


def test_project_scan_ignores_its_own_report(tmp_path: Path) -> None:
    """A report left in the tree must not be re-read as vulnerable source."""
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "deepsec-report.json").write_text('{"findings": [{"evidence": "eval(userInput)"}]}', encoding="utf-8")

    result = scan_path(tmp_path, ScanOptions())

    assert result.files_scanned == 1
    assert all("deepsec-report" not in item.target for item in result.findings)
