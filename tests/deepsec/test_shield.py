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
