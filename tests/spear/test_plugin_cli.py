from __future__ import annotations

import json

from typer.testing import CliRunner

from deepsec.spear.legacy_cli.main import app

runner = CliRunner()


def test_plugins_list_shows_builtin_plugins():
    result = runner.invoke(app, ["plugins", "list"])
    assert result.exit_code == 0
    assert "builtin.web.headers" in result.stdout


def test_plugins_list_unknown_stage_errors():
    result = runner.invoke(app, ["plugins", "list", "--stage", "nope"])
    assert result.exit_code == 1


def test_plugins_info_known_and_unknown():
    ok = runner.invoke(app, ["plugins", "info", "builtin.web.headers"])
    assert ok.exit_code == 0
    assert "builtin.web.headers" in ok.stdout

    missing = runner.invoke(app, ["plugins", "info", "does.not.exist"])
    assert missing.exit_code == 1


def test_plugins_run_with_inline_option_and_session_merge(tmp_path):
    session_file = tmp_path / "session.json"
    result = runner.invoke(
        app,
        [
            "plugins",
            "run",
            "builtin.web.headers",
            "--target",
            "http://t.com",
            "--option",
            'headers={"server": "nginx"}',
            "--session",
            str(session_file),
        ],
    )
    assert result.exit_code == 0
    assert "Missing common security headers" in result.stdout

    data = json.loads(session_file.read_text(encoding="utf-8"))
    titles = [f["title"] for f in data["findings"]]
    assert "Missing common security headers" in titles


def test_plugins_run_unknown_stage_errors():
    result = runner.invoke(
        app, ["plugins", "run", "builtin.web.headers", "--stage", "bogus"]
    )
    assert result.exit_code == 1
