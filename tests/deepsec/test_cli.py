from typer.testing import CliRunner

import typer

from deepsec.cli.app import app
from deepsec.spear import headless


def test_shield_json_stdout(tmp_path) -> None:
    source = tmp_path / "app.py"
    source.write_text('DEBUG = True\n', encoding="utf-8")

    result = CliRunner().invoke(app, ["shield", "scan", str(source), "--layer", "l1", "--format", "json", "--output", "-"])

    assert result.exit_code == 2
    assert '"insecure_config_debug_true"' in result.stdout


def test_shield_stream_is_newline_delimited_json(tmp_path) -> None:
    source = tmp_path / "app.py"
    source.write_text("DEBUG = True\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["shield", "scan", str(source), "--layer", "l1", "--stream"])

    assert result.exit_code == 2
    events = [__import__("json").loads(line) for line in result.stdout.splitlines()]
    assert [event["type"] for event in events] == ["status", "finding", "complete"]


def test_shield_stream_emits_each_file_finding_before_complete(tmp_path) -> None:
    (tmp_path / "first.py").write_text("DEBUG = True\n", encoding="utf-8")
    (tmp_path / "second.py").write_text('OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"\n', encoding="utf-8")

    result = CliRunner().invoke(app, ["shield", "scan", str(tmp_path), "--layer", "l1", "--stream"])

    assert result.exit_code == 2
    events = [__import__("json").loads(line) for line in result.stdout.splitlines()]
    assert events[0]["type"] == "status"
    assert events[-1]["type"] == "complete"
    assert [event["type"] for event in events[1:-1]] == ["finding", "finding"]


def test_spear_run_passes_real_option_defaults(monkeypatch, tmp_path) -> None:
    """Regression for the "--fail-on must be one of" crash.

    ``cli/app.py`` invokes the legacy ``run`` command as a plain Python
    function, bypassing typer's CLI parser. Its ``typer.Option(...)`` defaults
    are therefore NOT resolved, so every option we don't pass arrives as a
    ``typer.models.OptionInfo`` object instead of its real default. That made
    ``fail_on`` (an OptionInfo) fail ``_validate_headless_choices``. We now pass
    real defaults explicitly; this test pins that contract.
    """
    captured: dict = {}

    def fake_run(**kwargs):
        captured.update(kwargs)
        raise typer.Exit(0)

    def fake_authorize(target, scope_file, command):
        class FakeAuth:
            host = None

        return FakeAuth()

    monkeypatch.setattr("deepsec.cli.app._authorize_spear_target", fake_authorize)
    monkeypatch.setattr("deepsec.spear.legacy_cli.main.run", fake_run)

    scope = tmp_path / "scope.json"
    scope.write_text("{}", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["spear", "run", "https://example.com", "--authorized", str(scope)]
    )

    assert result.exit_code == 0, result.output
    assert captured, "legacy run() was never invoked"
    assert captured["fail_on"] in headless.FAIL_ON_MODES
    assert captured["scope_mode"] in headless.SCOPE_MODES
    assert captured["non_interactive"] is False
    assert captured["only_host"] is None
    # No OptionInfo objects should leak through as defaults.
    assert not any(type(v).__name__ == "OptionInfo" for v in captured.values())


def test_spear_recon_passes_real_option_defaults(monkeypatch, tmp_path) -> None:
    """Same direct-invocation contract for ``recon``: the unpassed constraint
    options must be real ``None`` values, not ``OptionInfo`` objects that would
    otherwise be treated as truthy filters."""
    captured: dict = {}

    def fake_recon(**kwargs):
        captured.update(kwargs)
        raise typer.Exit(0)

    def fake_authorize(target, scope_file, command):
        class FakeAuth:
            host = None

        return FakeAuth()

    monkeypatch.setattr("deepsec.cli.app._authorize_spear_target", fake_authorize)
    monkeypatch.setattr("deepsec.spear.legacy_cli.main.recon", fake_recon)

    scope = tmp_path / "scope.json"
    scope.write_text("{}", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["spear", "recon", "https://example.com", "--authorized", str(scope)]
    )

    assert result.exit_code == 0, result.output
    assert captured, "legacy recon() was never invoked"
    for key in (
        "only_port",
        "only_path",
        "blocked_host",
        "blocked_path",
        "allow_actions",
        "block_actions",
    ):
        assert captured[key] is None, f"{key} was {captured[key]!r}, expected None"
    assert not any(type(v).__name__ == "OptionInfo" for v in captured.values())
