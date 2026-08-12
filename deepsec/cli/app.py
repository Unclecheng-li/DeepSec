"""Typer entry point for the DeepSec Shield and Spear workflows."""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from deepsec.core.authorization import AuthorizationError, ScopeManifest, authorize_target, sign_manifest, write_audit_log
from deepsec.core.config import config_path, ensure_config_file, load_config, update_config_value
from deepsec.core.finding import DeepSecFinding
from deepsec.core.report import write_report
from deepsec.core.roles import list_roles, load_tools, tools_for_role
from deepsec.core.snapshot import SideGitSnapshot
from deepsec.report.attack_chain import write_attack_chain, write_attack_chain_data
from deepsec.shield.ignore import load_ignore_rules
from deepsec.shield.scanner import ScanOptions, scan_path
from deepsec.shield.supply_chain import scan_dependency_confusion, scan_typosquatting
from deepsec.spear import headless

app = typer.Typer(name="deepsec", help="DeepSec unified security CLI", no_args_is_help=True, add_completion=False)
shield_app = typer.Typer(help="Shield code-security auditing commands", no_args_is_help=True)
spear_app = typer.Typer(help="Spear authorized penetration-testing commands", no_args_is_help=True)
supply_chain_app = typer.Typer(help="Supply-chain security commands", no_args_is_help=True)
snapshot_app = typer.Typer(help="Side-Git snapshot commands", no_args_is_help=True)
config_app = typer.Typer(help="DeepSec configuration commands", no_args_is_help=True)
scope_app = typer.Typer(help="Spear target allow-list / authorization scopes (signing optional)", no_args_is_help=True)

app.add_typer(shield_app, name="shield")
app.add_typer(spear_app, name="spear")
app.add_typer(snapshot_app, name="snapshot")
app.add_typer(config_app, name="config")
app.add_typer(scope_app, name="scope")
console = Console()


@spear_app.callback()
def spear_root(
    role: Annotated[str | None, typer.Option(help="Default DeepSec role for the Spear session")] = None,
) -> None:
    if role:
        update_config_value("role.default", role)


@shield_app.command("scan")
def shield_scan(
    path: Annotated[Path, typer.Argument(help="Source file or directory")],
    layer: Annotated[str, typer.Option(help="all, l1, l2, or l3")] = "all",
    format_name: Annotated[str, typer.Option("--format", help="text, json, sarif, markdown, or html")] = "text",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    remote_l3: Annotated[bool, typer.Option(help="Send source to the configured LLM for opt-in L3 review")] = False,
    ignore_file: Annotated[Path | None, typer.Option("--ignore-file", help="YAML ignore rule file")] = None,
    include_tests: Annotated[bool, typer.Option("--include-tests", help="Also scan test, fixture, and example directories")] = False,
    stream: Annotated[bool, typer.Option("--stream", help="Emit newline-delimited JSON events for the DeepSec TUI")]=False,
) -> None:
    selected = _layers(layer)
    config = load_config()
    use_remote_l3 = remote_l3 or _explicit_l3_with_configured_provider(layer, selected, config)
    options = ScanOptions(
        l1="L1" in selected,
        l2="L2" in selected,
        l3="L3" in selected,
        remote_l3=use_remote_l3,
        dedup=config.shield.dedup,
        include_tests=include_tests,
        ignore_rules=load_ignore_rules(ignore_file),
    )
    if stream:
        typer.echo(json.dumps({"type": "status", "status": "started"}, separators=(",", ":")))

        def emit_finding(finding: DeepSecFinding) -> None:
            typer.echo(json.dumps({"type": "finding", "finding": finding.to_dict()}, separators=(",", ":")))

        result = scan_path(path, options, config, on_finding=emit_finding)
        typer.echo(json.dumps({"type": "complete", "result": result.to_dict()}, separators=(",", ":")))
    else:
        result = scan_path(path, options, config)
        _emit_result(result, format_name, output)
    if any(item.severity.value in {"critical", "high"} and not item.dismissed for item in result.findings):
        raise typer.Exit(2)


@shield_app.command("agent-audit")
def agent_audit(
    path: Annotated[Path, typer.Argument(help="Agent source or configuration path")],
    format_name: Annotated[str, typer.Option("--format")] = "text",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    result = scan_path(path, ScanOptions(l1=False, l2=False, l3=False, agent_audit=True))
    _emit_result(result, format_name, output)
    if any(item.severity.value in {"critical", "high"} for item in result.findings):
        raise typer.Exit(2)


@shield_app.command("watch")
def shield_watch(
    path: Annotated[Path, typer.Argument()] = Path("."),
    interval: Annotated[float, typer.Option(min=0.2)] = 1.0,
    once: Annotated[bool, typer.Option(help="Scan once rather than watch continuously")] = False,
) -> None:
    """Poll source modification times and rescan after changes."""
    previous: dict[Path, int] = {}
    while True:
        current = {item: item.stat().st_mtime_ns for item in path.rglob("*") if item.is_file()} if path.is_dir() else {path: path.stat().st_mtime_ns}
        if once or current != previous:
            result = scan_path(path)
            _print_table(result)
            previous = current
        if once:
            return
        time.sleep(interval)


shield_app.add_typer(supply_chain_app, name="supply-chain")


@supply_chain_app.command("check")
def supply_chain_check(
    path: Annotated[Path, typer.Argument(help="Directory, package.json, or requirements.txt")] = Path("."),
    private_package: Annotated[list[str] | None, typer.Option("--private-package", help="Private dependency names to protect from public resolution")] = None,
    format_name: Annotated[str, typer.Option("--format")] = "text",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    manifests = [path] if path.is_file() else [item for item in path.rglob("*") if item.name in {"package.json", "requirements.txt"} and "node_modules" not in item.parts]
    findings = []
    for manifest in manifests:
        findings.extend(scan_typosquatting(manifest))
        findings.extend(scan_dependency_confusion(manifest, set(private_package or [])))
    from deepsec.shield.scanner import ScanResult
    result = ScanResult(findings=findings, elapsed_ms=0, files_scanned=len(manifests), layers=("SupplyChain",))
    _emit_result(result, format_name, output)
    if any(item.severity.value in {"critical", "high"} for item in findings):
        raise typer.Exit(2)


@spear_app.command("run")
def spear_run(
    target: Annotated[str, typer.Argument(help="Authorized target host, IP, URL, or repository")],
    authorized: Annotated[Path, typer.Option("--authorized", exists=True, dir_okay=False, readable=True, help="Signed JSON scope manifest required for every Spear run")],
    scope: Annotated[str, typer.Option(help="full, web, api, or mobile")] = "full",
    mode: Annotated[str, typer.Option(help="quick, standard, or deep")] = "standard",
    output: Annotated[str | None, typer.Option()] = None,
    role: Annotated[str | None, typer.Option(help="DeepSec role name for this run")] = None,
) -> None:
    """Run the migrated Spear engine only after signed-scope verification."""
    authorization = _authorize_spear_target(target, authorized, "spear run")
    if mode not in {"quick", "standard", "deep"}:
        raise typer.BadParameter("mode must be quick, standard, or deep")
    if role:
        update_config_value("role.default", role)
    from deepsec.spear.legacy_cli.main import run

    # We invoke the legacy ``run`` command as a plain Python function rather
    # than through typer's CLI parser. Because of that, its ``typer.Option(...)``
    # defaults are NOT resolved — every option we don't pass arrives as a
    # ``typer.models.OptionInfo`` object instead of its real default value.
    # That previously made ``fail_on`` (OptionInfo) fail ``_validate_headless_choices``
    # with "--fail-on must be one of: verified, any, never". Pass real defaults
    # explicitly to keep the call valid and avoid the same trap for the other
    # options (e.g. ``scope_mode`` and the truthy ``non_interactive``/``only_*``
    # flags, which would otherwise be treated as enabled).
    run(
        target=target,
        scope=scope,
        output=output,
        prompt=None,
        engine=None,
        only_port=None,
        only_host=authorization.host,
        only_path=None,
        blocked_host=None,
        blocked_path=None,
        allow_actions=None,
        block_actions=None,
        resume=True,
        snapshot=None,
        non_interactive=False,
        scan_mode=mode,
        fail_on=headless.DEFAULT_FAIL_ON,
        scope_mode=headless.DEFAULT_SCOPE_MODE,
        max_steps=None,
        max_directions=None,
        max_tool_rounds=None,
        max_parallel=None,
        max_rounds=None,
        run_name=None,
        resume_run=None,
        runs_dir=None,
        additional_targets=None,
        target_type=None,
        mount=False,
        repair=False,
        force_fresh=False,
        no_import=False,
    )


@spear_app.command("recon")
def spear_recon(
    target: Annotated[str, typer.Argument(help="Authorized target domain, IP, or URL")],
    authorized: Annotated[Path, typer.Option("--authorized", exists=True, dir_okay=False, readable=True, help="Signed JSON scope manifest required for every Spear command")],
) -> None:
    authorization = _authorize_spear_target(target, authorized, "spear recon")
    from deepsec.spear.legacy_cli.main import recon

    # Direct-invocation caveat (see spear_run): pass real defaults so the
    # unpassed ``typer.Option`` params don't arrive as ``OptionInfo`` objects
    # that would otherwise be treated as truthy constraint filters.
    recon(
        target=target,
        prompt=None,
        only_port=None,
        only_host=authorization.host,
        only_path=None,
        blocked_host=None,
        blocked_path=None,
        allow_actions=None,
        block_actions=None,
        resume=True,
        snapshot=None,
        run_name=None,
        resume_run=None,
        runs_dir=None,
        additional_targets=None,
        target_type=None,
        mount=False,
        repair=False,
        force_fresh=False,
        no_import=False,
    )


@spear_app.command("roles")
def spear_roles() -> None:
    table = Table("Role", "Mode", "Description", "Tools")
    for role in list_roles():
        table.add_row(role.name, role.mode, role.description, ", ".join(role.tools))
    console.print(table)


@spear_app.command("tools")
def spear_tools(
    role: Annotated[str | None, typer.Option(help="Role whose permitted tool catalog should be displayed")] = None,
) -> None:
    active_role = role or load_config().role.default
    try:
        available_tools = tools_for_role(active_role)
    except ValueError as error:
        raise typer.BadParameter(str(error), param_hint="--role") from error
    table = Table("Tool", "Category", "Install check", "Skills")
    for tool in available_tools:
        table.add_row(tool.name, tool.category, tool.install.check, ", ".join(tool.skills))
    console.print(table)


@app.command("report")
def report(
    source: Annotated[Path, typer.Argument(help="A DeepSec JSON result file")],
    format_name: Annotated[str, typer.Option("--format")] = "markdown",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    chain: Annotated[bool, typer.Option(help="Generate an attack-chain HTML page")]=False,
) -> None:
    raw = json.loads(source.read_text(encoding="utf-8"))
    findings = [DeepSecFinding.from_dict(item) for item in raw.get("findings", [])]
    output = output or source.with_suffix({"markdown": ".md", "md": ".md", "json": ".json", "sarif": ".sarif", "html": ".html"}.get(format_name, ".txt"))
    write_report(findings, output, format_name)
    console.print(f"Wrote {format_name} report to {output}")
    if chain:
        chain_output = output.with_name(f"{output.stem}-attack-chain.html")
        write_attack_chain(findings, chain_output)
        console.print(f"Wrote attack chain to {chain_output}")
        data_output = output.with_name(f"{output.stem}-attack-chain.json")
        write_attack_chain_data(findings, data_output)
        console.print(f"Wrote attack-chain data to {data_output}")


@app.command("tui")
def tui() -> None:
    from deepsec.cli.tui import main
    raise typer.Exit(main())


@app.command("chat")
def chat() -> None:
    """Start the migrated interactive Spear workbench after explicit target authorization in each run."""
    from deepsec.spear.legacy_cli.main import main
    main()


@app.command("tools")
def tools() -> None:
    table = Table("Tool", "Category", "Install check", "Skills")
    for tool in load_tools():
        table.add_row(tool.name, tool.category, tool.install.check, ", ".join(tool.skills))
    console.print(table)


@snapshot_app.command("create")
def snapshot_create(
    path: Annotated[Path, typer.Argument()] = Path("."),
    mode: Annotated[str, typer.Option()] = "shield",
    description: Annotated[str, typer.Option()] = "",
) -> None:
    snapshot = SideGitSnapshot(path).create(mode, description)
    console.print("No changes to snapshot." if snapshot is None else f"Created snapshot {snapshot.id}")


@snapshot_app.command("list")
def snapshot_list(path: Annotated[Path, typer.Argument()] = Path(".")) -> None:
    table = Table("ID", "Timestamp", "Mode", "Description")
    for item in SideGitSnapshot(path).list():
        table.add_row(item.id, item.timestamp, item.mode, item.description)
    console.print(table)


@app.command("restore")
def restore(snapshot_id: Annotated[str, typer.Argument()], path: Annotated[Path, typer.Option()] = Path(".")) -> None:
    if not SideGitSnapshot(path).restore(snapshot_id):
        raise typer.Exit(1)
    console.print(f"Restored snapshot {snapshot_id}")


@config_app.command("init")
def config_init() -> None:
    console.print(ensure_config_file())


@config_app.command("set")
def config_set(key: Annotated[str, typer.Argument()], value: Annotated[str, typer.Argument()]) -> None:
    console.print(update_config_value(key, value))


@config_app.command("show")
def config_show() -> None:
    path = config_path()
    if not path.exists():
        console.print(f"No DeepSec config at {path}. Run `deepsec config init`.")
        return
    console.print(path.read_text(encoding="utf-8"))


@scope_app.command("sign")
def scope_sign(
    scope_file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True, writable=True, help="Unsigned or previously signed JSON scope manifest")],
) -> None:
    """Sign a scope manifest with DEEPSEC_SCOPE_SIGNING_KEY."""
    try:
        raw = json.loads(scope_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise typer.BadParameter(f"scope file must be a JSON object: {error}") from error
    if not isinstance(raw, dict):
        raise typer.BadParameter("scope file must be a JSON object")
    try:
        raw["signature"] = sign_manifest(raw, os.environ.get("DEEPSEC_SCOPE_SIGNING_KEY", ""))
    except AuthorizationError as error:
        raise typer.BadParameter(str(error)) from error
    scope_file.write_text(json.dumps(raw, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    console.print(f"Signed scope manifest: {scope_file}")


@scope_app.command("verify")
def scope_verify(
    scope_file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True, help="JSON scope manifest to validate")],
) -> None:
    """Validate a scope manifest: structure, time window, and optional signature.

    Signing is optional. An unsigned manifest is accepted as a local allow-list;
    the target list remains the authoritative gate for Spear.
    """
    import hmac as _hmac

    try:
        raw = json.loads(scope_file.read_text(encoding="utf-8"))
        manifest = ScopeManifest.model_validate(raw)
    except (OSError, json.JSONDecodeError, ValidationError) as error:
        raise typer.BadParameter(f"invalid scope manifest: {error}") from error

    lines = [f"Scope manifest: {scope_file}", f"  targets: {len(manifest.targets)} entry(ies)"]
    if manifest.valid_from is not None and manifest.valid_until is not None:
        now = datetime.now(timezone.utc)
        status = "valid" if manifest.valid_from <= now <= manifest.valid_until else "EXPIRED"
        lines.append(f"  time window: {manifest.valid_from.isoformat()} -> {manifest.valid_until.isoformat()} ({status})")
    else:
        lines.append("  time window: none (always valid)")
    if manifest.signature:
        key = os.environ.get("DEEPSEC_SCOPE_SIGNING_KEY", "")
        if key:
            expected = sign_manifest(raw, key)
            lines.append(f"  signature: {'verified' if _hmac.compare_digest(manifest.signature, expected) else 'MISMATCH'}")
        else:
            lines.append("  signature: present (set DEEPSEC_SCOPE_SIGNING_KEY to verify)")
    else:
        lines.append("  signature: none (unsigned allow-list — target list is authoritative)")
    console.print("\n".join(lines))


def _layers(value: str) -> set[str]:
    normalized = value.lower()
    if normalized == "all":
        return {"L1", "L2", "L3"}
    result = {part.strip().upper() for part in value.split(",")}
    if not result <= {"L1", "L2", "L3"}:
        raise typer.BadParameter("layer must be all, l1, l2, l3, or a comma-separated combination")
    return result


def _explicit_l3_with_configured_provider(layer: str, selected: set[str], config: object) -> bool:
    """`--layer l3` is an explicit opt-in; `all` keeps source local by default."""
    if layer.strip().lower() == "all" or "L3" not in selected:
        return False
    llm = config.llm
    if llm.provider.lower() == "local":
        return True
    if llm.api_key or os.environ.get("DEEPSEC_LLM_API_KEY"):
        return True
    return any(
        provider.api_key or os.environ.get(f"DEEPSEC_{name.upper()}_API_KEY")
        for name, provider in llm.providers.items()
    )


def _emit_result(result: object, format_name: str, output: Path | None) -> None:
    if format_name == "text":
        _print_table(result)
        return
    suffixes = {"json": ".json", "sarif": ".sarif", "markdown": ".md", "html": ".html"}
    if format_name not in suffixes:
        raise typer.BadParameter("format must be text, json, sarif, markdown, or html")
    if output is not None and str(output) == "-":
        if format_name != "json":
            raise typer.BadParameter("stdout output is only supported for JSON")
        typer.echo(json.dumps(result.to_dict(), separators=(",", ":")))
        return
    target = output or Path.cwd() / f"deepsec-report{suffixes[format_name]}"
    write_report(result.findings, target, format_name)
    console.print(f"Wrote {format_name} report to {target}")


def _print_table(result: object) -> None:
    table = Table("Severity", "Location", "Rule", "Finding")
    for item in result.findings:
        location = item.target if item.line is None else f"{item.target}:{item.line}"
        table.add_row(item.severity.value, location, item.detection_rule, item.description)
    console.print(table)
    console.print(f"Scanned {result.files_scanned} file(s) in {result.elapsed_ms:.1f} ms; {len(result.findings)} finding(s).")


def _authorize_spear_target(target: str, scope_file: Path, command: str):
    try:
        authorization = authorize_target(target, scope_file)
    except AuthorizationError as error:
        raise typer.BadParameter(str(error), param_hint="--authorized") from error
    audit_path = write_audit_log(load_config().storage.runs_dir, authorization, command)
    if authorization.manifest.signer:
        console.print(f"Authorized by {authorization.manifest.signer}; audit log: {audit_path}", style="green")
    else:
        console.print(f"Authorized (unsigned allow-list); audit log: {audit_path}", style="green")
    return authorization
