"""CLI shared helper functions."""

from __future__ import annotations

import re
from typing import Any, Optional

from rich.console import Console
from rich.text import Text

from deepsec import __version__
from deepsec.config.text_utils import format_think_tags, strip_think_tags

console = Console()
err_console = Console(stderr=True)

TERMINAL_TOOL_RESULT_PREVIEW_CHARS = 1200


def _collapse_terminal_text(text: str, limit: int = TERMINAL_TOOL_RESULT_PREVIEW_CHARS) -> tuple[str, bool]:
    """Return a human-sized terminal preview without changing model-visible content."""

    value = str(text or "")
    if limit <= 0 or len(value) <= limit:
        return value, False
    marker = f"\n...[terminal preview collapsed {len(value) - limit} chars]...\n"
    head = max(1, int(limit * 0.7))
    tail = max(1, limit - head)
    return f"{value[:head].rstrip()}{marker}{value[-tail:].lstrip()}", True


def _extract_evidence_id(text: str) -> str:
    match = re.search(r"\[evidence:(e\d+)\]", str(text or ""))
    return match.group(1) if match else ""


def _print_styled_plain(console_obj: Console, prefix: str, body: str, *, style: str = "dim") -> None:
    """Print dynamic text as Rich Text so payloads are never parsed as markup."""

    rendered = Text(prefix, style=style)
    rendered.append(str(body or ""))
    console_obj.print(rendered, soft_wrap=True)


class TerminalStreamSink:
    """CLI terminal stream renderer."""

    def __init__(self, console: Console, show_thinking: bool = False) -> None:
        self._console = console
        self._show_thinking = show_thinking
        self._status_printed = False

    def on_status(self, message: str) -> None:
        self._console.print(Text(f"{message} ", style="dim"), end="", soft_wrap=True)
        self._status_printed = True

    def on_thinking_token(self, token: str) -> None:
        if self._show_thinking:
            self._console.print(Text(str(token or ""), style="dim italic"), end="", soft_wrap=True)

    def on_content_token(self, token: str) -> None:
        if self._status_printed:
            self._console.print()
            self._status_printed = False
        self._console.print(Text(str(token or "")), end="", soft_wrap=True)

    def on_tool_call(self, tool_name: str, args: str) -> None:
        self._console.print()
        call_text = Text(f"→ 调用工具: {tool_name} ", style="bold cyan")
        call_text.append(str(args or "")[:100])
        self._console.print(call_text, soft_wrap=True)
        self._status_printed = False

    def on_tool_result(self, result_summary: str) -> None:
        self._console.print()
        preview, collapsed = _collapse_terminal_text(result_summary)
        if collapsed:
            evidence_id = _extract_evidence_id(result_summary)
            hint = (
                f"\n[terminal-only preview: {len(preview)}/{len(str(result_summary or ''))} chars shown; "
                "full output is stored as evidence"
            )
            if evidence_id:
                hint += f"; saved as {evidence_id}, use evidence_search/evidence_view to revisit"
            hint += "]"
            preview = f"{preview}{hint}"
        _print_styled_plain(self._console, "→ 工具结果: ", preview)

    def on_stream_end(self) -> None:
        self._status_printed = False
        self._console.print()


ASCII_LOGO = (
    " _    __      __      ________\n"
    "| |  / /_  __/ /___  / ____/ /___ __      __\n"
    "| | / / / / / / __ \\/ /   / / __ `/ | /| / /\n"
    "| |/ / /_/ / / / / / /___/ / /_/ /| |/ |/ /\n"
    "|___/\\__,_/_/_/ /_/\\____/_/\\__,_/ |__/|__/\n"
)

BANNER_SUBTITLE = f"VulnClaw v{__version__} - AI-powered penetration testing CLI"


def _print_banner() -> None:
    """Print the VulnClaw ASCII banner."""

    console.print(Text(ASCII_LOGO, style="bold red"))
    console.print(Text(BANNER_SUBTITLE))
    console.print()


def _print_agent_output(output: str, config: Any) -> None:
    """Print agent output with think-tag filtering based on config."""

    from rich.markup import escape as rich_escape

    formatted = format_think_tags(output, show=config.session.show_thinking)
    if formatted:
        console.print(rich_escape(formatted))
    elif not config.session.show_thinking:
        stripped = strip_think_tags(output)
        if (stripped != output) and not stripped:
            console.print("[dim](LLM returned only hidden reasoning and no visible answer.)[/dim]")


def _make_solve_event_printer(target_console: Console) -> Any:
    """Return an on_event callback that prints model-led solve progress."""

    def on_event(kind: str, payload: dict) -> None:
        if kind == "agent_step":
            target_console.print(f"[cyan]◆ Turn {payload.get('step', '?')}[/cyan]")
        elif kind == "agent_observation":
            reason = payload.get("reason") or "模型继续自主判断"
            tools = ", ".join(payload.get("tools") or []) or "无"
            evidence = (payload.get("evidence") or "").strip()
            _print_styled_plain(target_console, "理由: ", str(reason)[:120], style="yellow")
            _print_styled_plain(target_console, "工具: ", tools, style="magenta")
            if evidence:
                _print_styled_plain(target_console, "发现: ", evidence[:220], style="green")
        elif kind == "completed":
            target_console.print("[green]✓ Goal: 目标达成[/green]")
        elif kind == "complete_rejected":
            _print_styled_plain(target_console, "⚠ 拒绝完成: ", str(payload.get("reason", ""))[:90], style="red")
        elif kind == "ask_user":
            _print_styled_plain(target_console, "? 需要用户: ", str(payload.get("question", ""))[:160], style="yellow")
        elif kind == "no_path":
            _print_styled_plain(target_console, "⊘ 无可行路径: ", str(payload.get("reason", ""))[:160], style="yellow")
        elif kind == "error":
            _print_styled_plain(target_console, "error: ", str(payload.get("error", ""))[:160], style="red")

    return on_event


def _generate_report_for_target(
    target: str,
    *,
    current_session: Any = None,
    report_format: str = "markdown",
    output_path: Optional[str] = None,
) -> str:
    """Generate a report for a target using the best available source data."""

    from deepsec.spear.agent.context import SessionState
    from deepsec.spear.report.generator import generate_report, generate_report_from_target_state
    from deepsec.target_state.store import load_target_state

    if current_session is not None and (
        current_session.findings or current_session.executed_steps or current_session.notes
    ):
        path = generate_report(current_session, output_path, report_format=report_format)
        return str(path)

    state = load_target_state(target)
    if state:
        path = generate_report_from_target_state(state, output_path=output_path)
        return str(path)

    session = SessionState(target=target)
    path = generate_report(session, output_path, report_format=report_format)
    return str(path)


def _append_cli_constraints(
    prompt: str,
    only_port: Optional[int],
    only_host: Optional[str],
    only_path: Optional[str],
    blocked_host: Optional[str] = None,
    blocked_path: Optional[str] = None,
) -> str:
    """Append scope constraints to the task prompt."""

    constraints = []
    if only_port is not None:
        constraints.append(f"Only test port {only_port}")
    if only_host:
        constraints.append(f"Only test host {only_host}")
    if only_path:
        constraints.append(f"Only test path {only_path}")
    if blocked_host:
        constraints.append(f"Blocked host {blocked_host}")
    if blocked_path:
        constraints.append(f"Blocked path {blocked_path}")
    if not constraints:
        return prompt
    return f"{prompt} {' '.join(constraints)}."


def _append_cli_constraints_compat(
    prompt: str,
    only_port: Optional[int],
    only_host: Optional[str],
    only_path: Optional[str],
    blocked_host: Optional[str],
    blocked_path: Optional[str],
) -> str:
    """Append scope constraints while preserving older monkeypatch call shapes."""

    try:
        return _append_cli_constraints(
            prompt, only_port, only_host, only_path, blocked_host, blocked_path
        )
    except TypeError as exc:
        if "positional" not in str(exc) and "argument" not in str(exc):
            raise
        return _append_cli_constraints(prompt, only_port, only_host, only_path)


def _append_action_constraints(
    prompt: str, allow_actions: Optional[str], block_actions: Optional[str]
) -> str:
    """Append action constraints to the task prompt."""

    constraints = []
    if allow_actions:
        constraints.append(f"Only allowed actions: {allow_actions}")
    if block_actions:
        constraints.append(f"Blocked actions: {block_actions}")
    if not constraints:
        return prompt
    return f"{prompt} {' '.join(constraints)}."


async def _run_cli_orchestrated_task(
    *,
    command: str,
    target: str,
    resume: bool,
    snapshot: Optional[str],
    runner: Any,
) -> Any:
    """Run a CLI task through the shared orchestrator helpers."""

    from deepsec.spear.agent.core import AgentCore
    from deepsec.config.settings import load_config
    from deepsec.mcp.lifecycle import MCPLifecycleManager
    from deepsec.spear.orchestrator import run_agent_task

    config = load_config()
    mcp_manager = MCPLifecycleManager(config)
    mcp_manager.start_enabled_servers()
    agent = AgentCore(config, mcp_manager)

    try:
        def on_restored(restore_result: Any) -> None:
            console.print(
                f"[*] Restored saved target state: [bold]{restore_result.target or target}[/]"
            )

        return await run_agent_task(
            agent=agent,
            command=command,
            target=target,
            resume=resume,
            snapshot_id=snapshot,
            on_restored=on_restored,
            runner=lambda shared_agent: runner(shared_agent, config),
        )
    finally:
        import signal

        signal.signal(signal.SIGINT, signal.SIG_IGN)
        mcp_manager.stop_all()
