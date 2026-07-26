"""Run-directory persistence foundation."""

from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from deepsec.config.settings import CONFIG_DIR, ensure_dirs
from deepsec.spear.targets import Target

RUN_SCHEMA_VERSION = 1
RUN_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,120}$")


class RunContextError(RuntimeError):
    """Base class for run-context errors."""


class RunCollisionError(RunContextError):
    """Raised when an explicit run name would clobber an existing run."""


class RunCorruptError(RunContextError):
    """Raised when a run directory cannot be safely resumed."""

    def __init__(self, run_dir: Path, check: str) -> None:
        self.run_dir = run_dir
        self.check = check
        super().__init__(f"corrupt run state at {run_dir}: {check}")


@dataclass
class RunContext:
    """Loaded run directory and manifest."""

    run_dir: Path
    manifest: dict[str, Any]
    runs_root: Path
    targets: list[Target] = field(default_factory=list)

    @property
    def run_name(self) -> str:
        return str(self.manifest.get("run_name") or self.run_dir.name)

    def target_manifest(self, target: Target | str | None = None) -> dict[str, Any]:
        items = self.manifest.get("targets", [])
        if not isinstance(items, list) or not items:
            raise RunCorruptError(self.run_dir, "run.json targets[] is empty")
        if target is None:
            first = items[0]
            if not isinstance(first, dict):
                raise RunCorruptError(self.run_dir, "run.json target entry is invalid")
            return first

        target_id = target.target_id if isinstance(target, Target) else str(target)
        for item in items:
            if not isinstance(item, dict):
                continue
            if target_id in {
                str(item.get("target_id") or ""),
                str(item.get("state_key") or ""),
                str(item.get("input") or ""),
                str(item.get("canonical") or ""),
            }:
                return item
        raise RunCorruptError(self.run_dir, f"target {target_id} is not listed in run.json")

    def state_dir(self, target: Target | str | None = None) -> Path:
        item = self.target_manifest(target)
        state_path = item.get("state_path")
        if not isinstance(state_path, str) or not state_path:
            target_id = str(item.get("target_id") or item.get("state_key") or "")
            if not target_id:
                raise RunCorruptError(self.run_dir, "target state_path is missing")
            return self.run_dir / "targets" / target_id / "state"
        path = Path(state_path)
        if path.is_absolute():
            return path.parent
        return (self.run_dir / path).parent

    def state_path(self, target: Target | str | None = None) -> Path:
        item = self.target_manifest(target)
        state_path = item.get("state_path")
        if isinstance(state_path, str) and state_path:
            path = Path(state_path)
            return path if path.is_absolute() else self.run_dir / path
        return self.state_dir(target) / "current.json"

    def snapshot_path(self, snapshot_id: str, target: Target | str | None = None) -> Path:
        return self.state_dir(target) / "snapshots" / f"{snapshot_id}.json"

    def target_json_path(self, target: Target | str | None = None) -> Path:
        item = self.target_manifest(target)
        target_id = str(item.get("target_id") or item.get("state_key") or "")
        if not target_id:
            raise RunCorruptError(self.run_dir, "target id is missing")
        return self.run_dir / "targets" / target_id / "target.json"

    def append_event(self, kind: str, payload: dict[str, Any] | None = None) -> None:
        event = {
            "timestamp": _now_iso(),
            "kind": kind,
            "payload": payload or {},
        }
        path = self.run_dir / "events" / "events.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")

    def update_manifest(self, **updates: Any) -> None:
        self.manifest.update(updates)
        self.manifest["updated_at"] = _now_iso()
        write_manifest(self)

    def record_checkpoint(self, snapshot_id: str, *, reason: str, target_id: str = "") -> None:
        resume = self.manifest.setdefault("resume", {})
        if not isinstance(resume, dict):
            resume = {}
            self.manifest["resume"] = resume
        resume["last_checkpoint_at"] = _now_iso()
        resume["last_snapshot_id"] = snapshot_id
        if target_id:
            resume["last_target_id"] = target_id
        resume["last_reason"] = reason
        self.manifest["status"] = "running"
        self.update_manifest()
        self.append_event(
            "checkpoint",
            {"snapshot_id": snapshot_id, "reason": reason, "target_id": target_id},
        )


def resolve_runs_root(runs_dir: str | Path | None = None, config: Any | None = None) -> Path:
    ensure_dirs()
    if runs_dir:
        return Path(runs_dir).expanduser()
    if env_value := os.environ.get("DEEPSEC_RUNS_DIR"):
        return Path(env_value).expanduser()
    config_runs_dir = getattr(getattr(config, "session", None), "runs_dir", None)
    if config_runs_dir:
        return Path(config_runs_dir).expanduser()
    return CONFIG_DIR / "runs"


def create_run_context(
    *,
    command: str,
    targets: list[Target],
    runs_dir: str | Path | None = None,
    config: Any | None = None,
    run_name: str | None = None,
    replace: bool = False,
) -> RunContext:
    runs_root = resolve_runs_root(runs_dir, config)
    runs_root.mkdir(parents=True, exist_ok=True)
    explicit_name = bool(run_name)
    if run_name:
        _validate_run_name(run_name)
    else:
        run_name = generate_run_name(command, targets)

    run_dir = runs_root / run_name
    if explicit_name and run_dir.exists() and not replace:
        raise RunCollisionError(
            f"run name '{run_name}' already exists at {run_dir}; use resume or replace explicitly"
        )
    while not explicit_name and run_dir.exists():
        run_name = generate_run_name(command, targets)
        run_dir = runs_root / run_name

    _create_run_layout(run_dir, targets)
    manifest = _build_manifest(command=command, run_name=run_name, run_dir=run_dir, targets=targets)
    context = RunContext(run_dir=run_dir, manifest=manifest, runs_root=runs_root, targets=targets)
    write_manifest(context)
    for target in targets:
        atomic_write_json(context.target_json_path(target), target.to_manifest())
    context.append_event("run_created", {"command": command, "run_name": run_name})
    return context


def load_run_context(
    run_name: str,
    *,
    runs_dir: str | Path | None = None,
    config: Any | None = None,
    repair: bool = False,
) -> RunContext:
    _validate_run_name(run_name)
    runs_root = resolve_runs_root(runs_dir, config)
    run_dir = runs_root / run_name
    if repair:
        return repair_run_context(run_name, runs_dir=runs_dir, config=config)
    manifest = _read_manifest(run_dir)
    context = RunContext(run_dir=run_dir, manifest=manifest, runs_root=runs_root)
    validate_run_context(context, resume_request=True)
    return context


def validate_run_context(context: RunContext, *, resume_request: bool = False) -> None:
    manifest = context.manifest
    if int(manifest.get("schema_version", -1)) != RUN_SCHEMA_VERSION:
        raise RunCorruptError(context.run_dir, "unsupported run.json schema_version")
    targets = manifest.get("targets")
    if not isinstance(targets, list) or not targets:
        raise RunCorruptError(context.run_dir, "run.json targets[] is missing")

    required = [
        context.run_dir / "events" / "events.jsonl",
        context.run_dir / "logs",
        context.run_dir / "agents",
        context.run_dir / "evidence",
        context.run_dir / "findings",
        context.run_dir / "reports",
        context.run_dir / "temp",
    ]
    for path in required:
        if not path.exists():
            raise RunCorruptError(context.run_dir, f"required artifact path is missing: {path}")

    for item in targets:
        if not isinstance(item, dict):
            raise RunCorruptError(context.run_dir, "target entry is invalid")
        state_path = item.get("state_path")
        if not isinstance(state_path, str) or not state_path:
            raise RunCorruptError(context.run_dir, "target state_path is missing")
        path = Path(state_path)
        resolved = path if path.is_absolute() else context.run_dir / path
        if not resolved.exists():
            raise RunCorruptError(context.run_dir, f"target state is missing: {state_path}")

    resume = manifest.get("resume", {})
    if isinstance(resume, dict):
        snapshot_id = str(resume.get("last_snapshot_id") or "")
        if snapshot_id and not _snapshot_exists(context, snapshot_id):
            raise RunCorruptError(
                context.run_dir, f"resume.last_snapshot_id dangles: {snapshot_id}"
            )

    lock_path = context.run_dir / "temp" / "writer.lock"
    if lock_path.exists() and not resume_request:
        raise RunCorruptError(context.run_dir, "writer lock exists without a resume request")


def repair_run_context(
    run_name: str,
    *,
    runs_dir: str | Path | None = None,
    config: Any | None = None,
) -> RunContext:
    _validate_run_name(run_name)
    runs_root = resolve_runs_root(runs_dir, config)
    run_dir = runs_root / run_name
    manifest = _read_manifest(run_dir)
    context = RunContext(run_dir=run_dir, manifest=manifest, runs_root=runs_root)
    targets = manifest.get("targets", [])
    if not isinstance(targets, list) or not targets:
        raise RunCorruptError(run_dir, "cannot repair run without targets[]")

    latest_snapshot = ""
    for item in targets:
        if not isinstance(item, dict):
            continue
        target_id = str(item.get("target_id") or item.get("state_key") or "")
        if not target_id:
            continue
        state_dir = run_dir / "targets" / target_id / "state"
        snapshots = sorted((state_dir / "snapshots").glob("*.json"))
        if not snapshots:
            continue
        snapshot = snapshots[-1]
        latest_snapshot = snapshot.stem
        atomic_write_text(state_dir / "current.json", snapshot.read_text(encoding="utf-8"))

    if not latest_snapshot:
        raise RunCorruptError(run_dir, "cannot repair run because no valid snapshots exist")
    resume = manifest.setdefault("resume", {})
    if isinstance(resume, dict):
        resume["last_snapshot_id"] = latest_snapshot
        resume["last_checkpoint_at"] = _now_iso()
    manifest["status"] = "interrupted"
    context.update_manifest()
    context.append_event("repair", {"last_snapshot_id": latest_snapshot})
    validate_run_context(context, resume_request=True)
    return context


def write_manifest(context: RunContext) -> None:
    atomic_write_json(context.run_dir / "run.json", context.manifest)


def mark_run_status(
    context: RunContext,
    status: str,
    *,
    exit_code: int | None = None,
    message: str = "",
) -> None:
    updates: dict[str, Any] = {"status": status}
    if status in {"completed", "interrupted", "failed"}:
        updates["ended_at"] = _now_iso()
    if exit_code is not None:
        updates["exit_code"] = exit_code
    if message:
        updates["message"] = message
    context.update_manifest(**updates)
    context.append_event("run_status", updates)


def build_completion_summary(
    *,
    context: RunContext | None,
    session: Any,
    command: str,
    restored: bool,
    snapshot_id: str = "",
    status: str = "completed",
    exit_code: int = 0,
) -> dict[str, Any]:
    findings = list(getattr(session, "findings", []) or [])
    verified = (
        session.get_verified_findings()
        if hasattr(session, "get_verified_findings")
        else [f for f in findings if getattr(f, "verified", False)]
    )
    pending = (
        session.get_pending_findings()
        if hasattr(session, "get_pending_findings")
        else [f for f in findings if getattr(f, "verification_status", "pending") == "pending"]
    )
    summary: dict[str, Any] = {
        "target": getattr(session, "target", "") or "",
        "command": command,
        "restored": restored,
        "snapshot_id": snapshot_id,
        "status": status,
        "exit_code": exit_code,
        "exit_meaning": _exit_meaning(exit_code),
        "run_name": "",
        "run_dir": "",
        "resume_command": "",
        "artifact_locations": {},
        "findings_count": len(findings),
        "verified_count": len(verified),
        "pending_count": len(pending),
        "candidate_count": len(
            session.get_candidate_findings() if hasattr(session, "get_candidate_findings") else []
        ),
        "quarantined_count": 0,
    }
    if context is not None:
        summary.update(
            {
                "run_name": context.run_name,
                "run_dir": str(context.run_dir),
                "resume_command": f"vulnclaw --resume {context.run_name}",
                "artifact_locations": {
                    "manifest": str(context.run_dir / "run.json"),
                    "events": str(context.run_dir / "events" / "events.jsonl"),
                    "findings": str(context.run_dir / "findings"),
                    "reports": str(context.run_dir / "reports"),
                    "evidence": str(context.run_dir / "evidence"),
                },
            }
        )
    return summary


def atomic_write_json(path: Path, data: Any) -> None:
    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2))


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)
    dir_flags = getattr(os, "O_DIRECTORY", None)
    if dir_flags is None:
        return
    try:
        dir_fd = os.open(str(path.parent), dir_flags)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def generate_run_name(command: str, targets: Iterable[Target]) -> str:
    first = next(iter(targets), None)
    target_slug = _slugify(first.label or first.raw if first else "target")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{timestamp}-{_slugify(command or 'run')}-{target_slug}-{uuid4().hex[:8]}"


def _build_manifest(
    *,
    command: str,
    run_name: str,
    run_dir: Path,
    targets: list[Target],
) -> dict[str, Any]:
    now = _now_iso()
    target_entries = []
    for target in targets:
        state_path = f"targets/{target.target_id}/state/current.json"
        entry = target.to_manifest(state_path=state_path)
        target_entries.append(entry)
    return {
        "schema_version": RUN_SCHEMA_VERSION,
        "run_id": str(uuid4()),
        "run_name": run_name,
        "created_at": now,
        "updated_at": now,
        "started_at": now,
        "ended_at": "",
        "status": "created",
        "command": command,
        "mode": command,
        "targets": target_entries,
        "artifacts": {
            "events": "events/events.jsonl",
            "logs": "logs/",
            "agents": "agents/",
            "evidence": "evidence/",
            "findings": "findings/",
            "reports": "reports/",
        },
        "resume": {
            "last_checkpoint_at": "",
            "last_snapshot_id": "",
            "last_target_id": "",
            "last_reason": "",
        },
    }


def _read_manifest(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "run.json"
    if not run_dir.exists():
        raise RunCorruptError(run_dir, "run directory does not exist")
    if not path.exists():
        raise RunCorruptError(run_dir, "run.json is missing")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RunCorruptError(run_dir, f"run.json is invalid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise RunCorruptError(run_dir, "run.json root must be an object")
    return raw


def _create_run_layout(run_dir: Path, targets: list[Target]) -> None:
    for relative in [
        "events",
        "logs",
        "agents",
        "evidence",
        "findings",
        "reports",
        "temp",
    ]:
        (run_dir / relative).mkdir(parents=True, exist_ok=True)
    (run_dir / "events" / "events.jsonl").touch(exist_ok=True)
    for target in targets:
        (run_dir / "targets" / target.target_id / "state" / "snapshots").mkdir(
            parents=True, exist_ok=True
        )


def _snapshot_exists(context: RunContext, snapshot_id: str) -> bool:
    targets = context.manifest.get("targets", [])
    if not isinstance(targets, list):
        return False
    for item in targets:
        if not isinstance(item, dict):
            continue
        target_id = str(item.get("target_id") or item.get("state_key") or "")
        if not target_id:
            continue
        if (context.run_dir / "targets" / target_id / "state" / "snapshots" / f"{snapshot_id}.json").exists():
            return True
    return False


def _validate_run_name(run_name: str) -> None:
    if not RUN_NAME_PATTERN.fullmatch(run_name):
        raise ValueError("run name must match [A-Za-z0-9_.-]{1,120}")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip().lower()).strip("-._")
    return slug[:40] or "target"


def _exit_meaning(exit_code: int) -> str:
    if exit_code == 0:
        return "completed"
    if exit_code == 130:
        return "interrupted"
    return "failed"
