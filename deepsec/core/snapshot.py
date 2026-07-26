"""Side-Git snapshots kept outside a project's visible Git history."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(slots=True)
class Snapshot:
    id: str
    timestamp: str
    mode: str
    description: str
    git_ref: str


class SideGitSnapshot:
    def __init__(self, project_root: Path):
        self.root = project_root.resolve()
        self.snapshot_dir = self.root / ".deepsec" / "snapshots"

    def create(self, mode: str, description: str = "") -> Snapshot | None:
        if not (self.root / ".git").exists():
            raise ValueError(f"{self.root} is not a Git repository")
        result = self._git("stash", "create", "--include-untracked")
        git_ref = result.stdout.strip()
        if not git_ref:
            return None
        now = datetime.now(timezone.utc)
        snapshot = Snapshot(
            id=hashlib.sha1(f"{now.isoformat()}:{git_ref}".encode("utf-8")).hexdigest()[:8],
            timestamp=now.isoformat(),
            mode=mode,
            description=description or f"{mode} snapshot",
            git_ref=git_ref,
        )
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self._path(snapshot.id).write_text(json.dumps(asdict(snapshot), indent=2) + "\n", encoding="utf-8")
        return snapshot

    def restore(self, snapshot_id: str) -> bool:
        snapshot = self.load(snapshot_id)
        if snapshot is None:
            return False
        result = self._git("stash", "apply", "--index", snapshot.git_ref, check=False)
        return result.returncode == 0

    def list(self) -> list[Snapshot]:
        if not self.snapshot_dir.exists():
            return []
        snapshots = [self.load(path.stem) for path in self.snapshot_dir.glob("*.json")]
        return sorted((item for item in snapshots if item is not None), key=lambda item: item.timestamp, reverse=True)

    def load(self, snapshot_id: str) -> Snapshot | None:
        path = self._path(snapshot_id)
        if not path.exists():
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
        return Snapshot(**raw)

    def _path(self, snapshot_id: str) -> Path:
        if not snapshot_id or any(character not in "0123456789abcdef" for character in snapshot_id.lower()):
            raise ValueError("Snapshot id must be a hexadecimal identifier")
        return self.snapshot_dir / f"{snapshot_id}.json"

    def _git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=check,
        )
