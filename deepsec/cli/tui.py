"""Portable launcher for the separately built DeepSec Rust TUI."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    binary = _find_binary()
    if binary is None:
        print(
            "DeepSec TUI binary was not found. Install a DeepSec release, build `tui/`, or set DEEPSEC_TUI_BINARY.",
            file=sys.stderr,
        )
        return 1
    return subprocess.call([str(binary), *sys.argv[1:]])


def _find_binary() -> Path | str | None:
    override = os.environ.get("DEEPSEC_TUI_BINARY")
    if override:
        return override
    if binary := shutil.which("deepsec-tui-native"):
        return binary
    extension = ".exe" if os.name == "nt" else ""
    repository_binary = Path(__file__).resolve().parents[2] / "tui" / "target" / "release" / f"deepsec-tui-native{extension}"
    return repository_binary if repository_binary.exists() else None
