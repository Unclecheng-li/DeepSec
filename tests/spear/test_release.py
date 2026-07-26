from __future__ import annotations

from pathlib import Path


def test_package_version_matches_pyproject() -> None:
    import deepsec

    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    version_line = next(
        line
        for line in pyproject.read_text(encoding="utf-8").splitlines()
        if line.startswith("version = ")
    )
    pyproject_version = version_line.split('"')[1]
    assert deepsec.__version__ == pyproject_version
