"""Resolve where the traffic evidence store lives.

Inside the per-run Docker sandbox the store lives at ``<run>/evidence/traffic/``.
Until the run-directory PRD lands, resolution falls back to a config-scoped
evidence directory (overridable via ``DEEPSEC_EVIDENCE_DIR``), so headless/CI
runs still get a durable, addressable store.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from deepsec.traffic.store import TrafficStore

TRAFFIC_SUBDIR = "traffic"


def evidence_root() -> Path:
    override = os.environ.get("DEEPSEC_EVIDENCE_DIR")
    if override:
        return Path(override)
    from deepsec.config.settings import CONFIG_DIR

    return CONFIG_DIR / "evidence"


def traffic_dir(base: str | Path | None = None) -> Path:
    """Return the ``evidence/traffic`` directory for ``base`` (or the default)."""
    if base is not None:
        root = Path(base)
        # Accept either a run/evidence root or a direct traffic dir.
        if root.name == TRAFFIC_SUBDIR:
            return root
        if root.name == "evidence":
            return root / TRAFFIC_SUBDIR
        return root / "evidence" / TRAFFIC_SUBDIR
    return evidence_root() / TRAFFIC_SUBDIR


def resolve_traffic_store(run_dir: str | Path | None = None) -> "TrafficStore":
    """Resolve the store the agent *writes* captures to.

    Deterministic: a given ``run_dir`` always maps to its own
    ``evidence/traffic`` (config default when ``run_dir`` is None). It never
    falls back to another run's store — a fresh run's first capture must land in
    that run's directory, not get appended to stale global evidence.
    """
    from deepsec.traffic.store import TrafficStore

    return TrafficStore(traffic_dir(run_dir))


def resolve_report_traffic_store(run_dir: str | Path | None = None) -> "TrafficStore":
    """Resolve the store the report generator *reads* from.

    Prefers ``run_dir``'s store when it already holds captures; otherwise falls
    back to the config-scoped default, so a report generated outside the run
    directory still finds captures the agent wrote there (the common case until
    the run-directory PRD provides an explicit per-run path). Read-only: the
    fallback never affects where captures are written.
    """
    from deepsec.traffic.store import INDEX_FILENAME, TrafficStore

    candidates: list[Path] = []
    if run_dir is not None:
        candidates.append(traffic_dir(run_dir))
    candidates.append(traffic_dir(None))  # config-scoped default

    for path in candidates:
        if (path / INDEX_FILENAME).exists():
            return TrafficStore(path)
    # Nothing captured anywhere yet: honor the caller's run dir, else default.
    return TrafficStore(candidates[0])
