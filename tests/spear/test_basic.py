"""DeepSec basic integration tests: verify imports and version."""

import pytest


def test_import_deepsec():
    """Test that the main package can be imported."""
    from pathlib import Path

    import toml

    import deepsec

    # Read version from pyproject.toml to avoid hardcoding
    pyproject_path = Path(__file__).resolve().parents[2] / "pyproject.toml"
    pyproject = toml.load(pyproject_path)
    expected_version = pyproject["project"]["version"]

    assert deepsec.__version__ == expected_version


def test_no_import_errors():
    """Verify no module raises on import."""
    import importlib

    modules = [
        "deepsec",
        "deepsec.config.schema",
        "deepsec.config.settings",
        "deepsec.spear.agent.context",
        "deepsec.spear.agent.memory",
        "deepsec.spear.agent.prompts",
        "deepsec.spear.agent.core",
        "deepsec.mcp.registry",
        "deepsec.mcp.router",
        "deepsec.mcp.lifecycle",
        "deepsec.spear.skills.loader",
        "deepsec.spear.skills.dispatcher",
        "deepsec.kb.store",
        "deepsec.kb.retriever",
        "deepsec.kb.updater",
        "deepsec.spear.report.generator",
        "deepsec.spear.report.poc_builder",
        "deepsec.spear.legacy_cli.main",
    ]
    for mod_name in modules:
        try:
            importlib.import_module(mod_name)
        except ImportError as e:
            pytest.fail(f"Failed to import {mod_name}: {e}")
