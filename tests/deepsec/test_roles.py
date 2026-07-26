import logging

from deepsec.core.roles import ROLE_NAMES, load_tools, list_roles, tools_for_role


def test_roles_and_tool_catalog_cover_the_documented_access_model() -> None:
    assert {role.name.lower() for role in list_roles()} == ROLE_NAMES
    assert {tool.name for tool in load_tools()} >= {
        "nmap",
        "nuclei",
        "sqlmap",
        "dirsearch",
        "subfinder",
        "httpx",
        "ffuf",
        "feroxbuster",
    }
    assert {tool.name for tool in tools_for_role("ctf_player")} >= {"nmap", "httpx", "ffuf"}
    assert tools_for_role("blueteam") == []


def test_invalid_hot_loaded_tool_is_warned_and_skipped(tmp_path, caplog) -> None:
    (tmp_path / "valid.yaml").write_text(
        """name: valid
description: Valid catalog entry
category: recon
install:
  check: valid --version
  command: pip install valid
  method: pip
min_role: [pentester]
""",
        encoding="utf-8",
    )
    (tmp_path / "invalid.yaml").write_text("name: invalid\ncategory: unsupported\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        tools = load_tools(tmp_path)

    assert [tool.name for tool in tools] == ["valid"]
    assert "Skipping invalid DeepSec catalog entry invalid.yaml" in caplog.text
