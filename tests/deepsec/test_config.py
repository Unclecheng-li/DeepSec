from pathlib import Path

from deepsec.core.config import ensure_config_file, load_config, update_config_value


def test_config_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    ensure_config_file(path)
    update_config_value("shield.l3", "true", path)
    update_config_value("role.default", "auditor", path)

    config = load_config(path)

    assert config.shield.l3 is True
    assert config.role.default == "auditor"
