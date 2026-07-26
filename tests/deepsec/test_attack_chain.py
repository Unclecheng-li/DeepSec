import json

from deepsec.core.finding import DeepSecFinding, DeepSecMode, FindingType, Severity
from deepsec.report.attack_chain import attack_chain_data, write_attack_chain_data


def test_attack_chain_data_preserves_known_dependencies(tmp_path) -> None:
    first = DeepSecFinding.create(
        mode=DeepSecMode.SPEAR,
        type=FindingType.VULN_XSS,
        severity=Severity.HIGH,
        target="https://example.com",
        description="Reflected input",
        rule="xss",
        layer="Spear",
    )
    second = DeepSecFinding.create(
        mode=DeepSecMode.SPEAR,
        type=FindingType.VULN_AUTH_BYPASS,
        severity=Severity.CRITICAL,
        target="https://example.com/admin",
        description="Admin bypass",
        rule="auth",
        layer="Spear",
    )
    second.chain_depends_on = [first.id, "missing"]

    data = attack_chain_data([second, first])
    output = write_attack_chain_data([second, first], tmp_path / "chain.json")

    assert data["edges"] == [{"from": first.id, "to": second.id}]
    assert {node["id"] for node in json.loads(output.read_text(encoding="utf-8"))["nodes"]} == {first.id, second.id}
