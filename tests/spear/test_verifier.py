"""Tests for the PoC verifier (vulnclaw/report/verifier.py).

Regression coverage for the template-rendering bug: templates were authored
with ``str.format`` escaping (``{{`` / ``}}``) but rendered with ``str.replace``,
which left literal double-braces in the generated PoC. That turned every ``dict``
literal into a ``set`` (raising ``TypeError: unhashable type: 'dict'`` at runtime)
and made f-strings print literal ``{var}`` text — so every finding was silently
rejected as a false positive regardless of the target's actual behaviour.
"""

import contextlib
import io
import sys
import types

import pytest

from deepsec.spear.agent.context import VulnerabilityFinding
from deepsec.spear.report.verifier import (
    PoCGenerator,
    VerificationResult,
    VerifierExecutor,
)

ALL_TEMPLATE_TYPES = [
    "sql_injection",
    "xss",
    "command_injection",
    "debug_mode",
    "lfi",
    "sensitive_file",
    "info_disclosure",
    "totally_unknown_type",  # falls back to the generic template
    "",
]


def _gen(vuln_type: str, baseline_len: int = 100) -> str:
    finding = VulnerabilityFinding(title="t", vuln_type=vuln_type)
    return PoCGenerator.generate_poc(finding, "http://example.com", baseline_len=baseline_len)


@pytest.mark.parametrize("vuln_type", ALL_TEMPLATE_TYPES)
def test_generated_poc_has_no_stray_braces(vuln_type):
    """No template placeholder escaping should leak into the rendered PoC."""
    poc = _gen(vuln_type)
    assert "{{" not in poc, f"{vuln_type!r} leaked '{{{{' into the PoC"
    assert "}}" not in poc, f"{vuln_type!r} leaked '}}}}' into the PoC"


@pytest.mark.parametrize("vuln_type", ALL_TEMPLATE_TYPES)
def test_generated_poc_compiles(vuln_type):
    """Every generated PoC must be syntactically valid Python."""
    poc = _gen(vuln_type)
    compile(poc, f"poc_{vuln_type or 'generic'}.py", "exec")


class _FakeResp:
    def __init__(self, text="hello", status=200, headers=None):
        self.text = text
        self.content = text.encode()
        self.status_code = status
        self.headers = headers or {}


def _fake_requests(handler):
    module = types.ModuleType("requests")

    class Timeout(Exception):
        ...

    module.Timeout = Timeout
    state = {"n": 0}

    def get(url, params=None, timeout=None, verify=None):
        state["n"] += 1
        return handler(state["n"], params)

    module.get = get
    return module


def _run(poc, handler):
    """Execute a generated PoC with `requests` stubbed, returning stdout."""
    original = sys.modules.get("requests")
    sys.modules["requests"] = _fake_requests(handler)
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            with contextlib.suppress(SystemExit):
                exec(compile(poc, "poc.py", "exec"), {"__name__": "__main__"})
    finally:
        if original is not None:
            sys.modules["requests"] = original
        else:
            sys.modules.pop("requests", None)
    return buf.getvalue()


def test_dict_templates_execute_without_typeerror():
    """The templates that used to crash with an unhashable-dict TypeError now run.

    A clean response must yield a plain [REJECTED], never a Python traceback.
    """
    for vuln_type in ("sql_injection", "command_injection", "info_disclosure"):
        out = _run(_gen(vuln_type), lambda n, p: _FakeResp("nothing interesting here"))
        assert "Traceback" not in out, f"{vuln_type} raised at runtime:\n{out}"
        assert "TypeError" not in out


def test_sql_injection_confirms_on_error_signature():
    out = _run(
        _gen("sql_injection"),
        lambda n, p: _FakeResp("You have an error in your SQL syntax near '1'"),
    )
    assert "[CONFIRMED]" in out


def test_xss_confirms_on_reflection():
    payload = "<script>alert(1)</script>"
    out = _run(_gen("xss"), lambda n, p: _FakeResp(f"page echoes {payload} back"))
    assert "[CONFIRMED]" in out
    # f-string interpolation must render the real payload, not literal '{payload}'
    assert "{payload}" not in out


def test_generic_template_confirms_reflected_payload():
    # First call is the baseline (no reflection), later calls reflect the payload.
    out = _run(
        _gen("brand_new_bug_class"),
        lambda n, p: _FakeResp("baseline" if n == 1 else "reflected test here"),
    )
    assert "[CONFIRMED]" in out
    assert "{name}" not in out  # no literal f-string leakage


def test_generic_template_rejects_when_no_signal():
    out = _run(
        _gen("brand_new_bug_class"),
        lambda n, p: _FakeResp("identical page for every request"),
    )
    assert "[REJECTED]" in out


@pytest.mark.parametrize(
    "vuln_type,expected",
    [
        ("SQL Injection", "1' OR '1'='1"),
        ("Reflected XSS", "<script>alert(1)</script>"),
        ("Command Injection", ";id"),
        ("LFI", "../../../etc/passwd"),
        ("Some Unknown Type", "test"),
    ],
)
def test_guess_payload(vuln_type, expected):
    finding = VulnerabilityFinding(title="t", vuln_type=vuln_type)
    assert PoCGenerator._guess_payload(finding) == expected


@pytest.mark.parametrize(
    "output,returncode,expected",
    [
        ("[CONFIRMED] found sensitive data", 0, VerificationResult.SENSITIVE_DATA_EXPOSED),
        ("[CONFIRMED] auth bypass", 0, VerificationResult.SECURITY_BYPASS),
        ("[CONFIRMED] sqli", 0, VerificationResult.VULN_CONFIRMED),
        ("[REJECTED] nope", 0, VerificationResult.FALSE_POSITIVE),
        ("[POSSIBLE] diff", 0, VerificationResult.NO_RESPONSE_DIFF),
        ("plain output", 0, VerificationResult.NORMAL_RESPONSE),
        ("", -1, VerificationResult.TIMEOUT),
        ("", -2, VerificationResult.EXECUTION_ERROR),
        ("", -3, VerificationResult.EXECUTION_ERROR),
        ("boom", 1, VerificationResult.FALSE_POSITIVE),
    ],
)
def test_parse_result(output, returncode, expected):
    assert VerifierExecutor.parse_result(output, returncode) == expected
