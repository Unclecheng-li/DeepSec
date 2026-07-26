from deepsec.spear.agent.constraint_policy import infer_tool_action
from deepsec.spear.intel.tools import READ_ONLY_INTEL_TOOLS, RECON_INTEL_TOOLS


def test_read_only_intel_tools_are_recon():
    # Read-only intel tools must be classified as passive recon, never as an
    # active scan/exploit action (the default fallback is "scan").
    for tool in READ_ONLY_INTEL_TOOLS:
        assert infer_tool_action(tool, {"query": "x"}) == "recon"


def test_recon_intel_tools_are_recon():
    for tool in RECON_INTEL_TOOLS:
        assert infer_tool_action(tool, {"domain": "example.com"}) == "recon"


def test_cve_lookup_specifically_is_recon():
    assert infer_tool_action("cve_lookup", {"query": "openssl"}) == "recon"


def test_osint_recon_specifically_is_recon():
    assert infer_tool_action("osint_recon", {"domain": "example.com"}) == "recon"
