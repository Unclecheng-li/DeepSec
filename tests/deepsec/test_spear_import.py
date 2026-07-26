def test_migrated_spear_core_is_importable() -> None:
    from deepsec.spear.agent.core import AgentCore

    assert AgentCore.__name__ == "AgentCore"
