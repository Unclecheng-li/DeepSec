from deepsec.spear.agent.runtime_state import RuntimeState


def test_runtime_state_has_reflexion_field():
    runtime = RuntimeState()

    assert hasattr(runtime, "reflexion")
