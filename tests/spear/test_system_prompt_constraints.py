from deepsec.spear.agent.context import TaskConstraints
from deepsec.spear.agent.system_prompt import build_dynamic_system_prompt


def _build(task_constraints=None):
    return build_dynamic_system_prompt(
        target="example.com",
        phase=None,
        skill_context=None,
        mcp_tools=[],
        enable_personnel_dim=False,
        auto_mode=False,
        user_input=None,
        kb_context="",
        task_constraints=task_constraints,
    )


def test_prompt_includes_constraints_block_when_constraints_set():
    constraints = TaskConstraints(allowed_ports=[443], blocked_hosts=["internal.example.com"])

    prompt = _build(task_constraints=constraints)

    assert constraints.to_prompt_block() in prompt


def test_prompt_omits_constraints_block_when_constraints_empty():
    prompt = _build(task_constraints=TaskConstraints())

    assert "当前任务硬约束" not in prompt


def test_prompt_omits_constraints_block_when_constraints_none():
    prompt = _build(task_constraints=None)

    assert "当前任务硬约束" not in prompt
