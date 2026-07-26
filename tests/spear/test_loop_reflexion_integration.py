import pytest

from deepsec.spear.agent.context import PentestPhase
from deepsec.spear.agent.core import AgentCore
from deepsec.spear.agent.reflexion import FailureCategory
from deepsec.config.schema import VulnClawConfig


def _make_agent(tmp_path, reflexion_enabled=True):
    config = VulnClawConfig()
    config.session.output_dir = tmp_path
    config.session.reflexion_enabled = reflexion_enabled
    config.session.reflexion_max_same_vuln_fails = 2
    config.session.reflexion_max_total_no_progress = 5
    config.session.engine = "rounds"
    return AgentCore(config)


@pytest.mark.asyncio
async def test_consecutive_same_failures_generate_reflexion_prompt(tmp_path, monkeypatch):
    agent = _make_agent(tmp_path, reflexion_enabled=True)
    captured_contexts = []

    from deepsec.spear.agent import loop_controller

    async def _fake_call_llm_auto(agent_obj, system_prompt, round_context, **kwargs):
        captured_contexts.append(round_context)
        return "尝试 sqli payload，ConnectionError 请求失败。"

    monkeypatch.setattr(loop_controller, "call_llm_auto", _fake_call_llm_auto)

    await agent.auto_pentest("扫描 example.com 的 SQL注入漏洞", max_rounds=4)

    assert "🔴 反思接管" in captured_contexts[3]
    assert "停止在当前攻击路径上重复换 payload。" in captured_contexts[3]
    assert "路径切换强制指令" not in captured_contexts[3]
    assert agent.runtime.same_path_fail_count >= 2


def test_reflexion_disabled_keeps_legacy_same_path_warning(tmp_path):
    agent = _make_agent(tmp_path, reflexion_enabled=False)
    agent.context.state.advance_phase(PentestPhase.VULN_DISCOVERY)
    agent.runtime.same_path_fail_count = 3

    context = agent._build_round_context(5, 5)

    assert "路径切换强制指令" in context
    assert "🔴 反思接管" not in context
    assert agent.runtime.same_path_fail_count == 0
    assert agent.runtime.path_switch_forced is True


def test_reflexion_memory_persists_across_cycles(tmp_path):
    """P2-7: persistent 跨周期保留失败记忆，但重置本周期 stuck 计数。"""
    agent = _make_agent(tmp_path, reflexion_enabled=True)

    # 周期 1：累积同类失败
    rx = agent.runtime.reflexion
    for _ in range(2):
        rx.record_attempt(
            path="sqli",
            success=False,
            category=FailureCategory.ENV_CONSTRAINT,
            details="WAF 拦截",
            vuln_type="sqli",
        )
    assert rx.state.consecutive_failures == 2
    assert rx.state.vuln_type_fail_count == 2

    # 周期 1 结束：写回快照
    agent._save_reflexion_snapshot()
    assert agent.context.state.reflexion_snapshot

    # 周期 2 边界：重建 runtime 并恢复记忆
    agent._reset_runtime_state(user_input="[Persistent Cycle 2] 继续渗透")
    rx2 = agent.runtime.reflexion

    # 记忆保留：失败路径可见
    assert "sqli" in rx2.get_failed_paths()
    # 本周期 stuck 计数重置，卡住检测重新开始
    assert rx2.state.consecutive_failures == 0
    assert rx2.state.vuln_type_fail_count == 0


def test_reflexion_snapshot_skipped_when_disabled(tmp_path):
    """reflexion_enabled=False 时不写/不恢复快照。"""
    agent = _make_agent(tmp_path, reflexion_enabled=False)
    agent.runtime.reflexion.record_attempt(path="sqli", success=False, vuln_type="sqli")
    agent._save_reflexion_snapshot()
    assert agent.context.state.reflexion_snapshot == {}
