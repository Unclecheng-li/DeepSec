"""The production agent must satisfy the AgentContext seam its helpers rely on.

Helper modules annotate their handle as ``agent: AgentContext``. This test is
the drift guard for that contract: whenever a helper starts reaching for a new
member — or ``AgentCore`` drops one — the surface and the real object part ways,
and this fails.

Only the real ``AgentCore`` is required to conform. Focused test doubles
elsewhere in the suite are intentionally partial and are *not* checked here;
requiring them to implement the whole surface would defeat the point of a
narrow double.
"""

from __future__ import annotations

from deepsec.spear.agent.agent_context import AgentContext
from deepsec.spear.agent.core import AgentCore
from deepsec.config.schema import VulnClawConfig


def test_agent_core_satisfies_agent_context() -> None:
    agent = AgentCore(VulnClawConfig())
    assert isinstance(agent, AgentContext)


def test_agent_context_is_not_vacuous() -> None:
    # A bare object lacks the surface, so the protocol is a real constraint —
    # guards against the check silently degrading to "everything conforms".
    assert not isinstance(object(), AgentContext)
