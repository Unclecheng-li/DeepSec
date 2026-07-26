"""Role-specialized team planning and adaptive delegation."""

from __future__ import annotations

import asyncio
import copy
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Literal

from deepsec.spear.agent.parallel_agents import merge_session_state
from deepsec.spear.agent.roles import ROLE_REGISTRY, get_role, tool_allowed_for_role

logger = logging.getLogger(__name__)

TeamRole = Literal["adviser", "researcher", "developer", "executor"]
TeamDecisionAction = Literal["continue", "replan", "stop"]


@dataclass(frozen=True)
class TeamStep:
    role: TeamRole
    objective: str
    done_when: str
    depends_on: tuple[int, ...] | None = None


@dataclass(frozen=True)
class TeamPlan:
    steps: list[TeamStep]
    fallback_used: bool = False


@dataclass(frozen=True)
class TeamDecision:
    action: TeamDecisionAction
    reason: str = ""


@dataclass
class TeamRunResult:
    plan: TeamPlan
    worker_results: list[Any] = field(default_factory=list)
    adviser_decisions: list[TeamDecision] = field(default_factory=list)
    replans_used: int = 0
    stopped_by_adviser: bool = False


AgentFactory = Callable[[], Any]
Planner = Callable[[Any, str, str, list[str]], TeamPlan | dict[str, Any]]
Adviser = Callable[[Any, str, str, TeamStep, Any], TeamDecision | dict[str, Any]]


def is_tool_allowed_for_role(role: str | None, tool_name: str) -> bool:
    """Return whether ``tool_name`` may be exposed/executed for ``role``."""
    return tool_allowed_for_role(tool_name, role)


def validate_plan(raw: TeamPlan | dict[str, Any], *, fallback_goal: str) -> TeamPlan:
    """Validate planner output, falling back to one Executor step on any problem."""
    fallback_used = False
    if isinstance(raw, TeamPlan):
        steps = raw.steps
        fallback_used = raw.fallback_used
    elif isinstance(raw, dict):
        steps = [_coerce_step(item) for item in raw.get("steps") or []]
        if any(step is None for step in steps):
            return _fallback_plan(fallback_goal)
        steps = [step for step in steps if step is not None]
    else:
        return _fallback_plan(fallback_goal)

    if fallback_used:
        if len(steps) != 1:
            return _fallback_plan(fallback_goal)
        return TeamPlan(steps=list(steps), fallback_used=True)

    if not 3 <= len(steps) <= 7:
        return _fallback_plan(fallback_goal)
    if any(step.role not in ROLE_REGISTRY or not step.objective.strip() for step in steps):
        return _fallback_plan(fallback_goal)
    if any(_has_invalid_dependencies(step, len(steps), idx) for idx, step in enumerate(steps)):
        return _fallback_plan(fallback_goal)
    return TeamPlan(steps=list(steps), fallback_used=fallback_used)


async def make_team_plan(agent: Any, origin: str, goal: str, facts: list[str]) -> TeamPlan:
    """Ask the Adviser for a structured team plan."""
    from deepsec.spear.agent.solver import extract_json, structured_call

    if not hasattr(agent, "_get_client"):
        return _fallback_plan(goal)

    prompt = (
        "You are the Adviser for a role-specialized pentest team. "
        "Create 3-7 JSON steps. Roles must be one of researcher, developer, executor. "
        "Each step needs role, objective, done_when, and optional depends_on as zero-based "
        "step indexes. Omit depends_on for sequential order; use depends_on: [] for independent "
        "steps that may run in the same bounded-parallel wave.\n\n"
        f"Origin: {origin}\nGoal: {goal}\nFacts:\n" + "\n".join(f"- {fact}" for fact in facts)
        + '\n\nReturn only JSON: {"steps":[{"role":"researcher","objective":"...",'
        '"done_when":"...","depends_on":[0]}]}'
    )
    previous_role = getattr(agent, "active_role", None)
    agent.active_role = "adviser"
    try:
        try:
            raw = await structured_call(agent, prompt, max_tokens=1200)
        except Exception:
            return _fallback_plan(goal)
    finally:
        agent.active_role = previous_role
    return validate_plan(extract_json(raw) or {}, fallback_goal=goal)


async def ask_adviser(
    agent: Any,
    origin: str,
    goal: str,
    step: TeamStep,
    step_result: Any,
) -> TeamDecision:
    """Ask the Adviser whether to continue, re-plan, or stop after a step."""
    from deepsec.spear.agent.solver import extract_json, structured_call

    if not hasattr(agent, "_get_client"):
        return TeamDecision(action="continue", reason="no adviser LLM client available")

    research = getattr(getattr(agent, "session_state", None), "research", None)
    research_summary = research.to_prompt_summary() if research is not None else ""
    prompt = (
        "You are the Adviser reflection pass for a role-specialized team run. "
        "Use the updated shared research state and just-finished step result to decide the next action. "
        "Return only JSON with action: continue, replan, or stop. "
        "The evidence gate remains authoritative; use stop only when no further team steps "
        "are useful, not to override unproven completion.\n\n"
        f"Origin: {origin}\nGoal: {goal}\n"
        f"Finished step: {step.role} | {step.objective} | done_when={step.done_when}\n"
        f"Step result: {step_result}\n\nShared research state:\n{research_summary}\n"
    )
    previous_role = getattr(agent, "active_role", None)
    agent.active_role = "adviser"
    try:
        try:
            raw = await structured_call(agent, prompt, max_tokens=600)
        except Exception:
            return TeamDecision(action="continue", reason="adviser structured call failed")
    finally:
        agent.active_role = previous_role
    return _coerce_decision(extract_json(raw) or {})


async def run_team_pentest(
    root_agent: Any,
    *,
    user_input: str,
    target: str | None = None,
    planner: Planner | None = None,
    adviser: Adviser | None = None,
    agent_factory: AgentFactory | None = None,
    max_steps: int = 40,
    max_directions: int | None = None,
    max_intents: int | None = None,
    max_tool_rounds: int = 4,
    max_replans: int = 2,
    max_parallel: int | None = None,
    stream_sink: Any = None,
    on_event: Callable[[str, dict], None] | None = None,
) -> TeamRunResult:
    """Run a bounded adaptive team plan against the shared session state."""
    direction_limit = max_directions if max_directions is not None else max_intents
    if direction_limit is None:
        direction_limit = 3

    target = target or root_agent.session_state.target or user_input
    root_agent.session_state.target = target
    _seed_agent_state(root_agent, origin=target, goal=user_input)
    agent_factory = agent_factory or _default_agent_factory(root_agent)
    goal = user_input
    facts = _plan_facts(root_agent)
    plan = await _call_planner(planner, root_agent, target, goal, facts)
    plan = validate_plan(plan, fallback_goal=goal)
    _surface_plan(root_agent, plan, stream_sink=stream_sink)

    result = TeamRunResult(plan=plan)
    completed_steps: set[int] = set()
    remaining_steps = max(1, max_steps)
    max_parallel = max(1, max_parallel or len(plan.steps) or 1)
    previous_root_role = getattr(root_agent, "active_role", None)

    try:
        root_agent.active_role = None
        while len(completed_steps) < len(plan.steps) and remaining_steps > 0:
            ready = _ready_wave(plan.steps, completed=completed_steps)
            if not ready:
                remaining_idx = [i for i in range(len(plan.steps)) if i not in completed_steps]
                if not remaining_idx:
                    break
                ready = [remaining_idx[0]]
            wave = ready[: min(max_parallel, remaining_steps)]
            step_budget = max(1, remaining_steps // max(1, len(wave)))
            step_results = await asyncio.gather(
                *(
                    _run_team_step(
                        root_agent,
                        plan.steps[idx],
                        agent_factory=agent_factory,
                        target=target,
                        max_steps=step_budget,
                        max_directions=direction_limit,
                        max_tool_rounds=max_tool_rounds,
                        stream_sink=stream_sink,
                        on_event=on_event,
                    )
                    for idx in wave
                ),
                return_exceptions=True,
            )
            # Handle exceptions from failed steps
            for i, step_result in enumerate(step_results):
                if isinstance(step_result, Exception):
                    logger.error(
                        "Team step %d failed with exception: %s",
                        wave[i],
                        step_result,
                    )
                    # Create a minimal error result so the wave can continue
                    step_results[i] = {
                        "completed": False,
                        "reason": f"Step failed: {step_result}",
                        "steps": 0,
                        "facts": 0,
                    }
            result.worker_results.extend(step_results)
            remaining_steps -= sum(_steps_used(step_result, step_budget) for step_result in step_results)

            for idx, step_result in zip(wave, step_results):
                completed_steps.add(idx)
                decision = await _call_adviser(
                    adviser, root_agent, target, goal, plan.steps[idx], step_result
                )
                result.adviser_decisions.append(decision)

                if decision.action == "replan" and result.replans_used < max_replans:
                    result.replans_used += 1
                    new_plan = await _call_planner(
                        planner, root_agent, target, goal, _plan_facts(root_agent)
                    )
                    plan = validate_plan(new_plan, fallback_goal=goal)
                    _surface_plan(root_agent, plan, stream_sink=stream_sink)
                    result.plan = plan
                    completed_steps = set()
                    break

                if decision.action == "stop":
                    result.stopped_by_adviser = True
                    if getattr(root_agent.session_state.agent_state, "completed", False):
                        return result
                    if not _evidence_gate_completed(root_agent):
                        continue
                    return result
            else:
                continue
            continue
    finally:
        root_agent.active_role = previous_root_role

    return result


def _steps_used(result: Any, fallback: int) -> int:
    steps = getattr(result, "steps", fallback)
    if isinstance(steps, int) and steps > 0:
        return steps
    return fallback


def _default_agent_factory(root_agent: Any) -> AgentFactory:
    def factory() -> Any:
        cls = root_agent.__class__
        try:
            return cls(
                getattr(root_agent, "config", None),
                getattr(root_agent, "mcp_manager", None),
            )
        except TypeError:
            child = cls()
            if hasattr(child, "config"):
                child.config = getattr(root_agent, "config", None)
            if hasattr(child, "mcp_manager"):
                child.mcp_manager = getattr(root_agent, "mcp_manager", None)
            return child

    return factory


async def _run_team_step(
    root_agent: Any,
    step: TeamStep,
    *,
    agent_factory: AgentFactory,
    target: str,
    max_steps: int,
    max_directions: int,
    max_tool_rounds: int,
    stream_sink: Any = None,
    on_event: Callable[[str, dict], None] | None = None,
) -> Any:
    child = agent_factory()
    _seed_child_session(child, root_agent, step)
    previous_role = getattr(child, "active_role", None)
    child.active_role = step.role
    try:
        result = await child.solve(
            _step_prompt(step),
            target=target,
            goal=step.done_when,
            max_steps=max_steps,
            max_directions=max_directions,
            max_tool_rounds=max_tool_rounds,
            stream_sink=stream_sink,
            on_event=on_event,
        )
    finally:
        child.active_role = previous_role
    merge_session_state(root_agent.session_state, child.session_state)
    _preserve_distinct_team_findings(root_agent.session_state, child.session_state)
    _merge_agent_state(root_agent.session_state.agent_state, child.session_state.agent_state)
    return result


def _fallback_plan(goal: str) -> TeamPlan:
    return TeamPlan(
        steps=[
            TeamStep(
                role="executor",
                objective=goal,
                done_when="The evidence gate confirms the goal or the safety budget is exhausted.",
            )
        ],
        fallback_used=True,
    )


def _coerce_step(item: Any) -> TeamStep | None:
    if not isinstance(item, dict):
        return None
    role = str(item.get("role") or "").strip().lower()
    objective = str(item.get("objective") or "").strip()
    done_when = str(item.get("done_when") or "").strip()
    depends_on = item.get("depends_on", None)
    if isinstance(depends_on, int):
        deps = (depends_on,)
    elif isinstance(depends_on, list | tuple):
        deps = tuple(int(dep) for dep in depends_on if isinstance(dep, int))
    else:
        deps = None
    if role not in ROLE_REGISTRY or not objective or not done_when:
        return None
    return TeamStep(role=role, objective=objective, done_when=done_when, depends_on=deps)  # type: ignore[arg-type]


def _has_invalid_dependencies(step: TeamStep, plan_len: int, idx: int) -> bool:
    if step.depends_on is None:
        return False
    return any(dep < 0 or dep >= plan_len or dep == idx for dep in step.depends_on)


def _coerce_decision(raw: TeamDecision | dict[str, Any]) -> TeamDecision:
    if isinstance(raw, TeamDecision):
        return raw
    action = str((raw or {}).get("action") or "continue").strip().lower()
    if action not in {"continue", "replan", "stop"}:
        action = "continue"
    return TeamDecision(action=action, reason=str((raw or {}).get("reason") or ""))


async def _call_planner(
    planner: Planner | None, agent: Any, origin: str, goal: str, facts: list[str]
) -> TeamPlan | dict[str, Any]:
    if planner is None:
        return await make_team_plan(agent, origin, goal, facts)
    raw = planner(agent, origin, goal, facts)
    if hasattr(raw, "__await__"):
        raw = await raw  # type: ignore[assignment]
    return raw


async def _call_adviser(
    adviser: Adviser | None,
    agent: Any,
    origin: str,
    goal: str,
    step: TeamStep,
    step_result: Any,
) -> TeamDecision:
    if adviser is None:
        return await ask_adviser(agent, origin, goal, step, step_result)
    raw = adviser(agent, origin, goal, step, step_result)
    if hasattr(raw, "__await__"):
        raw = await raw  # type: ignore[assignment]
    return _coerce_decision(raw)


def _plan_facts(agent: Any) -> list[str]:
    agent_state = getattr(agent.session_state, "agent_state", None)
    if agent_state is None:
        return []
    claims = [claim.claim for claim in getattr(agent_state, "verified_claims", [])[-6:]]
    evidence = [
        f"{item.id}: {item.summary}" for item in getattr(agent_state, "evidence", [])[-8:]
    ]
    return [*claims, *evidence]


def _seed_agent_state(agent: Any, *, origin: str, goal: str) -> None:
    agent_state = getattr(getattr(agent, "session_state", None), "agent_state", None)
    if agent_state is None:
        return
    agent_state.origin = origin or agent_state.origin
    agent_state.goal = goal or agent_state.goal
    seed = f"Team run origin={agent_state.origin}; goal={agent_state.goal}"
    if seed not in agent_state.compact_summary:
        agent_state.compact_summary = (agent_state.compact_summary + "\n" + seed).strip()


def _surface_plan(agent: Any, plan: TeamPlan, *, stream_sink: Any = None) -> None:
    lines = [
        f"{idx + 1}. {step.role}: {step.objective} (done when: {step.done_when})"
        for idx, step in enumerate(plan.steps)
    ]
    rendered = "[team-plan]\n" + "\n".join(lines)
    agent.last_team_plan = rendered
    notes = getattr(agent.session_state, "notes", None)
    if isinstance(notes, list) and rendered not in notes:
        notes.append(rendered)
    if stream_sink is not None:
        stream_sink.on_status(rendered)


def _ready_wave(steps: list[TeamStep], *, completed: set[int]) -> list[int]:
    ready: list[int] = []
    for idx, step in enumerate(steps):
        if idx in completed:
            continue
        deps = step.depends_on
        if deps is None:
            deps = (idx - 1,) if idx > 0 else ()
        if all(dep in completed for dep in deps):
            ready.append(idx)
    return ready


def _seed_child_session(child: Any, root_agent: Any, step: TeamStep) -> None:
    parent = root_agent.session_state
    child.session_state.target = parent.target
    child.session_state.phase = parent.phase
    child.session_state.task_constraints = parent.task_constraints.model_copy(deep=True)
    child.session_state.agent_state = copy.deepcopy(parent.agent_state)
    child.session_state.resume_summary = (
        f"Team role {step.role} assigned objective: {step.objective}. "
        f"Done when: {step.done_when}."
    )


def _step_prompt(step: TeamStep) -> str:
    role = get_role(step.role)
    persona = role.persona if role else ""
    return (
        f"{persona}\n\n"
        f"Objective: {step.objective}\n"
        f"Done when: {step.done_when}\n\n"
        "Work only inside the inherited task constraints and record concrete evidence."
    )


def _evidence_gate_completed(agent: Any) -> bool:
    agent_state = getattr(agent.session_state, "agent_state", None)
    return bool(getattr(agent_state, "completed", False))


def _preserve_distinct_team_findings(parent: Any, child: Any) -> None:
    """Keep distinct per-role findings that the generic de-duper collapsed."""
    for finding in getattr(child, "findings", []):
        if any(
            existing.title == finding.title and existing.evidence == finding.evidence
            for existing in parent.findings
        ):
            continue
        preserved = copy.deepcopy(finding)
        preserved.finding_id = (
            f"{finding.finding_id or 'finding'}:team:{len(parent.findings) + 1}"
        )
        parent.findings.append(preserved)
        if hasattr(parent, "_finding_ids_cache"):
            parent._finding_ids_cache.add(preserved.finding_id)


def _merge_agent_state(parent: Any, child: Any) -> None:
    """Merge child AgentState additions without rewriting existing ids."""
    if parent is child:
        return

    seen_evidence = {item.fingerprint for item in getattr(parent, "evidence", [])}
    for item in getattr(child, "evidence", []):
        if item.fingerprint not in seen_evidence:
            parent.evidence.append(copy.deepcopy(item))
            seen_evidence.add(item.fingerprint)

    seen_claims = {item.claim for item in getattr(parent, "verified_claims", [])}
    for item in getattr(child, "verified_claims", []):
        if item.claim not in seen_claims:
            parent.verified_claims.append(copy.deepcopy(item))
            seen_claims.add(item.claim)

    for tool_call in getattr(child, "tool_calls", []):
        if tool_call not in parent.tool_calls:
            parent.tool_calls.append(copy.deepcopy(tool_call))

    for step in getattr(child, "steps", []):
        if step not in parent.steps:
            parent.steps.append(copy.deepcopy(step))

    parent.pending_questions.extend(
        question
        for question in getattr(child, "pending_questions", [])
        if question not in parent.pending_questions
    )

    # A worker's `completed` reflects its own step-scoped done_when (solver.solve
    # overwrites the step goal), not the team's overall goal.
    # Never let a subtask's local completion mark the shared root goal achieved.
