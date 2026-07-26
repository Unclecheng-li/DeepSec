"""Tests for the durable multi-agent lifecycle graph (AgentGraph)."""

from __future__ import annotations

import json

import pytest

from deepsec.spear.agent.agent_graph import (
    INTERRUPTED,
    AgentEvent,
    AgentGraph,
    AgentOutcome,
    AgentStatus,
    EventKind,
    FanOutCaps,
    GraphInconsistencyError,
    fold_events,
)


def _clock():
    """Deterministic, monotonically increasing ISO-ish timestamps."""
    counter = {"n": 0}

    def _tick() -> str:
        counter["n"] += 1
        return f"2026-01-01T00:00:{counter['n']:02d}"

    return _tick


def _graph(tmp_path, **caps):
    return AgentGraph(
        tmp_path / "agents",
        caps=FanOutCaps(**caps) if caps else None,
        clock=_clock(),
    )


# ── Node lifecycle ───────────────────────────────────────────────────


def test_create_root_starts_running(tmp_path):
    graph = _graph(tmp_path)
    root = graph.create_root(task_summary="pentest http://target")

    assert root.parent_id is None
    assert root.status == AgentStatus.RUNNING
    assert root.outcome is None
    assert graph.root_id == root.id


def test_create_agent_transitions_and_child_finish_outcome(tmp_path):
    graph = _graph(tmp_path, max_concurrent=3, max_total=10, max_depth=1)
    root = graph.create_root()
    created = graph.create_agent(root.id, role="worker", task_summary="scan :22")

    assert created.accepted is True
    assert created.queued is False
    node = created.node
    assert node.status == AgentStatus.RUNNING
    assert node.parent_id == root.id

    finished = graph.child_finish(node.id, result_ref="agents/results/a0001.json")
    assert finished.status == AgentStatus.DONE
    assert finished.outcome == AgentOutcome.FINISHED
    assert finished.result_ref == "agents/results/a0001.json"


def test_stop_agent_marks_stopped(tmp_path):
    graph = _graph(tmp_path)
    root = graph.create_root()
    node = graph.create_agent(root.id).node

    stopped = graph.stop_agent(node.id)
    assert stopped.status == AgentStatus.DONE
    assert stopped.outcome == AgentOutcome.STOPPED


def test_child_finish_failed_records_error(tmp_path):
    graph = _graph(tmp_path)
    root = graph.create_root()
    node = graph.create_agent(root.id).node

    failed = graph.child_finish(node.id, outcome=AgentOutcome.FAILED, error="boom")
    assert failed.status == AgentStatus.DONE
    assert failed.outcome == AgentOutcome.FAILED
    assert failed.error == "boom"


def test_child_finish_hook_failure_marks_failed(tmp_path):
    graph = _graph(tmp_path)
    root = graph.create_root()
    node = graph.create_agent(root.id).node

    def bad_hook():
        raise RuntimeError("merge exploded")

    finished = graph.child_finish(node.id, hook=bad_hook)
    assert finished.status == AgentStatus.DONE
    assert finished.outcome == AgentOutcome.FAILED
    assert "merge exploded" in finished.error


def test_wait_for_message_is_running_and_waiting(tmp_path):
    graph = _graph(tmp_path)
    root = graph.create_root()
    node = graph.create_agent(root.id).node

    graph.wait_for_message(node.id)
    waiting = graph.get_node(node.id)
    assert waiting.status == AgentStatus.RUNNING  # not a fourth state
    assert waiting.waiting is True


def test_send_message_clears_waiting_and_delivers(tmp_path):
    graph = _graph(tmp_path)
    root = graph.create_root()
    node = graph.create_agent(root.id).node
    graph.wait_for_message(node.id)

    graph.send_message(root.id, node.id, "focus on /admin")
    unblocked = graph.get_node(node.id)
    assert unblocked.waiting is False
    assert unblocked.status == AgentStatus.RUNNING

    messages = graph.read_messages(node.id)
    assert [m["content"] for m in messages] == ["focus on /admin"]
    assert graph.read_messages(node.id) == []


# ── Root-completion rule (fail-loud) ─────────────────────────────────


def test_root_finish_rejected_while_child_pending(tmp_path):
    graph = _graph(tmp_path, max_concurrent=1, max_total=10, max_depth=1)
    root = graph.create_root()
    running = graph.create_agent(root.id).node
    queued = graph.create_agent(root.id)  # exceeds max_concurrent → pending

    assert queued.queued is True
    assert queued.node.status == AgentStatus.PENDING

    result = graph.root_finish()
    assert result.accepted is False
    assert set(result.blocking_ids) == {running.id, queued.node.id}
    assert graph.get_node(root.id).status == AgentStatus.RUNNING  # still running


def test_root_finish_rejected_logs_reject_event(tmp_path):
    graph = _graph(tmp_path)
    root = graph.create_root()
    graph.create_agent(root.id)

    graph.root_finish()
    kinds = [e.kind for e in graph.events()]
    assert EventKind.REJECT in kinds


def test_root_finish_accepted_once_all_children_done(tmp_path):
    graph = _graph(tmp_path)
    root = graph.create_root()
    a = graph.create_agent(root.id).node
    b = graph.create_agent(root.id).node

    graph.child_finish(a.id)
    graph.stop_agent(b.id)

    result = graph.root_finish()
    assert result.accepted is True
    assert graph.get_node(root.id).status == AgentStatus.DONE
    assert graph.get_node(root.id).outcome == AgentOutcome.FINISHED


# ── Bounded fan-out caps ─────────────────────────────────────────────


def test_max_concurrent_queues_excess_as_pending(tmp_path):
    graph = _graph(tmp_path, max_concurrent=2, max_total=10, max_depth=1)
    root = graph.create_root()

    r1 = graph.create_agent(root.id)
    r2 = graph.create_agent(root.id)
    r3 = graph.create_agent(root.id)

    assert r1.node.status == AgentStatus.RUNNING and r1.queued is False
    assert r2.node.status == AgentStatus.RUNNING and r2.queued is False
    assert r3.node.status == AgentStatus.PENDING and r3.queued is True

    # Finishing a running worker drains one pending worker into the free slot.
    graph.child_finish(r1.node.id)
    assert graph.get_node(r3.node.id).status == AgentStatus.RUNNING


def test_max_total_rejects_and_logs(tmp_path):
    # max_total counts the root, so a total of 2 allows exactly one child.
    graph = _graph(tmp_path, max_concurrent=5, max_total=2, max_depth=2)
    root = graph.create_root()

    ok = graph.create_agent(root.id)
    assert ok.accepted is True

    rejected = graph.create_agent(root.id)
    assert rejected.accepted is False
    assert rejected.node is None
    assert rejected.reason == "max_total"
    assert EventKind.REJECT in [e.kind for e in graph.events()]


def test_max_depth_rejects_deeper_creates(tmp_path):
    graph = _graph(tmp_path, max_concurrent=5, max_total=10, max_depth=1)
    root = graph.create_root()
    child = graph.create_agent(root.id).node  # depth 1 — allowed

    grandchild = graph.create_agent(child.id)  # depth 2 — rejected
    assert grandchild.accepted is False
    assert grandchild.reason == "max_depth"


# ── Persistence ──────────────────────────────────────────────────────


def test_each_op_appends_event_and_rewrites_snapshot(tmp_path):
    storage = tmp_path / "agents"
    graph = AgentGraph(storage, clock=_clock())
    root = graph.create_root()
    node = graph.create_agent(root.id).node
    graph.child_finish(node.id)

    events_path = storage / "events.jsonl"
    graph_path = storage / "graph.json"
    assert events_path.exists()
    assert graph_path.exists()

    lines = [line for line in events_path.read_text().splitlines() if line.strip()]
    assert len(lines) == len(graph.events())
    assert len(lines) >= 5  # create root, start root, create child, start child, finish child


def test_graph_json_equals_fold_over_events(tmp_path):
    storage = tmp_path / "agents"
    graph = AgentGraph(storage, clock=_clock())
    root = graph.create_root()
    a = graph.create_agent(root.id).node
    b = graph.create_agent(root.id).node
    graph.wait_for_message(a.id)
    graph.send_message(root.id, a.id, "hi")
    graph.child_finish(a.id)
    graph.stop_agent(b.id)

    on_disk = json.loads((storage / "graph.json").read_text())
    events = [
        AgentEvent(**json.loads(line))
        for line in (storage / "events.jsonl").read_text().splitlines()
        if line.strip()
    ]
    folded = fold_events(events, graph.caps).model_dump(mode="json")

    assert on_disk["nodes"] == folded["nodes"]
    assert on_disk["inboxes"] == folded["inboxes"]
    assert on_disk["root_id"] == folded["root_id"]
    assert on_disk["seq"] == folded["seq"]


# ── Resume ───────────────────────────────────────────────────────────


def test_resume_from_snapshot(tmp_path):
    storage = tmp_path / "agents"
    graph = AgentGraph(storage, clock=_clock())
    root = graph.create_root()
    node = graph.create_agent(root.id).node
    graph.child_finish(node.id)

    resumed = AgentGraph.load(storage)
    assert resumed.root_id == root.id
    assert resumed.get_node(node.id).status == AgentStatus.DONE
    assert resumed.get_node(node.id).outcome == AgentOutcome.FINISHED


def test_resume_rebuilds_from_events_when_snapshot_missing(tmp_path):
    storage = tmp_path / "agents"
    graph = AgentGraph(storage, clock=_clock())
    root = graph.create_root()
    node = graph.create_agent(root.id).node
    graph.child_finish(node.id)

    (storage / "graph.json").unlink()  # snapshot gone — must replay events
    resumed = AgentGraph.load(storage)
    assert resumed.get_node(node.id).status == AgentStatus.DONE
    assert resumed.root_id == root.id


def test_resume_rebuilds_from_events_when_snapshot_corrupt(tmp_path):
    storage = tmp_path / "agents"
    graph = AgentGraph(storage, clock=_clock())
    root = graph.create_root()
    node = graph.create_agent(root.id).node
    graph.child_finish(node.id)

    (storage / "graph.json").write_text("{ not valid json ")
    resumed = AgentGraph.load(storage)
    assert resumed.get_node(node.id).status == AgentStatus.DONE


def test_resume_reconciles_running_node_to_failed_interrupted(tmp_path):
    storage = tmp_path / "agents"
    graph = AgentGraph(storage, clock=_clock())
    root = graph.create_root()
    running = graph.create_agent(root.id).node
    waiting = graph.create_agent(root.id).node
    graph.wait_for_message(waiting.id)  # running + waiting still counts as running

    resumed = AgentGraph.resume(storage)
    for node_id in (root.id, running.id, waiting.id):
        node = resumed.get_node(node_id)
        assert node.status == AgentStatus.DONE
        assert node.outcome == AgentOutcome.FAILED
        assert node.error == INTERRUPTED


def test_resume_does_not_restart_completed_nodes(tmp_path):
    storage = tmp_path / "agents"
    graph = AgentGraph(storage, clock=_clock())
    root = graph.create_root()
    done = graph.create_agent(root.id).node
    graph.child_finish(done.id)
    graph.root_finish()

    resumed = AgentGraph.resume(storage)
    assert resumed.get_node(done.id).outcome == AgentOutcome.FINISHED
    assert resumed.get_node(root.id).outcome == AgentOutcome.FINISHED


def test_replay_fails_loud_on_inconsistency(tmp_path):
    storage = tmp_path / "agents"
    storage.mkdir(parents=True)
    # A status event for a node that was never created — impossible to fold.
    bad = AgentEvent(seq=1, kind=EventKind.STATUS, node_id="ghost", data={"status": "running"})
    (storage / "events.jsonl").write_text(
        json.dumps(bad.model_dump(mode="json")) + "\n"
    )

    with pytest.raises(GraphInconsistencyError):
        AgentGraph.load(storage)


def test_resume_continues_appending_events(tmp_path):
    storage = tmp_path / "agents"
    graph = AgentGraph(storage, clock=_clock())
    root = graph.create_root()
    a = graph.create_agent(root.id).node
    graph.child_finish(a.id)

    resumed = AgentGraph.load(storage, clock=_clock())
    b = resumed.create_agent(root.id).node
    assert b.id != a.id  # ids don't collide across resume
    resumed.child_finish(b.id)
    assert resumed.root_finish().accepted is True
