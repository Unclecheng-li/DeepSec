"""Durable, resumable multi-agent lifecycle graph.

``AgentGraph`` is the source of truth for a run's agent team. It sits *on top of*
the fire-and-forget fan-out in :mod:`deepsec.spear.agent.parallel_agents` — the
surface-wave logic there is demoted to one *strategy* that drives this graph
(see :func:`deepsec.spear.agent.parallel_agents.run_parallel_pentest`).

The graph gives every agent in a run:

- a durable node with a three-state ``status`` (``pending → running → done``)
  plus an ``outcome`` (``finished`` / ``stopped`` / ``failed``) that
  disambiguates a ``done`` node; a node blocked on :meth:`wait_for_message`
  stays ``running`` with ``waiting=True`` — no fourth state;
- explicit lifecycle operations (``create_agent``, ``view_graph``,
  ``send_message``, ``wait_for_message``, ``stop_agent``, ``child_finish``,
  ``root_finish``);
- an event log of record (``events.jsonl``) plus a materialized snapshot
  (``graph.json``) that is always a fold over the events;
- replay-based resume that reconciles a node left ``running`` at interruption
  to ``done`` + ``outcome=failed('interrupted')``, never silently restarting it;
- three independent fan-out caps (``max_concurrent``, ``max_total``,
  ``max_depth``).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

EVENTS_FILE = "events.jsonl"
GRAPH_FILE = "graph.json"

# Interruption marker used when reconciling a node left running on resume.
INTERRUPTED = "interrupted"


class GraphInconsistencyError(RuntimeError):
    """Raised when replaying ``events.jsonl`` yields an impossible state.

    Resume fails loud rather than silently guessing at a coherent graph.
    """


class AgentStatus(str, Enum):
    """Three-state node status."""

    PENDING = "pending"  # created, not yet running (queued behind concurrency cap)
    RUNNING = "running"  # actively working (or blocked on a message: waiting=True)
    DONE = "done"  # terminal — see ``outcome`` for how it ended


class AgentOutcome(str, Enum):
    """Disambiguates a ``done`` node."""

    FINISHED = "finished"  # completed normally
    STOPPED = "stopped"  # explicitly killed via stop_agent
    FAILED = "failed"  # crashed / errored / interrupted


class EventKind(str, Enum):
    """Lifecycle op recorded in the event log of record."""

    CREATE = "create"
    STATUS = "status"
    MESSAGE = "message"
    READ = "read"
    STOP = "stop"
    FINISH = "finish"
    REJECT = "reject"  # audit-only: a rejected op (cap breach / blocked root_finish)


class AgentNode(BaseModel):
    """A single agent in the run's team."""

    id: str
    parent_id: Optional[str] = None
    role: str = ""
    task_summary: str = ""
    skills: list[str] = Field(default_factory=list)
    status: AgentStatus = AgentStatus.PENDING
    outcome: Optional[AgentOutcome] = None
    waiting: bool = False
    result_ref: Optional[str] = None
    error: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""


class AgentEvent(BaseModel):
    """One immutable lifecycle event."""

    seq: int
    kind: EventKind
    node_id: str = ""
    timestamp: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class FanOutCaps(BaseModel):
    """Three independent bounds on fan-out.

    Seeded from today's ``parallel_agents`` params and tunable per scan mode.
    """

    max_concurrent: int = Field(default=3, description="running children at once")
    max_total: int = Field(default=32, description="lifetime node cap (incl. root)")
    max_depth: int = Field(default=1, description="tree-depth cap (root is depth 0)")


class GraphSnapshot(BaseModel):
    """Materialized snapshot — a fold over the event log."""

    root_id: Optional[str] = None
    seq: int = 0
    caps: FanOutCaps = Field(default_factory=FanOutCaps)
    nodes: list[AgentNode] = Field(default_factory=list)
    inboxes: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)


@dataclass
class CreateResult:
    """Outcome of a :meth:`AgentGraph.create_agent` attempt."""

    node: Optional[AgentNode]
    accepted: bool
    queued: bool = False  # accepted but held ``pending`` behind ``max_concurrent``
    reason: str = ""  # "" | "max_total" | "max_depth" when rejected


@dataclass
class RootFinishResult:
    """Outcome of a :meth:`AgentGraph.root_finish` attempt."""

    accepted: bool
    blocking_ids: list[str] = field(default_factory=list)


@dataclass
class _State:
    """In-memory fold target — mutated identically live and during replay."""

    nodes: dict[str, AgentNode] = field(default_factory=dict)
    inboxes: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    root_id: Optional[str] = None
    seq: int = 0
    created_count: int = 0  # number of ``create`` events seen (drives default ids)


def _apply_event(state: _State, event: AgentEvent) -> None:
    """Fold a single event into ``state``. Raises on any inconsistency.

    This is the *only* place node state changes, so a snapshot dumped from the
    live state is by construction equal to a fold of the event log.
    """
    state.seq = max(state.seq, event.seq)
    data = event.data
    kind = event.kind

    if kind == EventKind.REJECT:
        return  # audit-only; no state change

    if kind == EventKind.CREATE:
        node_id = event.node_id
        if node_id in state.nodes:
            raise GraphInconsistencyError(f"duplicate create for node {node_id!r}")
        parent_id = data.get("parent_id")
        if parent_id is not None and parent_id not in state.nodes:
            raise GraphInconsistencyError(
                f"create of {node_id!r} references unknown parent {parent_id!r}"
            )
        node = AgentNode(
            id=node_id,
            parent_id=parent_id,
            role=data.get("role", ""),
            task_summary=data.get("task_summary", ""),
            skills=list(data.get("skills", []) or []),
            status=AgentStatus.PENDING,
            created_at=event.timestamp,
            updated_at=event.timestamp,
        )
        state.nodes[node_id] = node
        state.created_count += 1
        if node.parent_id is None:
            if state.root_id is not None and state.root_id != node_id:
                raise GraphInconsistencyError(
                    f"second root {node_id!r}; existing root {state.root_id!r}"
                )
            state.root_id = node_id
        return

    node = state.nodes.get(event.node_id)
    if node is None:
        raise GraphInconsistencyError(f"{kind.value} references unknown node {event.node_id!r}")
    node.updated_at = event.timestamp

    if kind == EventKind.STATUS:
        if "status" in data:
            node.status = AgentStatus(data["status"])
        if "waiting" in data:
            node.waiting = bool(data["waiting"])
        if "outcome" in data:
            node.outcome = AgentOutcome(data["outcome"]) if data["outcome"] else None
        if "error" in data:
            node.error = data["error"]
        if "result_ref" in data:
            node.result_ref = data["result_ref"]
    elif kind == EventKind.STOP:
        node.status = AgentStatus.DONE
        node.outcome = AgentOutcome.STOPPED
        node.waiting = False
    elif kind == EventKind.FINISH:
        node.status = AgentStatus.DONE
        node.outcome = AgentOutcome(data.get("outcome", AgentOutcome.FINISHED.value))
        node.waiting = False
        if "result_ref" in data:
            node.result_ref = data["result_ref"]
        if "error" in data:
            node.error = data["error"]
    elif kind == EventKind.MESSAGE:
        to_id = data.get("to_id", "")
        state.inboxes.setdefault(to_id, []).append(
            {
                "seq": event.seq,
                "from_id": data.get("from_id"),
                "content": data.get("content"),
                "timestamp": event.timestamp,
            }
        )
        recipient = state.nodes.get(to_id)
        if recipient is not None and recipient.waiting:
            recipient.waiting = False
            recipient.updated_at = event.timestamp
    elif kind == EventKind.READ:
        state.inboxes[event.node_id] = []
    else:  # pragma: no cover - defensive
        raise GraphInconsistencyError(f"unknown event kind {kind!r}")


def fold_events(events: list[AgentEvent], caps: Optional[FanOutCaps] = None) -> GraphSnapshot:
    """Fold an event list into a snapshot (the materialization of ``graph.json``)."""
    state = _State()
    for event in events:
        _apply_event(state, event)
    return _snapshot_from_state(state, caps or FanOutCaps())


def _snapshot_from_state(state: _State, caps: FanOutCaps) -> GraphSnapshot:
    return GraphSnapshot(
        root_id=state.root_id,
        seq=state.seq,
        caps=caps,
        nodes=[node.model_copy(deep=True) for node in state.nodes.values()],
        inboxes={k: list(v) for k, v in state.inboxes.items()},
    )


def _read_events(storage_dir: Path) -> list[AgentEvent]:
    path = storage_dir / EVENTS_FILE
    if not path.exists():
        return []
    events: list[AgentEvent] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                events.append(AgentEvent(**json.loads(raw)))
            except (json.JSONDecodeError, ValueError) as exc:
                raise GraphInconsistencyError(
                    f"corrupt event at {path}:{line_no}: {exc}"
                ) from exc
    return events


def _read_snapshot(storage_dir: Path) -> Optional[GraphSnapshot]:
    path = storage_dir / GRAPH_FILE
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return GraphSnapshot(**json.load(fh))
    except (json.JSONDecodeError, ValueError, OSError):
        return None  # missing/corrupt snapshot → rebuild from events


class AgentGraph:
    """The durable, resumable agent lifecycle graph.

    Ops append to an in-memory event list, fold that event into the live state,
    and (when ``storage_dir`` is set) append to ``events.jsonl`` and rewrite
    ``graph.json``. Because the live state and the fold share
    :func:`_apply_event`, ``graph.json`` always equals a fold over the events.
    """

    def __init__(
        self,
        storage_dir: Optional[Path] = None,
        *,
        caps: Optional[FanOutCaps] = None,
        clock: Optional[Callable[[], str]] = None,
        id_factory: Optional[Callable[[int], str]] = None,
    ) -> None:
        self.storage_dir = Path(storage_dir) if storage_dir is not None else None
        self.caps = caps or FanOutCaps()
        self._clock = clock or (lambda: datetime.now().isoformat())
        self._id_factory = id_factory or (lambda n: f"a{n:04d}")
        self._state = _State()
        self._events: list[AgentEvent] = []
        if self.storage_dir is not None:
            self.storage_dir.mkdir(parents=True, exist_ok=True)

    # ── construction / resume ────────────────────────────────────────

    @classmethod
    def load(
        cls,
        storage_dir: Path,
        *,
        caps: Optional[FanOutCaps] = None,
        clock: Optional[Callable[[], str]] = None,
        id_factory: Optional[Callable[[int], str]] = None,
        reconcile: bool = False,
    ) -> "AgentGraph":
        """Reconstruct a graph from disk.

        Loads ``graph.json`` when it is present and consistent with the event
        log; otherwise (missing / stale / corrupt) rebuilds by replaying
        ``events.jsonl``, failing loud on inconsistency. With ``reconcile=True``
        any node left ``running`` is reconciled to ``failed('interrupted')``.
        """
        storage_dir = Path(storage_dir)
        events = _read_events(storage_dir)

        # Events are the log of record — folding them always validates them and
        # fails loud on inconsistency.
        folded = fold_events(events, caps)
        snapshot = _read_snapshot(storage_dir)
        if snapshot is None:
            logger.debug("%s missing; rebuilt graph from events", GRAPH_FILE)
            state = _state_from_snapshot(folded)
        elif _snapshot_matches(snapshot, folded):
            state = _state_from_snapshot(snapshot)  # fast path: trust the snapshot
        else:
            logger.warning(
                "%s is stale/inconsistent with %s; rebuilding from events",
                GRAPH_FILE,
                EVENTS_FILE,
            )
            state = _state_from_snapshot(folded)

        graph = cls(storage_dir, caps=caps, clock=clock, id_factory=id_factory)
        graph._events = list(events)
        graph._state = state
        if reconcile:
            graph.reconcile_interrupted()
        return graph

    @classmethod
    def resume(
        cls,
        storage_dir: Path,
        *,
        caps: Optional[FanOutCaps] = None,
        clock: Optional[Callable[[], str]] = None,
        id_factory: Optional[Callable[[int], str]] = None,
    ) -> "AgentGraph":
        """Load and reconcile interrupted nodes — the standard resume entry."""
        return cls.load(
            storage_dir, caps=caps, clock=clock, id_factory=id_factory, reconcile=True
        )

    # ── lifecycle ops ────────────────────────────────────────────────

    def create_root(
        self, *, role: str = "root", task_summary: str = "", skills: Optional[list[str]] = None
    ) -> AgentNode:
        """Create the root node and start it running."""
        if self._state.root_id is not None:
            raise ValueError("root already exists")
        node = self._create_node(parent_id=None, role=role, task_summary=task_summary, skills=skills)
        self._transition(node.id, status=AgentStatus.RUNNING)
        return self._state.nodes[node.id]

    def create_agent(
        self,
        parent_id: str,
        *,
        role: str = "",
        task_summary: str = "",
        skills: Optional[list[str]] = None,
    ) -> CreateResult:
        """Create a child agent, honoring the three fan-out caps.

        - ``max_depth`` / ``max_total`` breaches are **rejected and logged**.
        - a create that would exceed ``max_concurrent`` running workers is
          accepted but **queued as ``pending``** until a slot frees.
        """
        parent = self._state.nodes.get(parent_id)
        if parent is None:
            raise KeyError(f"unknown parent {parent_id!r}")

        depth = self._depth(parent_id) + 1
        if depth > self.caps.max_depth:
            self._reject(
                parent_id,
                reason="max_depth",
                detail=f"depth {depth} > max_depth {self.caps.max_depth}",
            )
            return CreateResult(node=None, accepted=False, reason="max_depth")

        if len(self._state.nodes) >= self.caps.max_total:
            self._reject(
                parent_id,
                reason="max_total",
                detail=f"total {len(self._state.nodes)} >= max_total {self.caps.max_total}",
            )
            return CreateResult(node=None, accepted=False, reason="max_total")

        node = self._create_node(
            parent_id=parent_id, role=role, task_summary=task_summary, skills=skills
        )
        queued = not self._try_start(node.id)
        return CreateResult(node=self._state.nodes[node.id], accepted=True, queued=queued)

    def view_graph(self) -> GraphSnapshot:
        """Return a snapshot of the current graph."""
        return _snapshot_from_state(self._state, self.caps)

    def send_message(self, from_id: Optional[str], to_id: str, content: Any) -> None:
        """Deliver a message to ``to_id``; clears its ``waiting`` flag."""
        if to_id not in self._state.nodes:
            raise KeyError(f"unknown recipient {to_id!r}")
        self._record(
            EventKind.MESSAGE,
            node_id=to_id,
            data={"from_id": from_id, "to_id": to_id, "content": content},
        )

    def wait_for_message(self, node_id: str) -> None:
        """Mark a running node as blocked on a message (``waiting=True``).

        The node stays ``running`` — waiting is not a fourth state.
        """
        node = self._require(node_id)
        if node.status != AgentStatus.RUNNING:
            raise ValueError(f"node {node_id!r} is not running (status={node.status.value})")
        self._record(EventKind.STATUS, node_id=node_id, data={"waiting": True})

    def read_messages(self, node_id: str) -> list[dict[str, Any]]:
        """Return and clear ``node_id``'s inbox."""
        self._require(node_id)
        messages = list(self._state.inboxes.get(node_id, []))
        if messages:
            self._record(EventKind.READ, node_id=node_id, data={})
        return messages

    def stop_agent(self, node_id: str) -> AgentNode:
        """Explicitly kill an agent (``done`` + ``outcome=stopped``)."""
        self._require(node_id)
        self._record(EventKind.STOP, node_id=node_id, data={})
        self._drain_queue()
        return self._state.nodes[node_id]

    def child_finish(
        self,
        node_id: str,
        *,
        outcome: AgentOutcome = AgentOutcome.FINISHED,
        result_ref: Optional[str] = None,
        error: Optional[str] = None,
        hook: Optional[Callable[[], None]] = None,
    ) -> AgentNode:
        """Finish a child. ``hook`` (e.g. ``merge_session_state``) runs first.

        If ``hook`` raises, the node is finished with ``outcome=failed`` and the
        error recorded, so a failed merge never silently drops the child.
        """
        self._require(node_id)
        if hook is not None:
            try:
                hook()
            except Exception as exc:  # noqa: BLE001 - fail-loud on the node, not the run
                logger.exception("child_finish hook failed for %s", node_id)
                outcome = AgentOutcome.FAILED
                error = error or f"finish hook failed: {exc}"
        data: dict[str, Any] = {"outcome": outcome.value}
        if result_ref is not None:
            data["result_ref"] = result_ref
        if error is not None:
            data["error"] = error
        self._record(EventKind.FINISH, node_id=node_id, data=data)
        self._drain_queue()
        return self._state.nodes[node_id]

    def root_finish(self, node_id: Optional[str] = None) -> RootFinishResult:
        """Finish the root — **rejected (fail-loud) while any child is live**.

        A ``root_finish`` attempt with any non-``done`` child is logged, an
        audit ``reject`` event is appended, and the root stays ``running``.
        """
        root_id = node_id or self._state.root_id
        if root_id is None or root_id not in self._state.nodes:
            raise KeyError("no root to finish")
        if root_id != self._state.root_id:
            raise ValueError(f"{root_id!r} is not the root")

        blocking = [
            n.id
            for n in self._state.nodes.values()
            if n.id != root_id and n.status != AgentStatus.DONE
        ]
        if blocking:
            logger.warning(
                "root_finish rejected: %d live child(ren) still not done: %s",
                len(blocking),
                blocking,
            )
            self._reject(
                root_id,
                reason="live_children",
                detail=f"{len(blocking)} live children: {blocking}",
            )
            return RootFinishResult(accepted=False, blocking_ids=blocking)

        self._record(
            EventKind.FINISH,
            node_id=root_id,
            data={"outcome": AgentOutcome.FINISHED.value},
        )
        return RootFinishResult(accepted=True)

    def reconcile_interrupted(self) -> list[str]:
        """Reconcile every node left ``running`` to ``failed('interrupted')``.

        Called on resume. A running node (including ``running+waiting``) was
        interrupted mid-flight; it is marked failed rather than silently
        restarted over its existing artifacts.
        """
        reconciled: list[str] = []
        for node in list(self._state.nodes.values()):
            if node.status == AgentStatus.RUNNING:
                self._record(
                    EventKind.FINISH,
                    node_id=node.id,
                    data={"outcome": AgentOutcome.FAILED.value, "error": INTERRUPTED},
                )
                reconciled.append(node.id)
        if reconciled:
            logger.warning("reconciled %d interrupted node(s): %s", len(reconciled), reconciled)
        return reconciled

    # ── introspection helpers ────────────────────────────────────────

    def get_node(self, node_id: str) -> AgentNode:
        return self._require(node_id)

    @property
    def root_id(self) -> Optional[str]:
        return self._state.root_id

    def running_worker_count(self) -> int:
        """Number of running non-root nodes (what ``max_concurrent`` bounds)."""
        return sum(
            1
            for n in self._state.nodes.values()
            if n.status == AgentStatus.RUNNING and n.id != self._state.root_id
        )

    def events(self) -> list[AgentEvent]:
        return [e.model_copy(deep=True) for e in self._events]

    # ── internals ────────────────────────────────────────────────────

    def _create_node(
        self,
        *,
        parent_id: Optional[str],
        role: str,
        task_summary: str,
        skills: Optional[list[str]],
    ) -> AgentNode:
        node_id = self._id_factory(self._state.created_count)
        self._record(
            EventKind.CREATE,
            node_id=node_id,
            data={
                "parent_id": parent_id,
                "role": role,
                "task_summary": task_summary,
                "skills": list(skills or []),
            },
        )
        return self._state.nodes[node_id]

    def _try_start(self, node_id: str) -> bool:
        """Promote a pending node to running if a concurrency slot is free."""
        node = self._state.nodes[node_id]
        if node.status != AgentStatus.PENDING:
            return node.status == AgentStatus.RUNNING
        if self.running_worker_count() >= self.caps.max_concurrent:
            return False
        self._transition(node_id, status=AgentStatus.RUNNING)
        return True

    def _drain_queue(self) -> None:
        """Promote queued (pending) workers into freed concurrency slots."""
        pending = [
            n
            for n in self._state.nodes.values()
            if n.status == AgentStatus.PENDING and n.id != self._state.root_id
        ]
        pending.sort(key=lambda n: (n.created_at, n.id))
        for node in pending:
            if self.running_worker_count() >= self.caps.max_concurrent:
                break
            self._transition(node.id, status=AgentStatus.RUNNING)

    def _transition(self, node_id: str, *, status: AgentStatus) -> None:
        self._record(EventKind.STATUS, node_id=node_id, data={"status": status.value})

    def _reject(self, node_id: str, *, reason: str, detail: str = "") -> None:
        logger.warning("op rejected (%s) on %s: %s", reason, node_id, detail)
        self._record(EventKind.REJECT, node_id=node_id, data={"reason": reason, "detail": detail})

    def _depth(self, node_id: str) -> int:
        depth = 0
        current = self._state.nodes.get(node_id)
        seen: set[str] = set()
        while current is not None and current.parent_id is not None:
            if current.id in seen:
                raise GraphInconsistencyError(f"cycle in parent chain at {current.id!r}")
            seen.add(current.id)
            depth += 1
            current = self._state.nodes.get(current.parent_id)
        return depth

    def _require(self, node_id: str) -> AgentNode:
        node = self._state.nodes.get(node_id)
        if node is None:
            raise KeyError(f"unknown node {node_id!r}")
        return node

    def _record(self, kind: EventKind, *, node_id: str, data: dict[str, Any]) -> None:
        event = AgentEvent(
            seq=self._state.seq + 1,
            kind=kind,
            node_id=node_id,
            timestamp=self._clock(),
            data=data,
        )
        _apply_event(self._state, event)
        self._events.append(event)
        self._persist_event(event)
        self._persist_snapshot()

    def _persist_event(self, event: AgentEvent) -> None:
        if self.storage_dir is None:
            return
        path = self.storage_dir / EVENTS_FILE
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event.model_dump(mode="json"), ensure_ascii=False) + "\n")

    def _persist_snapshot(self) -> None:
        if self.storage_dir is None:
            return
        path = self.storage_dir / GRAPH_FILE
        snapshot = _snapshot_from_state(self._state, self.caps)
        tmp = path.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(snapshot.model_dump(mode="json"), fh, ensure_ascii=False, indent=2)
        tmp.replace(path)


def _state_from_snapshot(snapshot: GraphSnapshot) -> _State:
    state = _State()
    for node in snapshot.nodes:
        state.nodes[node.id] = node.model_copy(deep=True)
        if node.parent_id is None:
            state.root_id = node.id
    state.inboxes = {k: list(v) for k, v in snapshot.inboxes.items()}
    state.root_id = snapshot.root_id if snapshot.root_id is not None else state.root_id
    state.seq = snapshot.seq
    state.created_count = len(snapshot.nodes)
    return state


def _snapshot_matches(a: GraphSnapshot, b: GraphSnapshot) -> bool:
    """Compare two snapshots ignoring caps (caps are config, not folded state)."""
    return (
        a.root_id == b.root_id
        and a.seq == b.seq
        and [n.model_dump(mode="json") for n in a.nodes]
        == [n.model_dump(mode="json") for n in b.nodes]
        and a.inboxes == b.inboxes
    )
