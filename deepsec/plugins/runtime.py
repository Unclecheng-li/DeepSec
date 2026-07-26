from __future__ import annotations

import asyncio
import inspect
import time
from typing import Any
from urllib.parse import urlparse

# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: 消除 V4 违规 — validate_action_constraints 已移至 config/domain_models.py。
from deepsec.config.domain_models import validate_action_constraints
from deepsec.plugins.base import PluginContext, VulnPlugin
from deepsec.plugins.registry import PluginRegistry, registry
from deepsec.plugins.result import PluginResult, PluginStage

PluginRequest = PluginContext


class PluginRuntime:
    def __init__(
        self,
        plugin_registry: PluginRegistry | None = None,
        *,
        config: Any = None,
        allowed_targets: set[str] | None = None,
    ) -> None:
        self.registry = plugin_registry or registry
        self.config = config
        self.allowed_targets = set(allowed_targets or ())
        self._request_counts: dict[str, int] = {}

    async def execute(
        self,
        plugin_id: str,
        context: PluginContext | dict[str, Any] | None = None,
    ) -> PluginResult:
        normalized_context = self._coerce_context(context)
        plugin_cls = self.registry.get(plugin_id)
        stage = normalized_context.stage
        started = time.monotonic()

        gate = self._preflight(plugin_id, plugin_cls, normalized_context)
        if gate is not None:
            return gate

        assert plugin_cls is not None
        self._consume_budget(normalized_context.target, plugin_cls.request_cost)
        remaining = self.remaining_requests(normalized_context.target)
        timeout = self._timeout_for(plugin_cls, normalized_context)
        plugin = plugin_cls()

        try:
            raw = plugin.run(normalized_context)
            if inspect.isawaitable(raw):
                raw = await asyncio.wait_for(raw, timeout=timeout)
            elif timeout is not None:
                raw = await asyncio.wait_for(asyncio.to_thread(lambda: raw), timeout=timeout)
        except (asyncio.TimeoutError, TimeoutError):
            # Python 3.10 下 asyncio.wait_for 抛 asyncio.TimeoutError（与内置 TimeoutError
            # 不是同一类，3.11 起才合并），两者都捕获以保证跨版本一致
            result = PluginResult.error_result(
                plugin_id,
                "Plugin execution timed out",
                stage=stage,
                error_type="timeout",
                remaining_requests=remaining,
            )
        except Exception as exc:
            result = PluginResult.error_result(
                plugin_id,
                f"{type(exc).__name__}: {exc}",
                stage=stage,
                error_type="error",
                remaining_requests=remaining,
            )
        else:
            result = self._coerce_result(plugin_id, raw, stage=stage, remaining_requests=remaining)

        result.elapsed_seconds = time.monotonic() - started
        return result

    run = execute

    def remaining_requests(self, target: str | None) -> int | None:
        limit = self._max_requests_per_target()
        if limit is None:
            return None
        return max(limit - self._request_counts.get(self._budget_key(target), 0), 0)

    def _preflight(
        self,
        plugin_id: str,
        plugin_cls: type[VulnPlugin] | None,
        context: PluginContext,
    ) -> PluginResult | None:
        if not self._runtime_enabled():
            return PluginResult.skipped_result(
                plugin_id,
                "Plugin runtime is disabled",
                stage=context.stage,
                error_type="disabled",
            )

        remaining = self.remaining_requests(context.target)
        if plugin_cls is None:
            return PluginResult.skipped_result(
                plugin_id,
                "Plugin was not found",
                stage=context.stage,
                error_type="not_found",
                remaining_requests=remaining,
            )

        if not plugin_cls.enabled:
            return PluginResult.skipped_result(
                plugin_id,
                "Plugin is disabled",
                stage=context.stage,
                error_type="disabled",
                remaining_requests=remaining,
            )

        if plugin_cls.destructive and not context.allow_destructive:
            return PluginResult.skipped_result(
                plugin_id,
                "Destructive plugin execution requires explicit permission",
                stage=context.stage,
                error_type="blocked",
                remaining_requests=remaining,
            )

        target_error = self._target_error(plugin_cls, context)
        if target_error is not None:
            return PluginResult.skipped_result(
                plugin_id,
                target_error,
                stage=context.stage,
                error_type="target_blocked",
                remaining_requests=remaining,
            )

        policy_error = self._policy_error(plugin_cls, context)
        if policy_error is not None:
            return PluginResult.skipped_result(
                plugin_id,
                policy_error,
                stage=context.stage,
                error_type="constraint_violation",
                remaining_requests=remaining,
            )

        if remaining == 0:
            return PluginResult.skipped_result(
                plugin_id,
                "Plugin request budget is exhausted for target",
                stage=context.stage,
                error_type="budget_exhausted",
                remaining_requests=0,
            )

        return None

    def _target_error(self, plugin_cls: type[VulnPlugin], context: PluginContext) -> str | None:
        if plugin_cls.requires_target and not context.target:
            return "Plugin requires a target"

        target = context.target
        if not target:
            return None

        host = self._host_for(target)
        if self.allowed_targets and target not in self.allowed_targets and host not in self.allowed_targets:
            return "Target is outside runtime scope"

        if context.scope_targets and target not in context.scope_targets and host not in context.scope_targets:
            return "Target is outside request scope"

        return None

    def _policy_error(self, plugin_cls: type[VulnPlugin], context: PluginContext) -> str | None:
        constraints = context.task_constraints
        if constraints is None or getattr(constraints, "is_empty", lambda: True)():
            return None

        action = self._action_for(plugin_cls, context.stage)
        action_error = validate_action_constraints(action, constraints)
        if action_error is not None:
            return action_error

        host = self._host_for(context.target)
        port = self._port_for(context.target)
        path = self._path_for(context.target)

        if host:
            allowed_hosts = set(getattr(constraints, "allowed_hosts", []) or [])
            blocked_hosts = set(getattr(constraints, "blocked_hosts", []) or [])
            if allowed_hosts and host not in allowed_hosts and context.target not in allowed_hosts:
                return f"constraint_violation: host '{host}' is outside allowed hosts"
            if host in blocked_hosts or context.target in blocked_hosts:
                return f"constraint_violation: host '{host}' is blocked"

        if port is not None:
            allowed_ports = set(getattr(constraints, "allowed_ports", []) or [])
            blocked_ports = set(getattr(constraints, "blocked_ports", []) or [])
            if allowed_ports and port not in allowed_ports:
                return f"constraint_violation: port '{port}' is outside allowed ports"
            if port in blocked_ports:
                return f"constraint_violation: port '{port}' is blocked"

        if path:
            allowed_paths = set(getattr(constraints, "allowed_paths", []) or [])
            blocked_paths = set(getattr(constraints, "blocked_paths", []) or [])
            if allowed_paths and path not in allowed_paths:
                return f"constraint_violation: path '{path}' is outside allowed paths"
            if path in blocked_paths:
                return f"constraint_violation: path '{path}' is blocked"

        return None

    def _coerce_context(self, context: PluginContext | dict[str, Any] | None) -> PluginContext:
        if context is None:
            return PluginContext()
        if isinstance(context, PluginContext):
            return context
        return PluginContext(**context)

    def _coerce_result(
        self,
        plugin_id: str,
        raw: Any,
        *,
        stage: PluginStage,
        remaining_requests: int | None,
    ) -> PluginResult:
        if isinstance(raw, PluginResult):
            raw.remaining_requests = remaining_requests
            return raw
        if isinstance(raw, dict):
            return PluginResult(
                plugin_id=plugin_id,
                stage=stage,
                metadata=dict(raw),
                remaining_requests=remaining_requests,
            )
        return PluginResult(
            plugin_id=plugin_id,
            stage=stage,
            metadata={"result": raw},
            remaining_requests=remaining_requests,
        )

    def _runtime_enabled(self) -> bool:
        return bool(self._session_value("plugin_runtime_enabled", True))

    def _timeout_for(self, plugin_cls: type[VulnPlugin], context: PluginContext) -> float | None:
        value = context.timeout_seconds or plugin_cls.timeout_seconds
        if value is None:
            value = self._session_value("plugin_default_timeout", None)
        if value is None:
            return None
        return float(value)

    def _max_requests_per_target(self) -> int | None:
        value = self._session_value("plugin_max_requests_per_target", None)
        if value is None:
            return None
        limit = int(value)
        if limit < 1:
            return None
        return limit

    def _consume_budget(self, target: str | None, cost: int) -> None:
        key = self._budget_key(target)
        self._request_counts[key] = self._request_counts.get(key, 0) + max(1, cost)

    def _budget_key(self, target: str | None) -> str:
        return target or "__global__"

    def _session_value(self, name: str, default: Any) -> Any:
        session = getattr(self.config, "session", self.config)
        return getattr(session, name, default)

    def _action_for(self, plugin_cls: type[VulnPlugin], stage: PluginStage) -> str:
        if plugin_cls.destructive:
            return "exploit"
        if stage == PluginStage.RECON:
            return "recon"
        if stage == PluginStage.EXPLOITATION:
            return "exploit"
        if stage == PluginStage.POST_EXPLOITATION:
            return "post_exploitation"
        if stage == PluginStage.REPORTING:
            return "report"
        return "scan"

    def _host_for(self, target: str) -> str:
        if not target:
            return ""
        parsed = urlparse(target if "://" in target else f"//{target}")
        return (parsed.hostname or target).lower().rstrip(".")

    def _port_for(self, target: str) -> int | None:
        if not target:
            return None
        parsed = urlparse(target if "://" in target else f"//{target}")
        if parsed.port is not None:
            return parsed.port
        if parsed.scheme == "https":
            return 443
        if parsed.scheme == "http":
            return 80
        return None

    def _path_for(self, target: str) -> str:
        if not target:
            return ""
        parsed = urlparse(target if "://" in target else f"//{target}")
        return parsed.path or ""
