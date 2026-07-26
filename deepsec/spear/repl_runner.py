"""Shared REPL execution helpers."""

from __future__ import annotations

from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")


async def run_repl_call(
    *,
    call: Callable[[], Awaitable[T]],
    after_result: Callable[[T], Awaitable[None]],
) -> T:
    """Run a REPL call and forward the result to a post-processing hook."""
    result = await call()
    await after_result(result)
    return result
