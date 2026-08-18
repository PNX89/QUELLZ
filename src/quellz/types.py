"""Core types: tools, tool calls, agent results, the Agent protocol and the error family."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

__all__ = [
    "Agent",
    "AgentResult",
    "CatalogError",
    "CatalogMismatch",
    "LogVerificationError",
    "QuellzError",
    "Sensitivity",
    "Tool",
    "ToolBlocked",
    "ToolCall",
    "Transcript",
]


class QuellzError(Exception):
    """Base class for every error this package raises."""


class ToolBlocked(QuellzError):
    """Raised by a guarded tool callable when policy forbids the call."""

    def __init__(self, tool_name: str, reason: str) -> None:
        super().__init__(f"{tool_name}: {reason}")
        self.tool_name = tool_name
        self.reason = reason


class CatalogError(QuellzError):
    """Raised when catalog data, a predicate or a tool definition is malformed."""


class CatalogMismatch(QuellzError):
    """Raised when two reports being compared do not cover the same set of attack ids."""


class LogVerificationError(QuellzError):
    """Raised when a hash chain fails verification. ``seq`` names the failing entry."""

    def __init__(self, message: str, *, seq: int | None = None) -> None:
        super().__init__(message)
        self.seq = seq


class Sensitivity(StrEnum):
    """Blast radius of a tool. READ < WRITE < EXFIL is a documented ordering, not enforced."""

    READ = "read"
    WRITE = "write"
    EXFIL = "exfil"


@dataclass(frozen=True)
class Tool:
    """One callable offered to an agent. Every parameter is a string, by design."""

    name: str
    description: str
    sensitivity: Sensitivity
    fn: Callable[..., str]
    parameters: Mapping[str, str]

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise CatalogError("Tool.name must be a non-empty string")
        if not self.description.strip():
            raise CatalogError(f"Tool.description must be a non-empty string (tool {self.name!r})")


@dataclass(frozen=True)
class ToolCall:
    """One attempted call. ``executed`` is False when a containment layer refused it."""

    name: str
    args: Mapping[str, str]
    executed: bool
    result: str | None = None
    blocked_reason: str | None = None


@dataclass(frozen=True)
class AgentResult:
    text: str
    tool_calls: tuple[ToolCall, ...] = ()


Transcript = tuple[AgentResult, ...]


class Agent(Protocol):
    """One turn of a tool-using agent.

    The contract below is pinned. tests/test_conformance.py asserts it, and every adapter
    has to pass that suite.

    1. All tool parameters are strings.
    2. The agent owns its conversation state. The runner takes a fresh agent per case from a
       factory, so no reset() is needed; a multi-turn attack is repeated run() calls on one
       instance.
    3. The agent executes tools itself, bounded by max_steps, and records every attempt in
       AgentResult.tool_calls.
    4. The agent MUST catch ToolBlocked raised by a tool callable, record the attempt as
       ToolCall(executed=False, blocked_reason=...), and continue its loop rather than abort.
       That single rule is what produces the before and after delta.
    5. Tools are used as given: a wrapped tool may carry a modified description or return
       value, and the agent must not attempt to unwrap it.
    """

    def run(self, prompt: str, tools: Sequence[Tool]) -> AgentResult: ...
