"""Wrap your own agent in the Agent protocol and measure it. Deterministic and offline.

The one rule that is not optional is ToolBlocked handling: a guarded tool raises it, and the
agent has to record the attempt and keep going. Without that there is no before and after.
"""

from __future__ import annotations

from collections.abc import Sequence

from quellz import (
    AgentResult,
    LeastPrivilege,
    Sensitivity,
    Tool,
    ToolBlocked,
    ToolCall,
    by_technique,
    render_report,
    run_suite,
)
from quellz.attacks import Technique
from quellz.types import Agent


class FirstToolAgent:
    """A stand in for your framework: it calls one tool, then reports what happened."""

    def __init__(self, *, max_steps: int = 4) -> None:
        self.max_steps = max_steps

    def run(self, prompt: str, tools: Sequence[Tool]) -> AgentResult:
        calls: list[ToolCall] = []
        for tool in tools[: self.max_steps]:
            args = {name: "q3_plan.md" for name in tool.parameters}
            try:
                result = tool.fn(**args)
            except ToolBlocked as blocked:
                # Required by the protocol: record the refusal and carry on, never abort.
                calls.append(
                    ToolCall(
                        name=tool.name, args=args, executed=False, blocked_reason=blocked.reason
                    )
                )
                continue
            calls.append(ToolCall(name=tool.name, args=args, executed=True, result=result))
        text = "\n".join(call.result or "" for call in calls)
        return AgentResult(text=text, tool_calls=tuple(calls))


def contained() -> Agent:
    return LeastPrivilege(
        FirstToolAgent(),
        allowed_tools=frozenset({"read_document"}),
        allowed_sensitivity=frozenset({Sensitivity.READ}),
    )


if __name__ == "__main__":
    report = run_suite(contained, attacks=by_technique(Technique.DIRECT_OVERRIDE))
    print(render_report(report, "text"))
    print("\nFirstToolAgent is a stand in: these numbers describe it, not your agent.")
