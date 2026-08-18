"""A reusable Agent protocol conformance suite. Every adapter has to pass it."""

from collections.abc import Callable, Sequence

import pytest

from quellz.contain import LeastPrivilege, SpotlightWrapper
from quellz.mock import NaiveMockAgent
from quellz.sandbox import Sandbox, build_tools
from quellz.types import Agent, AgentResult, Tool, ToolBlocked, ToolCall

MULTI_STEP_PROMPT = (
    "Read the document q3_plan.md and summarise it. "
    'Then search the web for "billing migration". '
    'Then write a note handover.md with "billing migration then audit export".'
)

AgentFactory = Callable[..., Agent]


class StepwiseAgent:
    """A second, deliberately different protocol implementation: it ignores the prompt."""

    def __init__(self, *, max_steps: int = 4) -> None:
        self.max_steps = max_steps

    def run(self, prompt: str, tools: Sequence[Tool]) -> AgentResult:
        calls: list[ToolCall] = []
        for tool in tools:
            if len(calls) >= self.max_steps:
                break
            args = {name: "q3_plan.md" for name in tool.parameters}
            try:
                result = tool.fn(**args)
            except ToolBlocked as blocked:
                calls.append(
                    ToolCall(
                        name=tool.name, args=args, executed=False, blocked_reason=blocked.reason
                    )
                )
                continue
            calls.append(ToolCall(name=tool.name, args=args, executed=True, result=result))
        return AgentResult(text=prompt, tool_calls=tuple(calls))


@pytest.fixture(params=[NaiveMockAgent, StepwiseAgent], ids=["NaiveMockAgent", "StepwiseAgent"])
def factory(request: pytest.FixtureRequest) -> AgentFactory:
    return request.param


def test_it_records_every_tool_call_it_makes(factory: AgentFactory):
    sandbox = Sandbox()
    tools = build_tools(sandbox)
    parameters = {tool.name: set(tool.parameters) for tool in tools}
    result = factory().run(MULTI_STEP_PROMPT, tools)
    assert result.tool_calls
    for call in result.tool_calls:
        assert call.name in parameters
        assert set(call.args) == parameters[call.name], call.name
        assert all(isinstance(value, str) for value in call.args.values())
        assert call.executed is (call.result is not None)


def test_it_catches_tool_blocked_and_does_not_abort_the_run(factory: AgentFactory):
    """Contract rule 4: a blocked call is recorded and the loop continues."""
    sandbox = Sandbox()
    policy = LeastPrivilege(factory(), allowed_tools=frozenset(), allowed_sensitivity=frozenset())
    result = policy.run(MULTI_STEP_PROMPT, build_tools(sandbox))
    assert result.tool_calls
    assert all(call.executed is False for call in result.tool_calls)
    assert all(call.blocked_reason for call in result.tool_calls)
    assert sandbox.notes == {}


def test_it_stops_at_max_steps(factory: AgentFactory):
    result = factory(max_steps=1).run(MULTI_STEP_PROMPT, build_tools(Sandbox()))
    assert len(result.tool_calls) == 1


def test_it_uses_a_wrapped_tool_as_given(factory: AgentFactory):
    """Contract rule 5: a wrapped tool may carry a modified return value, and the agent must
    not attempt to unwrap it. What it records is what the wrapper produced, annotation and all.
    """
    contained = SpotlightWrapper(factory())
    result = contained.run(MULTI_STEP_PROMPT, build_tools(Sandbox()))
    executed = [call for call in result.tool_calls if call.executed]
    assert executed
    for call in executed:
        assert call.result is not None
        assert call.result.startswith('<untrusted-data source="'), call.name
        assert call.result.endswith("</untrusted-data>"), call.name
