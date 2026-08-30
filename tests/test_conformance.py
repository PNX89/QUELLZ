"""A reusable Agent protocol conformance suite. Every adapter has to pass it.

Including the one that ships. AnthropicAgent was absent from the parameter set below, which is
the quiet form of this defect: an adapter left out of a hand-maintained set is uncovered rather
than red, and two of the rules here, string-only tool parameters and the max_steps bound, were
being asserted for the two bundled fixtures and for nothing that talks to a model. The adapter
imports without the optional SDK because its import of it is deferred, so a stub client is all
it needs to sit in this suite on both CI legs.
"""

import pkgutil
from collections.abc import Callable, Sequence
from types import SimpleNamespace
from typing import Any

import pytest

import quellz.adapters
from quellz.adapters.anthropic import AnthropicAgent
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
    """A second, deliberately different protocol implementation: it ignores the prompt.

    It still owns its conversation state, in the only form an agent that ignores the prompt
    can have one: it remembers the tools it has already reached for, so a second run() on the
    same instance carries on rather than starting the same walk again. Protocol rule 2 asks
    for that of every implementation, and this one used to satisfy the whole suite without it.
    """

    def __init__(self, *, max_steps: int = 4) -> None:
        self.max_steps = max_steps
        self.reached_for: set[str] = set()

    def run(self, prompt: str, tools: Sequence[Tool]) -> AgentResult:
        calls: list[ToolCall] = []
        for tool in tools:
            if len(calls) >= self.max_steps:
                break
            if tool.name in self.reached_for:
                continue
            self.reached_for.add(tool.name)
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


class StubMessages:
    """A model that answers out of the conversation it is sent, and out of nothing else.

    Deciding from `messages` rather than from a counter of its own is what lets this stub say
    anything about the ADAPTER's state: an adapter that had forgotten its history would send a
    short conversation and be handed the first tool all over again, which is the failure the
    rule 2 test is looking for. It asks for whichever offered tool the conversation does not
    already show it using, and stops when there are none left.
    """

    def create(self, **kwargs: Any) -> SimpleNamespace:
        schemas = kwargs["tools"]
        used = {
            block.name
            for message in kwargs["messages"]
            if isinstance(message["content"], list)
            for block in message["content"]
            if getattr(block, "type", None) == "tool_use"
        }
        remaining = [schema for schema in schemas if schema["name"] not in used]
        if not remaining:
            text = SimpleNamespace(type="text", text="Nothing further.")
            return SimpleNamespace(stop_reason="end_turn", content=[text])
        schema = remaining[0]
        args: dict[str, Any] = dict.fromkeys(schema["input_schema"]["properties"], "q3_plan.md")
        # One argument goes out as an int on purpose. Rule 1 says every tool parameter reaches
        # the tool as a string, and the adapter is the only layer that can make that true.
        args[next(iter(args))] = len(used)
        request = SimpleNamespace(
            type="tool_use", id=f"toolu_{len(used)}", name=schema["name"], input=args
        )
        return SimpleNamespace(stop_reason="tool_use", content=[request])


class StubClient:
    def __init__(self) -> None:
        self.messages = StubMessages()


def stub_anthropic_agent(*, max_steps: int = 4) -> Agent:
    """The shipped adapter behind a stub client, taking max_steps like the other two."""
    return AnthropicAgent(model="claude-opus-5", client=StubClient(), max_steps=max_steps)


#: Keyed by the agent class each factory builds, so the guard below can name what is missing.
FACTORIES: dict[str, AgentFactory] = {
    "AnthropicAgent": stub_anthropic_agent,
    "NaiveMockAgent": NaiveMockAgent,
    "StepwiseAgent": StepwiseAgent,
}


@pytest.fixture(params=sorted(FACTORIES), ids=sorted(FACTORIES))
def factory(request: pytest.FixtureRequest) -> AgentFactory:
    return FACTORIES[request.param]


def test_every_shipped_adapter_is_in_the_conformance_parameter_set() -> None:
    """The set is hand maintained, so an adapter left out of it is uncovered, not red.

    That is what happened: AnthropicAgent shipped, this file said every adapter has to pass,
    and the only adapter there is passed none of it. Reading the shipped adapters out of the
    package makes the omission fail here instead of going unnoticed, and the pinned literal
    keeps the derivation honest: deleting an adapter has to be a deliberate edit to this line.
    """
    shipped = {
        name
        for info in pkgutil.iter_modules(quellz.adapters.__path__)
        for module in [__import__(f"quellz.adapters.{info.name}", fromlist=["_"])]
        for name, value in vars(module).items()
        if isinstance(value, type) and value.__module__ == module.__name__
        if name.endswith("Agent")
    }
    assert shipped == {"AnthropicAgent"}, f"the shipped adapters changed: {sorted(shipped)}"
    assert len(FACTORIES) == 3, f"the conformance set is {sorted(FACTORIES)}"
    missing = shipped - set(FACTORIES)
    assert missing == set(), f"these adapters are not in the conformance set: {sorted(missing)}"


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


CLEAN_SECOND_TURN = "Thank you, that is all for now."


def _key(call: ToolCall) -> tuple[str, tuple[tuple[str, str], ...]]:
    return call.name, tuple(sorted(call.args.items()))


def test_it_carries_its_conversation_state_across_turns(factory: AgentFactory):
    """Contract rule 2: a multi-turn attack is repeated run() calls on ONE instance.

    Nothing enforced it. An implementation that forgot everything between turns passed this
    whole suite and reproduced the published delta table byte for byte, while four
    multi_turn_hijack payloads whose objectives read "carries across turns" measured nothing
    about persistence at all.

    Turn one is bounded to a single call so there is work left over, and turn two asks for
    nothing new. An agent holding the first turn carries on from it; one that forgot starts
    the same conversation again, and the repeated call is what says so.
    """
    agent = factory(max_steps=1)
    tools = build_tools(Sandbox())
    first = agent.run(MULTI_STEP_PROMPT, tools)
    second = agent.run(CLEAN_SECOND_TURN, tools)

    assert len(first.tool_calls) == 1, "turn one has to leave work over for turn two"
    assert second.tool_calls, "turn two made no call, so nothing of turn one survived it"
    repeated = {_key(call) for call in first.tool_calls} & {_key(c) for c in second.tool_calls}
    assert repeated == set(), (
        f"turn two repeated {sorted(repeated)}, which is what an agent that had started the "
        "conversation over would do"
    )


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
