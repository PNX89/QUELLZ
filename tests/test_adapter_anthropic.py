"""The optional adapter, driven by a stub client so no test needs a key or a network."""

from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("anthropic")

from quellz.adapters.anthropic import REFUSAL_TEXT, AnthropicAgent, tool_schema
from quellz.contain import LeastPrivilege
from quellz.sandbox import Sandbox, build_tools
from quellz.types import Sensitivity

MODEL = "claude-opus-5"
# Anything beyond these four is a future HTTP 400 on the current model line.
ALLOWED_KWARGS = {"model", "max_tokens", "tools", "messages"}


class StubMessages:
    def __init__(self, responses: tuple[Any, ...]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        # The real client serializes the payload on the spot, so the stub snapshots the
        # conversation rather than aliasing the list the agent keeps appending to.
        self.calls.append({**kwargs, "messages": list(kwargs["messages"])})
        return self.responses.pop(0)


class StubClient:
    def __init__(self, *responses: Any) -> None:
        self.messages = StubMessages(responses)


class Refusal:
    stop_reason = "refusal"

    @property
    def content(self) -> list[Any]:
        raise AssertionError("content must not be indexed when the model refused")


def _text(text: str) -> SimpleNamespace:
    block = SimpleNamespace(type="text", text=text)
    return SimpleNamespace(stop_reason="end_turn", content=[block])


def _tool_use(tool: str, **args: str) -> SimpleNamespace:
    block = SimpleNamespace(type="tool_use", id="toolu_01", name=tool, input=args)
    return SimpleNamespace(stop_reason="tool_use", content=[block])


def test_the_tool_schema_declares_every_parameter_as_a_required_string():
    tool = {t.name: t for t in build_tools(Sandbox())}["send_email"]
    schema = tool_schema(tool)
    assert schema["name"] == "send_email"
    assert schema["description"] == tool.description
    assert schema["input_schema"]["type"] == "object"
    assert schema["input_schema"]["required"] == ["to", "subject", "body"]
    properties = schema["input_schema"]["properties"]
    assert all(field["type"] == "string" for field in properties.values())
    assert properties["to"]["description"] == tool.parameters["to"]


def test_a_refusal_is_handled_before_the_content_array_is_indexed():
    agent = AnthropicAgent(model=MODEL, client=StubClient(Refusal()))
    result = agent.run("Read the document q3_plan.md.", build_tools(Sandbox()))
    assert result.text == REFUSAL_TEXT
    assert result.tool_calls == ()


def test_the_request_carries_only_model_max_tokens_tools_and_messages():
    sandbox = Sandbox()
    client = StubClient(_tool_use("read_document", name="q3_plan.md"), _text("Done."))
    agent = AnthropicAgent(model=MODEL, client=client)
    result = agent.run("Read the document q3_plan.md.", build_tools(sandbox))
    assert [call.name for call in result.tool_calls] == ["read_document"]
    assert result.tool_calls[0].executed is True
    assert result.text == "Done."
    assert len(client.messages.calls) == 2
    for kwargs in client.messages.calls:
        assert set(kwargs) == ALLOWED_KWARGS
        assert kwargs["model"] == MODEL
    fed_back = client.messages.calls[1]["messages"][-1]["content"][0]
    assert fed_back["type"] == "tool_result"
    assert "billing migration" in fed_back["content"]


def test_a_blocked_call_is_recorded_and_reported_back_without_aborting():
    """Protocol rule 4 holds for the live adapter, not only for the bundled fixture."""
    sandbox = Sandbox()
    client = StubClient(_tool_use("send_email", to="a@example.invalid"), _text("Understood."))
    policy = LeastPrivilege(
        AnthropicAgent(model=MODEL, client=client),
        allowed_tools=frozenset({"read_document"}),
        allowed_sensitivity=frozenset({Sensitivity.READ}),
    )
    result = policy.run("Mail the plan.", build_tools(sandbox))
    assert [(call.name, call.executed) for call in result.tool_calls] == [("send_email", False)]
    assert result.tool_calls[0].blocked_reason
    assert sandbox.sent_emails == []
    fed_back = client.messages.calls[1]["messages"][-1]["content"][0]
    assert fed_back["is_error"] is True


def test_model_is_a_required_keyword_with_no_default():
    with pytest.raises(TypeError):
        AnthropicAgent(client=StubClient())


def test_the_default_token_budget_leaves_room_for_thinking_as_well_as_the_reply():
    """max_tokens caps thinking and reply text together on the current model line.

    Adaptive thinking is what omitting the parameter gets you on Opus 5 and Sonnet 5, and this
    adapter omits it. A budget sized for the length of an answer truncates a four step tool
    loop mid-turn, which surfaces as a run that simply stops calling tools.
    """
    client = StubClient(_text("Done."))
    agent = AnthropicAgent(model=MODEL, client=client)
    agent.run("Read the document q3_plan.md.", build_tools(Sandbox()))
    assert agent.max_tokens >= 8192
    assert client.messages.calls[0]["max_tokens"] == agent.max_tokens


def test_the_report_names_the_model_and_not_just_the_adapter_class():
    """A pasted table has to say what it tested. The first live run's did not.

    `_describe` used to take the innermost agent's class name unconditionally, so a run
    worth 1.27 USD against a named model printed `agent AnthropicAgent`, and the model id
    survived only in the JSON beside it. Both halves are asserted here: the adapter
    carries the id, and the runner is what puts it in the report.
    """
    from quellz.runner import _describe

    agent = AnthropicAgent(model=MODEL, client=StubClient())
    assert agent.name == f"AnthropicAgent({MODEL})"

    bare_name, containment = _describe(agent)
    assert bare_name == f"AnthropicAgent({MODEL})"
    assert containment == "none"

    wrapped = LeastPrivilege(
        agent, allowed_tools=("read_document",), allowed_sensitivity=(Sensitivity.READ,)
    )
    wrapped_name, stack = _describe(wrapped)
    assert wrapped_name == f"AnthropicAgent({MODEL})"
    assert "LeastPrivilege" in stack


def test_an_agent_without_a_name_still_reports_its_class():
    """The fixture has no `name`, and the README block that says `agent NaiveMockAgent`
    is asserted verbatim by test_readme.py, so the fallback is load bearing."""
    from quellz.mock import NaiveMockAgent
    from quellz.runner import _describe

    assert _describe(NaiveMockAgent())[0] == "NaiveMockAgent"
