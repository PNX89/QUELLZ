import dataclasses

import pytest

from quellz.types import AgentResult, CatalogError, Sensitivity, Tool, ToolBlocked, ToolCall


def _tool(**overrides: object) -> Tool:
    fields: dict[str, object] = {
        "name": "read_document",
        "description": "Return one workspace document.",
        "sensitivity": Sensitivity.READ,
        "fn": lambda name: name,
        "parameters": {"name": "file name"},
    }
    fields.update(overrides)
    return Tool(**fields)  # type: ignore[arg-type]


def test_sensitivity_values_are_the_documented_strings():
    assert [level.value for level in Sensitivity] == ["read", "write", "exfil"]
    assert Sensitivity("exfil") is Sensitivity.EXFIL


def test_tool_rejects_an_empty_name_or_description():
    with pytest.raises(CatalogError, match=r"Tool\.name"):
        _tool(name="  ")
    with pytest.raises(CatalogError, match=r"Tool\.description"):
        _tool(description="")


def test_tool_call_is_frozen():
    call = ToolCall(name="read_document", args={"name": "q3_plan.md"}, executed=True, result="ok")
    with pytest.raises(dataclasses.FrozenInstanceError):
        call.executed = False  # type: ignore[misc]


def test_agent_result_defaults_to_no_tool_calls():
    assert AgentResult(text="hello").tool_calls == ()


def test_tool_blocked_carries_the_tool_name_and_the_reason():
    blocked = ToolBlocked("send_email", "tool is not in allowed_tools")
    assert blocked.tool_name == "send_email"
    assert blocked.reason == "tool is not in allowed_tools"
    assert "send_email" in str(blocked)
