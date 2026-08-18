"""Live adapter for the Anthropic Messages API. Optional extra: pip install quellz[anthropic].

Nothing on the default demo or test path imports this module. The CLI imports it lazily and
only when --agent names it, so the core install stays dependency free. Wire it up with a zero
argument factory of your own::

    # my_agents.py
    from quellz.adapters.anthropic import AnthropicAgent

    def build():
        return AnthropicAgent(model="claude-opus-5")

    # then: quellz run --agent my_agents:build --mode both
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from quellz.types import AgentResult, Tool, ToolBlocked, ToolCall

__all__ = ["REFUSAL_TEXT", "AnthropicAgent", "tool_schema"]

REFUSAL_TEXT = "[refusal]"


def tool_schema(tool: Tool) -> dict[str, Any]:
    """The Messages API tool definition for one Tool. Every parameter is a string, by design."""
    return {
        "name": tool.name,
        "description": tool.description,
        "input_schema": {
            "type": "object",
            "properties": {
                name: {"type": "string", "description": description}
                for name, description in tool.parameters.items()
            },
            "required": list(tool.parameters),
        },
    }


class AnthropicAgent:
    """A real model behind the same Agent protocol the bundled fixture implements.

    Model ids as of August 2026 are claude-opus-5 and claude-sonnet-5 (1M context) and
    claude-haiku-4-5 (200K). The id strings are complete as written; no date suffix.

    Deliberately free of sampling parameters. temperature, top_p and top_k all return HTTP 400
    on Opus 4.7 and later, on Opus 5, Sonnet 5 and Fable 5, so hardcoding any of them here
    would be a future breakage. `thinking` is a narrower story and worth stating precisely:
    the legacy {"type": "enabled", "budget_tokens": N} form returns 400 on those models, while
    {"type": "adaptive"} is valid and is what omitting the parameter already gets you on
    Opus 5 and Sonnet 5. This adapter omits it, so it runs adaptive there by default. The call
    surface is messages.create with model, max_tokens, tools and messages, and no beta headers.

    Conversation state lives on the instance, per protocol rule 2, so a multi turn attack is
    repeated run() calls on one object.
    """

    def __init__(
        self, *, model: str, max_tokens: int = 1024, client: Any = None, max_steps: int = 4
    ) -> None:
        if client is None:
            import anthropic  # deferred: the SDK is an optional extra

            # Raises at construction when no api_key is passed and ANTHROPIC_API_KEY is unset,
            # which is why the test suite injects a stub client instead.
            client = anthropic.Anthropic()
        self.client = client
        self.model = model
        self.max_tokens = max_tokens
        self.max_steps = max_steps
        self.messages: list[dict[str, Any]] = []

    def run(self, prompt: str, tools: Sequence[Tool]) -> AgentResult:
        available = {tool.name: tool for tool in tools}
        schemas = [tool_schema(tool) for tool in tools]
        self.messages.append({"role": "user", "content": prompt})
        calls: list[ToolCall] = []
        texts: list[str] = []
        # The bound is checked between round trips: a parallel batch is executed whole so the
        # message history never carries a tool_use block without its tool_result.
        while len(calls) < self.max_steps:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                tools=schemas,
                messages=self.messages,
            )
            # A safety classifier can decline with HTTP 200 and an empty content array, and an
            # injection workload is exactly what trips one, so this precedes any indexing.
            if getattr(response, "stop_reason", None) == "refusal":
                return AgentResult(text=REFUSAL_TEXT, tool_calls=tuple(calls))
            blocks = list(response.content)
            texts.extend(block.text for block in blocks if block.type == "text")
            self.messages.append({"role": "assistant", "content": blocks})
            requests = [block for block in blocks if block.type == "tool_use"]
            if response.stop_reason != "tool_use" or not requests:
                break
            results = []
            for block in requests:
                call, result = _execute(available, block)
                calls.append(call)
                results.append(result)
            self.messages.append({"role": "user", "content": results})
        return AgentResult(text="\n".join(texts), tool_calls=tuple(calls))


def _execute(available: Mapping[str, Tool], block: Any) -> tuple[ToolCall, dict[str, Any]]:
    args = {name: str(value) for name, value in dict(block.input).items()}
    tool = available.get(block.name)
    if tool is None:
        reason = f"tool {block.name!r} was not offered to this agent"
    else:
        try:
            output = tool.fn(**args)
        except ToolBlocked as blocked:
            reason = blocked.reason
        else:
            return (
                ToolCall(name=block.name, args=args, executed=True, result=output),
                {"type": "tool_result", "tool_use_id": block.id, "content": output},
            )
    # Protocol rule 4: a refused call is recorded, fed back as an error, and the loop goes on.
    return (
        ToolCall(name=block.name, args=args, executed=False, blocked_reason=reason),
        {"type": "tool_result", "tool_use_id": block.id, "content": reason, "is_error": True},
    )
