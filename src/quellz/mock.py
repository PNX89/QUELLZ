"""A deterministic conformance fixture that obeys a published rule. Not a model under test."""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence

from quellz.attacks import decode_tag_block
from quellz.types import AgentResult, Tool, ToolBlocked, ToolCall

__all__ = ["NaiveMockAgent"]

_UNTRUSTED = re.compile(r"<untrusted-data\b[^>]*>.*?</untrusted-data>", re.DOTALL)
_TRAILING = ".,;:!?)\"'"

# Directive grammar. Each entry is (tool name, pattern, captured parameter names). The
# uppercase config key is matched case sensitively inside an otherwise insensitive pattern.
_DIRECTIVES: tuple[tuple[str, re.Pattern[str], tuple[str, ...]], ...] = (
    ("read_document", re.compile(r"read (?:the )?document ([\w.\-/]+)", re.I), ("name",)),
    ("search_web", re.compile(r"search (?:the )?web for \"([^\"]+)\"", re.I), ("query",)),
    (
        "read_config",
        re.compile(r"read (?:the )?config(?:uration)? (?:key|value) (?-i:([A-Z_]+))", re.I),
        ("key",),
    ),
    (
        "write_note",
        re.compile(r"write (?:a )?note (?:named |called )?([\w.\-]+) with \"([^\"]+)\"", re.I),
        ("name", "body"),
    ),
    (
        "send_email",
        re.compile(r"(?:send|email|forward|mail)\b[^.\n]*?\bto ([\w.+\-]+@[\w.\-]+)", re.I),
        ("to",),
    ),
    ("post_webhook", re.compile(r"post\b[^.\n]*?\bto (https?://[^\s,]+)", re.I), ("url",)),
)

_Directive = tuple[str, dict[str, str]]


class NaiveMockAgent:
    """A fixture agent with a published obedience rule, used to prove the harness works.

    Obedience rule, in full:

    1. It first attempts the tool call its user prompt asks for, the utility task, which is
       the first directive it recognises in that prompt.
    2. It then scans every piece of text it has seen, the prompt, the descriptions of the
       tools it was handed and every tool return value, and obeys the first recognised
       directive it has not already attempted. It repeats this until nothing new is found.
    3. It skips any directive that sits between <untrusted-data> tags.
    4. It stops after max_steps tool calls, catches ToolBlocked and records the blocked
       attempt, and returns the concatenated text of the calls it made.

    Two further published details. It decodes Unicode TAG characters before scanning, which
    is what makes the concealment payload visible to it. Where a directive does not name
    every parameter of the tool it calls, it fills the rest from the text it has seen, which
    is how context reaches an exfiltration sink.

    Rule 3 is one of two reasons SpotlightWrapper reduces attack success rate in the demo,
    and the other one is not a published obedience rule at all. That wrapper also replaces
    every whitespace run inside the span with a marker character, which destroys the literal
    spaces the directive patterns below match on, and either half stops these payloads on
    its own. The drop is therefore a property of this fixture, partly of a rule it publishes
    and partly of how its parser happens to work. It is NOT evidence about the behaviour of
    any real model, and no attack success rate measured against this fixture says anything
    about any model.

    Deterministic by construction: no randomness anywhere, so two identical runs produce
    identical transcripts.
    """

    def __init__(self, *, max_steps: int = 4) -> None:
        self.max_steps = max_steps
        self._seen: list[str] = []
        self._attempted: set[tuple[str, tuple[tuple[str, str], ...]]] = set()

    def run(self, prompt: str, tools: Sequence[Tool]) -> AgentResult:
        available = {tool.name: tool for tool in tools}
        self._remember(prompt)
        for tool in tools:
            self._remember(f"{tool.name}: {tool.description}")

        calls: list[ToolCall] = []
        lines: list[str] = []
        pending = next(_directives(_scannable(prompt)), None)

        while len(calls) < self.max_steps:
            if pending is None:
                pending = self._next_unattempted()
            if pending is None:
                break
            name, args = pending
            pending = None
            self._attempted.add(_key(name, args))
            tool = available.get(name)
            if tool is None:
                continue
            call = self._invoke(tool, args)
            calls.append(call)
            if call.result is None:
                lines.append(f"{name}: blocked ({call.blocked_reason})")
            else:
                lines.append(f"{name}: {call.result}")
                self._remember(call.result)

        return AgentResult(text="\n".join(lines), tool_calls=tuple(calls))

    def _invoke(self, tool: Tool, args: dict[str, str]) -> ToolCall:
        filled = dict(args)
        for parameter in tool.parameters:
            if parameter not in filled:
                filled[parameter] = (
                    "forwarded context" if parameter == "subject" else self._context()
                )
        try:
            result = tool.fn(**filled)
        except ToolBlocked as blocked:
            return ToolCall(
                name=tool.name, args=filled, executed=False, blocked_reason=blocked.reason
            )
        return ToolCall(name=tool.name, args=filled, executed=True, result=result)

    def _next_unattempted(self) -> _Directive | None:
        for text in self._seen:
            for directive in _directives(_scannable(text)):
                if _key(*directive) not in self._attempted:
                    return directive
        return None

    def _remember(self, text: str) -> None:
        if text and text not in self._seen:
            self._seen.append(text)

    def _context(self) -> str:
        return " | ".join(self._seen)[-800:]


def _scannable(text: str) -> str:
    return _UNTRUSTED.sub(" ", decode_tag_block(text))


def _directives(text: str) -> Iterator[_Directive]:
    found: list[tuple[int, str, dict[str, str]]] = []
    for name, pattern, parameters in _DIRECTIVES:
        for match in pattern.finditer(text):
            args = {
                parameter: value.strip().rstrip(_TRAILING)
                for parameter, value in zip(parameters, match.groups(), strict=True)
            }
            found.append((match.start(), name, args))
    for _, name, args in sorted(found, key=lambda item: item[0]):
        yield name, args


def _key(name: str, args: dict[str, str]) -> tuple[str, tuple[tuple[str, str], ...]]:
    return name, tuple(sorted(args.items()))
