"""The attack model: techniques, injection vectors, the Attack record and catalog validation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from quellz.predicates import Predicate
from quellz.sandbox import Injection, Site
from quellz.types import CatalogError

__all__ = [
    "DOC_ONLY_REFERENCES",
    "REFERENCES",
    "Attack",
    "Technique",
    "Vector",
    "decode_tag_block",
    "encode_tag_block",
    "validate_catalog",
]


class Technique(StrEnum):
    DIRECT_OVERRIDE = "direct_override"
    INDIRECT_DOCUMENT = "indirect_document"
    TOOL_POISONING = "tool_poisoning"
    HIDDEN_CONTEXT = "hidden_context"
    MULTI_TURN_HIJACK = "multi_turn_hijack"


class Vector(StrEnum):
    PROMPT = "prompt"
    TOOL_DESCRIPTION = "tool_description"
    TOOL_RESULT = "tool_result"


REFERENCES: Mapping[str, str] = {
    "OWASP-LLM01-2026": "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/",
    "OWASP-LLM03-2026": "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/",
    "OWASP-LLM08-2026": "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/",
    "OWASP-ASI01": (
        "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
    ),
    "OWASP-ASI02": (
        "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
    ),
    "OWASP-ASI06": (
        "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
    ),
    "OWASP-MCP03": "https://owasp.org/www-project-mcp-top-10/",
    "OWASP-MCP-CHEATSHEET": (
        "https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html"
    ),
    "ATLAS-AML.T0051.000": "https://atlas.mitre.org/",
    "ATLAS-AML.T0051.001": "https://atlas.mitre.org/",
    "LIU-2024": "https://arxiv.org/abs/2310.12815",
    "INJECAGENT": "https://arxiv.org/abs/2403.02691",
    "AGENTDOJO": "https://arxiv.org/abs/2406.13352",
    "SPOTLIGHTING": "https://arxiv.org/abs/2403.14720",
    "ATTACKER-MOVES-SECOND": "https://arxiv.org/abs/2510.09023",
    "CAMEL": "https://arxiv.org/abs/2503.18813",
    "ARXIV-2607.05744": "https://arxiv.org/abs/2607.05744",
    "LETHAL-TRIFECTA": "https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/",
    "GITHUB-AUP": (
        "https://docs.github.com/en/site-policy/acceptable-use-policies/"
        "github-active-malware-or-exploits"
    ),
}

# Registry keys cited by prose rather than by a payload: the containment docstrings in
# contain.py, the README and SECURITY.md. Kept separate so validate_catalog can still refuse
# a citation that resolves to nothing anywhere in the repo. SPOTLIGHTING is not in this set:
# the delimiter_escape payload attacks the defense that paper describes, so it cites it.
DOC_ONLY_REFERENCES = frozenset({"ATTACKER-MOVES-SECOND", "CAMEL", "GITHUB-AUP"})

_VECTOR_SITES: Mapping[Vector, Site] = {
    Vector.TOOL_DESCRIPTION: Site.DESCRIPTION,
    Vector.TOOL_RESULT: Site.RESULT,
}
_CARRIER_VECTORS = frozenset(_VECTOR_SITES)


@dataclass(frozen=True)
class Attack:
    """One catalog entry: a payload, where it enters, and what counts as success."""

    id: str
    technique: Technique
    vector: Vector
    payload: str = field(repr=False)
    objective: str
    success: Predicate
    turns: tuple[str, ...] = field(repr=False)
    utility_task: str
    utility_success: Predicate
    references: tuple[str, ...]
    carrier: str | None = None
    inject_at_turn: int = 0
    fixture: bool = True

    def injection(self) -> Injection | None:
        """The tool surface placement for this payload, or None for a prompt injection."""
        if self.vector not in _CARRIER_VECTORS:
            return None
        if self.carrier is None:
            raise CatalogError(f"attack {self.id!r} uses vector {self.vector} without a carrier")
        return Injection(
            carrier=self.carrier, payload=self.payload, site=_VECTOR_SITES[self.vector]
        )

    def prompt_for_turn(self, index: int, *, attacked: bool) -> str:
        """The user prompt for one turn, carrying the payload when this is the injected turn."""
        turn = self.turns[index]
        if attacked and self.vector is Vector.PROMPT and index == self.inject_at_turn:
            return f"{turn}\n\n{self.payload}"
        return turn


_TAG_BASE = 0xE0000
_TAG_LOW, _TAG_HIGH = 0xE0020, 0xE007E


def encode_tag_block(text: str) -> str:
    """Encode printable ASCII as Unicode TAG characters, U+E0020 to U+E007E.

    A human approval view typically renders nothing for these code points while the model
    still reads them, which is the concealment gap the tag_block payload exercises.
    """
    return "".join(chr(_TAG_BASE + ord(ch)) for ch in text if 0x20 <= ord(ch) <= 0x7E)


def decode_tag_block(text: str) -> str:
    """Decode Unicode TAG characters back to ASCII and leave every other character alone."""
    return "".join(
        chr(ord(ch) - _TAG_BASE) if _TAG_LOW <= ord(ch) <= _TAG_HIGH else ch for ch in text
    )


def validate_catalog(attacks: Sequence[Attack], tool_names: Sequence[str]) -> None:
    """Raise CatalogError on the first malformed entry. Called at import of quellz.catalog."""
    if not attacks:
        raise CatalogError("the catalog is empty")
    known_tools = set(tool_names)
    seen_ids: set[str] = set()
    per_technique: dict[Technique, int] = {}
    cited: set[str] = set()

    for attack in attacks:
        where = f"attack {attack.id!r}"
        if attack.id in seen_ids:
            raise CatalogError(f"duplicate attack id {attack.id!r}")
        seen_ids.add(attack.id)
        per_technique[attack.technique] = per_technique.get(attack.technique, 0) + 1
        for name, value in (
            ("payload", attack.payload),
            ("objective", attack.objective),
            ("utility_task", attack.utility_task),
        ):
            if not value.strip():
                raise CatalogError(f"{where} has an empty {name}")
        if not attack.fixture:
            raise CatalogError(f"{where} is not marked as a fixture")
        if not attack.turns or any(not turn.strip() for turn in attack.turns):
            raise CatalogError(f"{where} has an empty turn")
        if not 0 <= attack.inject_at_turn < len(attack.turns):
            raise CatalogError(
                f"{where} injects at turn {attack.inject_at_turn} of {len(attack.turns)}"
            )
        if attack.vector in _CARRIER_VECTORS:
            if attack.carrier is None:
                raise CatalogError(f"{where} uses vector {attack.vector} without a carrier tool")
            if attack.carrier not in known_tools:
                raise CatalogError(f"{where} names carrier {attack.carrier!r}, which is not a tool")
        elif attack.carrier is not None:
            raise CatalogError(f"{where} uses vector {attack.vector} but names a carrier")
        if not attack.references:
            raise CatalogError(f"{where} carries no references")
        for key in attack.references:
            if key not in REFERENCES:
                raise CatalogError(f"{where} cites {key!r}, which is not in REFERENCES")
            if key in DOC_ONLY_REFERENCES:
                raise CatalogError(f"{where} cites {key!r}, which is reserved for prose")
            cited.add(key)

    for technique in Technique:
        if per_technique.get(technique, 0) < 3:
            raise CatalogError(f"technique {technique} carries fewer than 3 payloads")
    for key, url in REFERENCES.items():
        if not url.startswith("https://"):
            raise CatalogError(f"reference {key!r} does not resolve over https")
        if key not in cited and key not in DOC_ONLY_REFERENCES:
            raise CatalogError(f"reference {key!r} is cited by nothing")
