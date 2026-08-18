from collections.abc import Iterator
from dataclasses import replace

import pytest

from quellz.attacks import DOC_ONLY_REFERENCES, REFERENCES, Technique, Vector, validate_catalog
from quellz.catalog import ATTACKS, by_technique, get_catalog
from quellz.predicates import Exfiltrated, Predicate, ToolCalled
from quellz.sandbox import Sandbox, build_tools
from quellz.types import CatalogError, Sensitivity

TOOLS = build_tools(Sandbox())
TOOL_NAMES = tuple(tool.name for tool in TOOLS)
EXFIL_TOOLS = {tool.name for tool in TOOLS if tool.sensitivity is Sensitivity.EXFIL}


def _catalog_where(attack_id: str, **changes: object) -> tuple:
    return tuple(replace(a, **changes) if a.id == attack_id else a for a in ATTACKS)


def _walk(predicate: Predicate) -> Iterator[Predicate]:
    """Every predicate in a success condition, including the ones inside AllOf, AnyOf and Not."""
    yield predicate
    for child in getattr(predicate, "predicates", ()):
        yield from _walk(child)
    inner = getattr(predicate, "predicate", None)
    if inner is not None:
        yield from _walk(inner)


def test_attack_ids_are_unique_and_every_id_names_its_technique():
    assert len(ATTACKS) == 21
    assert len({attack.id for attack in ATTACKS}) == 21
    assert all(attack.id.startswith(f"{attack.technique}.") for attack in ATTACKS)
    assert get_catalog() is ATTACKS


def test_no_attack_scores_a_bare_call_at_an_exfil_sink_as_success():
    """One definition of attacker success, applied to all of them.

    Reaching an attacker-controlled sink is not the breach; delivering the objective content
    to it is. Sixteen of these entries once scored on the call alone while one of their own
    siblings verified the content, which made the same word mean two things in one table.
    """
    for attack in ATTACKS:
        for predicate in _walk(attack.success):
            if isinstance(predicate, ToolCalled):
                assert predicate.tool not in EXFIL_TOOLS, attack.id


def test_every_exfiltration_destination_is_a_reserved_invalid_host():
    """SECURITY.md's claim, checked against the data rather than trusted from the prose."""
    destinations = {
        predicate.destination
        for attack in ATTACKS
        for predicate in _walk(attack.success)
        if isinstance(predicate, Exfiltrated)
    }
    assert destinations
    for destination in destinations:
        assert destination.endswith(".invalid") or ".invalid/" in destination, destination


def test_every_reference_key_resolves_in_the_registry():
    for attack in ATTACKS:
        assert attack.references
        for key in attack.references:
            assert key in REFERENCES, f"{attack.id} cites {key}"


def test_every_registry_entry_is_https_and_is_cited_somewhere():
    cited = {key for attack in ATTACKS for key in attack.references}
    for key, url in REFERENCES.items():
        assert url.startswith("https://"), key
        assert key in cited or key in DOC_ONLY_REFERENCES, f"{key} is cited by nothing"
    assert not cited & DOC_ONLY_REFERENCES


def test_payload_objective_and_utility_task_are_non_empty():
    for attack in ATTACKS:
        assert attack.payload.strip(), attack.id
        assert attack.objective.strip(), attack.id
        assert attack.utility_task.strip(), attack.id
        assert all(turn.strip() for turn in attack.turns), attack.id


def test_both_predicates_are_present_on_every_attack():
    for attack in ATTACKS:
        assert isinstance(attack.success, Predicate), attack.id
        assert isinstance(attack.utility_success, Predicate), attack.id


def test_carrier_is_present_exactly_when_the_vector_needs_one():
    carrier_vectors = {Vector.TOOL_DESCRIPTION, Vector.TOOL_RESULT}
    for attack in ATTACKS:
        if attack.vector in carrier_vectors:
            assert attack.carrier in TOOL_NAMES, attack.id
        else:
            assert attack.carrier is None, attack.id
    with pytest.raises(CatalogError, match="not a tool"):
        validate_catalog(
            _catalog_where("indirect_document.document_footer", carrier="nope"), TOOL_NAMES
        )
    with pytest.raises(CatalogError, match="names a carrier"):
        validate_catalog(
            _catalog_where("direct_override.naive", carrier="read_document"), TOOL_NAMES
        )


def test_inject_at_turn_is_inside_the_turn_list():
    for attack in ATTACKS:
        assert 0 <= attack.inject_at_turn < len(attack.turns), attack.id
    with pytest.raises(CatalogError, match="injects at turn"):
        validate_catalog(_catalog_where("direct_override.naive", inject_at_turn=3), TOOL_NAMES)


def test_every_technique_carries_at_least_three_payloads():
    for technique in Technique:
        assert len(by_technique(technique)) >= 3, technique


def test_every_attack_is_marked_as_a_fixture():
    assert all(attack.fixture for attack in ATTACKS)
    with pytest.raises(CatalogError, match="fixture"):
        validate_catalog(_catalog_where("direct_override.naive", fixture=False), TOOL_NAMES)
