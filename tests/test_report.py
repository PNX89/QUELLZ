import json

import pytest

from quellz import __version__
from quellz.catalog import CATALOG_VERSION, get_catalog
from quellz.mock import NaiveMockAgent
from quellz.report import METHODOLOGY_CAVEAT, Report, render_delta, render_report
from quellz.runner import compare, run_suite


def _flat(body: str) -> str:
    """Collapse wrapping and markdown quote prefixes so a wrapped paragraph can be matched."""
    return " ".join(body.replace("> ", "").split())


def _table_rows(body: str) -> list[str]:
    return [line for line in body.splitlines() if line.startswith("| ")]


def test_json_output_round_trips_through_json_loads(baseline: Report, contained: Report):
    document = json.loads(render_report(contained, "json"))
    assert document["label"] == "contained"
    assert document["containment"].startswith("LeastPrivilege")
    assert len(document["cases"]) == contained.n_cases
    assert len(document["by_technique"]) == len(contained.by_technique)
    assert document["meta"]["caveat"] == METHODOLOGY_CAVEAT
    delta = json.loads(render_delta(compare(baseline, contained), "json"))
    assert delta["overall"]["technique"] == "overall"
    assert len(delta["rows"]) == len(contained.by_technique)


def test_markdown_carries_one_row_per_technique_plus_overall(baseline: Report, contained: Report):
    for body, expected in (
        (render_report(contained, "markdown"), len(contained.by_technique)),
        (render_delta(compare(baseline, contained), "markdown"), len(contained.by_technique)),
    ):
        rows = _table_rows(body)
        # header, alignment rule, one row per technique, one overall row
        assert len(rows) == expected + 3
        assert rows[-1].startswith("| overall |")


def test_the_caveat_is_printed_beneath_every_table(baseline: Report, contained: Report):
    delta = compare(baseline, contained)
    bodies = [
        render_report(baseline, "text"),
        render_report(contained, "markdown"),
        render_delta(delta, "text"),
        render_delta(delta, "markdown"),
    ]
    assert all(METHODOLOGY_CAVEAT in _flat(body) for body in bodies)


def test_meta_carries_the_seed_the_catalog_version_and_the_package_version(contained: Report):
    assert contained.meta.seed == 0
    assert contained.meta.max_steps == 4
    assert contained.meta.catalog_version == CATALOG_VERSION
    assert contained.meta.quellz_version == __version__
    seeded = run_suite(NaiveMockAgent, attacks=get_catalog()[:2], seed=7, max_steps=2)
    assert (seeded.meta.seed, seeded.meta.max_steps) == (7, 2)
    assert "seed 7, max_steps 2" in render_report(seeded, "text")


def test_an_unknown_format_names_the_accepted_values(baseline: Report, contained: Report):
    with pytest.raises(ValueError, match="text, markdown, json"):
        render_report(baseline, "html")
    with pytest.raises(ValueError, match="text, markdown, json"):
        render_delta(compare(baseline, contained), "html")
