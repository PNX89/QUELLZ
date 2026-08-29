"""Documentation integrity: the README has to stay true to the code it documents.

Every command block in the README is executed here and every number it quotes is compared
against live output. `uv run X` is translated to the interpreter running this suite, which is
the environment uv would hand it, so these tests need neither uv nor the network.
"""

import html
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from quellz import __version__
from quellz.attacks import REFERENCES
from quellz.report import METHODOLOGY_CAVEAT

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
ANNOTATED = re.compile(r"^(uv run .+?)\s+#\s*exit (\d)$")


def _block(heading: str, language: str) -> str:
    """The first fenced block of that language under that heading."""
    section = README.split(f"\n## {heading}\n", 1)[1]
    return section.split(f"```{language}\n", 1)[1].split("```", 1)[0]


def _argv(command: str) -> list[str]:
    uv, run, program, *rest = shlex.split(command)
    assert (uv, run) == ("uv", "run"), command
    if program == "quellz":
        return [sys.executable, "-m", "quellz.cli", *rest]
    assert program == "python", command
    return [sys.executable, str(ROOT / rest[0]), *rest[1:]]


def _execute(command: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(_argv(command), cwd=cwd, capture_output=True, text=True, timeout=120)


def test_every_quickstart_command_runs_and_exits_zero(tmp_path: Path):
    commands = [
        line
        for line in _block("Quickstart", "bash").splitlines()
        if line.startswith("uv run") and not line.startswith("uv run pytest")
    ]
    assert commands
    for command in commands:
        finished = _execute(command, tmp_path)
        assert finished.returncode == 0, f"{command}\n{finished.stderr}"


def test_the_documented_gate_exit_codes_are_the_real_ones(tmp_path: Path):
    """The README claims one gate passes and one fails. Both claims are executed here."""
    annotated = [
        match.groups()
        for match in map(ANNOTATED.match, _block("Using it as a gate", "bash").splitlines())
        if match
    ]
    assert len(annotated) == 2
    for command, expected in annotated:
        finished = _execute(command, tmp_path)
        assert finished.returncode == int(expected), f"{command}\n{finished.stdout}"


def test_the_hero_table_is_captured_output_from_the_bundled_demo(tmp_path: Path):
    """No hand-written table. The block under 'The delta' has to come out of the example."""
    hero = _block("The delta", "text").strip()
    # An empty block would make the substring assertion below vacuous.
    assert hero.startswith("QUELLZ delta:") and "overall" in hero
    finished = _execute("uv run python examples/demo_ab.py", tmp_path)
    assert finished.returncode == 0, finished.stderr
    assert hero in finished.stdout


def test_the_quoted_line_count_of_the_adapter_example_is_the_real_one():
    """A number about a file in this repository, checked against the file."""
    quoted = re.search(
        r"`examples/(\S+?)` puts your own agent behind the `Agent` protocol in "
        r"(\d+) lines",
        README,
    )
    assert quoted, "the README no longer states the line count this test exists to check"
    path = ROOT / "examples" / quoted.group(1)
    assert len(path.read_text(encoding="utf-8").splitlines()) == int(quoted.group(2))


def test_the_methodology_caveat_appears_verbatim():
    flattened = " ".join(README.replace("> ", "").split())
    assert METHODOLOGY_CAVEAT in flattened


def test_every_registry_citation_is_reproduced_in_the_readme():
    for key, url in REFERENCES.items():
        assert f"`{key}`" in README, key
        assert url in README, key


@pytest.mark.parametrize(
    "banned",
    ["prevents", "blocks all", "solves prompt injection", "secure by design", "eliminates"],
)
def test_the_readme_avoids_the_overclaiming_vocabulary(banned: str):
    assert banned not in README.lower()


CHAIN_HEAD = re.compile(r"\b[0-9a-f]{64}\b")


def _escaped(text: str) -> str:
    """The card is HTML, so the captured output appears in it escaped, not raw."""
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def test_the_committed_demo_output_still_matches_a_live_run() -> None:
    """The Pages card publishes this output, so a stale copy is a lie on a public page.

    The hash chain head is masked on both sides and only the head. It is a different value on
    every run by construction, which is the property the chain exists to have, so comparing it
    would fail every time and comparing nothing would catch nothing. Every other line, and
    that is every number the demo reports, still has to match exactly.

    The log path is pinned so the capture does not carry one machine's temp directory layout
    onto a public page.
    """
    committed = (ROOT / "docs" / "evidence" / "demo.txt").read_text(encoding="utf-8")
    live = subprocess.run(
        [sys.executable, "examples/demo_ab.py", "--log", "/tmp/quellz-demo.log.jsonl"],
        capture_output=True,
        text=True,
        timeout=600,
        check=True,
        cwd=ROOT,
    ).stdout
    assert CHAIN_HEAD.sub("<head>", committed) == CHAIN_HEAD.sub("<head>", live), (
        "docs/evidence/demo.txt no longer matches a live run. "
        "Run: uv run --extra anthropic python scripts/capture_evidence.py, then regenerate."
    )
    # The masking must not be doing all the work: a real chain head has to be in there.
    assert CHAIN_HEAD.search(committed), "the committed capture carries no hash chain head"


def test_the_published_card_carries_the_output_it_claims_to() -> None:
    card = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
    demo = (ROOT / "docs" / "evidence" / "demo.txt").read_text(encoding="utf-8")
    assert _escaped(demo.rstrip()) in card, "the card's terminal block is not the captured output"
    assert "a test fails when it" in card
    # No machine specific path may reach a public page.
    assert "/Users/" not in card and "/var/folders/" not in card


def test_the_card_states_numbers_that_are_true_today() -> None:
    """Skipped without the optional extra, because the total is a different number then.

    `tests/test_adapter_anthropic.py` skips at import when anthropic is absent, so a
    collection run without the extra counts fewer tests than the suite has. CI installs all
    extras on 3.11 to 3.13 and this assertion runs there; the 3.14 leg deliberately installs
    the zero dependency core only and skips it.
    """
    pytest.importorskip("anthropic")
    facts = json.loads((ROOT / "docs" / "evidence" / "facts.json").read_text(encoding="utf-8"))
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-o", "addopts=", "--collect-only", "-q"],
        capture_output=True,
        text=True,
        timeout=600,
        check=True,
        cwd=ROOT,
    )
    match = re.search(r"^(\d+) tests? collected", result.stdout, re.MULTILINE)
    assert match is not None, f"no collection total in:\n{result.stdout[-400:]}"
    assert facts["tests"] == int(match.group(1)), "facts.json's test total is stale"
    assert facts["release"] == f"v{__version__}"
    card = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
    assert f"<dd>{facts['tests']}</dd>" in card
    assert f"<dd>{facts['release']}</dd>" in card


def test_the_readme_frame_is_built_from_the_captured_output() -> None:
    """The animated frame in the first screenful has to be the real run, not a picture of one.

    Every text line the SVG draws, minus the prompt line it adds and the truncation note it
    ends with, must appear in the captured output in the same order. Written this way rather
    than by re-deriving the generator's truncation arithmetic, because a test that reimplements
    the thing it checks passes for the wrong reason.
    """
    svg = (ROOT / "docs" / "demo.svg").read_text(encoding="utf-8")
    demo = (ROOT / "docs" / "evidence" / "demo.txt").read_text(encoding="utf-8")

    drawn = [html.unescape(m) for m in re.findall(r"<text[^>]*>(.*?)</text>", svg, re.DOTALL)]
    assert drawn, "the frame draws no text at all"
    assert drawn[0].startswith("$ "), "the frame does not open on the command it ran"
    assert drawn[-1].startswith("... ") and "more lines" in drawn[-1]

    body = [line for line in drawn[1:-2] if line.strip()]
    haystack = demo.splitlines()
    position = 0
    for line in body:
        stem = line[:-3] if line.endswith("...") else line
        while position < len(haystack) and not haystack[position].startswith(stem):
            position += 1
        assert position < len(haystack), f"the frame draws a line the run never printed: {line!r}"
        position += 1

    # ASCII only, and STRICTLY so, which the tree-wide scan in test_bytes.py is not: that one
    # exempts the datamarking marker. Nothing exempts it here. The frame is generated, so a non
    # ASCII glyph would arrive silently from a code change rather than from anyone typing one,
    # and the one non ASCII character this repository owns is the last one that should reach an
    # image rendered by a proxy. The comment that used to sit here named a test in a sibling
    # repository and claimed it covered this tree; it did not exist here under any name.
    assert svg.isascii()
    assert "<script" not in svg, "a README image is served through a proxy that strips script"
