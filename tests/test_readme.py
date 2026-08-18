"""Documentation integrity: the README has to stay true to the code it documents.

Every command block in the README is executed here and every number it quotes is compared
against live output. `uv run X` is translated to the interpreter running this suite, which is
the environment uv would hand it, so these tests need neither uv nor the network.
"""

import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

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
