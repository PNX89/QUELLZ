"""Packaging claims, and the claims the contributing guide makes about the gates."""

import re
import tomllib
from pathlib import Path

import quellz

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
CONTRIBUTING = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

#: The command that runs each gate the contributing guide is allowed to name. A word in that
#: sentence with no entry here fails rather than passing quietly, because a gate this file has
#: never heard of is exactly the one nobody is running.
GATE_COMMANDS = {
    "linting": "ruff check",
    "formatting": "ruff format",
    "typing": "mypy",
    "tests": "pytest",
}


def _listed_commands() -> list[str]:
    """The fenced block under the heading that promises it matches CI."""
    section = CONTRIBUTING.split("\n## The checks you can run here\n", 1)[1]
    block = section.split("```bash\n", 1)[1].split("```", 1)[0]
    return [line.strip() for line in block.splitlines() if line.strip()]


def _gates_claimed() -> list[str]:
    """The checks the guide's own sentence commits to, read out of that sentence alone.

    Searching the whole file for a word would find it in any paragraph that happens to mention
    it, which is a check that cannot fail. The claim lives in one sentence, so the subject of
    that sentence is what is read.
    """
    flat = " ".join(CONTRIBUTING.split())
    sentences = [s for s in re.split(r"(?<=[.:])\s+", flat) if "are gates here" in s]
    assert len(sentences) == 1, f"expected one sentence claiming gates, found {len(sentences)}"
    subject = sentences[0].split("are gates here", 1)[0].lower()
    return [word.strip() for word in re.split(r",|\band\b", subject) if word.strip()]


def test_the_core_install_has_no_runtime_dependencies():
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    assert project["dependencies"] == []
    assert project["version"] == quellz.__version__


def test_every_gate_the_guide_names_has_a_command_in_the_list_above_it():
    """The guide called typing a gate while nothing in the repository type checked.

    The command list is generated out of ci.yml; the sentence under it is written by hand, and
    it named a check that had no command, no dev dependency and no CI leg. A repository whose
    whole argument is that prose drifts away from code had the drift in its own guide.
    """
    claimed = _gates_claimed()
    assert claimed, "the sentence claims gates and names none of them"
    unknown = [word for word in claimed if word not in GATE_COMMANDS]
    assert unknown == [], f"this test does not know which command runs {unknown}"
    listed = " ".join(_listed_commands())
    for word in claimed:
        assert GATE_COMMANDS[word] in listed, (
            f"the guide calls {word} a gate and lists no command that runs it. Either add the "
            "command, or stop claiming it."
        )


def test_the_typing_gate_is_installed_configured_and_switched_on_in_ci():
    """Three separate places, because the gate is only real where all three agree.

    A checker that is not a dev dependency cannot run at all, a checker with no configuration
    checks whatever the command line happens to say, and the shared workflow's run-mypy input
    defaults to false, so a leg that does not set it runs nothing. All three were the case here
    while the wheel shipped py.typed and the metadata claimed Typing :: Typed.
    """
    config = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    dev = config["dependency-groups"]["dev"]
    assert any(dependency.startswith("mypy") for dependency in dev), dev

    mypy = config["tool"]["mypy"]
    assert mypy["strict"] is True
    assert "src" in mypy["files"], "the package is what py.typed promises, so it has to be checked"

    legs = CI.count("uses: PNX89/.github/.github/workflows/checks.yml@")
    assert legs == 2, f"ci.yml calls the shared workflow {legs} times, not twice"
    assert CI.count("run-mypy: true") == legs, (
        "run-mypy defaults to false in the shared workflow, so every leg has to switch it on "
        "or the guide is naming a gate that leg does not run"
    )


def test_the_typing_metadata_promises_only_what_the_gate_keeps():
    """`Typing :: Typed` and py.typed are a promise to a consumer that the annotations hold.

    They are asserted here beside the checker rather than on their own, so the promise and the
    thing that keeps it cannot be separated by deleting either one.
    """
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    assert "Typing :: Typed" in project["classifiers"]
    assert (ROOT / "src" / "quellz" / "py.typed").is_file()
