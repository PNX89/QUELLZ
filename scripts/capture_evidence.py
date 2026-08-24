"""Capture the demo's real output and the numbers the Pages card states.

WHY THIS EXISTS. The card at pnx89.github.io/QUELLZ shows the output of a real run and four
numbers about this repository. Both are committed, which means both can go stale.
`tests/test_readme.py` fails when what is committed stops matching a live run.

TWO THINGS ABOUT THIS DEMO IN PARTICULAR.

The log path is pinned with --log. Left to itself the demo writes into the platform temp
directory, and on macOS that is a path containing a per-user token, which would put one
machine's directory layout on a public page for no reason at all.

The hash chain head is different on every run and that is the point of it, so the committed
capture keeps the real head from the real run that produced it, and the freshness test masks
the head on both sides before comparing. Nothing is faked and drift anywhere else is still
caught.

    uv run python scripts/capture_evidence.py
"""

from __future__ import annotations

import datetime
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs" / "evidence"
LOG = "/tmp/quellz-demo.log.jsonl"
DEMO = [sys.executable, "examples/demo_ab.py", "--log", LOG]


def run(*args: str) -> str:
    result = subprocess.run(args, capture_output=True, text=True, cwd=ROOT, timeout=600)
    if result.returncode:
        raise SystemExit(f"{args[0]} failed: {result.stderr.strip()[:400]}")
    return result.stdout


def test_total() -> int:
    """Collected with the optional adapter extra present, because that is the whole suite.

    Without it `tests/test_adapter_anthropic.py` skips at import and the total is lower. A
    card stating the smaller number would be understating the repository, and one stating the
    larger while the extra was absent would be overstating it, so the capture requires it.
    """
    try:
        import anthropic  # noqa: F401
    except ImportError:
        raise SystemExit(
            "the anthropic extra is not installed, so the adapter tests would not be counted. "
            "Run: uv sync --all-extras --dev"
        ) from None
    out = run(sys.executable, "-m", "pytest", "-o", "addopts=", "--collect-only", "-q")
    match = re.search(r"^(\d+) tests? collected", out, re.MULTILINE)
    if not match:
        raise SystemExit(f"could not read a collection total from:\n{out[-400:]}")
    return int(match.group(1))


def python_range() -> str:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    versions = sorted({v for v in re.findall(r'"(3\.\d+)"', workflow)}, key=lambda v: int(v[2:]))
    if not versions:
        raise SystemExit("no Python versions found in the CI matrix")
    return f"{versions[0]} to {versions[-1]}"


def release() -> str:
    """From the package version, cross-checked against the newest reachable tag."""
    from quellz import __version__

    tag = f"v{__version__}"
    described = subprocess.run(
        ["git", "describe", "--tags", "--abbrev=0"], capture_output=True, text=True, cwd=ROOT
    )
    if described.returncode == 0 and described.stdout.strip() != tag:
        raise SystemExit(
            f"the newest tag is {described.stdout.strip()} but the version is {__version__}"
        )
    return tag


def main() -> int:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    output = run(*DEMO)
    if not output.strip():
        raise SystemExit("the demo produced no output, refusing to write empty evidence")
    if "/Users/" in output or "/var/folders/" in output:
        raise SystemExit("the demo output still carries a machine specific path, refusing")
    (EVIDENCE / "demo.txt").write_text(output, encoding="utf-8")

    run_id = os.environ.get("GITHUB_RUN_ID")
    slug = os.environ.get("GITHUB_REPOSITORY", "PNX89/QUELLZ")
    facts = {
        "tests": test_total(),
        "python": python_range(),
        "release": release(),
        "captured": datetime.date.today().isoformat(),
        "runUrl": f"https://github.com/{slug}/actions/runs/{run_id}" if run_id else None,
    }
    (EVIDENCE / "facts.json").write_text(json.dumps(facts, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {EVIDENCE / 'demo.txt'} ({len(output.splitlines())} lines)")
    print(f"wrote {EVIDENCE / 'facts.json'} {facts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
