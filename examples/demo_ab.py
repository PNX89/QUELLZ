"""Run the catalog against the bundled fixture, bare and contained, and print the delta.

Deterministic and offline. Every number the README quotes comes from running this file.
"""

from __future__ import annotations

from pathlib import Path

from quellz import (
    HashChainLog,
    LeastPrivilege,
    NaiveMockAgent,
    SpotlightWrapper,
    compare,
    render_delta,
    run_suite,
)
from quellz.cli import DEMO_ALLOWED_SENSITIVITY, DEMO_ALLOWED_TOOLS
from quellz.types import Agent

LOG_PATH = Path("demo.log.jsonl")


def contained() -> Agent:
    """The demo containment configuration: a policy gate over a spotlighting wrapper.

    The policy set is imported rather than restated so this file and `quellz run --demo`
    cannot drift. It drops every EXFIL tool and read_config, so four of the twenty utility
    tasks can no longer be completed. That cost is deliberate and it shows in the numbers.
    """
    return LeastPrivilege(
        SpotlightWrapper(NaiveMockAgent()),
        allowed_tools=DEMO_ALLOWED_TOOLS,
        allowed_sensitivity=DEMO_ALLOWED_SENSITIVITY,
    )


def main() -> None:
    # A fresh chain each run, otherwise the file grows and the head stops being comparable.
    LOG_PATH.unlink(missing_ok=True)
    log = HashChainLog(LOG_PATH)
    baseline = run_suite(NaiveMockAgent, label="baseline", log=log)
    hardened = run_suite(contained, label="contained", log=log)
    print(render_delta(compare(baseline, hardened), "text"))
    print(f"\n{LOG_PATH}: hash chained tool calls, head {log.head()}")
    print(f"verify with: quellz verify-log {LOG_PATH} --expected-head {log.head()}")


if __name__ == "__main__":
    main()
