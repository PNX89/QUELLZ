"""Run the catalog once against a real model, bare and contained, and report cost with it.

WHY THIS EXISTS. Every number in the README is produced by `demo_ab.py` against the bundled
NaiveMockAgent, which is a conformance fixture with a published obedience rule. That proves
the containment layer enforces its stated policy. It proves nothing about a real model, and
the README says so. This file closes that gap once, on a dated run, and prints what it cost.

WHAT IT IS NOT. It is not the CI subject and must never become one. CI stays offline: no job
needs a key and `conftest.py` blocks sockets for the whole session. This is a hand run.

THE PUBLISHED-NULL POLICY, WRITTEN BEFORE THE FIRST RUN AND NOT REVISED AFTER IT.
A current frontier model is expected to refuse most naive injections unprompted. If it does,
the bare condition scores a low attack success rate on its own and the containment layer will
look like it is solving a problem the model already solved. **That result gets published in
the README exactly as it lands.** A harness that only reports the runs that flatter it is the
thing this repository exists to argue against, and reporting a null here is the same
discipline as reporting one in a backtest.

Usage, with a key in the environment:

    ANTHROPIC_API_KEY=... uv run python examples/live_run.py --model claude-sonnet-5
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pathlib
import threading
from typing import Any

from quellz import LeastPrivilege, SpotlightWrapper, compare, render_delta, run_suite
from quellz.adapters.anthropic import AnthropicAgent
from quellz.catalog import ATTACKS, CATALOG_VERSION
from quellz.cli import DEMO_ALLOWED_SENSITIVITY, DEMO_ALLOWED_TOOLS

# Published prices per million tokens, USD, at the time of the run. Recorded here rather than
# fetched, so the cost line in the README can be re-derived from the token counts by anyone.
PRICES = {
    "claude-sonnet-5": (3.00, 15.00),
    "claude-opus-5": (15.00, 75.00),
    "claude-haiku-4-5-20251001": (1.00, 5.00),
}


class MeteredMessages:
    """Wraps client.messages so every call's token usage is accumulated."""

    def __init__(self, inner: Any, meter: dict[str, int], lock: threading.Lock) -> None:
        self.inner, self.meter, self.lock = inner, meter, lock

    def create(self, **kwargs: Any) -> Any:
        response = self.inner.create(**kwargs)
        usage = getattr(response, "usage", None)
        if usage is not None:
            with self.lock:
                self.meter["calls"] += 1
                self.meter["input"] += getattr(usage, "input_tokens", 0) or 0
                self.meter["output"] += getattr(usage, "output_tokens", 0) or 0
        return response


class MeteredClient:
    def __init__(self, inner: Any, meter: dict[str, int], lock: threading.Lock) -> None:
        self._inner, self._meter, self._lock = inner, meter, lock

    @property
    def messages(self) -> MeteredMessages:
        return MeteredMessages(self._inner.messages, self._meter, self._lock)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="claude-sonnet-5")
    parser.add_argument("--out", default="docs/evidence/live-run.json")
    args = parser.parse_args()

    import anthropic

    meter = {"calls": 0, "input": 0, "output": 0}
    lock = threading.Lock()
    raw = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    def build() -> AnthropicAgent:
        # A fresh agent per attack, per the Agent protocol: conversation state lives on the
        # instance, so reusing one would leak turn N into turn N+1.
        return AnthropicAgent(model=args.model, client=MeteredClient(raw, meter, lock))

    bare = run_suite(build, attacks=ATTACKS, label="bare")

    # Same stack and same policy as examples/demo_ab.py, so the live numbers are comparable
    # with the mock numbers in the README rather than measuring a different configuration.
    def contained_factory() -> Any:
        return LeastPrivilege(
            SpotlightWrapper(build()),
            allowed_tools=DEMO_ALLOWED_TOOLS,
            allowed_sensitivity=DEMO_ALLOWED_SENSITIVITY,
        )

    contained = run_suite(contained_factory, attacks=ATTACKS, label="contained")

    cost_in, cost_out = PRICES.get(args.model, (0.0, 0.0))
    usd = meter["input"] / 1e6 * cost_in + meter["output"] / 1e6 * cost_out
    delta = compare(bare, contained)

    # Written in two stages deliberately. Stage one holds everything the API calls paid for
    # and is saved before any enrichment touches it, because a serialisation bug in the
    # enrichment destroyed a completed 1.25 USD run on 24-8-2026. Never transform an
    # expensive result before persisting it.
    record = {
        "model": args.model,
        "catalog_version": CATALOG_VERSION,
        "attacks": len(ATTACKS),
        "calls": meter["calls"],
        "input_tokens": meter["input"],
        "output_tokens": meter["output"],
        "usd": round(usd, 4),
        "bare": {
            "targeted_asr": bare.targeted_asr,
            "benign_utility": bare.benign_utility,
            "utility_under_attack": bare.utility_under_attack,
        },
        "contained": {
            "targeted_asr": contained.targeted_asr,
            "benign_utility": contained.benign_utility,
            "utility_under_attack": contained.utility_under_attack,
        },
        # Per technique, because an aggregate of 21 cannot tell you WHICH family moved, and
        # a two case difference on a non deterministic model is inside run to run noise.
        "by_technique": {
            "bare": [dataclasses.asdict(t) for t in bare.by_technique],
            "contained": [dataclasses.asdict(t) for t in contained.by_technique],
        },
        "delta_rows": [dataclasses.asdict(r) for r in delta.rows],
    }
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=2) + "\n")
    print(f"[saved] {out}")
    print(json.dumps(record, indent=2))
    print()
    print(render_delta(delta, "markdown"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
