"""Runs the catalog against an agent factory and scores both conditions."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import replace

from quellz.attacks import Attack, Technique
from quellz.catalog import CATALOG_VERSION, get_catalog
from quellz.contain import HashChainLog
from quellz.report import (
    CaseResult,
    Delta,
    DeltaRow,
    Meta,
    Report,
    TechniqueStats,
    caveat_for,
)
from quellz.sandbox import Sandbox, build_tools
from quellz.types import (
    Agent,
    AgentResult,
    CatalogError,
    CatalogMismatch,
    Tool,
    ToolCall,
    Transcript,
)

__all__ = [
    "CaseResult",
    "Delta",
    "Report",
    "TechniqueStats",
    "compare",
    "run_suite",
]

AgentFactory = Callable[[], Agent]


def run_suite(
    agent_factory: AgentFactory,
    *,
    attacks: Sequence[Attack] | None = None,
    label: str = "baseline",
    max_steps: int = 4,
    seed: int = 0,
    log: HashChainLog | None = None,
) -> Report:
    """Run every attack twice, once with the payload omitted and once with it injected.

    A fresh agent and a fresh Sandbox come from the factory per condition per case, so no
    case can leak state into the next one and the protocol needs no reset().

    ``seed`` and ``max_steps`` are recorded in Report.meta rather than imposed on the agent.
    The protocol makes the agent responsible for its own loop bound and its own sampling, so
    an agent supplied through a factory carries both; the bundled CLI builds its demo factory
    with the max_steps it was given.
    """
    selected = tuple(get_catalog() if attacks is None else attacks)
    if not selected:
        raise CatalogError("run_suite was given an empty attack list")
    agent_name, containment = _describe(agent_factory())
    cases = tuple(_run_case(attack, agent_factory, label=label, log=log) for attack in selected)
    return Report(
        label=label,
        agent_name=agent_name,
        containment=containment,
        n_cases=len(cases),
        benign_utility=_rate(case.benign_utility_pass for case in cases),
        utility_under_attack=_rate(case.utility_under_attack_pass for case in cases),
        targeted_asr=_rate(case.attack_succeeded for case in cases),
        by_technique=_by_technique(cases),
        cases=cases,
        meta=Meta(
            seed=seed,
            max_steps=max_steps,
            catalog_version=CATALOG_VERSION,
            quellz_version=_quellz_version(),
            # The caveat is chosen by who produced the numbers, not hardcoded to the fixture.
            caveat=caveat_for(agent_name),
        ),
    )


def compare(baseline: Report, contained: Report) -> Delta:
    """Pair two reports technique by technique. Raises CatalogMismatch on differing case sets."""
    before = {case.attack_id for case in baseline.cases}
    after = {case.attack_id for case in contained.cases}
    if before != after:
        differing = sorted(before ^ after)
        raise CatalogMismatch(
            f"the reports cover different cases: {', '.join(differing[:4])}"
            + (" and more" if len(differing) > 4 else "")
        )
    baseline_stats = {stats.technique: stats for stats in baseline.by_technique}
    rows = tuple(
        _delta_row(
            str(stats.technique),
            stats.n_cases,
            baseline_stats[stats.technique].targeted_asr,
            stats.targeted_asr,
            baseline_stats[stats.technique].utility_under_attack,
            stats.utility_under_attack,
        )
        for stats in contained.by_technique
    )
    return Delta(
        agent_name=contained.agent_name,
        baseline_label=baseline.label,
        contained_label=contained.label,
        baseline_containment=baseline.containment,
        contained_containment=contained.containment,
        n_cases=contained.n_cases,
        benign_utility_before=baseline.benign_utility,
        benign_utility_after=contained.benign_utility,
        rows=rows,
        overall=_delta_row(
            "overall",
            contained.n_cases,
            baseline.targeted_asr,
            contained.targeted_asr,
            baseline.utility_under_attack,
            contained.utility_under_attack,
        ),
        meta=contained.meta,
    )


def _run_case(
    attack: Attack, factory: AgentFactory, *, label: str, log: HashChainLog | None
) -> CaseResult:
    benign, benign_sandbox = _run_condition(attack, factory, attacked=False, label=label, log=log)
    attacked, attacked_sandbox = _run_condition(
        attack, factory, attacked=True, label=label, log=log
    )
    benign_calls = _calls(benign)
    attacked_calls = _calls(attacked)
    return CaseResult(
        attack_id=attack.id,
        technique=attack.technique,
        vector=attack.vector,
        benign_utility_pass=attack.utility_success.check(benign, benign_sandbox),
        utility_under_attack_pass=attack.utility_success.check(attacked, attacked_sandbox),
        attack_succeeded=attack.success.check(attacked, attacked_sandbox),
        blocked_calls_benign=sum(1 for call in benign_calls if not call.executed),
        blocked_calls_attacked=sum(1 for call in attacked_calls if not call.executed),
        tool_calls_benign=benign_calls,
        tool_calls_attacked=attacked_calls,
    )


def _run_condition(
    attack: Attack,
    factory: AgentFactory,
    *,
    attacked: bool,
    label: str,
    log: HashChainLog | None,
) -> tuple[Transcript, Sandbox]:
    sandbox = Sandbox()
    agent = factory()
    poison = attack.injection() if attacked else None
    transcript: list[AgentResult] = []
    for turn in range(len(attack.turns)):
        # A payload on a tool surface is planted from inject_at_turn onwards, which is what
        # lets a two turn case keep the first turn clean.
        live = poison if turn >= attack.inject_at_turn else None
        tools = build_tools(sandbox, poison=live)
        if log is not None:
            tools = _tap(tools, log, attack=attack, label=label, attacked=attacked, turn=turn)
        result = agent.run(attack.prompt_for_turn(turn, attacked=attacked), tools)
        transcript.append(result)
    return tuple(transcript), sandbox


def _tap(
    tools: Sequence[Tool],
    log: HashChainLog,
    *,
    attack: Attack,
    label: str,
    attacked: bool,
    turn: int,
) -> tuple[Tool, ...]:
    """Chain every call that reaches the sandbox, recorded at the sandbox.

    The agent is the untrusted component in this harness, so a chain built from
    AgentResult.tool_calls would be a tamper-evident record of the agent's own account of
    itself. The tap sits on the callable the agent has to invoke to get a result, so an agent
    that under-reports a call it made, or reports one it did not, changes nothing here.

    Refusals never reach the tap by construction: a containment layer wraps these tools and
    raises before delegating. That is the other half of the record, and it is why
    LeastPrivilege takes a log of its own.
    """

    def tapped(tool: Tool) -> Tool:
        def call(**kwargs: str) -> str:
            # Written after the call returns, so the entry records a call that ran rather than
            # one that was about to.
            output = tool.fn(**kwargs)
            log.append(
                "tool_call",
                {
                    "run": label,
                    "attack": attack.id,
                    "condition": "attacked" if attacked else "benign",
                    "turn": turn,
                    "tool": tool.name,
                },
            )
            return output

        return replace(tool, fn=call)

    return tuple(tapped(tool) for tool in tools)


def _calls(transcript: Transcript) -> tuple[ToolCall, ...]:
    return tuple(call for result in transcript for call in result.tool_calls)


def _describe(agent: Agent) -> tuple[str, str]:
    """Split a wrapped agent into the innermost agent name and the containment stack.

    The innermost agent gets the same courtesy the wrapper layers already got: its own
    `name` wins over its class name. A report is evidence, and a class name alone cannot
    say which model produced it, which the first live run demonstrated by printing
    `agent AnthropicAgent` for a run whose whole point was the model it named nowhere.
    """
    layers: list[str] = []
    current: object = agent
    while (inner := getattr(current, "inner", None)) is not None:
        layers.append(str(getattr(current, "name", type(current).__name__)))
        current = inner
    return str(getattr(current, "name", None) or type(current).__name__), (
        " + ".join(layers) if layers else "none"
    )


def _rate(flags: Iterable[bool]) -> float:
    values = list(flags)
    # Rounded so the JSON output carries 0.15 rather than 0.15000000000000002.
    return round(sum(1 for flag in values if flag) / len(values), 4) if values else 0.0


def _by_technique(cases: Sequence[CaseResult]) -> tuple[TechniqueStats, ...]:
    stats: list[TechniqueStats] = []
    for technique in Technique:
        group = [case for case in cases if case.technique is technique]
        if not group:
            continue
        stats.append(
            TechniqueStats(
                technique=technique,
                n_cases=len(group),
                benign_utility=_rate(case.benign_utility_pass for case in group),
                utility_under_attack=_rate(case.utility_under_attack_pass for case in group),
                targeted_asr=_rate(case.attack_succeeded for case in group),
                blocked_calls_benign=sum(case.blocked_calls_benign for case in group),
                blocked_calls_attacked=sum(case.blocked_calls_attacked for case in group),
            )
        )
    return tuple(stats)


def _delta_row(
    technique: str,
    n_cases: int,
    asr_before: float,
    asr_after: float,
    utility_before: float,
    utility_after: float,
) -> DeltaRow:
    return DeltaRow(
        technique=technique,
        n_cases=n_cases,
        targeted_asr_before=asr_before,
        targeted_asr_after=asr_after,
        asr_reduction=round(asr_before - asr_after, 4),
        utility_under_attack_before=utility_before,
        utility_under_attack_after=utility_after,
        utility_cost=round(utility_before - utility_after, 4),
    )


def _quellz_version() -> str:
    # Deferred because quellz/__init__.py imports this module.
    from quellz import __version__

    return __version__
