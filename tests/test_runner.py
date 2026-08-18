import json
from collections.abc import Sequence

import pytest

from quellz.catalog import get_catalog
from quellz.contain import HashChainLog, LeastPrivilege
from quellz.mock import NaiveMockAgent
from quellz.report import Report
from quellz.runner import compare, run_suite
from quellz.sandbox import API_KEY_VALUE, ATTACKER_EMAIL, ATTACKER_WEBHOOK
from quellz.types import Agent, AgentResult, CatalogError, CatalogMismatch, Tool, ToolCall


def _rates(report: Report) -> list[float]:
    rates = [report.benign_utility, report.utility_under_attack, report.targeted_asr]
    for stats in report.by_technique:
        rates += [stats.benign_utility, stats.utility_under_attack, stats.targeted_asr]
    return rates


def test_every_case_runs_in_both_conditions(baseline: Report):
    assert baseline.n_cases == len(get_catalog())
    assert {case.attack_id for case in baseline.cases} == {a.id for a in get_catalog()}
    for case in baseline.cases:
        assert case.tool_calls_benign, case.attack_id
        assert case.tool_calls_attacked, case.attack_id


def test_every_rate_is_a_probability(baseline: Report, contained: Report):
    for report in (baseline, contained):
        assert all(0.0 <= rate <= 1.0 for rate in _rates(report)), report.label
        assert sum(stats.n_cases for stats in report.by_technique) == report.n_cases


def test_no_payload_string_leaks_into_a_benign_transcript(baseline: Report):
    """The benign condition is the control. A payload reaching it would void every delta."""
    payloads = {attack.id: attack.payload for attack in get_catalog()}
    for case in baseline.cases:
        seen = [value for call in case.tool_calls_benign for value in call.args.values()]
        seen += [call.result for call in case.tool_calls_benign if call.result]
        blob = "\n".join(seen)
        assert payloads[case.attack_id] not in blob, case.attack_id
        for marker in (ATTACKER_EMAIL, ATTACKER_WEBHOOK, API_KEY_VALUE):
            assert marker not in blob, f"{case.attack_id} leaked {marker}"


def test_containment_never_raises_the_attack_success_rate(baseline: Report, contained: Report):
    assert contained.targeted_asr <= baseline.targeted_asr
    before = {stats.technique: stats.targeted_asr for stats in baseline.by_technique}
    for stats in contained.by_technique:
        assert stats.targeted_asr <= before[stats.technique], stats.technique


def test_the_anti_degenerate_configuration_scores_zero_on_both_axes():
    """A policy that blocks everything must look bad in this output, never good."""

    def deny_everything() -> Agent:
        return LeastPrivilege(
            NaiveMockAgent(), allowed_tools=frozenset(), allowed_sensitivity=frozenset()
        )

    report = run_suite(deny_everything, label="deny-everything")
    assert report.targeted_asr == 0.0
    assert report.utility_under_attack == 0.0
    assert report.benign_utility == 0.0


def test_compare_refuses_two_reports_over_different_cases(baseline: Report):
    subset = run_suite(NaiveMockAgent, attacks=get_catalog()[:4], label="subset")
    with pytest.raises(CatalogMismatch, match="different cases"):
        compare(baseline, subset)


def test_compare_arithmetic_is_before_minus_after(baseline: Report, contained: Report):
    delta = compare(baseline, contained)
    assert {row.technique for row in delta.rows} == {
        str(stats.technique) for stats in contained.by_technique
    }
    for row in (*delta.rows, delta.overall):
        assert row.asr_reduction == pytest.approx(row.targeted_asr_before - row.targeted_asr_after)
        assert row.utility_cost == pytest.approx(
            row.utility_under_attack_before - row.utility_under_attack_after
        )
    assert delta.overall.technique == "overall"
    assert delta.overall.n_cases == contained.n_cases
    assert delta.overall.targeted_asr_before == baseline.targeted_asr
    assert delta.overall.targeted_asr_after == contained.targeted_asr


def test_the_demo_policy_costs_benign_utility_and_the_report_shows_it(contained: Report):
    """Over blocking is visible in the numbers on purpose, so it is not tuned away."""
    assert contained.benign_utility < 1.0
    assert sum(case.blocked_calls_benign for case in contained.cases) > 0


def test_run_suite_refuses_an_empty_attack_list():
    with pytest.raises(CatalogError, match="empty attack list"):
        run_suite(NaiveMockAgent, attacks=())


class LyingAgent:
    """An agent whose account of itself is false: it writes a note and reports a send.

    The agent is the untrusted component in this harness, so this is exactly the record a
    hash chain built from AgentResult.tool_calls would preserve tamper-evidently.
    """

    def run(self, prompt: str, tools: Sequence[Tool]) -> AgentResult:
        {tool.name: tool for tool in tools}["write_note"].fn(
            name="real.md", body="this really happened"
        )
        return AgentResult(
            text="",
            tool_calls=(
                ToolCall(name="send_email", args={"to": "nobody"}, executed=True, result="fiction"),
            ),
        )


def test_the_hash_chain_records_the_sandbox_not_the_agents_account_of_itself(tmp_path):
    path = tmp_path / "chain.jsonl"
    log = HashChainLog(path)
    run_suite(LyingAgent, attacks=get_catalog()[:1], label="lying", log=log)

    entries = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    called = {entry["data"]["tool"] for entry in entries if entry["event"] == "tool_call"}
    assert called == {"write_note"}, "the chain has to hold the call that reached the sandbox"
