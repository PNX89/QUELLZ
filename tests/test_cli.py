import argparse
import json

import pytest

from quellz import __version__, cli
from quellz.attacks import Technique
from quellz.catalog import get_catalog
from quellz.cli import EXIT_GATE, EXIT_OK, EXIT_USAGE, UTILITY_GATE_OFF, _gate, main
from quellz.contain import HashChainLog
from quellz.report import Meta, Report, TechniqueStats

PERMISSIVE = ["--max-asr", "1.0", "--min-utility", "0.0"]


def _single_technique_report(*, targeted_asr: float) -> Report:
    """A minimal Report with one technique, for unit testing _gate at an exact ASR boundary
    without depending on the demo catalog's own numbers, which change independently of this.
    """
    stats = TechniqueStats(
        technique=Technique.DIRECT_OVERRIDE,
        n_cases=4,
        benign_utility=1.0,
        utility_under_attack=1.0,
        targeted_asr=targeted_asr,
        blocked_calls_benign=0,
        blocked_calls_attacked=0,
    )
    return Report(
        label="contained",
        agent_name="NaiveMockAgent",
        containment="none",
        n_cases=4,
        benign_utility=1.0,
        utility_under_attack=1.0,
        targeted_asr=targeted_asr,
        by_technique=(stats,),
        cases=(),
        meta=Meta(seed=0, max_steps=4, catalog_version="test", quellz_version=__version__),
    )


def test_the_demo_run_passes_permissive_gates_and_writes_both_files(tmp_path, capsys):
    as_json = tmp_path / "report.json"
    as_markdown = tmp_path / "report.md"
    code = main(["run", "--demo", *PERMISSIVE, "--json", str(as_json), "--md", str(as_markdown)])
    printed = capsys.readouterr().out
    assert code == EXIT_OK
    assert "QUELLZ delta: baseline to contained" in printed
    assert UTILITY_GATE_OFF in printed
    document = json.loads(as_json.read_text(encoding="utf-8"))
    assert set(document) == {"baseline", "contained", "delta"}
    assert document["delta"]["overall"]["targeted_asr_after"] <= 1.0
    assert "| overall |" in as_markdown.read_text(encoding="utf-8")


def test_an_impossible_asr_gate_fails_the_baseline_run(capsys):
    code = main(["run", "--demo", "--mode", "baseline", "--max-asr", "0.0"])
    printed = capsys.readouterr().out
    assert code == EXIT_GATE
    assert "gate FAILED on the baseline report" in printed
    assert "above --max-asr 0.00" in printed

    # The help text for --max-asr says "fail if the worst technique scores above this", and
    # 0.0 above is nowhere near that boundary: any positive ASR fails it. Nothing here exercised
    # the boundary itself, so > against >= in _gate would leave the whole suite green.
    report = _single_technique_report(targeted_asr=0.25)
    at_boundary = argparse.Namespace(max_asr=0.25, min_utility=0.0)
    assert _gate({"contained": report}, at_boundary) == EXIT_OK
    just_past = argparse.Namespace(max_asr=0.24, min_utility=0.0)
    assert _gate({"contained": report}, just_past) == EXIT_GATE


def test_an_impossible_utility_gate_fails_the_contained_run(capsys):
    code = main(
        ["run", "--demo", "--mode", "contained", "--max-asr", "1.0", "--min-utility", "1.0"]
    )
    printed = capsys.readouterr().out
    assert code == EXIT_GATE
    assert "below --min-utility 1.00" in printed


def test_a_bad_agent_path_names_the_path_and_prints_no_traceback(monkeypatch, capsys):
    assert main(["run", "--agent", "nosuch.module:build"]) == EXIT_USAGE
    printed = capsys.readouterr().err
    assert "nosuch.module:build" in printed
    assert "Traceback" not in printed

    # main's dispatch is an explicit if-chain, not an exhaustive match, and it used to end in
    # a bare `return _verify_log(args)` standing in for every command the two `if`s above it
    # did not name. _verify_log reads args.path immediately, which a fourth subcommand would
    # not define, so adding one without also adding its dispatch branch used to crash with an
    # uncaught AttributeError instead of the no-traceback contract just checked above. The real
    # parser enforces `required=True` over a fixed choice set, so it can never itself hand main
    # a name the dispatcher does not expect; this fakes exactly that one gap.
    class _StubParser:
        def parse_args(self, argv=None):
            return argparse.Namespace(command="selftest")

    monkeypatch.setattr(cli, "_parser", _StubParser)
    assert main(["selftest"]) == EXIT_USAGE
    printed = capsys.readouterr().err
    assert "unknown command 'selftest'" in printed
    assert "Traceback" not in printed


def test_catalog_json_parses_and_lists_every_fixture(capsys):
    assert main(["catalog", "--json"]) == EXIT_OK
    entries = json.loads(capsys.readouterr().out)
    assert len(entries) == 21
    assert {entry["id"] for entry in entries} == {attack.id for attack in get_catalog()}
    assert all(entry["fixture"] for entry in entries)


def test_verify_log_passes_on_a_good_chain_and_fails_on_a_tampered_one(tmp_path, capsys):
    path = tmp_path / "run.jsonl"
    run = ["run", "--demo", "--mode", "contained", *PERMISSIVE, "--log", str(path)]
    assert main(run) == EXIT_OK
    capsys.readouterr()
    head = HashChainLog(path).head()
    assert main(["verify-log", str(path), "--expected-head", head]) == EXIT_OK
    assert "log verified" in capsys.readouterr().out

    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[2])
    entry["data"]["tool"] = "post_webhook"
    lines[2] = json.dumps(entry, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert main(["verify-log", str(path)]) == EXIT_GATE
    assert "FAILED" in capsys.readouterr().err


def test_verify_log_reports_an_undecodable_file_without_a_traceback(tmp_path, capsys):
    """A byte that will not decode raises UnicodeDecodeError, which is a ValueError.

    Uncaught it escapes main() entirely: the caller gets a traceback and an exit code nobody
    chose. Exit 1 is deliberate here. The file did not verify, and answering a byte the tool
    could not read with the usage code would let a corrupted log read as a configuration
    problem to a gate that only checks for zero.
    """
    path = tmp_path / "run.jsonl"
    run = ["run", "--demo", "--mode", "contained", *PERMISSIVE, "--log", str(path)]
    assert main(run) == EXIT_OK
    capsys.readouterr()
    path.write_bytes(path.read_bytes().replace(b"read_document", b"read_\xffdocument", 1))

    assert main(["verify-log", str(path)]) == EXIT_GATE
    printed = capsys.readouterr().err
    assert "not valid UTF-8" in printed
    assert "Traceback" not in printed


def test_version_prints_the_package_version(capsys):
    with pytest.raises(SystemExit) as raised:
        main(["--version"])
    assert raised.value.code == EXIT_OK
    assert capsys.readouterr().out.strip() == f"quellz {__version__}"
