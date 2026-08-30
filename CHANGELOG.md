# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `escape_delimiter` matches the delimiter against the text a consumer decodes rather than
  against the bytes as fetched. A closing `<untrusted-data>` tag spelled in the Unicode TAG
  characters this package generates passed the escape untouched, survived datamarking because
  those characters are not whitespace, and closed the span on the far side.
- `Exfiltrated` reads its content half from what a record carries rather than from the whole
  flattened record, so neither the address the destination half already matched on nor the
  record's own key names can stand in for the content the attack set out to steal.
- `main`'s command dispatch ended in a bare `return _verify_log(args)` standing in for every
  subcommand its two `if`s did not name. `_verify_log` reads `args.path` immediately, which a
  fourth subcommand would not define, so adding one without also adding its own dispatch branch
  crashed with an uncaught `AttributeError` instead of the exit-code contract this module
  documents. The three names are now all explicit, and the fallback raises `_UsageError`.

### Added

- mypy, strict over the package, as a dev dependency and on both CI legs. `CONTRIBUTING.md`
  called typing a gate while nothing here type checked, and the wheel ships `py.typed`.
- Direct tests for the claims that had none, each proved to fail against the defect it
  describes: `Exfiltrated`, the sequence, `prev` and field-set checks in the chain verifier,
  the byte scan run against its own encoder, the sensitivity tag on every tool, protocol rule 2
  across turns, and the shipped adapter, which now sits in the conformance parameter set behind
  a stub client rather than outside it.
- Tests for the remaining claims that had none: `HashChainLog`'s hash survives an entry's keys
  being reordered on disk without a value changing, `SpotlightWrapper` refuses an empty marker,
  `DOC_ONLY_REFERENCES` still resolves against `REFERENCES`, `encode_tag_block`'s
  printable-range filter is exercised against a newline and a tab rather than only against text
  already inside its range, the `--max-asr` gate at its exact boundary rather than only far
  above or below it, and the Pages card's `python` and `captured` fields against `facts.json`.

## [0.1.0] - 2026-08-18

### Added

- `Agent` protocol with a pinned five-rule contract, string-only tool parameters, and a
  reusable conformance suite that runs against two independent implementations.
- Sandbox of six tools over a fake workspace, tagged `READ`, `WRITE` or `EXFIL`, with every
  attacker destination on a reserved `.invalid` host per RFC 2606.
- Catalog of 21 static payload fixtures across five techniques: `direct_override`,
  `indirect_document`, `tool_poisoning`, `hidden_context` and `multi_turn_hijack`, with
  three injection vectors and structured success predicates. An exfiltration objective is
  scored by `Exfiltrated`, which requires the content the attack set out to steal to reach the
  attacker's own record rather than treating any call at the sink as the breach.
  `validate_catalog` runs at import.
- `LeastPrivilege`, which hands the agent guarded tools and allows a call only when the name
  is in `allowed_tools` and the sensitivity is in `allowed_sensitivity`, and which records
  every policy decision it makes when it is given a log.
- `SpotlightWrapper`, the datamarking variant of spotlighting, documented alongside the
  adaptive-attack evidence against its whole defense class. Tool output carrying the
  `<untrusted-data>` delimiter is escaped, so untrusted content can neither close the span it
  sits in nor forge a second one.
- `HashChainLog` and `verify_file`, append-only JSONL with a SHA-256 chain and an injectable
  clock, written at the sandbox boundary and at the policy gate rather than from the agent's
  own account of the calls it made. A file that does not decode as UTF-8 fails verification
  with a message naming that as the reason, rather than raising out of the CLI.
- `NaiveMockAgent`, a deterministic conformance fixture with a published obedience rule.
- `run_suite` and `compare`, reporting benign utility, utility under attack and targeted
  attack success rate per technique and overall, with a before and after delta.
- `quellz` CLI: `run`, `catalog`, `verify-log`, `--version`, text, markdown and JSON output,
  and an exit taxonomy of 0 pass, 1 gate breach, 2 usage.
- Optional `quellz[anthropic]` extra with a live Messages API adapter, exercised in CI
  against a stub client.
- `examples/demo_ab.py` and `examples/adapt_your_agent.py`, both deterministic and offline.
- CI on Python 3.11, 3.12, 3.13 and 3.14, all required legs.

[Unreleased]: https://github.com/PNX89/QUELLZ/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/PNX89/QUELLZ/releases/tag/v0.1.0
