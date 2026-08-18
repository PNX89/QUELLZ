# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-18

### Added

- `Agent` protocol with a pinned four-rule contract, string-only tool parameters, and a
  reusable conformance suite that runs against two independent implementations.
- Sandbox of six tools over a fake workspace, tagged `READ`, `WRITE` or `EXFIL`, with every
  attacker destination on a reserved `.invalid` host per RFC 2606.
- Catalog of 20 static payload fixtures across five techniques: `direct_override`,
  `indirect_document`, `tool_poisoning`, `hidden_context` and `multi_turn_hijack`, with
  three injection vectors and structured success predicates. `validate_catalog` runs at
  import.
- `LeastPrivilege`, which hands the agent guarded tools and allows a call only when the name
  is in `allowed_tools` and the sensitivity is in `allowed_sensitivity`.
- `SpotlightWrapper`, the datamarking variant of spotlighting, documented alongside the
  adaptive-attack evidence against its whole defense class.
- `HashChainLog` and `verify_file`, append-only JSONL with a SHA-256 chain and an injectable
  clock.
- `NaiveMockAgent`, a deterministic conformance fixture with a published obedience rule.
- `run_suite` and `compare`, reporting benign utility, utility under attack and targeted
  attack success rate per technique and overall, with a before and after delta.
- `quellz` CLI: `run`, `catalog`, `verify-log`, `--version`, text, markdown and JSON output,
  and an exit taxonomy of 0 pass, 1 gate breach, 2 usage.
- Optional `quellz[anthropic]` extra with a live Messages API adapter, exercised in CI
  against a stub client.
- `examples/demo_ab.py` and `examples/adapt_your_agent.py`, both deterministic and offline.
- CI on Python 3.11, 3.12, 3.13 and 3.14, all required legs.

[0.1.0]: https://github.com/PNX89/QUELLZ/releases/tag/v0.1.0
