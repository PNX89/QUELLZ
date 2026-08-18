# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/PNX89/QUELLZ/releases/tag/v0.1.0
