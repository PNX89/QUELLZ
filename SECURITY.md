# Security

QUELLZ is for defensive testing of systems you own or are explicitly authorised to test.

## Scope of the payload catalog

- Text fixtures only. There are no working exploit chains, no live command and control, no
  real credentials and no PII in this repository.
- The payloads are deliberately obvious and non-novel. They carry no zero-day value; they
  exist so the harness has something citable to run.
- Every attacker destination is a reserved `.invalid` hostname per RFC 2606
  (`attacker@example.invalid`, `https://attacker.example.invalid/collect`), so no payload can
  address a real host. `tests/test_catalog.py` asserts that against the data rather than
  leaving it as a promise in this file.
- Nothing here targets a third party. The only environment any payload reaches is the
  in-process `Sandbox`.

Every entry in `catalog.py` carries `fixture=True` and the file opens with the same
statement, so anyone reading the raw data without this document still sees it.

## Authorisation

Prompt injection against a system you do not own is not automatically lawful research.
Depending on the jurisdiction and on what the target is, it can be treated as unauthorised
access or as misappropriation rather than as reverse engineering, and that analysis turns on
facts a file like this cannot know. Get written authorisation before pointing any of this at a
system you do not control, and take advice from someone qualified to give it. No statute or
case is named here on purpose: every other claim in this repository carries a source, and a
legal one summarised from memory would be the weakest sentence in it.

## Dual use

GitHub's Acceptable Use Policies state:

> GitHub allows dual-use content and supports the posting of content that is used for
> research into vulnerabilities, malware, or exploits, as the publication and distribution of
> such content has educational value and provides a net benefit to the security community.

Source: https://docs.github.com/en/site-policy/acceptable-use-policies/github-active-malware-or-exploits

## Contact

Open an issue at https://github.com/PNX89/QUELLZ/issues.
