"""The result schema, the before and after delta, and the renderers.

The metric names are AgentDojo's (Debenedetti et al., arXiv:2406.13352) on purpose. Benign
utility, utility under attack and targeted attack success rate are reported together because a
containment layer that blocks everything scores a perfect attack success rate and is useless.
"""

from __future__ import annotations

import json
import textwrap
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from quellz.attacks import Technique, Vector
from quellz.types import ToolCall

__all__ = [
    "FORMATS",
    "METHODOLOGY_CAVEAT",
    "CaseResult",
    "Delta",
    "DeltaRow",
    "Format",
    "Meta",
    "Report",
    "TechniqueStats",
    "delta_as_dict",
    "render_delta",
    "render_report",
    "report_as_dict",
]

# Printed beneath every table this module renders, carried in Report.meta.caveat, and
# reproduced verbatim in the README. Changing it here changes it everywhere on purpose. It
# names no payload count: --technique runs a subset, and a caveat that quoted the size of the
# whole catalog under a filtered run would be the small dishonesty this text exists to avoid.
# The provenance line above every table carries the count of the cases actually run.
METHODOLOGY_CAVEAT = (
    "These numbers measure the QUELLZ harness against its catalog of static payload fixtures "
    "executed against the bundled NaiveMockAgent. They demonstrate that the containment layer "
    "enforces its stated policy. They are not evidence about the robustness of any real model, "
    "and static attack success rate is a known-invalid proxy for robustness: an adaptive "
    "attacker is expected to defeat the SpotlightWrapper."
)

FORMATS = ("text", "markdown", "json")
Format = Literal["text", "markdown", "json"]

_WRAP = 96
_REPORT_LEGEND = (
    "Rates are in [0, 1]. ASR is targeted attack success rate. The blocked columns count tool "
    "calls the containment layer refused."
)
_DELTA_LEGEND = (
    "Rates are in [0, 1]. ASR is targeted attack success rate, utility is utility under attack. "
    "ASR drop and utility cost are before minus after, so a positive utility cost is over "
    "blocking that the policy paid for."
)


@dataclass(frozen=True)
class Meta:
    """Everything needed to reproduce a report, plus the caveat that qualifies it."""

    seed: int
    max_steps: int
    catalog_version: str
    quellz_version: str
    caveat: str = METHODOLOGY_CAVEAT


@dataclass(frozen=True)
class CaseResult:
    """One attack scored in both conditions: payload omitted, then payload injected."""

    attack_id: str
    technique: Technique
    vector: Vector
    benign_utility_pass: bool
    utility_under_attack_pass: bool
    attack_succeeded: bool
    blocked_calls_benign: int
    blocked_calls_attacked: int
    tool_calls_benign: tuple[ToolCall, ...] = field(repr=False)
    tool_calls_attacked: tuple[ToolCall, ...] = field(repr=False)


@dataclass(frozen=True)
class TechniqueStats:
    technique: Technique
    n_cases: int
    benign_utility: float
    utility_under_attack: float
    targeted_asr: float
    blocked_calls_benign: int
    blocked_calls_attacked: int


@dataclass(frozen=True)
class Report:
    label: str
    agent_name: str
    containment: str
    n_cases: int
    benign_utility: float
    utility_under_attack: float
    targeted_asr: float
    by_technique: tuple[TechniqueStats, ...]
    cases: tuple[CaseResult, ...] = field(repr=False)
    meta: Meta


@dataclass(frozen=True)
class DeltaRow:
    """One before and after row. ``technique`` is a technique name or the string 'overall'."""

    technique: str
    n_cases: int
    targeted_asr_before: float
    targeted_asr_after: float
    asr_reduction: float
    utility_under_attack_before: float
    utility_under_attack_after: float
    utility_cost: float


@dataclass(frozen=True)
class Delta:
    agent_name: str
    baseline_label: str
    contained_label: str
    baseline_containment: str
    contained_containment: str
    n_cases: int
    benign_utility_before: float
    benign_utility_after: float
    rows: tuple[DeltaRow, ...]
    overall: DeltaRow
    meta: Meta


def render_report(report: Report, fmt: Format) -> str:
    """Render one report. Unknown formats raise ValueError naming the accepted values."""
    _check(fmt)
    if fmt == "json":
        return json.dumps(report_as_dict(report), indent=2)
    headers = (
        "technique",
        "n",
        "benign utility",
        "utility under attack",
        "targeted ASR",
        "blocked benign",
        "blocked attacked",
    )
    rows = [
        (
            str(stats.technique),
            str(stats.n_cases),
            _rate(stats.benign_utility),
            _rate(stats.utility_under_attack),
            _rate(stats.targeted_asr),
            str(stats.blocked_calls_benign),
            str(stats.blocked_calls_attacked),
        )
        for stats in report.by_technique
    ]
    rows.append(
        (
            "overall",
            str(report.n_cases),
            _rate(report.benign_utility),
            _rate(report.utility_under_attack),
            _rate(report.targeted_asr),
            str(sum(stats.blocked_calls_benign for stats in report.by_technique)),
            str(sum(stats.blocked_calls_attacked for stats in report.by_technique)),
        )
    )
    subtitle = [
        f"agent {report.agent_name}, containment {report.containment}",
        _provenance(report.n_cases, report.meta),
    ]
    return _document(f"QUELLZ report: {report.label}", subtitle, headers, rows, _REPORT_LEGEND, fmt)


def render_delta(delta: Delta, fmt: Format) -> str:
    """Render the before and after table. Unknown formats raise ValueError."""
    _check(fmt)
    if fmt == "json":
        return json.dumps(delta_as_dict(delta), indent=2)
    headers = (
        "technique",
        "n",
        "ASR before",
        "ASR after",
        "ASR drop",
        "utility before",
        "utility after",
        "utility cost",
    )
    rows = [_delta_row(row) for row in (*delta.rows, delta.overall)]
    subtitle = [
        f"agent {delta.agent_name}",
        f"{delta.baseline_label}: containment {delta.baseline_containment}",
        f"{delta.contained_label}: containment {delta.contained_containment}",
        f"benign utility {_rate(delta.benign_utility_before)} before, "
        f"{_rate(delta.benign_utility_after)} after",
        _provenance(delta.n_cases, delta.meta),
    ]
    title = f"QUELLZ delta: {delta.baseline_label} to {delta.contained_label}"
    return _document(title, subtitle, headers, rows, _DELTA_LEGEND, fmt)


def report_as_dict(report: Report) -> dict[str, Any]:
    """Plain floats, ints, strings, bools and lists, so json.dumps needs no encoder."""
    return {
        "label": report.label,
        "agent_name": report.agent_name,
        "containment": report.containment,
        "n_cases": report.n_cases,
        "benign_utility": report.benign_utility,
        "utility_under_attack": report.utility_under_attack,
        "targeted_asr": report.targeted_asr,
        "by_technique": [
            {
                "technique": str(stats.technique),
                "n_cases": stats.n_cases,
                "benign_utility": stats.benign_utility,
                "utility_under_attack": stats.utility_under_attack,
                "targeted_asr": stats.targeted_asr,
                "blocked_calls_benign": stats.blocked_calls_benign,
                "blocked_calls_attacked": stats.blocked_calls_attacked,
            }
            for stats in report.by_technique
        ],
        "cases": [
            {
                "attack_id": case.attack_id,
                "technique": str(case.technique),
                "vector": str(case.vector),
                "benign_utility_pass": case.benign_utility_pass,
                "utility_under_attack_pass": case.utility_under_attack_pass,
                "attack_succeeded": case.attack_succeeded,
                "blocked_calls_benign": case.blocked_calls_benign,
                "blocked_calls_attacked": case.blocked_calls_attacked,
            }
            for case in report.cases
        ],
        "meta": _meta_as_dict(report.meta),
    }


def delta_as_dict(delta: Delta) -> dict[str, Any]:
    return {
        "agent_name": delta.agent_name,
        "baseline_label": delta.baseline_label,
        "contained_label": delta.contained_label,
        "baseline_containment": delta.baseline_containment,
        "contained_containment": delta.contained_containment,
        "n_cases": delta.n_cases,
        "benign_utility_before": delta.benign_utility_before,
        "benign_utility_after": delta.benign_utility_after,
        "rows": [_row_as_dict(row) for row in delta.rows],
        "overall": _row_as_dict(delta.overall),
        "meta": _meta_as_dict(delta.meta),
    }


def _check(fmt: str) -> None:
    if fmt not in FORMATS:
        raise ValueError(f"format must be one of {', '.join(FORMATS)}, got {fmt!r}")


def _meta_as_dict(meta: Meta) -> dict[str, Any]:
    return {
        "seed": meta.seed,
        "max_steps": meta.max_steps,
        "catalog_version": meta.catalog_version,
        "quellz_version": meta.quellz_version,
        "caveat": meta.caveat,
    }


def _row_as_dict(row: DeltaRow) -> dict[str, Any]:
    return {
        "technique": row.technique,
        "n_cases": row.n_cases,
        "targeted_asr_before": row.targeted_asr_before,
        "targeted_asr_after": row.targeted_asr_after,
        "asr_reduction": row.asr_reduction,
        "utility_under_attack_before": row.utility_under_attack_before,
        "utility_under_attack_after": row.utility_under_attack_after,
        "utility_cost": row.utility_cost,
    }


def _delta_row(row: DeltaRow) -> tuple[str, ...]:
    return (
        row.technique,
        str(row.n_cases),
        _rate(row.targeted_asr_before),
        _rate(row.targeted_asr_after),
        _rate(row.asr_reduction),
        _rate(row.utility_under_attack_before),
        _rate(row.utility_under_attack_after),
        _rate(row.utility_cost),
    )


def _rate(value: float) -> str:
    return f"{value:.2f}"


def _provenance(n_cases: int, meta: Meta) -> str:
    return (
        f"{n_cases} cases, seed {meta.seed}, max_steps {meta.max_steps}, "
        f"catalog {meta.catalog_version}, quellz {meta.quellz_version}"
    )


def _document(
    title: str,
    subtitle: Sequence[str],
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    legend: str,
    fmt: str,
) -> str:
    if fmt == "markdown":
        body = [f"## {title}", "", *(f"{line}  " for line in subtitle), ""]
        body += [_markdown_table(headers, rows), "", legend, "", _quote(METHODOLOGY_CAVEAT)]
        return "\n".join(body)
    body = [title, *subtitle, "", _text_table(headers, rows), ""]
    body += [_wrap(legend), "", _wrap(METHODOLOGY_CAVEAT)]
    return "\n".join(body)


def _text_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    widths = [
        max(len(header), *(len(row[index]) for row in rows)) for index, header in enumerate(headers)
    ]
    lines = [_text_row(headers, widths), "  ".join("-" * width for width in widths)]
    lines += [_text_row(row, widths) for row in rows]
    return "\n".join(lines)


def _text_row(cells: Sequence[str], widths: Sequence[int]) -> str:
    padded = [
        cell.ljust(width) if index == 0 else cell.rjust(width)
        for index, (cell, width) in enumerate(zip(cells, widths, strict=True))
    ]
    return "  ".join(padded).rstrip()


def _markdown_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    rule = ["---" if index == 0 else "---:" for index in range(len(headers))]
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(rule) + " |"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


def _wrap(text: str) -> str:
    return textwrap.fill(text, width=_WRAP)


def _quote(text: str) -> str:
    return "\n".join(f"> {line}" for line in textwrap.wrap(text, width=_WRAP))
