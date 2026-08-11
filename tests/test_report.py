"""Tests for stage 4 report assembly.

The report is deterministic by design — no LLM call unless --summarize is passed — so
the same inputs must always produce the same document. That property is what the
report's own consistency claim rests on.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from main.stage4_report import build_report, load_stage_outputs, sort_key, strip_comments

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


@pytest.fixture
def records(tmp_path: pathlib.Path) -> list[dict]:
    """A one-use-case output tree, built from the shipped examples."""
    examples = ROOT / "output" / "_example"
    for sub in ("use-cases", "dfds", "threats"):
        (tmp_path / sub).mkdir()

    use_case = json.loads((examples / "use-cases" / "UC-LOGIN.json").read_text())
    (tmp_path / "use-cases" / "UC-LOGIN.json").write_text(json.dumps(use_case))
    (tmp_path / "dfds" / "UC-LOGIN.mmd").write_text((examples / "dfds" / "UC-LOGIN.mmd").read_text())

    merged = json.loads((examples / "threats" / "UC-LOGIN.json").read_text())
    merged["use_case_id"] = "UC-LOGIN"
    (tmp_path / "threats" / "UC-LOGIN.json").write_text(json.dumps(merged))

    return load_stage_outputs(tmp_path)


def test_loads_use_case_diagram_and_threats(records):
    assert len(records) == 1
    assert records[0]["id"] == "UC-LOGIN"
    assert records[0]["threats"]
    assert "flowchart" in records[0]["diagram"]


def test_examples_are_skipped(tmp_path):
    (tmp_path / "threats").mkdir()
    (tmp_path / "threats" / "_example.json").write_text('{"use_case_id": "_example", "threats": []}')
    with pytest.raises(SystemExit, match="no threat files"):
        load_stage_outputs(tmp_path)


def test_report_is_deterministic(records):
    first = build_report(records, "Target", MODEL)
    second = build_report(records, "Target", MODEL)
    assert first == second


def test_report_contains_the_required_sections(records):
    report = build_report(records, "OWASP Juice Shop", MODEL)
    for section in (
        "# Threat model — OWASP Juice Shop",
        "## Findings at a glance",
        "### Coverage by STRIDE category",
        "## Method",
        "### Limitations",
        "## UC-LOGIN",
    ):
        assert section in report, f"missing section: {section}"


def test_diagram_is_inlined_as_a_mermaid_fence(records):
    report = build_report(records, "Target", MODEL)
    assert "```mermaid" in report
    assert "flowchart LR" in report
    assert "%% file:" not in report, "authoring comments must not reach the report"


def test_every_threat_appears_with_its_evidence(records):
    report = build_report(records, "Target", MODEL)
    for threat in records[0]["threats"]:
        assert threat["id"] in report
        for item in threat.get("evidence") or []:
            assert f"{item['file']}:{item['line']}" in report


def test_threats_are_ordered_by_severity(records):
    report = build_report(records, "Target", MODEL)
    positions = [report.index(t["id"]) for t in sorted(records[0]["threats"], key=sort_key)]
    assert positions == sorted(positions), "findings must appear worst-first"


def test_sort_key_puts_critical_before_high():
    critical = {"risk": "critical", "confidence": "low", "id": "T-Z"}
    high = {"risk": "high", "confidence": "high", "id": "T-A"}
    assert sorted([high, critical], key=sort_key)[0] is critical


def test_strip_comments_removes_notes_and_collapses_blanks():
    stripped = strip_comments("%% a note\n\n%% another\n\nflowchart LR\n\n\n  A(B)\n")
    assert "%%" not in stripped
    assert stripped.startswith("flowchart LR")
    assert "\n\n\n" not in stripped


def test_coverage_table_marks_letters_that_returned_nothing(records):
    """A zero must be visible — it is a considered result, not a missing analysis."""
    report = build_report(records, "Target", MODEL)
    coverage = report.split("### Coverage by STRIDE category")[1].split("###")[0]
    assert "| UC-LOGIN |" in coverage
    assert " 0 " in coverage
