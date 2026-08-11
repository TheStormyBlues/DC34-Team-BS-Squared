"""Contract tests for STRIDE skill output.

Run from the repo root with the course venv active:

    pytest tests/ -q

These cover three things:
  1. The risk matrix is complete and agrees with the six SKILL.md files.
  2. A conforming blob passes, and each way of breaking it is caught.
  3. Any real run output under output/ conforms (skipped when there is none).
"""

from __future__ import annotations

import copy
import json
import pathlib
import re

import pytest

from main.contract import (
    ALLOWED_ELEMENTS,
    LETTERS,
    RISK_MATRIX,
    SKILL_FOR_LETTER,
    AgentOutputError,
    coverage_table,
    derive_risk,
    parse_agent_json,
    validate_merged,
    validate_skill_output,
)

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = pathlib.Path(__file__).parent / "fixtures"


@pytest.fixture
def blob() -> dict:
    return json.loads((FIXTURES / "valid_spoofing.json").read_text())


# --- the matrix -------------------------------------------------------------


def test_risk_matrix_is_complete():
    assert len(RISK_MATRIX) == 9, "every likelihood/impact pair needs an entry"


@pytest.mark.parametrize(
    "likelihood,impact,expected",
    [
        ("high", "high", "critical"),
        ("high", "medium", "high"),
        ("high", "low", "medium"),
        ("medium", "high", "high"),
        ("medium", "medium", "medium"),
        ("medium", "low", "low"),
        ("low", "high", "medium"),
        ("low", "medium", "low"),
        ("low", "low", "low"),
    ],
)
def test_derive_risk(likelihood, impact, expected):
    assert derive_risk(likelihood, impact) == expected


def test_risk_matrix_matches_every_skill_file():
    """The matrix lives in six SKILL.md files and here. Catch drift between them."""
    rows = {"High": "Likelihood High", "Medium": "Likelihood Medium", "Low": "Likelihood Low"}
    for letter, skill in SKILL_FOR_LETTER.items():
        path = ROOT / "skills" / skill / "SKILL.md"
        assert path.exists(), f"missing skill file for letter {letter}: {path}"
        text = path.read_text()
        for likelihood, label in rows.items():
            match = re.search(rf"\| \*\*{label}\*\* \|(.+)", text)
            assert match, f"{skill}: no '{label}' row in the risk matrix"
            cells = [c.strip() for c in match.group(1).split("|") if c.strip()]
            assert len(cells) == 3, f"{skill}: expected 3 cells in the '{label}' row, got {cells}"
            for impact, cell in zip(("high", "medium", "low"), cells):
                expected = derive_risk(likelihood.lower(), impact)
                assert cell.lower() == expected, (
                    f"{skill}: matrix says {likelihood}/{impact} is {cell!r}, contract.py says {expected!r}"
                )


def test_every_letter_has_a_skill_directory():
    for letter, skill in SKILL_FOR_LETTER.items():
        assert (ROOT / "skills" / skill / "SKILL.md").exists(), f"letter {letter} has no skill"


# --- the happy path ---------------------------------------------------------


def test_valid_blob_passes(blob):
    assert validate_skill_output(blob, expected_letter="S", expected_use_case="UC-LOGIN") == []


def test_low_confidence_without_evidence_is_allowed(blob):
    """The anti-fabrication rule: an honest empty evidence list must not fail."""
    assert blob["threats"][2]["confidence"] == "low"
    assert blob["threats"][2]["evidence"] == []
    assert validate_skill_output(blob) == []


def test_empty_threat_list_is_valid():
    empty = {"use_case_id": "UC-LOGIN", "stride_letter": "R", "threats": []}
    assert validate_skill_output(empty, expected_letter="R") == []


# --- the ways it breaks -----------------------------------------------------


def mutate(blob: dict, index: int, **changes) -> dict:
    out = copy.deepcopy(blob)
    out["threats"][index].update(changes)
    return out


@pytest.mark.parametrize(
    "changes,fragment",
    [
        ({"risk": "low"}, "derive"),
        ({"likelihood": "certain"}, "likelihood"),
        ({"status": "open"}, "status"),
        ({"confidence": "certain"}, "confidence"),
        ({"id": "T-UC-LOGIN-S-1"}, "does not match"),
        ({"id": "T-UC-LOGIN-X-001"}, "does not match"),
        ({"id": "T-UC-SIGNUP-S-001"}, "use case"),
        ({"stride": "T"}, "stride is"),
        ({"dfd_element": {"name": "Session Store", "type": "data_store"}}, "does not apply"),
        ({"dfd_element": {"name": "X", "type": "datastore"}}, "not one of"),
        ({"evidence": "routes/login.ts:31"}, "must be a list"),
        ({"evidence": [{"file": "routes/login.ts"}]}, "line"),
        ({"evidence": [{"file": "routes/login.ts", "line": "31"}]}, "positive integer"),
        ({"evidence": []}, "requires at least one evidence"),
        ({"existing_mitigations": "none"}, "must be a list"),
        ({"cwe": ["307"]}, "CWE-287"),
        ({"title": ""}, "title"),
        ({"recommendation": "   "}, "recommendation"),
    ],
)
def test_broken_threat_is_rejected(blob, changes, fragment):
    errors = validate_skill_output(mutate(blob, 0, **changes))
    assert errors, f"expected {changes} to be rejected"
    assert any(fragment in e for e in errors), f"errors {errors} did not mention {fragment!r}"


def test_missing_required_field_is_rejected(blob):
    broken = copy.deepcopy(blob)
    del broken["threats"][0]["attack_scenario"]
    errors = validate_skill_output(broken)
    assert any("attack_scenario" in e for e in errors)


def test_duplicate_ids_within_one_call_are_rejected(blob):
    broken = copy.deepcopy(blob)
    broken["threats"][1]["id"] = broken["threats"][0]["id"]
    assert any("duplicate id" in e for e in validate_skill_output(broken))


def test_wrong_letter_for_the_skill_is_rejected(blob):
    errors = validate_skill_output(blob, expected_letter="R")
    assert any("skill" in e for e in errors)


def test_missing_top_level_field_is_rejected():
    assert any("stride_letter" in e for e in validate_skill_output({"use_case_id": "UC-LOGIN", "threats": []}))


@pytest.mark.parametrize("letter", sorted(LETTERS))
def test_element_mapping_rejects_disallowed_types(blob, letter):
    """Each letter accepts only its STRIDE-per-element types."""
    disallowed = {"external_entity", "process", "data_store", "data_flow"} - ALLOWED_ELEMENTS[letter]
    for element_type in disallowed:
        candidate = copy.deepcopy(blob)
        candidate["stride_letter"] = letter
        threat = candidate["threats"][0]
        threat["stride"] = letter
        threat["id"] = f"T-UC-LOGIN-{letter}-001"
        threat["dfd_element"] = {"name": "Some Element", "type": element_type}
        candidate["threats"] = [threat]
        errors = validate_skill_output(candidate)
        assert any("does not apply" in e for e in errors), (
            f"{letter} should reject {element_type}, got {errors}"
        )


# --- parsing what the model actually returns --------------------------------


def test_parse_bare_json():
    assert parse_agent_json('{"use_case_id": "UC-LOGIN"}')["use_case_id"] == "UC-LOGIN"


def test_parse_fenced_json():
    assert parse_agent_json('```json\n{"a": 1}\n```')["a"] == 1


def test_parse_json_with_preamble():
    text = 'Here is the analysis you requested:\n\n{"a": 1}\n\nLet me know if you need more.'
    assert parse_agent_json(text)["a"] == 1


@pytest.mark.parametrize("text", ["", "   ", "No JSON here at all.", "```json\n{oops\n```"])
def test_parse_rejects_unusable_output(text):
    with pytest.raises(AgentOutputError):
        parse_agent_json(text)


# --- merged output ----------------------------------------------------------


def test_merged_flags_missing_letters(blob):
    errors = validate_merged(blob["threats"])
    assert any("T, R, I, D, E" in e or "letter(s)" in e for e in errors)


def test_merged_accepts_full_coverage(blob):
    threats = []
    for letter in LETTERS:
        threat = copy.deepcopy(blob["threats"][0])
        threat["id"] = f"T-UC-LOGIN-{letter}-001"
        threat["stride"] = letter
        threats.append(threat)
    assert validate_merged(threats) == []


def test_coverage_table_counts_per_letter(blob):
    table = coverage_table(blob["threats"])
    assert table["UC-LOGIN"]["S"] == 3
    assert table["UC-LOGIN"]["R"] == 0


# --- real run output --------------------------------------------------------


def test_per_letter_output_conforms():
    """Validate every per-letter file stage 3 has written, plus the shipped example."""
    threats_root = ROOT / "output" / "threats"
    files = sorted(threats_root.glob("*/*.json")) if threats_root.is_dir() else []
    if not files:
        pytest.skip("no stage 3 output yet — run the pipeline first")
    for path in files:
        payload = json.loads(path.read_text())
        errors = validate_skill_output(payload, expected_letter=path.stem)
        assert errors == [], f"{path.relative_to(ROOT)}: {errors}"


def test_merged_output_conforms():
    """The per-use-case files stage 4 reads must hold well-formed, unique threats."""
    threats_root = ROOT / "output" / "threats"
    files = sorted(threats_root.glob("*.json")) if threats_root.is_dir() else []
    if not files:
        pytest.skip("no stage 3 output yet — run the pipeline first")
    for path in files:
        threats = json.loads(path.read_text())["threats"]
        ids = [t["id"] for t in threats]
        assert len(ids) == len(set(ids)), f"{path.relative_to(ROOT)}: duplicate threat ids"
