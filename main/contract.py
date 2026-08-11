"""Shared contract for STRIDE skill output.

Stage 3 runs one agent call per STRIDE letter per use case. Every call must return
the same JSON shape so the merge step can concatenate results without normalizing.
This module is the single definition of that shape.

It is imported by both sides:
  - tests/test_contract.py    validates fixtures and real run output
  - main/stage3_stride.py      validates each agent response and retries on failure

Standard library only, so it runs anywhere without the course venv.
"""

from __future__ import annotations

import json
import re
from typing import Any

# --- vocabulary -------------------------------------------------------------

LETTERS = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}

SKILL_FOR_LETTER = {
    "S": "stride-spoofing",
    "T": "stride-tampering",
    "R": "stride-repudiation",
    "I": "stride-information-disclosure",
    "D": "stride-denial-of-service",
    "E": "stride-elevation-of-privilege",
}

ELEMENT_TYPES = {"external_entity", "process", "data_store", "data_flow"}

# Classic STRIDE-per-element. Each skill iterates only these element types, so a
# threat against any other type means the agent ignored its skill.
ALLOWED_ELEMENTS = {
    "S": {"external_entity", "process"},
    "T": {"process", "data_store", "data_flow"},
    "R": {"process", "data_store"},
    "I": {"process", "data_store", "data_flow"},
    "D": {"process", "data_store", "data_flow"},
    "E": {"process"},
}

LEVELS = {"high", "medium", "low"}
STATUSES = {"unmitigated", "partial", "mitigated"}
CONFIDENCES = {"high", "medium", "low"}
RISKS = {"critical", "high", "medium", "low"}

# Risk is derived, never assigned. Must stay identical to the matrix in all six
# SKILL.md files: rows are likelihood, columns are impact.
RISK_MATRIX = {
    ("high", "high"): "critical",
    ("high", "medium"): "high",
    ("high", "low"): "medium",
    ("medium", "high"): "high",
    ("medium", "medium"): "medium",
    ("medium", "low"): "low",
    ("low", "high"): "medium",
    ("low", "medium"): "low",
    ("low", "low"): "low",
}

REQUIRED_THREAT_FIELDS = (
    "id",
    "stride",
    "title",
    "dfd_element",
    "description",
    "attack_scenario",
    "evidence",
    "existing_mitigations",
    "status",
    "likelihood",
    "impact",
    "risk",
    "confidence",
    "recommendation",
)

CWE_RE = re.compile(r"^CWE-\d+$")
ID_RE = re.compile(r"^T-(?P<use_case>.+)-(?P<letter>[STRIDE])-(?P<seq>\d{3})$")


def derive_risk(likelihood: str, impact: str) -> str:
    """Look up risk from the shared matrix. Raises on an unknown level."""
    try:
        return RISK_MATRIX[(likelihood, impact)]
    except KeyError:
        raise ValueError(f"unknown likelihood/impact pair: {likelihood!r}/{impact!r}") from None


# --- parsing ----------------------------------------------------------------


class AgentOutputError(ValueError):
    """The agent response could not be parsed as the expected JSON object."""


def parse_agent_json(text: str) -> dict[str, Any]:
    """Recover the JSON object from an agent response.

    The skills instruct the model to emit bare JSON, but models routinely wrap it
    in a markdown fence or add a sentence of preamble. Rather than fail the run
    over formatting, strip the common wrappers. Anything beyond that is a genuine
    instruction-following failure and should be retried by the caller.
    """
    if isinstance(text, dict):
        return text
    if not isinstance(text, str) or not text.strip():
        raise AgentOutputError("empty agent response")

    candidate = text.strip()

    fenced = re.search(r"```(?:json)?\s*(.+?)\s*```", candidate, re.S)
    if fenced:
        candidate = fenced.group(1).strip()

    if not candidate.startswith("{"):
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start == -1 or end <= start:
            raise AgentOutputError(f"no JSON object found in response: {text[:120]!r}")
        candidate = candidate[start : end + 1]

    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise AgentOutputError(f"invalid JSON: {exc}") from None

    if not isinstance(parsed, dict):
        raise AgentOutputError(f"expected a JSON object, got {type(parsed).__name__}")
    return parsed


# --- validation -------------------------------------------------------------


def validate_skill_output(
    blob: dict[str, Any],
    expected_letter: str | None = None,
    expected_use_case: str | None = None,
) -> list[str]:
    """Validate one skill call's output. Returns a list of human-readable errors.

    An empty list means the blob conforms. Errors are phrased so they can be fed
    straight back to the agent as retry instructions.
    """
    errors: list[str] = []

    for key in ("use_case_id", "stride_letter", "threats"):
        if key not in blob:
            errors.append(f"missing top-level field {key!r}")
    if errors:
        return errors

    letter = blob["stride_letter"]
    use_case = blob["use_case_id"]

    if letter not in LETTERS:
        errors.append(f"stride_letter {letter!r} is not one of {sorted(LETTERS)}")
    if expected_letter and letter != expected_letter:
        errors.append(f"stride_letter is {letter!r} but this call used the {expected_letter!r} skill")
    if expected_use_case and use_case != expected_use_case:
        errors.append(f"use_case_id is {use_case!r} but the supplied DFD was {expected_use_case!r}")
    if not isinstance(blob["threats"], list):
        errors.append("threats must be a list")
        return errors

    seen_ids: set[str] = set()
    for index, threat in enumerate(blob["threats"]):
        errors.extend(f"threats[{index}]: {e}" for e in _validate_threat(threat, letter, use_case, seen_ids))

    return errors


def _validate_threat(threat: Any, letter: str, use_case: str, seen_ids: set[str]) -> list[str]:
    errors: list[str] = []

    if not isinstance(threat, dict):
        return [f"expected an object, got {type(threat).__name__}"]

    missing = [f for f in REQUIRED_THREAT_FIELDS if f not in threat]
    if missing:
        errors.append(f"missing field(s) {', '.join(missing)}")

    threat_id = threat.get("id")
    if isinstance(threat_id, str):
        match = ID_RE.match(threat_id)
        if not match:
            errors.append(f"id {threat_id!r} does not match T-<use_case_id>-<LETTER>-<nnn>")
        else:
            if match.group("letter") != letter:
                errors.append(f"id {threat_id!r} carries letter {match.group('letter')!r}, expected {letter!r}")
            if match.group("use_case") != use_case:
                errors.append(f"id {threat_id!r} carries use case {match.group('use_case')!r}, expected {use_case!r}")
        if threat_id in seen_ids:
            errors.append(f"duplicate id {threat_id!r}")
        seen_ids.add(threat_id)

    if threat.get("stride") != letter:
        errors.append(f"stride is {threat.get('stride')!r}, expected {letter!r}")

    element = threat.get("dfd_element")
    if not isinstance(element, dict):
        errors.append("dfd_element must be an object with name and type")
    else:
        if not element.get("name"):
            errors.append("dfd_element.name is empty")
        element_type = element.get("type")
        if element_type not in ELEMENT_TYPES:
            errors.append(f"dfd_element.type {element_type!r} is not one of {sorted(ELEMENT_TYPES)}")
        elif element_type not in ALLOWED_ELEMENTS[letter]:
            errors.append(
                f"{LETTERS[letter]} does not apply to a {element_type!r}; "
                f"allowed for {letter}: {sorted(ALLOWED_ELEMENTS[letter])}"
            )

    for field, allowed in (
        ("likelihood", LEVELS),
        ("impact", LEVELS),
        ("risk", RISKS),
        ("status", STATUSES),
        ("confidence", CONFIDENCES),
    ):
        value = threat.get(field)
        if value not in allowed:
            errors.append(f"{field} is {value!r}, expected one of {sorted(allowed)}")

    likelihood, impact, risk = threat.get("likelihood"), threat.get("impact"), threat.get("risk")
    if likelihood in LEVELS and impact in LEVELS:
        expected = derive_risk(likelihood, impact)
        if risk != expected:
            errors.append(
                f"risk is {risk!r} but likelihood={likelihood!r} and impact={impact!r} "
                f"derive {expected!r} from the shared matrix"
            )

    evidence = threat.get("evidence")
    if not isinstance(evidence, list):
        errors.append("evidence must be a list (use [] when no code was located)")
    else:
        for i, item in enumerate(evidence):
            if not isinstance(item, dict):
                errors.append(f"evidence[{i}] must be an object")
                continue
            if not item.get("file"):
                errors.append(f"evidence[{i}].file is empty")
            line = item.get("line")
            if not isinstance(line, int) or isinstance(line, bool) or line < 1:
                errors.append(f"evidence[{i}].line must be a positive integer, got {line!r}")
        # The anti-fabrication rule: a high-confidence claim must cite something.
        if threat.get("confidence") == "high" and not evidence:
            errors.append("confidence 'high' requires at least one evidence entry citing file and line")

    if not isinstance(threat.get("existing_mitigations"), list):
        errors.append("existing_mitigations must be a list (use [] when none exist)")

    for cwe in threat.get("cwe", []) or []:
        if not isinstance(cwe, str) or not CWE_RE.match(cwe):
            errors.append(f"cwe entry {cwe!r} must look like 'CWE-287'")

    for field in ("title", "description", "attack_scenario", "recommendation"):
        value = threat.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{field} must be a non-empty string")

    return errors


def validate_merged(threats: list[dict[str, Any]]) -> list[str]:
    """Validate the concatenation of every skill call, before the report stage."""
    errors: list[str] = []

    ids: dict[str, int] = {}
    for threat in threats:
        threat_id = threat.get("id")
        if isinstance(threat_id, str):
            ids[threat_id] = ids.get(threat_id, 0) + 1
    errors.extend(f"duplicate id {i!r} appears {n} times across the merged set" for i, n in ids.items() if n > 1)

    by_use_case: dict[str, set[str]] = {}
    for threat in threats:
        match = ID_RE.match(threat.get("id", "") or "")
        if match:
            by_use_case.setdefault(match.group("use_case"), set()).add(match.group("letter"))

    for use_case, letters in sorted(by_use_case.items()):
        missing = sorted(set(LETTERS) - letters)
        if missing:
            errors.append(
                f"use case {use_case!r} has no threats for letter(s) {', '.join(missing)} — "
                "confirm those skill calls ran and returned an empty list on purpose"
            )

    return errors


def coverage_table(threats: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Threat counts per use case per letter, for the report's metrics section."""
    table: dict[str, dict[str, int]] = {}
    for threat in threats:
        match = ID_RE.match(threat.get("id", "") or "")
        if not match:
            continue
        row = table.setdefault(match.group("use_case"), {letter: 0 for letter in LETTERS})
        row[match.group("letter")] += 1
    return table
