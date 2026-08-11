"""Stage 4 — assemble the final report.

Reads everything the earlier stages wrote and produces one markdown document:

    output/use-cases/<id>.json    what was analyzed
    output/dfds/<id>.mmd          inlined as mermaid fences, so the report carries the DFDs
    output/threats/<id>.json      the findings
                                → output/report.md

Deliberately deterministic — no LLM call, so the same inputs always produce the same
report. That is what makes the consistency claim in the report honest, and it means
the demo cannot fail on a model call. The one exception is `--summarize`, which adds
a generated executive summary paragraph; everything else is assembled from the JSON.

    python -m main.stage4_report
    python -m main.stage4_report --summarize          # adds an LLM executive summary
    python -m main.stage4_report --output output --target "OWASP Juice Shop"
"""

from __future__ import annotations

import argparse
import collections
import datetime
import json
import pathlib
import sys
from typing import Any

from main.contract import LETTERS, coverage_table, validate_merged

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
STATUS_LABEL = {"unmitigated": "Unmitigated", "partial": "Partially mitigated", "mitigated": "Mitigated"}


# --- loading ----------------------------------------------------------------


def load_stage_outputs(output_root: pathlib.Path) -> list[dict[str, Any]]:
    """Gather one record per use case: metadata, diagram, and threats."""
    threats_dir = output_root / "threats"
    if not threats_dir.is_dir():
        raise SystemExit(f"no threats directory at {threats_dir} — has stage 3 run?")

    records = []
    for path in sorted(threats_dir.glob("*.json")):
        if path.name.startswith("_"):
            continue
        payload = json.loads(path.read_text())
        use_case_id = payload.get("use_case_id", path.stem)

        meta_path = output_root / "use-cases" / f"{use_case_id}.json"
        meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}

        diagram_path = output_root / "dfds" / f"{use_case_id}.mmd"
        diagram = diagram_path.read_text() if diagram_path.exists() else ""

        records.append(
            {
                "id": use_case_id,
                "name": payload.get("name") or meta.get("name") or use_case_id,
                "description": meta.get("description", ""),
                "entry_points": meta.get("entry_points", []),
                "diagram": diagram,
                "threats": payload.get("threats", []),
            }
        )

    if not records:
        raise SystemExit(f"no threat files in {threats_dir} (files starting with '_' are skipped)")
    return records


def strip_comments(diagram: str) -> str:
    """Drop `%%` lines so the report shows the picture, not the authoring notes.

    Removing whole lines leaves runs of blank lines where a comment block was, so
    collapse them — the diagram is going into a rendered document.
    """
    kept: list[str] = []
    for line in diagram.splitlines():
        if line.lstrip().startswith("%%"):
            continue
        if not line.strip() and (not kept or not kept[-1].strip()):
            continue
        kept.append(line)
    return "\n".join(kept).strip()


def sort_key(threat: dict[str, Any]) -> tuple[int, int, str]:
    return (
        RISK_ORDER.get(threat.get("risk"), 9),
        CONFIDENCE_ORDER.get(threat.get("confidence"), 9),
        threat.get("id", ""),
    )


# --- sections ---------------------------------------------------------------


def render_metrics(records: list[dict[str, Any]], all_threats: list[dict[str, Any]]) -> str:
    lines = ["## Findings at a glance", ""]

    by_risk = collections.Counter(t.get("risk") for t in all_threats)
    lines += [
        "| Severity | Count |",
        "|---|---:|",
        *[f"| {r.title()} | {by_risk.get(r, 0)} |" for r in ("critical", "high", "medium", "low")],
        f"| **Total** | **{len(all_threats)}** |",
        "",
    ]

    table = coverage_table(all_threats)
    lines += [
        "### Coverage by STRIDE category",
        "",
        "Every use case is analyzed by all six categories in separate passes, so a zero is a",
        "considered result rather than a gap in the method.",
        "",
        "| Use case | " + " | ".join(LETTERS) + " | Total |",
        "|---" * (len(LETTERS) + 2) + "|",
    ]
    for record in records:
        row = table.get(record["id"], {letter: 0 for letter in LETTERS})
        counts = " | ".join(str(row.get(letter, 0)) for letter in LETTERS)
        lines.append(f"| {record['id']} | {counts} | {sum(row.values())} |")
    lines += ["", "S Spoofing · T Tampering · R Repudiation · I Information disclosure · "
              "D Denial of service · E Elevation of privilege", ""]

    by_confidence = collections.Counter(t.get("confidence") for t in all_threats)
    cited = sum(1 for t in all_threats if t.get("evidence"))
    lines += [
        "### Evidence",
        "",
        f"- {by_confidence.get('high', 0)} high confidence, {by_confidence.get('medium', 0)} medium, "
        f"{by_confidence.get('low', 0)} low",
        f"- {cited} of {len(all_threats)} threats cite a specific file and line",
        "",
        "A high-confidence threat is guaranteed to cite source; a low-confidence one applies to the",
        "element by type but no supporting code was located. Low-confidence entries are retained",
        "rather than dropped so the reader can judge them.",
        "",
    ]

    by_status = collections.Counter(t.get("status") for t in all_threats)
    if by_status.get("mitigated") or by_status.get("partial"):
        lines += [
            "### Existing controls",
            "",
            f"- {by_status.get('mitigated', 0)} threats already mitigated in the codebase",
            f"- {by_status.get('partial', 0)} partially mitigated",
            f"- {by_status.get('unmitigated', 0)} unmitigated",
            "",
        ]

    return "\n".join(lines)


def render_threat(threat: dict[str, Any]) -> str:
    risk = (threat.get("risk") or "unknown").title()
    letter = threat.get("stride", "?")
    element = threat.get("dfd_element") or {}
    lines = [
        f"#### {threat.get('id')} — {threat.get('title')}",
        "",
        f"**{risk}** · {LETTERS.get(letter, letter)} · {element.get('name', 'unknown element')} "
        f"({(element.get('type') or '').replace('_', ' ')}) · "
        f"{STATUS_LABEL.get(threat.get('status'), threat.get('status'))} · "
        f"{threat.get('confidence', 'unknown')} confidence",
        "",
    ]
    if threat.get("trust_boundary"):
        lines += [f"*Crosses:* {threat['trust_boundary']}", ""]
    if threat.get("description"):
        lines += [threat["description"], ""]
    if threat.get("attack_scenario"):
        lines += ["**Attack scenario.** " + threat["attack_scenario"], ""]

    for item in threat.get("evidence") or []:
        lines.append(f"*{item.get('file')}:{item.get('line')}*")
        if item.get("snippet"):
            lines += ["", "```", item["snippet"], "```"]
        lines.append("")

    if threat.get("existing_mitigations"):
        lines += ["**Already in place.** " + "; ".join(threat["existing_mitigations"]), ""]
    if threat.get("recommendation"):
        lines += ["**Recommendation.** " + threat["recommendation"], ""]
    if threat.get("cwe"):
        lines += ["*" + ", ".join(threat["cwe"]) + "*", ""]

    return "\n".join(lines)


def render_use_case(record: dict[str, Any]) -> str:
    threats = sorted(record["threats"], key=sort_key)
    lines = [f"## {record['id']} — {record['name']}", ""]
    if record["description"]:
        lines += [record["description"], ""]
    if record["entry_points"]:
        lines += ["**Entry points:** " + ", ".join(f"`{e}`" for e in record["entry_points"]), ""]

    diagram = strip_comments(record["diagram"])
    if diagram:
        lines += ["### Data flow", "", "```mermaid", diagram, "```", ""]

    if not threats:
        lines += ["No threats were raised for this use case.", ""]
        return "\n".join(lines)

    lines += [
        "### Threats",
        "",
        "| ID | Severity | Category | Element | Status |",
        "|---|---|---|---|---|",
    ]
    for threat in threats:
        element = (threat.get("dfd_element") or {}).get("name", "")
        lines.append(
            f"| {threat.get('id')} | {(threat.get('risk') or '').title()} | "
            f"{LETTERS.get(threat.get('stride'), '?')} | {element} | "
            f"{STATUS_LABEL.get(threat.get('status'), '')} |"
        )
    lines += ["", "### Detail", ""]
    lines += [render_threat(t) for t in threats]
    return "\n".join(lines)


def render_method(model_id: str, records: list[dict[str, Any]]) -> str:
    return "\n".join(
        [
            "## Method",
            "",
            "Static analysis of the application source. No running instance was exercised, so",
            "findings describe reachable code paths rather than confirmed exploits.",
            "",
            "The pipeline runs in stages, each writing files the next reads:",
            "",
            "1. **Characterize** — the codebase is surveyed and authentication use cases identified.",
            "2. **Model** — a data flow diagram is drawn per use case, with elements typed as external",
            "   entities, processes, data stores and data flows, and grouped by trust boundary.",
            "3. **Analyze** — six independent agent passes per use case, one per STRIDE category, each",
            "   loading a single skill scoped to that category. Coverage is guaranteed by the loop",
            "   rather than left to one agent's judgement.",
            "4. **Report** — this document, assembled deterministically from the stage 3 output.",
            "",
            "### Consistency",
            "",
            "- Each STRIDE pass loads exactly one skill, so every category receives equal attention.",
            "- Severity is **derived**, never assigned: likelihood × impact through a fixed matrix",
            "  identical across all six skills. Two runs cannot disagree about what `high × high` means.",
            "- Every agent response is validated against a shared JSON contract before it is accepted;",
            "  a response that violates it is returned to the model with its own error list and retried.",
            "- Threat identifiers are derived from the use case and category, so runs can be diffed.",
            f"- Model: `{model_id}`, temperature 0.3.",
            "",
            "### Limitations",
            "",
            "- Static analysis only. No dynamic testing, no exploitation, no runtime confirmation.",
            f"- Scope is authentication: {len(records)} use case(s). Other areas of the application",
            "  were not analyzed.",
            "- Findings are machine-generated. High-confidence entries cite a file and line and can be",
            "  checked directly; low-confidence entries are hypotheses worth triaging, not conclusions.",
            "",
        ]
    )


def generate_summary(records: list[dict[str, Any]], all_threats: list[dict[str, Any]], model_id: str) -> str:
    """Optional LLM executive summary. Everything else in the report is deterministic."""
    from langchain_aws import ChatBedrockConverse

    top = sorted(all_threats, key=sort_key)[:12]
    digest = "\n".join(
        f"- [{t.get('risk')}] {t.get('id')} {t.get('title')} "
        f"({(t.get('dfd_element') or {}).get('name')})"
        for t in top
    )
    prompt = (
        "Write a three-paragraph executive summary of an application security threat model, "
        "for an engineering leader who will not read the detail.\n\n"
        f"Scope: authentication, {len(records)} use case(s), static analysis.\n"
        f"{len(all_threats)} threats total. Highest-severity findings:\n{digest}\n\n"
        "Say what the overall security posture looks like, what the most serious themes are, and "
        "what to fix first. Be specific and measured. No headings, no bullet points, no preamble."
    )
    llm = ChatBedrockConverse(model_id=model_id, temperature=0.3)
    return llm.invoke(prompt).content.strip()


# --- driver -----------------------------------------------------------------


def build_report(
    records: list[dict[str, Any]],
    target: str,
    model_id: str,
    summary: str | None = None,
) -> str:
    all_threats = [t for r in records for t in r["threats"]]
    today = datetime.date.today().isoformat()

    parts = [
        f"# Threat model — {target}",
        "",
        f"Authentication scope · static analysis · {today}",
        "",
        f"{len(all_threats)} threats across {len(records)} use case(s), "
        f"analyzed against all six STRIDE categories.",
        "",
    ]
    if summary:
        parts += ["## Executive summary", "", summary, ""]
    parts += [render_metrics(records, all_threats), render_method(model_id, records)]
    parts += [render_use_case(record) for record in records]

    warnings = validate_merged(all_threats)
    if warnings:
        parts += [
            "## Notes on this run",
            "",
            *[f"- {w}" for w in warnings],
            "",
        ]

    parts += [
        "---",
        "",
        "Generated by the BS-Squared threat modelling pipeline. Regenerate with "
        "`python -m main.stage4_report`.",
        "",
    ]
    return "\n".join(parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Assemble the final threat model report.")
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("output"))
    parser.add_argument("--target", default="OWASP Juice Shop", help="application name for the title")
    parser.add_argument("--model-id", default="us.anthropic.claude-haiku-4-5-20251001-v1:0")
    parser.add_argument("--summarize", action="store_true", help="add an LLM-written executive summary")
    args = parser.parse_args(argv)

    records = load_stage_outputs(args.output)
    all_threats = [t for r in records for t in r["threats"]]

    summary = None
    if args.summarize:
        print("generating executive summary...", file=sys.stderr)
        try:
            summary = generate_summary(records, all_threats, args.model_id)
        except Exception as exc:  # noqa: BLE001 - a failed summary must not lose the report
            print(f"  summary failed ({exc}); continuing without it", file=sys.stderr)

    report = build_report(records, args.target, args.model_id, summary)
    destination = args.output / "report.md"
    destination.write_text(report)

    print(f"{len(all_threats)} threat(s) across {len(records)} use case(s) -> {destination}")
    for record in records:
        print(f"  {record['id']}: {len(record['threats'])} threat(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
