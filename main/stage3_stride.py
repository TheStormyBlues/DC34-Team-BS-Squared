"""Stage 3 — STRIDE analysis driver.

Runs one DeepAgent call per (use case x STRIDE letter), each loading exactly one
skill. Six letters means six calls per use case, which guarantees coverage instead
of hoping a single agent holding all six skills gives Repudiation a fair shake.

Each response is validated against main/contract.py. A malformed response is fed
its own error list and retried, so one bad generation does not cost the run.

    # see the prompts without spending a token or needing langchain installed
    python -m main.stage3_stride --dry-run

    # real run
    python -m main.stage3_stride --repo ./juice-shop

    # iterate on one call while debugging
    python -m main.stage3_stride --repo ./juice-shop \
        --only-use-case UC-LOGIN --only-letter R --force

Reads and writes the shared output layout:

    <output>/use-cases/<id>.json    stage 1 — name, description, entry points
    <output>/dfds/<id>.mmd          stage 2 — the Mermaid diagram
    <output>/threats/<id>/<L>.json  one file per agent call, the cache unit
    <output>/threats/<id>.json      merged per use case — what stage 4 reads

Results are cached per call: an existing per-letter file is skipped unless --force.
That matters when you are iterating on one letter and do not want to pay for the
other five again.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import random
import sys
import time
from typing import Any

from main.contract import (
    LETTERS,
    SKILL_FOR_LETTER,
    AgentOutputError,
    coverage_table,
    parse_agent_json,
    validate_merged,
    validate_skill_output,
)
from main.mermaid import parse_mermaid, render_inventory

DEFAULT_MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
DEFAULT_TEMPERATURE = 0.3
MAX_ATTEMPTS = 3

SYSTEM_PROMPT = """You are a threat modelling analyst working through a single \
data flow diagram for a single STRIDE category.

You have one skill loaded. It defines the threat category you are responsible for, \
which diagram elements it applies to, the patterns to look for, and the exact JSON \
you must return. Follow it precisely and do not analyze any other STRIDE category.

The application source is available through your filesystem tools. Read the files \
that implement the elements in the diagram before making a claim about them. When \
you cite evidence it must be a real file path and a real line number that you have \
actually read — an empty evidence list with low confidence is correct and expected \
when you cannot locate the code, and is far better than a plausible guess.

Return only the JSON object your skill specifies. No preamble, no explanation, no \
markdown fence."""


# --- input ------------------------------------------------------------------


def load_use_cases(output_root: pathlib.Path) -> list[dict[str, Any]]:
    """Read stage 1 and stage 2 output from the shared layout.

        <output>/use-cases/<id>.json    stage 1 — name, description, entry points
        <output>/dfds/<id>.mmd          stage 2 — the Mermaid diagram

    The file stem is the use case id, so the two stages never have to agree on
    anything but a filename. Files whose name starts with `_` are skipped, which is
    how the shipped `_example` artifacts sit in the real directories without being
    analyzed.
    """
    cases_dir = output_root / "use-cases"
    dfds_dir = output_root / "dfds"

    if not cases_dir.is_dir():
        raise SystemExit(f"no use cases directory at {cases_dir} — has stage 1 run?")

    cases: list[dict[str, Any]] = []
    for path in sorted(cases_dir.glob("*.json")):
        if path.name.startswith("_"):
            continue
        try:
            case = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}: invalid JSON — {exc}") from None
        if not isinstance(case, dict):
            raise SystemExit(f"{path}: expected a JSON object describing one use case")

        case.setdefault("id", path.stem)
        if case["id"] != path.stem:
            raise SystemExit(
                f"{path}: id is {case['id']!r} but the filename says {path.stem!r}. "
                "The filename is the id — rename one to match."
            )

        diagram = dfds_dir / f"{path.stem}.mmd"
        if diagram.exists():
            case["mermaid"] = diagram.read_text()
        elif not case.get("mermaid") and not case.get("dfd"):
            print(
                f"warning [{case['id']}]: no diagram at {diagram} — the analysis will have "
                "no elements to iterate",
                file=sys.stderr,
            )
        cases.append(case)

    if not cases:
        raise SystemExit(f"no use cases found in {cases_dir} (files starting with '_' are skipped)")
    return cases


def dfd_warnings(use_case: dict[str, Any]) -> list[str]:
    """Diagram problems worth telling the operator about, from the Mermaid parser."""
    if not use_case.get("mermaid"):
        return []
    return parse_mermaid(use_case["mermaid"])["warnings"]


def render_dfd(use_case: dict[str, Any]) -> str:
    """Render stage 2's diagram into text the agent can iterate.

    Mermaid is the expected input. It is parsed into a typed element inventory so
    the agent never has to infer whether a box is a process or a data store, and the
    raw diagram is included after it for context. A structured `dfd` object is still
    accepted as a fallback.
    """
    if use_case.get("mermaid"):
        parsed = parse_mermaid(use_case["mermaid"])
        # Mermaid cannot carry per-node source locations, so they ride in `%% file:`
        # comments inside the diagram. A `file_hints` map on the use case JSON still
        # works and wins on conflict. This is what points the agent at the code
        # instead of making it search.
        hints = {**parsed.get("file_hints", {}), **(use_case.get("file_hints") or {})}
        for key in ("external_entities", "processes", "data_stores"):
            for item in parsed[key]:
                found = hints.get(item.get("id")) or hints.get(item["name"])
                if found:
                    item["file_hints"] = [found] if isinstance(found, str) else list(found)
        inventory = render_inventory(parsed)
        blocks = []
        if inventory:
            blocks.append("Elements (typed, extracted from the diagram below):\n" + inventory)
        else:
            blocks.append(
                "No elements could be extracted from the diagram. Report this rather than "
                "inventing elements."
            )
        blocks.append("Diagram (Mermaid):\n" + use_case["mermaid"].strip())
        return "\n\n".join(blocks)

    lines: list[str] = []
    dfd = use_case.get("dfd") or {}

    groups = (
        ("External entities", "external_entities"),
        ("Processes", "processes"),
        ("Data stores", "data_stores"),
        ("Data flows", "data_flows"),
        ("Trust boundaries", "trust_boundaries"),
    )
    for label, key in groups:
        items = dfd.get(key) or []
        if not items:
            continue
        lines.append(f"{label}:")
        for item in items:
            if isinstance(item, str):
                lines.append(f"  - {item}")
                continue
            name = item.get("name", "<unnamed>")
            detail = []
            if item.get("from") and item.get("to"):
                detail.append(f"{item['from']} -> {item['to']}")
            if item.get("file_hints"):
                detail.append("implemented in " + ", ".join(item["file_hints"]))
            if item.get("description"):
                detail.append(item["description"])
            lines.append(f"  - {name}" + (f" ({'; '.join(detail)})" if detail else ""))
        lines.append("")

    if not lines:
        lines.append("(no diagram supplied — report this rather than inventing elements)")

    return "\n".join(lines).strip()


def build_task(use_case: dict[str, Any], letter: str) -> str:
    return f"""Use case: {use_case['id']} — {use_case.get('name', '')}
{use_case.get('description', '')}

Data flow diagram
-----------------
{render_dfd(use_case)}

Task
----
Apply your loaded skill to this diagram. Analyze the {LETTERS[letter]} category and \
nothing else. Work element by element through the element types your skill says the \
letter applies to, reading the relevant source before judging it.

Use "{use_case['id']}" as the use_case_id and "{letter}" as the stride_letter in your output."""


# --- one call ---------------------------------------------------------------


def build_agent(skill_dir: pathlib.Path, repo: pathlib.Path, model_id: str, temperature: float):
    """Imported lazily so --dry-run works without the course venv."""
    from deepagents import create_deep_agent
    from deepagents.backends import FilesystemBackend
    from langchain_aws import ChatBedrockConverse

    return create_deep_agent(
        model=ChatBedrockConverse(model_id=model_id, temperature=temperature),
        tools=[],
        backend=FilesystemBackend(root_dir=str(repo), virtual_mode=False),
        system_prompt=SYSTEM_PROMPT,
        skills=[str(skill_dir)],  # exactly one skill — this is what forces single-letter focus
    )


def extract_text(result: Any) -> str:
    """Pull the final assistant text out of whatever the agent returned."""
    if isinstance(result, str):
        return result
    messages = result.get("messages", []) if isinstance(result, dict) else []
    for message in reversed(messages):
        content = getattr(message, "content", None)
        if content is None and isinstance(message, dict):
            content = message.get("content")
        if isinstance(content, list):  # content blocks
            content = "".join(b.get("text", "") for b in content if isinstance(b, dict))
        if isinstance(content, str) and content.strip():
            return content
    raise AgentOutputError("no text content in agent result")


def invoke_with_backoff(agent, messages: list[dict[str, str]]) -> Any:
    """Bedrock throttles under a tight loop. Back off rather than dropping the call."""
    for retry in range(5):
        try:
            return agent.invoke({"messages": messages})
        except Exception as exc:  # noqa: BLE001 - botocore error classes vary by version
            name = type(exc).__name__
            text = str(exc)
            throttled = "Throttl" in name or "Throttl" in text or "TooManyRequests" in text
            if not throttled or retry == 4:
                raise
            delay = min(2**retry + random.random(), 30)
            print(f"      throttled, retrying in {delay:.1f}s", flush=True)
            time.sleep(delay)
    raise RuntimeError("unreachable")


def run_one(
    use_case: dict[str, Any],
    letter: str,
    repo: pathlib.Path,
    skills_root: pathlib.Path,
    model_id: str,
    temperature: float,
) -> dict[str, Any]:
    """Run one skill against one use case, retrying on a contract violation."""
    agent = build_agent(skills_root / SKILL_FOR_LETTER[letter], repo, model_id, temperature)
    messages = [{"role": "user", "content": build_task(use_case, letter)}]
    last_errors: list[str] = []
    raw = ""

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            raw = extract_text(invoke_with_backoff(agent, messages))
            blob = parse_agent_json(raw)
            errors = validate_skill_output(blob, expected_letter=letter, expected_use_case=use_case["id"])
            if not errors:
                return blob
            last_errors = errors
        except AgentOutputError as exc:
            last_errors = [str(exc)]

        if attempt < MAX_ATTEMPTS:
            print(f"      attempt {attempt} rejected ({len(last_errors)} problem(s)), retrying", flush=True)
            messages += [
                {"role": "assistant", "content": raw},
                {
                    "role": "user",
                    "content": (
                        "Your response did not satisfy the output contract in your skill:\n"
                        + "\n".join(f"- {e}" for e in last_errors)
                        + "\n\nReturn the corrected JSON object only. Do not add commentary, "
                        "and do not invent evidence to satisfy a confidence level — lower the "
                        "confidence instead."
                    ),
                },
            ]

    raise RuntimeError(
        f"{use_case['id']}/{letter}: gave up after {MAX_ATTEMPTS} attempts. Last errors:\n"
        + "\n".join(f"  - {e}" for e in last_errors)
    )


# --- driver -----------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run six STRIDE skills over each use case.")
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=pathlib.Path("output"),
        help="shared output root holding use-cases/, dfds/ and threats/",
    )
    parser.add_argument("--repo", type=pathlib.Path, help="target application clone (required unless --dry-run)")
    parser.add_argument("--skills", type=pathlib.Path, default=pathlib.Path("skills"))
    parser.add_argument("--model-id", default=DEFAULT_MODEL_ID)
    parser.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)
    parser.add_argument("--only-use-case", help="run a single use case id")
    parser.add_argument("--only-letter", help="run a single STRIDE letter")
    parser.add_argument("--force", action="store_true", help="re-run calls that already have output")
    parser.add_argument("--dry-run", action="store_true", help="print prompts, call nothing")
    args = parser.parse_args(argv)

    use_cases = load_use_cases(args.output)
    if args.only_use_case:
        use_cases = [u for u in use_cases if u["id"] == args.only_use_case]
        if not use_cases:
            raise SystemExit(f"no use case with id {args.only_use_case!r}")

    letters = [args.only_letter.upper()] if args.only_letter else list(LETTERS)
    for letter in letters:
        if letter not in LETTERS:
            raise SystemExit(f"{letter!r} is not a STRIDE letter")
        skill_dir = args.skills / SKILL_FOR_LETTER[letter]
        if not (skill_dir / "SKILL.md").exists():
            raise SystemExit(f"missing skill: {skill_dir / 'SKILL.md'}")

    for use_case in use_cases:
        for warning in dfd_warnings(use_case):
            print(f"diagram warning [{use_case['id']}]: {warning}", file=sys.stderr)

    if args.dry_run:
        for use_case in use_cases:
            for letter in letters:
                print("=" * 78)
                print(f"{use_case['id']} / {letter} — skill: {SKILL_FOR_LETTER[letter]}")
                print("=" * 78)
                print(build_task(use_case, letter))
                print()
        return 0

    if not args.repo:
        raise SystemExit("--repo is required unless --dry-run")
    if not args.repo.exists():
        raise SystemExit(f"repo path does not exist: {args.repo}")

    threats_root = args.output / "threats"
    threats_root.mkdir(parents=True, exist_ok=True)
    total = len(use_cases) * len(letters)
    done = 0
    failures: list[str] = []
    all_threats: list[dict[str, Any]] = []

    for use_case in use_cases:
        # Per-letter files are the working artifacts: one agent call each, so a
        # re-run of a single letter costs one call rather than six. The merged
        # per-use-case file below is what stage 4 reads.
        per_letter_dir = threats_root / use_case["id"]
        per_letter_dir.mkdir(parents=True, exist_ok=True)
        case_threats: list[dict[str, Any]] = []

        for letter in letters:
            done += 1
            target = per_letter_dir / f"{letter}.json"
            label = f"[{done}/{total}] {use_case['id']} / {letter} ({LETTERS[letter]})"

            if target.exists() and not args.force:
                blob = json.loads(target.read_text())
                case_threats.extend(blob.get("threats", []))
                print(f"{label}: cached, {len(blob.get('threats', []))} threat(s)", flush=True)
                continue

            print(f"{label}: running", flush=True)
            try:
                blob = run_one(use_case, letter, args.repo, args.skills, args.model_id, args.temperature)
            except Exception as exc:  # noqa: BLE001 - one bad call must not end the run
                print(f"      FAILED: {exc}", file=sys.stderr, flush=True)
                failures.append(f"{use_case['id']}/{letter}")
                continue

            target.write_text(json.dumps(blob, indent=2) + "\n")
            case_threats.extend(blob["threats"])
            print(f"      {len(blob['threats'])} threat(s) -> {target}", flush=True)

        # Merge whichever letters ran this time with any already on disk, so a
        # partial run still leaves a complete, readable per-use-case file.
        if letters != list(LETTERS):
            for existing in sorted(per_letter_dir.glob("*.json")):
                if existing.stem in letters:
                    continue
                case_threats.extend(json.loads(existing.read_text()).get("threats", []))

        merged_case = threats_root / f"{use_case['id']}.json"
        merged_case.write_text(
            json.dumps(
                {"use_case_id": use_case["id"], "name": use_case.get("name", ""), "threats": case_threats},
                indent=2,
            )
            + "\n"
        )
        all_threats.extend(case_threats)

    print("\ncoverage (threats per letter)")
    table = coverage_table(all_threats)
    header = "  " + "use case".ljust(24) + "".join(l.rjust(4) for l in LETTERS) + "  total"
    print(header)
    for use_case_id, row in sorted(table.items()):
        counts = "".join(str(row[l]).rjust(4) for l in LETTERS)
        print(f"  {use_case_id.ljust(24)}{counts}{str(sum(row.values())).rjust(7)}")

    print(f"\n{len(all_threats)} threat(s) across {len(table)} use case(s) -> {threats_root}/<use-case-id>.json")

    for warning in validate_merged(all_threats):
        print(f"  note: {warning}")
    if failures:
        print(f"\n{len(failures)} call(s) failed: {', '.join(failures)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
