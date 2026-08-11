"""Stage 3 — STRIDE analysis driver.

Runs one DeepAgent call per (use case x STRIDE letter), each loading exactly one
skill. Six letters means six calls per use case, which guarantees coverage instead
of hoping a single agent holding all six skills gives Repudiation a fair shake.

Each response is validated against main/contract.py. A malformed response is fed
its own error list and retried, so one bad generation does not cost the run.

    # see the prompts without spending a token or needing langchain installed
    python -m main.stage3_stride --use-cases output/use-cases.json --dry-run

    # real run
    python -m main.stage3_stride \
        --use-cases output/use-cases.json \
        --repo ./juice-shop \
        --out output/stride

    # iterate on one call while debugging
    python -m main.stage3_stride ... --only-use-case UC-LOGIN --only-letter R --force

Results are cached per call: an existing output file is skipped unless --force.
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


def load_use_cases(path: pathlib.Path) -> list[dict[str, Any]]:
    """Read stage 2 output.

    Accepts either {"use_cases": [...]} or a bare list, and tolerates a use case
    that carries a structured `dfd`, a `mermaid` string, or both.
    """
    payload = json.loads(path.read_text())
    cases = payload.get("use_cases", payload) if isinstance(payload, dict) else payload
    if not isinstance(cases, list):
        raise SystemExit(f"{path}: expected a list of use cases or a 'use_cases' key")

    for i, case in enumerate(cases):
        if not isinstance(case, dict) or not case.get("id"):
            raise SystemExit(f"{path}: use case {i} has no 'id' — stage 2 must assign a stable id")
    return cases


def render_dfd(use_case: dict[str, Any]) -> str:
    """Render whatever shape stage 2 produced into text the agent can iterate."""
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

    if use_case.get("mermaid"):
        lines.append("Diagram:")
        lines.append(use_case["mermaid"].strip())
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
    parser.add_argument("--use-cases", type=pathlib.Path, required=True, help="stage 2 output JSON")
    parser.add_argument("--repo", type=pathlib.Path, help="target application clone (required unless --dry-run)")
    parser.add_argument("--out", type=pathlib.Path, default=pathlib.Path("output/stride"))
    parser.add_argument("--skills", type=pathlib.Path, default=pathlib.Path("skills"))
    parser.add_argument("--model-id", default=DEFAULT_MODEL_ID)
    parser.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)
    parser.add_argument("--only-use-case", help="run a single use case id")
    parser.add_argument("--only-letter", help="run a single STRIDE letter")
    parser.add_argument("--force", action="store_true", help="re-run calls that already have output")
    parser.add_argument("--dry-run", action="store_true", help="print prompts, call nothing")
    args = parser.parse_args(argv)

    use_cases = load_use_cases(args.use_cases)
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

    args.out.mkdir(parents=True, exist_ok=True)
    total = len(use_cases) * len(letters)
    done = 0
    failures: list[str] = []
    all_threats: list[dict[str, Any]] = []

    for use_case in use_cases:
        for letter in letters:
            done += 1
            target = args.out / f"{use_case['id']}-{letter}.json"
            label = f"[{done}/{total}] {use_case['id']} / {letter} ({LETTERS[letter]})"

            if target.exists() and not args.force:
                blob = json.loads(target.read_text())
                all_threats.extend(blob.get("threats", []))
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
            all_threats.extend(blob["threats"])
            print(f"      {len(blob['threats'])} threat(s) -> {target}", flush=True)

    merged = args.out / "all_threats.json"
    merged.write_text(json.dumps({"threats": all_threats}, indent=2) + "\n")

    print("\ncoverage (threats per letter)")
    table = coverage_table(all_threats)
    header = "  " + "use case".ljust(24) + "".join(l.rjust(4) for l in LETTERS) + "  total"
    print(header)
    for use_case_id, row in sorted(table.items()):
        counts = "".join(str(row[l]).rjust(4) for l in LETTERS)
        print(f"  {use_case_id.ljust(24)}{counts}{str(sum(row.values())).rjust(7)}")

    print(f"\n{len(all_threats)} threat(s) across {len(table)} use case(s) -> {merged}")

    for warning in validate_merged(all_threats):
        print(f"  note: {warning}")
    if failures:
        print(f"\n{len(failures)} call(s) failed: {', '.join(failures)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
