"""Chat with the threat model.

A DeepAgent whose filesystem is the project directory, so it can read everything the
pipeline produced — use cases, diagrams, threats, the assembled report — and the target
source alongside it, and quote the actual code behind a finding.

No vector store. The whole corpus is a few hundred kilobytes of structured JSON, so
retrieval buys nothing over letting the agent read files directly: no index to build, no
staleness after a stage 3 re-run, and it can quote source rather than a chunk.

    python -m main.chatbot                                  # interactive
    python -m main.chatbot --ask "What is the worst finding in the login flow?"
    python -m main.chatbot --repo ./juice-shop              # let it read the target too

Grounding is the point. In a security review a confabulated threat is worse than no
answer, so the prompt requires every claim to cite a threat id or a file and line, and
to decline when the corpus does not cover the question.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

DEFAULT_MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
DEFAULT_TEMPERATURE = 0.3

SYSTEM_PROMPT = """You answer questions about a threat model that has already been \
produced. You are a reference over its output, not a new analysis.

## Your corpus

Everything is on your filesystem, under `output/`:

- `output/report.md` — the assembled report. Start here for anything general; it has the
  severity counts, the STRIDE coverage table, and the method.
- `output/threats/<use-case-id>.json` — every threat for one use case, all six STRIDE
  categories merged. This is the authoritative detail.
- `output/threats/<use-case-id>/<LETTER>.json` — the same threats split by category.
- `output/use-cases/<use-case-id>.json` — what each use case is.
- `output/dfds/<use-case-id>.mmd` — the data flow diagram, in Mermaid.

Files whose name begins with `_` are format examples, not real analysis. Never cite them.

If a target application clone is present in the working directory, you may read it to
show the code behind a finding.

## How to answer

Read before you answer. Do not rely on memory of a previous question.

Cite specifically. Every claim about a threat carries its id, like `T-UC-LOGIN-S-001`.
Every claim about code carries a file and line. A reader must be able to check you.

Say when you do not know. If the corpus does not contain the answer, say so plainly and
name what would be needed. Never infer a threat that is not in `output/threats/`, never
invent a file path or a line number, and never upgrade a low-confidence finding into a
certainty. Declining is a correct answer.

Respect what the data means:

- `risk` is derived from likelihood and impact through a fixed matrix. Report it; do not
  re-rate a threat yourself.
- `confidence: high` means the finding cites real source. `low` means the category applies
  to that element but no supporting code was found — describe those as unverified.
- `status: mitigated` threats were considered and found already handled. They are evidence
  of a control, not an open problem. Do not present them as findings.
- A STRIDE category with zero threats for a use case was analyzed and returned nothing. It
  is not a gap in coverage, and you can say so.

Be direct and brief. A specific answer with two citations beats a survey. Use prose;
reach for a table only when comparing several threats."""


def build_agent(root: pathlib.Path, model_id: str, temperature: float):
    """Imported lazily so --help works without the course venv."""
    from deepagents import create_deep_agent
    from deepagents.backends import FilesystemBackend
    from langchain_aws import ChatBedrockConverse
    from langgraph.checkpoint.memory import MemorySaver

    return create_deep_agent(
        model=ChatBedrockConverse(model_id=model_id, temperature=temperature),
        tools=[],
        backend=FilesystemBackend(root_dir=str(root), virtual_mode=False),
        system_prompt=SYSTEM_PROMPT,
        checkpointer=MemorySaver(),  # keeps the thread across turns
    )


def ask(agent, question: str, thread_id: str = "chat", show_tools: bool = True) -> str:
    """Send one turn, printing tool activity as it happens, and return the answer."""
    answer = ""
    for event in agent.stream(
        {"messages": [{"role": "user", "content": question}]},
        config={"configurable": {"thread_id": thread_id}},
    ):
        for key, value in event.items():
            if "Middleware" in key or not isinstance(value, dict):
                continue
            for message in value.get("messages", []):
                calls = getattr(message, "tool_calls", None)
                if calls:
                    if show_tools:
                        for call in calls:
                            target = call.get("args", {}).get("file_path") or ""
                            print(f"  · {call['name']} {target}".rstrip(), file=sys.stderr, flush=True)
                    continue
                content = getattr(message, "content", None)
                if isinstance(content, list):
                    content = "".join(b.get("text", "") for b in content if isinstance(b, dict))
                if isinstance(content, str) and content.strip():
                    answer = content
    return answer


BANNER = """Threat model chat. The corpus is output/ — report, threats, diagrams, use cases.
Ask about a finding, a use case, coverage, or what was looked for and not found.
Ctrl-D or 'exit' to quit.
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Chat with the generated threat model.")
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("output"))
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path("."),
                        help="filesystem root the agent can read (default: the project directory)")
    parser.add_argument("--repo", type=pathlib.Path,
                        help="target clone, if outside the project directory; widens the root to cover both")
    parser.add_argument("--model-id", default=DEFAULT_MODEL_ID)
    parser.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)
    parser.add_argument("--ask", help="ask one question and exit, instead of starting a session")
    parser.add_argument("--quiet", action="store_true", help="hide tool activity")
    args = parser.parse_args(argv)

    if not (args.output / "threats").is_dir():
        raise SystemExit(
            f"no threats found under {args.output} — run stage 3 first, then stage 4 for the report"
        )
    if not (args.output / "report.md").exists():
        print(
            f"note: {args.output / 'report.md'} does not exist yet. Answers will come from the raw "
            "threat JSON. Run `python -m main.stage4_report` for a better corpus.",
            file=sys.stderr,
        )

    root = args.root.resolve()
    if args.repo:
        # Both trees must sit under one root for a single filesystem backend to see them.
        repo = args.repo.resolve()
        try:
            repo.relative_to(root)
        except ValueError:
            import os

            root = pathlib.Path(os.path.commonpath([root, repo]))
            print(f"widening filesystem root to {root} to cover the target clone", file=sys.stderr)

    agent = build_agent(root, args.model_id, args.temperature)

    if args.ask:
        print(ask(agent, args.ask, show_tools=not args.quiet))
        return 0

    print(BANNER)
    while True:
        try:
            question = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not question:
            continue
        if question.lower() in {"exit", "quit", ":q"}:
            return 0
        try:
            print("\n" + ask(agent, question, show_tools=not args.quiet) + "\n")
        except Exception as exc:  # noqa: BLE001 - a bad turn must not end the session
            print(f"\nerror: {exc}\n", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
