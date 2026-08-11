"""BS-Squared threat modelling pipeline — run the whole chain.

    python main.py --repo repo
    python main.py --repo repo --dry-run          # deterministic parts only, no model calls
    python main.py --repo repo --from stride      # resume without redoing stages 1 and 2
    python main.py --repo repo --only report      # one stage
    python main.py --repo repo --force            # re-run stages that already have output

Each stage reads and writes files under one directory, so the chain is the filesystem
rather than anything passed in memory:

    output/<repo>/use-cases/<id>.json    stage 1  characterize
    output/<repo>/dfds/<id>.mmd          stage 2  data flow diagrams
    output/<repo>/threats/<id>.json      stage 3  STRIDE analysis
    output/<repo>/report.md              stage 4  the report

That layout comes from stage 1, which namespaces output by target directory name so
several applications can be analyzed without collision. This runner derives the same
path and hands it to every later stage.

Stages are invoked through their own CLIs, so each keeps its own defaults — notably
stage 1 runs an open-weight model with validated tools while the others run Claude.
A stage that has not been written yet is reported and skipped rather than crashing
the run.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import pathlib
import sys
import time
from typing import Callable


class Stage:
    """One pipeline stage: how to invoke it, and how to tell whether it has run."""

    def __init__(
        self,
        key: str,
        title: str,
        module: str,
        argv: Callable[[argparse.Namespace, pathlib.Path], list[str]],
        produces: Callable[[pathlib.Path], list[pathlib.Path]],
        needs_model: bool = True,
    ) -> None:
        self.key = key
        self.title = title
        self.module = module
        self.argv = argv
        self.produces = produces
        self.needs_model = needs_model

    def is_available(self) -> bool:
        return importlib.util.find_spec(self.module) is not None

    def existing_output(self, out_dir: pathlib.Path) -> list[pathlib.Path]:
        return self.produces(out_dir)


def _use_case_files(out_dir: pathlib.Path) -> list[pathlib.Path]:
    directory = out_dir / "use-cases"
    return [p for p in sorted(directory.glob("*.json")) if not p.name.startswith("_")] if directory.is_dir() else []


def _dfd_files(out_dir: pathlib.Path) -> list[pathlib.Path]:
    directory = out_dir / "dfds"
    return [p for p in sorted(directory.glob("*.mmd")) if not p.name.startswith("_")] if directory.is_dir() else []


def _threat_files(out_dir: pathlib.Path) -> list[pathlib.Path]:
    directory = out_dir / "threats"
    return [p for p in sorted(directory.glob("*.json")) if not p.name.startswith("_")] if directory.is_dir() else []


def _report_file(out_dir: pathlib.Path) -> list[pathlib.Path]:
    path = out_dir / "report.md"
    return [path] if path.exists() else []


STAGES: list[Stage] = [
    Stage(
        key="characterize",
        title="Characterize the application and identify use cases",
        module="main.stage1_characterize",
        # Stage 1 names this flag --out-dir, not --output.
        argv=lambda a, out: ["--repo", str(a.repo), "--out-dir", str(out)]
        + (["--dry-run"] if a.dry_run else []),
        produces=_use_case_files,
    ),
    Stage(
        key="dfds",
        title="Draw a data flow diagram per use case",
        module="main.stage2_dfds",
        argv=lambda a, out: ["--repo", str(a.repo), "--output", str(out)]
        + (["--dry-run"] if a.dry_run else []),
        produces=_dfd_files,
    ),
    Stage(
        key="stride",
        title="Six STRIDE passes per use case",
        module="main.stage3_stride",
        argv=lambda a, out: ["--output", str(out), "--repo", str(a.repo)]
        + (["--dry-run"] if a.dry_run else [])
        + (["--force"] if a.force else []),
        produces=_threat_files,
    ),
    Stage(
        key="report",
        title="Assemble the report",
        module="main.stage4_report",
        # Stage 4 is deterministic, so it runs even under --dry-run.
        argv=lambda a, out: ["--output", str(out), "--target", a.target or a.repo.resolve().name],
        produces=_report_file,
        needs_model=False,
    ),
]

STAGE_KEYS = [s.key for s in STAGES]


def run_stage(stage: Stage, args: argparse.Namespace, out_dir: pathlib.Path, index: int) -> str:
    """Run one stage. Returns a short status word for the summary."""
    label = f"[{index}/{len(STAGES)}] {stage.key}"
    print(f"\n{label} — {stage.title}", flush=True)

    if not stage.is_available():
        print(f"       not implemented yet ({stage.module} does not exist) — skipping", flush=True)
        return "missing"

    existing = stage.existing_output(out_dir)
    if existing and not args.force:
        print(f"       {len(existing)} existing artifact(s), skipping (use --force to re-run)", flush=True)
        return "cached"

    if args.dry_run and stage.needs_model:
        print("       dry run", flush=True)

    argv = stage.argv(args, out_dir)
    print(f"       $ python -m {stage.module} {' '.join(argv)}", flush=True)

    started = time.monotonic()
    try:
        # Imported here, not above, so a stage whose dependencies are missing reports
        # as a failed stage rather than a traceback out of the runner.
        module = importlib.import_module(stage.module)
        code = module.main(argv)
    except ModuleNotFoundError as exc:
        print(
            f"       FAILED: {exc.name} is not installed — activate the course venv "
            f"(pip install -r requirements.txt)",
            file=sys.stderr,
            flush=True,
        )
        return "failed"
    except SystemExit as exc:  # a stage's own argparse/validation error
        code = exc.code if isinstance(exc.code, int) else 1
        print(f"       {exc}", file=sys.stderr, flush=True)
    except Exception as exc:  # noqa: BLE001 - report which stage broke, not a bare traceback
        print(f"       FAILED: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return "failed"

    elapsed = time.monotonic() - started
    produced = len(stage.existing_output(out_dir))
    if code:
        print(f"       exited {code} after {elapsed:.0f}s", file=sys.stderr, flush=True)
        return "failed"
    print(f"       {produced} artifact(s) in {elapsed:.0f}s", flush=True)
    return "ok"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the BS-Squared threat modelling pipeline end to end.",
        epilog="Stages: " + ", ".join(STAGE_KEYS),
    )
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("repo"),
                        help="target application clone (default: ./repo)")
    parser.add_argument("--output", type=pathlib.Path,
                        help="output directory (default: output/<repo dir name>, matching stage 1)")
    parser.add_argument("--target", help="application name for the report title (default: repo dir name)")
    parser.add_argument("--from", dest="from_stage", choices=STAGE_KEYS, help="start at this stage")
    parser.add_argument("--only", choices=STAGE_KEYS, help="run just this stage")
    parser.add_argument("--force", action="store_true", help="re-run stages that already have output")
    parser.add_argument("--dry-run", action="store_true",
                        help="run only the deterministic parts of each stage; no model calls")
    args = parser.parse_args(argv)

    if not args.repo.is_dir():
        raise SystemExit(
            f"target not found: {args.repo}\n"
            f"  git clone --depth 1 https://github.com/juice-shop/juice-shop.git {args.repo}"
        )

    # Stage 1 derives output/<repo dir name>; mirror it so every stage agrees.
    out_dir = args.output or pathlib.Path("output") / args.repo.resolve().name
    out_dir.mkdir(parents=True, exist_ok=True)

    selected = STAGES
    if args.only:
        selected = [s for s in STAGES if s.key == args.only]
    elif args.from_stage:
        selected = STAGES[STAGE_KEYS.index(args.from_stage):]

    print(f"target  {args.repo.resolve()}")
    print(f"output  {out_dir.resolve()}")
    print(f"stages  {', '.join(s.key for s in selected)}" + ("  (dry run)" if args.dry_run else ""))

    results: dict[str, str] = {}
    for stage in selected:
        results[stage.key] = run_stage(stage, args, out_dir, STAGE_KEYS.index(stage.key) + 1)
        if results[stage.key] == "failed":
            print(f"\nstopping: {stage.key} failed", file=sys.stderr)
            break

    print("\n" + "-" * 60)
    for stage in STAGES:
        status = results.get(stage.key, "not run")
        print(f"  {stage.key.ljust(14)} {status}")

    counts = {
        "use cases": len(_use_case_files(out_dir)),
        "diagrams": len(_dfd_files(out_dir)),
        "threat files": len(_threat_files(out_dir)),
    }
    print("\n  " + " · ".join(f"{v} {k}" for k, v in counts.items()))

    # The chain degrades quietly when a middle stage is missing: stage 3 still runs, but
    # with no elements to iterate it falls back to generic advice. Say so plainly.
    if counts["use cases"] and not counts["diagrams"]:
        print(
            "\n  note: no diagrams. Stage 3 analyzes elements from the DFD, so without stage 2\n"
            "        its findings will be generic rather than grounded in this application.",
            file=sys.stderr,
        )

    report = out_dir / "report.md"
    if report.exists():
        print(f"\n  report   {report}")
        print(f"  chat     python -m main.chatbot --output {out_dir}")

    return 1 if "failed" in results.values() else 0


if __name__ == "__main__":
    raise SystemExit(main())
