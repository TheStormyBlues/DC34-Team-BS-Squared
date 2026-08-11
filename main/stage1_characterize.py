"""Stage 1 — characterization.

Produces two artifacts per target repo, under output/<repo-dir-name>/:

  use-cases.json        consumed by stage 2 (DFD) and stage 3 (STRIDE,
                         main/stage3_stride.py). Fixed contract:

    {
      "use_cases": [
        {
          "id": "UC-LOGIN",
          "name": "Registered customer signs in with email and password",
          "description": "...",
          "entry_points": ["POST /rest/user/login"],
          "source_refs": ["routes/login.ts", "lib/insecurity.ts", "models/user.ts"]
        }
      ]
    }

  characterization.json general description of the target application — what it
                         does and what it's for. Not consumed by a later stage;
                         it's the "what is this app" artifact for the report/demo.

    {
      "app_name": "...",
      "summary": "...",
      "goal": "..."
    }

Design rule: an open-weight model (Qwen) never emits this JSON directly — free-text
JSON from a smaller model is not reliable enough to trust as a pipeline artifact.
Instead:

  1. Everything that can be extracted mechanically IS extracted mechanically, in this
     file, with no model involved: dependency classification, Express route table,
     candidate auth-relevant source files. These functions are plain stdlib (json,
     re, pathlib) so they can be unit tested without the course venv, same as
     main/contract.py.
  2. The model's only job is judgement: which of those mechanically-found candidates
     belong together as one use case, and what to call it. It does that by calling
     the `submit_use_case` tool below — never by writing JSON prose.
  3. The tool's pydantic args_schema validates types, and _run() additionally
     rejects any entry_point or source_ref the model names that was not in the
     candidate lists it was given. A model cannot hallucinate a file into the
     output; it can only select from what stage 1's own scan actually found.
  4. Our Python code (not the model) accumulates validated tool calls and writes
     the final JSON. The model never touches serialization.

    # see exactly what the deterministic scan finds and what prompt the model would
    # get, without spending a token or needing the course venv
    python -m main.stage1_characterize --repo repo --dry-run

    # real run -> output/repo/use-cases.json and output/repo/characterization.json
    python -m main.stage1_characterize --repo repo
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
from typing import Any, Optional, Type

from langchain_core.callbacks.manager import CallbackManagerForToolRun
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

DEFAULT_MODEL_ID = "qwen.qwen3-coder-30b-a3b-v1:0"
DEFAULT_TEMPERATURE = 0.1
DEFAULT_TAXONOMY_PATH = pathlib.Path(__file__).parent / "auth_taxonomy.json"

SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", "coverage", "test", "tests", "spec", "__pycache__",
    # Juice-Shop-specific noise: these are CTF answer-key snippets, not real app code, and
    # match auth keywords heavily (e.g. loginAdminChallenge_*.ts) without being real evidence.
    "codefixes",
}
SOURCE_SUFFIXES = {".ts", ".js"}
MAX_SCANNED_FILE_BYTES = 200_000

# --- 1. dependency classification -------------------------------------------
#
# package.json tells you most of the auth architecture before you read a line of
# app code. A dependency listed here (main/auth_taxonomy.json) is 'curated' — we
# know exactly what role it plays. Anything else that merely LOOKS auth-related
# (matched by the keyword regex below) is 'heuristic' — flagged for the agent to
# check with the description tools rather than silently trusted or silently
# dropped.

HEURISTIC_PACKAGE_RE = re.compile(
    r"auth|jwt|oauth|saml|sso|session|passport|bcrypt|argon2|2fa|totp|login|crypt",
    re.IGNORECASE,
)


def load_taxonomy(path: pathlib.Path = DEFAULT_TAXONOMY_PATH) -> dict[str, str]:
    data = json.loads(path.read_text())
    return {k: v for k, v in data.items() if not k.startswith("_")}


def parse_manifest(package_json_path: pathlib.Path) -> dict[str, str]:
    """Merge dependencies, devDependencies, and peerDependencies into one map.

    All three matter: an auth library can legitimately sit in devDependencies
    (test fixtures) or peerDependencies (plugin architecture), not just prod deps.
    """
    data = json.loads(package_json_path.read_text())
    merged: dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        merged.update(data.get(key, {}))
    return merged


def classify_dependencies(
    deps: dict[str, str], taxonomy: dict[str, str]
) -> list[dict[str, str]]:
    """Tag each dependency 'curated' (known role) or 'heuristic' (name-shaped only)."""
    findings = []
    for name, version in sorted(deps.items()):
        if name in taxonomy:
            findings.append(
                {"name": name, "version": version, "category": taxonomy[name], "confidence": "curated"}
            )
        elif HEURISTIC_PACKAGE_RE.search(name):
            findings.append(
                {
                    "name": name,
                    "version": version,
                    "category": "unclassified-auth-candidate",
                    "confidence": "heuristic",
                }
            )
    return findings


# --- 2. route table -----------------------------------------------------------
#
# Express registers routes as app.METHOD('/path', ...handlers) or the same on a
# router instance. Matching that literally, rather than asking a model to read
# server.ts and summarize it, gets every route with zero hallucination risk.
# An array-of-paths call (app.get(['/a', '/b'], ...)) is matched on its first path
# — good enough for a candidate list; nothing downstream trusts this as exhaustive.

ROUTE_RE = re.compile(r"\b(?:app|router)\.(get|post|put|delete|patch|all)\s*\(\s*(?:\[\s*)?'([^']+)'")

AUTH_PATH_RE = re.compile(
    r"login|logout|auth|password|2fa|verify|security[-_]?question|user|token|credential|session",
    re.IGNORECASE,
)


def _iter_source_files(repo_path: pathlib.Path):
    for path in repo_path.rglob("*"):
        if path.is_dir():
            continue
        if path.suffix not in SOURCE_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name.endswith(".spec.ts") or path.name.endswith(".spec.js"):
            continue
        if path.stat().st_size > MAX_SCANNED_FILE_BYTES:
            continue
        yield path


def extract_routes(repo_path: pathlib.Path) -> list[dict[str, Any]]:
    """Every Express route in the repo: method, path, defining file, line number."""
    routes = []
    for path in _iter_source_files(repo_path):
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, start=1):
            for match in ROUTE_RE.finditer(line):
                routes.append(
                    {
                        "method": match.group(1).upper(),
                        "path": match.group(2),
                        "file": str(path.relative_to(repo_path)),
                        "line": line_no,
                    }
                )
    return routes


def filter_auth_routes(routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Narrow the full route table to auth-shaped candidates by path keyword."""
    return [r for r in routes if AUTH_PATH_RE.search(r["path"])]


# --- 3. candidate source files --------------------------------------------------
#
# Routes alone miss shared infrastructure a route handler calls into but doesn't
# define — e.g. Juice Shop's lib/insecurity.ts (JWT signing, password hashing,
# auth middleware) or models/user.ts. A keyword content scan catches those too.

AUTH_CONTENT_RE = re.compile(
    r"\bjwt\b|\bbcrypt\b|\bpassword\b|\b2fa\b|\btotp\b|\boauth\b|\bsession\b|"
    r"\blogin\b|\blogout\b|\bcredential\b|security[-_]?question",
    re.IGNORECASE,
)


def scan_candidate_files(repo_path: pathlib.Path) -> list[str]:
    """Relative paths of source files whose name or content look auth-related."""
    candidates: set[str] = set()
    for path in _iter_source_files(repo_path):
        rel = str(path.relative_to(repo_path))
        if AUTH_CONTENT_RE.search(rel):
            candidates.add(rel)
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if AUTH_CONTENT_RE.search(text):
            candidates.add(rel)
    return sorted(candidates)


# --- 4. the candidate bundle the model is allowed to see and select from -------


def build_candidates(repo_path: pathlib.Path, package_json_path: pathlib.Path) -> dict[str, Any]:
    deps = parse_manifest(package_json_path)
    taxonomy = load_taxonomy()
    routes = extract_routes(repo_path)
    return {
        "dependencies": classify_dependencies(deps, taxonomy),
        "auth_routes": filter_auth_routes(routes),
        "candidate_files": scan_candidate_files(repo_path),
    }


def render_candidates(candidates: dict[str, Any]) -> str:
    """Plain text the model reads as its ONLY source of truth for grouping."""
    lines = ["Auth-relevant dependencies:"]
    for dep in candidates["dependencies"]:
        lines.append(f"  - {dep['name']}@{dep['version']} ({dep['category']}, {dep['confidence']})")

    lines.append("\nCandidate routes (method + path -> defining file:line):")
    for route in candidates["auth_routes"]:
        lines.append(f"  - {route['method']} {route['path']} -> {route['file']}:{route['line']}")

    lines.append("\nCandidate source files:")
    for f in candidates["candidate_files"]:
        lines.append(f"  - {f}")

    return "\n".join(lines)


# --- 4b. app metadata for the characterization.json summary --------------------
#
# The "what does this app do" facts already exist in the repo — package.json's own
# description and the README — so read them directly instead of asking the model
# to explore and guess. The model's job here is condensing this excerpt into a
# short summary/goal, not discovering the facts themselves.

README_CANDIDATES = ("README.md", "Readme.md", "readme.md")
README_EXCERPT_MAX_CHARS = 20000


def read_app_metadata(package_json_path: pathlib.Path) -> dict[str, Any]:
    data = json.loads(package_json_path.read_text())
    return {
        "name": data.get("name", ""),
        "description": data.get("description", ""),
        "keywords": data.get("keywords", []),
    }


def read_readme_excerpt(repo_path: pathlib.Path, max_chars: int = README_EXCERPT_MAX_CHARS) -> str:
    for filename in README_CANDIDATES:
        path = repo_path / filename
        if path.exists():
            return path.read_text(errors="replace")[:max_chars]
    return ""


# --- 5. the validated tool: the model's only path to producing output ----------


class UseCaseStepInput(BaseModel):
    actor: str = Field(
        description="Who/what performs this step, e.g. 'Client', 'Login Handler', 'User Table'"
    )
    action: str = Field(
        description="One concrete sentence: what happens in this step, grounded in code you "
        "actually read — not guessed from a filename"
    )
    file: str = Field(
        default="",
        description="The file implementing this step, copied EXACTLY from source_refs. Leave "
        "empty only for a step with no server-side file (e.g. the client submitting input).",
    )


class SubmitUseCaseInput(BaseModel):
    id: str = Field(description="Stable id, format UC-<SHORT-NAME> e.g. UC-LOGIN")
    name: str = Field(description="Short human-readable use case name")
    entry_points: list[str] = Field(
        description="Route strings, each copied EXACTLY from the candidate route list "
        "as 'METHOD /path' — do not invent or reword one"
    )
    source_refs: list[str] = Field(
        description="File paths copied EXACTLY from the candidate file/route list — "
        "do not invent a path or guess one that wasn't shown to you"
    )
    steps: list[UseCaseStepInput] = Field(
        description="At least 2 steps, IN ORDER, tracing this use case from where user input "
        "enters (the client request) to where the data finally ends up — a database write, a "
        "response/cookie, an external call, whatever the real sink is. Read each cited file's "
        "actual content with your filesystem tools before describing its step; do not narrate "
        "a plausible-sounding step you didn't verify in the code."
    )


ID_RE = re.compile(r"^UC-[A-Z0-9-]+$")
MIN_STEPS = 2


def _render_description(steps: list[UseCaseStepInput]) -> str:
    """Build the final description text from validated steps — never from model prose."""
    lines = []
    for i, step in enumerate(steps, start=1):
        location = f" ({step.file})" if step.file else ""
        lines.append(f"{i}. {step.actor}: {step.action}{location}")
    return "\n".join(lines)


class SubmitUseCaseTool(BaseTool): 
    """Records one use case — but only if every field passes deterministic checks.

    allowed_entry_points / allowed_source_refs are the exact candidate strings this
    run's deterministic scan produced. A call naming anything outside those sets —
    including a step's `file` — is rejected, and the tool returns the validation
    errors so the agent can retry with a real candidate instead of a plausible-
    looking invention. The final `description` text is assembled by
    _render_description from the validated steps, never taken from the model as a
    free-text field, so its precision is bounded by what the model was willing to
    cite rather than what it was willing to claim.
    """

    name: str = "submit_use_case"
    description: str = (
        "Record one authentication use case, with an ordered step-by-step trace from "
        "user input to the sink. entry_points, source_refs, and every step's file MUST "
        "be copied verbatim from the candidate lists you were given — this call is "
        "rejected otherwise."
    )
    args_schema: Type[SubmitUseCaseInput] = SubmitUseCaseInput

    allowed_entry_points: set[str] = Field(default_factory=set)
    allowed_source_refs: set[str] = Field(default_factory=set)
    accepted: list[dict[str, Any]] = Field(default_factory=list)
    seen_ids: set[str] = Field(default_factory=set)

    def _run(
        self,
        id: str,
        name: str,
        entry_points: list[str],
        source_refs: list[str],
        steps: list[UseCaseStepInput],
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        errors = []

        if not ID_RE.match(id):
            errors.append(f"id {id!r} must match UC-<SHORT-NAME> (uppercase, digits, hyphens)")
        if id in self.seen_ids:
            errors.append(f"id {id!r} was already submitted")

        unknown_entry_points = [e for e in entry_points if e not in self.allowed_entry_points]
        if unknown_entry_points:
            errors.append(
                f"entry_points {unknown_entry_points!r} are not in the candidate route list — "
                "copy an exact 'METHOD /path' string from the candidates instead"
            )

        unknown_source_refs = [s for s in source_refs if s not in self.allowed_source_refs]
        if unknown_source_refs:
            errors.append(
                f"source_refs {unknown_source_refs!r} are not in the candidate file list — "
                "copy an exact path from the candidates instead"
            )

        if len(steps) < MIN_STEPS:
            errors.append(f"steps must have at least {MIN_STEPS} entries — this isn't a trace yet")

        unknown_step_files = [s.file for s in steps if s.file and s.file not in self.allowed_source_refs]
        if unknown_step_files:
            errors.append(
                f"step file(s) {unknown_step_files!r} are not in the candidate file list — "
                "copy an exact path from the candidates instead, or leave file empty"
            )

        empty_actions = [i + 1 for i, s in enumerate(steps) if not s.action.strip()]
        if empty_actions:
            errors.append(f"step(s) {empty_actions!r} have an empty action")

        if errors:
            return json.dumps({"accepted": False, "errors": errors})

        self.seen_ids.add(id)
        self.accepted.append(
            {
                "id": id,
                "name": name,
                "description": _render_description(steps),
                "entry_points": entry_points,
                "source_refs": source_refs,
            }
        )
        return json.dumps({"accepted": True, "id": id})


class SubmitCharacterizationInput(BaseModel):
    app_name: str = Field(description="The application's name, from package.json")
    summary: str = Field(description="2-4 sentences: what the application does")
    goal: str = Field(description="1-2 sentences: what this application is FOR (its purpose)")


class SubmitCharacterizationTool(BaseTool):
    """Records the single general-description artifact for the whole app.

    No candidate whitelist here — there's no file path to hallucinate, since
    summary/goal are prose grounded in the package.json/README excerpt already put
    in the prompt. What stays deterministic is the JSON shape: this tool's schema
    fixes the exact three keys, call count is capped at one, and Python (not the
    model) writes the file — same rule as SubmitUseCaseTool, applied to a single
    call instead of a per-use-case loop.
    """

    name: str = "submit_characterization"
    description: str = (
        "Record the application's general description. Call this exactly once, "
        "based only on the package.json/README excerpt you were given."
    )
    args_schema: Type[SubmitCharacterizationInput] = SubmitCharacterizationInput

    accepted: Optional[dict[str, Any]] = None

    def _run(
        self,
        app_name: str,
        summary: str,
        goal: str,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        errors = []
        if not app_name.strip():
            errors.append("app_name must not be empty")
        if not summary.strip():
            errors.append("summary must not be empty")
        if not goal.strip():
            errors.append("goal must not be empty")
        if self.accepted is not None:
            errors.append("submit_characterization was already called once — only one call is kept")

        if errors:
            return json.dumps({"accepted": False, "errors": errors})

        self.accepted = {"app_name": app_name, "summary": summary, "goal": goal}
        return json.dumps({"accepted": True})


class SubmitDependencyReviewInput(BaseModel):
    name: str = Field(description="Dependency name, copied EXACTLY from the heuristic dependency list")
    is_auth_related: bool = Field(description="True only if the package's real description confirms an auth role")
    category: str = Field(
        default="",
        description="Short category label if is_auth_related is True (e.g. 'password-hashing'); leave empty otherwise",
    )
    reasoning: str = Field(description="1 sentence citing what the package's own description actually said")


class SubmitDependencyReviewTool(BaseTool):
    """Records one confirm/reject verdict for a dependency flagged 'heuristic'.

    allowed_names is the exact set of heuristic-confidence dependency names from
    this run — same anti-hallucination guardrail as SubmitUseCaseTool, applied to
    dependency names. A non-empty reasoning is required so a verdict that skipped
    the actual lookup is at least visible on inspection, even though the tool
    can't force the model to have called the lookup tool first.
    """

    name: str = "submit_dependency_review"
    description: str = (
        "Record whether a package flagged 'heuristic' is genuinely auth-related. "
        "Look it up with local_package_description or registry_package_description "
        "first — do not guess from the name alone. name MUST be copied verbatim "
        "from the heuristic dependency list."
    )
    args_schema: Type[SubmitDependencyReviewInput] = SubmitDependencyReviewInput

    allowed_names: set[str] = Field(default_factory=set)
    accepted: list[dict[str, Any]] = Field(default_factory=list)
    reviewed_names: set[str] = Field(default_factory=set)

    def _run(
        self,
        name: str,
        is_auth_related: bool,
        category: str = "",
        reasoning: str = "",
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        errors = []
        if name not in self.allowed_names:
            errors.append(f"{name!r} is not in the heuristic dependency list — copy a name from it exactly")
        if name in self.reviewed_names:
            errors.append(f"{name!r} was already reviewed")
        if is_auth_related and not category.strip():
            errors.append("category must not be empty when is_auth_related is true")
        if not reasoning.strip():
            errors.append("reasoning must not be empty — cite what the package's own description said")

        if errors:
            return json.dumps({"accepted": False, "errors": errors})

        self.reviewed_names.add(name)
        self.accepted.append(
            {
                "name": name,
                "is_auth_related": is_auth_related,
                "category": category if is_auth_related else "",
                "reasoning": reasoning,
            }
        )
        return json.dumps({"accepted": True, "name": name})


# --- 6. orchestration (imports the agent stack lazily, like stage3_stride.py) ---


def build_agent(repo_path: pathlib.Path, tools: list, model_id: str, temperature: float):
    from deepagents import create_deep_agent
    from deepagents.backends import FilesystemBackend
    from dotenv import load_dotenv
    from langchain_aws import ChatBedrockConverse

    from main.package_description_tools import (
        LocalPackageDescriptionTool,
        RegistryPackageDescriptionTool,
    )

    load_dotenv()  # AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION from .env

    system_prompt = """You are characterizing an application's authentication surface.

You have three tools. Call them in this order:

1. submit_characterization — exactly once. Read the package.json description and
   README excerpt you were given and condense them into app_name/summary/goal.
   Do not explore the filesystem for this; use only the excerpt in the prompt.

2. submit_dependency_review — once per dependency listed as 'heuristic' (its name
   only matched a keyword; its role is unconfirmed). Before calling it, look the
   package up with local_package_description or registry_package_description —
   do not guess from the name alone. Confirm or reject whether it is really
   auth-related, citing what the description actually said. Skip this step
   entirely if there are no heuristic dependencies.

3. submit_use_case — once per authentication use case. You are given a fixed,
   already-extracted list of candidate dependencies, routes, and source files.
   You must not name a route or file that isn't in that list. GROUP the candidates
   into coherent use cases (login, registration, password reset, MFA, OAuth,
   logout, session refresh, etc. — only ones actually evidenced by the
   candidates). Use your step-2 verdicts to decide whether an unverified
   dependency should factor into a use case at all.

   For each use case's `steps`, you MUST actually open and read the candidate
   files involved with your filesystem tools before describing them — read the
   route handler, follow what it calls into, and trace the data to wherever it
   really ends up (a database write, a response header/cookie, an external call).
   Write each step from what the code actually does, not from what a file with
   that name would plausibly do. A step you cannot verify by reading real code is
   a step you leave out.

Do not write a final JSON summary yourself. Your only output channels are the
three tool calls above."""

    return create_deep_agent(
        model=ChatBedrockConverse(model_id=model_id, temperature=temperature),
        tools=[*tools, LocalPackageDescriptionTool(), RegistryPackageDescriptionTool()],
        backend=FilesystemBackend(root_dir=str(repo_path), virtual_mode=False),
        system_prompt=system_prompt,
    )


def characterize(
    repo_path: pathlib.Path,
    package_json_path: pathlib.Path,
    model_id: str = DEFAULT_MODEL_ID,
    temperature: float = DEFAULT_TEMPERATURE,
) -> dict[str, Any]:
    candidates = build_candidates(repo_path, package_json_path)
    metadata = read_app_metadata(package_json_path)
    readme_excerpt = read_readme_excerpt(repo_path)

    heuristic_names = {d["name"] for d in candidates["dependencies"] if d["confidence"] == "heuristic"}

    use_case_tool = SubmitUseCaseTool(
        allowed_entry_points={f"{r['method']} {r['path']}" for r in candidates["auth_routes"]},
        allowed_source_refs=set(candidates["candidate_files"]) | {r["file"] for r in candidates["auth_routes"]},
    )
    characterization_tool = SubmitCharacterizationTool()
    dependency_review_tool = SubmitDependencyReviewTool(allowed_names=heuristic_names)

    tools = [use_case_tool, characterization_tool, dependency_review_tool]
    agent = build_agent(repo_path, tools, model_id, temperature)

    heuristic_instruction = (
        f"\n\nUnverified ('heuristic') dependencies to review before grouping: {', '.join(sorted(heuristic_names))}"
        if heuristic_names
        else "\n\n(No 'heuristic' dependencies this run — skip submit_dependency_review.)"
    )
    task = (
        "package.json metadata:\n"
        f"  name: {metadata['name']}\n"
        f"  description: {metadata['description']}\n"
        f"  keywords: {', '.join(metadata['keywords'])}\n\n"
        + (f"README excerpt:\n{readme_excerpt}\n\n" if readme_excerpt else "(no README found)\n\n")
        + "Candidates (the ONLY facts you may reference for use cases):\n\n"
        + render_candidates(candidates)
        + heuristic_instruction
        + "\n\nFirst call submit_characterization once. Then review any heuristic dependencies. "
        "Then call submit_use_case once per authentication use case."
    )
    agent.invoke({"messages": [{"role": "user", "content": task}]})

    # All three final JSON files are built here, from validated tool calls — never from agent prose.
    return {
        "use_cases": {"use_cases": use_case_tool.accepted},
        "characterization": characterization_tool.accepted or {},
        "dependency_review": dependency_review_tool.accepted,
    }


# --- CLI, mirrors main/stage3_stride.py ----------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage 1 — characterize an app's authentication surface.")
    parser.add_argument("--repo", type=pathlib.Path, required=True, help="target application clone")
    parser.add_argument("--package-json", type=pathlib.Path, help="defaults to <repo>/package.json")
    parser.add_argument(
        "--out-dir",
        type=pathlib.Path,
        default=None,
        help="defaults to output/<owner>/<repo>/ from the target's git remote, "
        "so each target app gets its own folder",
    )
    parser.add_argument("--model-id", default=DEFAULT_MODEL_ID)
    parser.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)
    parser.add_argument(
        "--dry-run", action="store_true", help="print the deterministic scan and the exact model prompt, call nothing"
    )
    args = parser.parse_args(argv)

    if args.out_dir is None:
        # Namespaced by the repository being scanned, not the local clone directory,
        # which is whatever the person cloning happened to type. main.py derives the
        # same path, so standalone and orchestrated runs land in the same place.
        from main.target import output_dir

        args.out_dir = output_dir(args.repo)

    package_json_path = args.package_json or (args.repo / "package.json")
    candidates = build_candidates(args.repo, package_json_path)

    if args.dry_run:
        print(render_candidates(candidates))
        return 0

    result = characterize(args.repo, package_json_path, args.model_id, args.temperature)
    use_cases_doc = result["use_cases"]  # {"use_cases": [...]} — the contract stage3_stride.py reads
    characterization_doc = result["characterization"]
    dependency_review_doc = {"dependency_review": result["dependency_review"]}

    args.out_dir.mkdir(parents=True, exist_ok=True)

    characterization_path = args.out_dir / "characterization.json"
    characterization_path.write_text(json.dumps(characterization_doc, indent=2) + "\n")

    dependency_review_path = args.out_dir / "dependency-review.json"
    dependency_review_path.write_text(json.dumps(dependency_review_doc, indent=2) + "\n")

    use_cases_path = args.out_dir / "use-cases.json"
    use_cases_path.write_text(json.dumps(use_cases_doc, indent=2) + "\n")

    # One file per use case too, same review/diff convenience as stage3_stride.py's
    # per-call cache files — but use-cases.json above remains the file stage 3 reads.
    use_cases_dir = args.out_dir / "use-cases"
    use_cases_dir.mkdir(parents=True, exist_ok=True)
    for use_case in use_cases_doc["use_cases"]:
        (use_cases_dir / f"{use_case['id']}.json").write_text(json.dumps(use_case, indent=2) + "\n")

    print(f"{len(use_cases_doc['use_cases'])} use case(s) -> {use_cases_path} and {use_cases_dir}/<id>.json")
    print(f"characterization -> {characterization_path}")
    print(f"dependency review -> {dependency_review_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
