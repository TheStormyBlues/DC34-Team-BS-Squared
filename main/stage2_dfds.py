"""Stage 2 — data flow diagrams.

Two chained phases, each an orchestrator that fans out to one subagent per file:

    <output>/use-cases/<id>.json   stage 1
        -> data-flow-diagram-builder, one call per use case
    <output>/graphs/<id>.json      a typed node/edge graph
        -> mermaid-dfd-builder, one call per graph
    <output>/dfds/<id>.mmd         what stage 3 reads

The intermediate graph JSON is worth keeping: it is the structured form, so the
rendering step is a mechanical transformation that can be checked — and re-done
deterministically when the model gets it wrong.

    python -m main.stage2_dfds --dry-run             # what would run, no model calls
    python -m main.stage2_dfds --output output/juice-shop
    python -m main.stage2_dfds --output output/juice-shop --force

Node shape in the rendered Mermaid carries the element type, and stage 3 depends on
it: `[Name]` external entity, `(Name)` process, `[(Name)]` data store. Every generated
diagram is parsed back before the stage exits; one that did not come out right is
re-rendered from its graph JSON by render_mermaid() below rather than left to degrade
stage 3 silently.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any

from main.mermaid import parse_mermaid

DEFAULT_MODEL_ID = "qwen.qwen3-coder-30b-a3b-v1:0"
DEFAULT_TEMPERATURE = 0.6

USE_CASE_DIR = "/use-cases"
GRAPH_DIR = "/graphs"
MERMAID_DIR = "/dfds"

SHAPE = {
    "external_entity": "{id}[{name}]",
    "process": "{id}({name})",
    "data_store": "{id}[({name})]",
}


# ---------------------------------------------------------------------------
# DFD builder subagent
# ---------------------------------------------------------------------------

dfd_builder_prompt = """You are given ONE use case from a JSON file.

### Task

1. Read and understand the supplied use case.
2. Convert it into a data flow diagram.
3. Nodes must be exactly one of:
   - external_entity: user, client, browser, or external service
   - process: application logic that receives, validates, transforms, or routes data
   - data_store: persistent system state
4. Create directional edges describing the data or relationship flowing between nodes.
5. Credentials, tokens, codes, and request data belong on edges, not as nodes.
6. Where the use case's `source_refs` or a step's `file` names the file that implements
   a node, copy that path verbatim into that node's `file`. Leave `file` out when the
   use case does not say — never guess a path.
7. Write the completed graph to the exact JSON output path supplied by the parent.

### Output Format

{
  "use_case_id": "(str)",
  "name": "(str)",
  "nodes": [
    {
      "id": "(str)",
      "type": "external_entity | process | data_store",
      "name": "(str)",
      "file": "(optional str, copied verbatim from the use case)"
    }
  ],
  "edges": [
    {
      "from": "(node id)",
      "to": "(node id)",
      "description": "(str)"
    }
  ]
}

Every edge must reference existing nodes. Keep the graph concise and only model
what is stated or directly implied by the use case.
"""

dfd_builder_subagent_base = {
    "name": "data-flow-diagram-builder",
    "description": (
        "Converts one use case into a JSON data flow diagram containing external "
        "entities, processes, data stores, and directional relationship edges. "
        "Use once per use-case file and write the result to the requested JSON path."
    ),
    "system_prompt": dfd_builder_prompt,
    "tools": [],
}


graph_orchestrator_prompt = f"""You orchestrate data flow diagram generation.

### Task

1. List every `.json` file directly inside `{USE_CASE_DIR}`.
2. Create `{GRAPH_DIR}` if required.
3. For EACH use-case file:
   - Read the complete JSON object.
   - Invoke `data-flow-diagram-builder` exactly once.
   - Pass it the complete use case and an output path of:
     `{GRAPH_DIR}/<original-file-stem>.json`
4. Every use case must be processed independently.
5. Do not generate, edit, merge, or reinterpret graphs yourself.
6. Verify that one graph JSON file exists for every input use-case file.

Process all files even if one fails. Report failed files after processing the rest.
"""


# ---------------------------------------------------------------------------
# Mermaid renderer subagent
# ---------------------------------------------------------------------------

mermaid_builder_prompt = """You are given ONE data flow diagram JSON file.

### Task

1. Read the supplied graph JSON.
2. Convert every node into Mermaid flowchart syntax using these shapes:

   external_entity:
       CUST[Customer]

   process:
       LOGIN(Login Handler)

   data_store:
       USERS[(User Table)]

3. Convert every edge into:
       SOURCE -->|relationship description| TARGET

4. Preserve node IDs, node names, direction, and edge descriptions exactly.
5. Write the result to the exact `.mmd` output path supplied by the parent.

### Output Format

flowchart LR
    CUST[Customer]
    LOGIN(Login Handler)
    USERS[(User Table)]

    CUST -->|Submits email and password| LOGIN
    LOGIN -->|Queries user by email| USERS
    USERS -->|Returns user record| LOGIN

The node shape is not decoration — it is how the next stage knows whether a box is a
process or a data store, so use exactly the three shapes above and no others.

Return a valid Mermaid flowchart. Do not add nodes or relationships that do not
exist in the graph JSON.
"""

mermaid_builder_subagent_base = {
    "name": "mermaid-dfd-builder",
    "description": (
        "Reads one JSON data flow diagram and converts it into a corresponding "
        "Mermaid .mmd flowchart using the required external entity, process, "
        "and data store node shapes."
    ),
    "system_prompt": mermaid_builder_prompt,
    "tools": [],
}


mermaid_orchestrator_prompt = f"""You orchestrate Mermaid DFD generation.

### Task

1. List every `.json` file directly inside `{GRAPH_DIR}`.
2. Create `{MERMAID_DIR}` if required.
3. For EACH graph JSON file:
   - Invoke `mermaid-dfd-builder` exactly once.
   - Pass it the graph JSON file path.
   - Give it an output path of:
     `{MERMAID_DIR}/<original-file-stem>.mmd`
4. Every graph must be processed independently.
5. Do not create, edit, or reinterpret Mermaid diagrams yourself.
6. Verify that one `.mmd` file exists for every graph JSON file.

Process all files even if one fails. Report failed files after processing the rest.
"""


# ---------------------------------------------------------------------------
# Deterministic rendering — the safety net under the mermaid subagent
# ---------------------------------------------------------------------------

_ID_RE = re.compile(r"[^A-Za-z0-9_]")


def _node_id(raw: str, index: int) -> str:
    """Mermaid node ids are bare words; make one that cannot break the syntax."""
    cleaned = _ID_RE.sub("_", str(raw or "")).strip("_")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = f"N{index}_{cleaned}".rstrip("_")
    return cleaned


def _label(raw: str) -> str:
    """Brackets and pipes inside a label break the diagram."""
    return re.sub(r"[\[\]\(\)\{\}|]", " ", str(raw or "")).strip() or "unnamed"


def render_mermaid(graph: dict[str, Any]) -> str:
    """Render a graph JSON to Mermaid — the same shapes the subagent is asked for.

    Used to repair a diagram the subagent got wrong, and to append the `%% file:`
    hints, which the graph carries per node but Mermaid has nowhere to put.
    """
    lines = ["flowchart LR"]
    ids: dict[str, str] = {}

    for index, node in enumerate(graph.get("nodes") or []):
        node_type = node.get("type")
        if node_type not in SHAPE:
            continue
        ident = _node_id(node.get("id") or node.get("name"), index)
        ids[str(node.get("id"))] = ident
        lines.append("  " + SHAPE[node_type].format(id=ident, name=_label(node.get("name"))))

    hints = [
        f"  %% file: {ids[str(n.get('id'))]} {n['file']}"
        for n in (graph.get("nodes") or [])
        if n.get("file") and str(n.get("id")) in ids
    ]
    if hints:
        lines += ["", *hints]

    edges = []
    for edge in graph.get("edges") or []:
        source, target = ids.get(str(edge.get("from"))), ids.get(str(edge.get("to")))
        if not source or not target:
            continue  # an edge to a node that was never declared would break the parse
        description = _label(edge.get("description"))
        edges.append(f"  {source} -->|{description}| {target}" if description else f"  {source} --> {target}")
    if edges:
        lines += ["", *edges]

    return "\n".join(lines) + "\n"


def add_file_hints(diagram: str, graph: dict[str, Any]) -> str:
    """Append `%% file:` lines for graph nodes whose file the diagram does not mention."""
    existing = set(re.findall(r"^\s*%%\s*file:\s*(\S+)", diagram, re.M | re.I))
    declared = {m.group(1) for m in re.finditer(r"(?<![A-Za-z0-9_])([A-Za-z0-9_-]+)\s*[\[({]", diagram)}

    additions = []
    for node in graph.get("nodes") or []:
        ident = str(node.get("id") or "")
        if node.get("file") and ident in declared and ident not in existing:
            additions.append(f"%% file: {ident} {node['file']}")
    if not additions:
        return diagram
    return diagram.rstrip("\n") + "\n\n" + "\n".join(additions) + "\n"


def verify_and_repair(output_root: pathlib.Path) -> list[str]:
    """Parse every generated diagram; repair the ones that did not come out right.

    Stage 3 reads element types out of node shape, so a diagram the parser cannot
    read costs findings silently. Repair is possible because the graph JSON is the
    structured source — rendering it is mechanical.
    """
    graphs_dir = output_root / "graphs"
    dfds_dir = output_root / "dfds"
    dfds_dir.mkdir(parents=True, exist_ok=True)
    notes: list[str] = []

    for graph_path in sorted(graphs_dir.glob("*.json")) if graphs_dir.is_dir() else []:
        if graph_path.name.startswith("_"):
            continue
        try:
            graph = json.loads(graph_path.read_text())
        except json.JSONDecodeError as exc:
            notes.append(f"{graph_path.name}: unreadable graph JSON ({exc}) — skipped")
            continue

        diagram_path = dfds_dir / f"{graph_path.stem}.mmd"
        rendered_here = False

        if not diagram_path.exists():
            diagram_path.write_text(render_mermaid(graph))
            notes.append(f"{diagram_path.name}: was not produced — rendered from the graph JSON")
            rendered_here = True
        else:
            parsed = parse_mermaid(diagram_path.read_text())
            broken = (
                not (parsed["external_entities"] or parsed["processes"] or parsed["data_stores"])
                or any("did not follow the shape convention" in w for w in parsed["warnings"])
            )
            if broken:
                diagram_path.write_text(render_mermaid(graph))
                notes.append(f"{diagram_path.name}: shapes were wrong — re-rendered from the graph JSON")
                rendered_here = True

        if not rendered_here:
            with_hints = add_file_hints(diagram_path.read_text(), graph)
            if with_hints != diagram_path.read_text():
                diagram_path.write_text(with_hints)

        final = parse_mermaid(diagram_path.read_text())
        for warning in final["warnings"]:
            notes.append(f"{diagram_path.name}: {warning}")

    return notes


# ---------------------------------------------------------------------------
# Agents — built lazily so --dry-run and --help work without the course venv
# ---------------------------------------------------------------------------


def build_orchestrators(output_root: pathlib.Path, model_id: str, temperature: float, region: str | None):
    from deepagents import create_deep_agent
    from deepagents.backends import FilesystemBackend
    from dotenv import load_dotenv
    from langchain_aws import ChatBedrockConverse

    load_dotenv()

    kwargs: dict[str, Any] = {"model_id": model_id, "temperature": temperature}
    if region:  # otherwise AWS_DEFAULT_REGION from .env applies
        kwargs["region_name"] = region
    model = ChatBedrockConverse(**kwargs)

    backend = FilesystemBackend(root_dir=str(output_root.resolve()), virtual_mode=True)

    graph_orchestrator = create_deep_agent(
        model=model,
        backend=backend,
        system_prompt=graph_orchestrator_prompt,
        subagents=[{**dfd_builder_subagent_base, "model": model}],
        name="dfd-orchestrator",
    )
    mermaid_orchestrator = create_deep_agent(
        model=model,
        backend=backend,
        system_prompt=mermaid_orchestrator_prompt,
        subagents=[{**mermaid_builder_subagent_base, "model": model}],
        name="mermaid-orchestrator",
    )
    return graph_orchestrator, mermaid_orchestrator


def generate_dfds(
    output_root: pathlib.Path,
    model_id: str = DEFAULT_MODEL_ID,
    temperature: float = DEFAULT_TEMPERATURE,
    region: str | None = None,
) -> dict[str, Any]:
    """use-cases/*.json -> graphs/*.json -> dfds/*.mmd"""
    graph_orchestrator, mermaid_orchestrator = build_orchestrators(
        output_root, model_id, temperature, region
    )

    graph_result = graph_orchestrator.invoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": (
                        f"Process every use case in {USE_CASE_DIR} and generate "
                        f"the corresponding graph JSON files in {GRAPH_DIR}."
                    ),
                }
            ]
        }
    )

    mermaid_result = mermaid_orchestrator.invoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": (
                        f"Process every graph in {GRAPH_DIR} and generate "
                        f"the corresponding Mermaid files in {MERMAID_DIR}."
                    ),
                }
            ]
        }
    )

    return {"graph_generation": graph_result, "mermaid_generation": mermaid_result}


# ---------------------------------------------------------------------------
# CLI, mirroring the other stages
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage 2 — build a data flow diagram per use case.")
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("output"),
                        help="output root for this target, e.g. output/juice-shop")
    parser.add_argument("--repo", type=pathlib.Path, help="target clone (unused; accepted for pipeline symmetry)")
    parser.add_argument("--model-id", default=DEFAULT_MODEL_ID)
    parser.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)
    parser.add_argument("--region", help="AWS region (default: AWS_DEFAULT_REGION from .env)")
    parser.add_argument("--force", action="store_true", help="regenerate diagrams that already exist")
    parser.add_argument("--dry-run", action="store_true", help="list the work, call nothing")
    args = parser.parse_args(argv)

    use_cases_dir = args.output / "use-cases"
    if not use_cases_dir.is_dir():
        raise SystemExit(f"no use cases at {use_cases_dir} — has stage 1 run?")

    use_cases = [p for p in sorted(use_cases_dir.glob("*.json")) if not p.name.startswith("_")]
    if not use_cases:
        raise SystemExit(f"no use cases found in {use_cases_dir}")

    dfds_dir = args.output / "dfds"
    pending = [p for p in use_cases if args.force or not (dfds_dir / f"{p.stem}.mmd").exists()]

    if args.dry_run:
        print(f"use cases in {use_cases_dir}:")
        for path in use_cases:
            state = "would generate" if path in pending else "already has a diagram"
            print(f"  {path.stem:<28} {state}")
        print(f"\nwould write {args.output / 'graphs'}/<id>.json then {dfds_dir}/<id>.mmd")
        print(f"model {args.model_id}, temperature {args.temperature}")
        return 0

    if not pending:
        print(f"all {len(use_cases)} use case(s) already have a diagram (use --force to regenerate)")
    else:
        print(f"generating diagrams for {len(pending)} of {len(use_cases)} use case(s)", flush=True)
        generate_dfds(args.output, args.model_id, args.temperature, args.region)

    # The subagent writes prose that must parse as a diagram; check it, and fall back
    # to deterministic rendering where it did not.
    notes = verify_and_repair(args.output)
    for note in notes:
        print(f"  {note}", file=sys.stderr)

    produced = sorted(p for p in dfds_dir.glob("*.mmd") if not p.name.startswith("_"))
    print(f"{len(produced)} diagram(s) -> {dfds_dir}")
    missing = [p.stem for p in use_cases if not (dfds_dir / f"{p.stem}.mmd").exists()]
    if missing:
        print(f"no diagram for: {', '.join(missing)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
