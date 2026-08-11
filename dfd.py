
from langchain_aws import ChatBedrockConverse
from deepagents.backends import FilesystemBackend
from deepagents import create_deep_agent
from dotenv import load_dotenv

import os
from pathlib import Path


# ---------------------------------------------------------------------------
# Paths / model
# ---------------------------------------------------------------------------

ROOT_DIR = Path("./output/juice-shop").resolve()

USE_CASE_DIR = "/use-cases"
GRAPH_DIR = "/graphs"
MERMAID_DIR = "/mermaid"

load_dotenv()

subagent_llm = ChatBedrockConverse(
    model_id="qwen.qwen3-coder-30b-a3b-v1:0",
    region_name="us-east-1",
    temperature=0.6,
)


model = subagent_llm

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
6. Write the completed graph to the exact JSON output path supplied by the parent.

### Output Format

{
  "use_case_id": "(str)",
  "name": "(str)",
  "nodes": [
    {
      "id": "(str)",
      "type": "external_entity | process | data_store",
      "name": "(str)"
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

dfd_builder_subagent = {
    "name": "data-flow-diagram-builder",
    "description": (
        "Converts one use case into a JSON data flow diagram containing external "
        "entities, processes, data stores, and directional relationship edges. "
        "Use once per use-case file and write the result to the requested JSON path."
    ),
    "system_prompt": dfd_builder_prompt,
    "tools": [],
    "model": model,
}


# ---------------------------------------------------------------------------
# Phase 1 orchestrator
# ---------------------------------------------------------------------------

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

backend = FilesystemBackend(
    root_dir=str(ROOT_DIR),
    virtual_mode=True,
)

graph_orchestrator = create_deep_agent(
    model=model,
    backend=backend,
    system_prompt=graph_orchestrator_prompt,
    subagents=[dfd_builder_subagent],
    name="dfd-orchestrator",
)


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

Return a valid Mermaid flowchart. Do not add nodes or relationships that do not
exist in the graph JSON.
"""

mermaid_builder_subagent = {
    "name": "mermaid-dfd-builder",
    "description": (
        "Reads one JSON data flow diagram and converts it into a corresponding "
        "Mermaid .mmd flowchart using the required external entity, process, "
        "and data store node shapes."
    ),
    "system_prompt": mermaid_builder_prompt,
    "tools": [],
    "model": model,
}


# ---------------------------------------------------------------------------
# Phase 2 orchestrator
# ---------------------------------------------------------------------------

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

mermaid_orchestrator = create_deep_agent(
    model=model,
    backend=backend,
    system_prompt=mermaid_orchestrator_prompt,
    subagents=[mermaid_builder_subagent],
    name="mermaid-orchestrator",
)


# ---------------------------------------------------------------------------
# Chain
# ---------------------------------------------------------------------------

def generate_dfds():
    """
    use_cases/*.json
        -> one DFD-builder subagent per file
        -> graphs/*.json
        -> one Mermaid-builder subagent per graph
        -> mermaid/*.mmd
    """

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

    return {
        "graph_generation": graph_result,
        "mermaid_generation": mermaid_result,
    }


if __name__ == "__main__":
    generate_dfds()