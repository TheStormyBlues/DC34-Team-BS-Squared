
from langchain_aws import ChatBedrockConverse
from deepagents.backends import FilesystemBackend
from deepagents import create_deep_agent

import os

dfd_builder_prompt = """You are given ONE software use case describing a specific authentication
or authorization flow, including its description, entry points, and source references.

### Task

1. Identify the nodes involved in the use case.
2. Classify each node as exactly one of:
   - external_entity: user, client, browser, external service, or identity provider
   - process: application logic that receives, validates, transforms, or routes data
   - data_store: persistent system state such as users, sessions, API keys, or tokens
3. Create directional edges between nodes describing the data or relationship flowing
   between them. Put credentials, tokens, codes, and request data on edges, not as nodes.
4. Model only what is stated or directly implied by this single use case.

### Output Format

Return valid JSON only:

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
      "description": "(str) data or relationship between the nodes"
    }
  ]
}

Every edge must reference existing nodes. Do not create nodes for credentials, tokens,
routes, or source files. Keep the diagram concise and focused on this one use case.
"""
subagent_llm = ChatBedrockConverse(
    model_id="qwen.qwen3-coder-30b-a3b-v1:0",
    region_name="us-east-1",
    temperature=0.6,
)

subagents = [
    {
        "name": "data-flow-diagram-builder",
        # The description tells the parent agent when this subagent should be invoked
        "description": (
            "Converts one authentication or authorization use case into a concise JSON data flow "
            "diagram containing external entities, processes, data stores, and directional edges. "
            "Delegate each use case to a separate call so every flow is modeled independently."
        ),
        "system_prompt": dfd_builder_prompt,
        "tools": [],
        "model": subagent_llm,
    },
]

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

backend=FilesystemBackend(root_dir="../output/test-use-cases.json", virtual_mode=True),


dfd_orchestrator_prompt = """You are given a JSON file containing multiple software use cases.
Your job is to orchestrate generation of a data flow diagram for every use case.

### Task

1. Read the JSON file and extract every object in the `use_cases` array.
2. For EACH use case, invoke the `data-flow-diagram-builder` subagent exactly once,
   passing the complete use case object unchanged.
3. Keep use cases independent. Never combine multiple use cases into one subagent call.
4. Collect each returned DFD and preserve its corresponding use case ID.
5. Do not generate or modify DFD nodes or edges yourself. The subagent is responsible
   for interpreting each use case and generating its graph.
6. If one use case fails, continue processing the remaining use cases and record the error.

### Output Format

Return valid JSON only:

{
  "graphs": [
    {
      "use_case_id": "(str)",
      "name": "(str)",
      "nodes": [...],
      "edges": [...]
    }
  ],
  "errors": [
    {
      "use_case_id": "(str)",
      "error": "(str)"
    }
  ]
}

Return one graph for every successfully processed use case. Do not add commentary,
merge graphs, or infer relationships between separate use cases.
"""



llm = ChatBedrockConverse(
    model_id="us.anthropic.claude-haiku-4-5-20251001-v1:0",
    region_name="us-east-1",
    # model_id="qwen.qwen3-coder-30b-a3b-v1:0",
    temperature=0.6,
)

subagents = [
{
"name": "data-flow-diagram-orchestrator",
"description": (
"Reads a JSON file containing multiple software use cases and delegates each use case "
"independently to the data-flow-diagram-builder subagent. Collects the resulting JSON "
"graphs into a single response while preserving use case IDs and reporting failures."
),
"system_prompt": dfd_orchestrator_prompt,
"model": llm,
},
]



dfd_agent = create_deep_agent(
    model=llm,
    system_prompt=dfd_orchestrator_prompt,
    subagents=subagents,
    backend=backend
)

