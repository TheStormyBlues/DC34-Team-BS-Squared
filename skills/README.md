# STRIDE Skills — Authentication Scope

Six skills, one per STRIDE letter, each scoped to **authentication use cases**. They are the
third stage of the pipeline: stage 1 characterizes the app and produces use cases, stage 2
produces a data flow diagram per use case, and these skills turn each DFD into threats.

## How to invoke

Run **one agent call per skill per use case**. Do not hand a single agent all six skills and
ask for "a STRIDE analysis" — the model will cover Spoofing and Information Disclosure well
and give Repudiation a token paragraph. Coverage should be guaranteed by the loop, not left
to the model's judgement.

```python
from deepagents import create_deep_agent
from deepagents.backends import FilesystemBackend
from langchain_aws import ChatBedrockConverse

LETTERS = [
    ("S", "stride-spoofing"),
    ("T", "stride-tampering"),
    ("R", "stride-repudiation"),
    ("I", "stride-information-disclosure"),
    ("D", "stride-denial-of-service"),
    ("E", "stride-elevation-of-privilege"),
]

llm = ChatBedrockConverse(
    model_id="us.anthropic.claude-haiku-4-5-20251001-v1:0",
    temperature=0.3,
)

for use_case in use_cases:                      # output/use-cases/*.json + output/dfds/*.mmd
    for letter, skill_name in LETTERS:          # deterministic coverage
        agent = create_deep_agent(
            model=llm,
            tools=[],
            backend=FilesystemBackend(root_dir=REPO_PATH, virtual_mode=False),
            system_prompt=BASE_PROMPT,
            skills=[f"skills/{skill_name}"],    # exactly one skill per call
        )
        result = agent.invoke({"messages": [{"role": "user", "content": task(use_case)}]})
        write(f"output/threats/{use_case['id']}/{letter}.json", parse_json(result))
```

That loop is implemented in [`main/stage3_stride.py`](../main/stage3_stride.py), with
caching, contract validation, and retry — run it rather than rewriting it:

```bash
python -m main.stage3_stride --dry-run          # prompts only, no credentials needed
python -m main.stage3_stride --repo ./juice-shop
```

Passing `skills=[f"skills/{skill_name}"]` — a single skill directory — rather than the whole
`skills/` folder is what makes each call single-purpose.

## What each skill receives

The user message for each call should contain:

1. The **use case** description from stage 1.
2. The **DFD** for that use case from stage 2, listing external entities, processes,
   data stores, data flows, and trust boundaries by name.
3. The **repo path**, so the agent can read source through the filesystem backend.

The skills assume those three things are present. If the DFD is missing, the agent has
nothing to iterate and will fall back to generic advice — which is exactly the failure mode
these skills exist to prevent.

## The shared contract

All six skills emit the same JSON object and use the same risk matrix, so stage 3 can
concatenate their output without normalizing anything:

```json
{
  "use_case_id": "UC-LOGIN",
  "stride_letter": "S",
  "threats": [
    {
      "id": "T-UC-LOGIN-S-001",
      "stride": "S",
      "title": "Short imperative phrase",
      "dfd_element": { "name": "Login Handler", "type": "process" },
      "trust_boundary": "Internet → Application Server",
      "description": "What the threat is, in the context of this element.",
      "attack_scenario": "Concrete steps an attacker takes.",
      "evidence": [
        { "file": "routes/login.ts", "line": 42, "snippet": "verbatim source line" }
      ],
      "existing_mitigations": ["What the code already does about it"],
      "status": "unmitigated",
      "likelihood": "high",
      "impact": "high",
      "risk": "critical",
      "confidence": "high",
      "cwe": ["CWE-307"],
      "recommendation": "Concrete fix."
    }
  ]
}
```

**Risk is derived, never guessed** — every skill contains this matrix:

| | Impact High | Impact Medium | Impact Low |
|---|---|---|---|
| **Likelihood High** | Critical | High | Medium |
| **Likelihood Medium** | High | Medium | Low |
| **Likelihood Low** | Medium | Low | Low |

**ID scheme:** `T-<use_case_id>-<letter>-<nnn>`, numbered from 001 within each call. Stable
across runs because the use case ID and letter are fixed inputs, which makes run-to-run
diffing possible.

**Status values:** `unmitigated`, `partial`, `mitigated`. Keep mitigated threats in the
output — a threat model that shows which controls already exist is more credible than one
that only lists problems.

**Confidence values:** `high` when a cited file and line prove it, `medium` when the code was
read but the conclusion is inferential, `low` when the threat applies to the element by type
but no supporting code was found. Never drop a low-confidence threat silently; the judge
stage decides what survives.

## Files

| Skill | Letter | Applies to DFD elements |
|---|---|---|
| `stride-spoofing/` | S | External entities, processes |
| `stride-tampering/` | T | Processes, data stores, data flows |
| `stride-repudiation/` | R | Processes, data stores |
| `stride-information-disclosure/` | I | Processes, data stores, data flows |
| `stride-denial-of-service/` | D | Processes, data stores, data flows |
| `stride-elevation-of-privilege/` | E | Processes |

That mapping is classic STRIDE-per-element. It is repeated inside each skill so the agent
iterates only the elements the letter can apply to, rather than inventing a Repudiation
threat against a data flow.
