# Worked example

One target's complete output, in the layout every stage reads and writes. A real run
lands in `output/<owner>/<repo>/` — resolved from the target's git remote, so a Juice
Shop clone produces `output/juice-shop/juice-shop/`. This directory has the same shape
under a name no real target will take.

```
_example/
  use-cases/UC-LOGIN.json      stage 1  what was analyzed
  dfds/UC-LOGIN.mmd            stage 2  the data flow diagram
  threats/UC-LOGIN/S.json      stage 3  one agent call — the cache unit
  threats/UC-LOGIN.json        stage 3  merged, what stage 4 reads
  report.md                    stage 4  the deliverable, and the chatbot's corpus
```

Each file carries a `_comment` (or a `%%` header) explaining its own contract, so open
the one for the stage you are building.

It is a real target, not a mock — point the pipeline at it to smoke-test a stage
without touching a live run:

```bash
python -m main.stage3_stride --output output/_example --repo ../repo --dry-run
python -m main.stage4_report --output output/_example
```

The three rules worth knowing before you copy it:

- **The filename is the use case id.** Stage 3 rejects a file whose `id` field disagrees
  with its stem rather than guessing which is right.
- **Node shape carries the element type** in the diagram: `[Name]` external entity,
  `(Name)` process, `[(Name)]` data store, `subgraph` trust boundary. Five of the six
  STRIDE letters go quiet if the shapes are wrong — see the comments in the `.mmd`.
- **`risk` is derived** from likelihood × impact through a fixed matrix, and
  `confidence: "high"` guarantees a real file and line. See `main/contract.py`.

Full contracts: [`docs/STAGE-CONTRACTS.md`](../../docs/STAGE-CONTRACTS.md).
