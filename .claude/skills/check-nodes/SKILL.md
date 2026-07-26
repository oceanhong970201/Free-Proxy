---
name: check-nodes
description: Run the repository verifier without bypassing its fail-closed checks
disable-model-invocation: true
allowed-tools: Read
---

Use only the canonical command from the repository root:

```text
python src/aggregator/cli.py verify
```

Do not invoke the verifier binary with an ad-hoc schema, reuse endpoint-level
results, edit `alive` manually, or publish when the command exits nonzero.
`state/verify-progress.json` is the only supported resume state. Report the
structured summary and leave the previous DB/live snapshot in place on error.
