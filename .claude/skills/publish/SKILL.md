---
description: Emit and publish a verified snapshot through the canonical contract
disable-model-invocation: true
allowed-tools: Read
---

Use only these repository commands:

```text
python src/aggregator/cli.py emit
python src/aggregator/cli.py publish --strict
```

Require both commands to succeed. Do not POST files to an arbitrary endpoint,
fall back to non-strict mode, commit, push, or deploy as an implicit side effect.
`WORKER_URL` must be HTTPS (except loopback development) and `ADMIN_TOKEN` must
come from the local/CI secret environment.
