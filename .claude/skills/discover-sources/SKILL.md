---
description: Record candidate subscription sources for review
disable-model-invocation: true
allowed-tools: Read
---

There is no automatic discovery-to-production command. Record a candidate for
manual review and keep it disabled until its response format, size, redirect
chain and parser output have been checked. Discovery must not write staging/live
output, enable a source, expose credentials, or trigger publication implicitly.
