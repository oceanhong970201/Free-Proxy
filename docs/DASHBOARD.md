# Operations Dashboard

The dashboard is a local operator surface for the proxy aggregation pipeline. It
keeps production serving health, the latest local pipeline result, the candidate
node pool, and generated artifacts as separate signals.

## Start

```powershell
python src\aggregator\cli.py dashboard --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765/`. The server rejects non-loopback bind addresses,
untrusted Host headers, and cross-origin write requests.

The exit-IP checker needs Mihomo and curl. Put `mihomo.exe` in `bin/`, add
Mihomo to `PATH`, or set `MIHOMO_BIN` to an absolute executable path. The
dashboard capability indicator reports whether the runtime is available.

## Views

- **Overview** separates three operational signals: production serving health,
  the latest remote automation snapshot, and local candidate verification. The
  remote and local verification cards each show total, verified, alive, dead,
  and unverified counts, so a local backlog is not presented as a production
  outage.
- **Nodes** provides server-side filters and pagination. Select up to 20 opaque
  node IDs for endpoint, exit-IP, or IP-purity checks.
- **Sources** shows enabled, disabled, and canary source state without exposing
  complete upstream URLs.
- **Outputs** validates each generated format and reports count, size, hash, and
  age independently.

## Status model

`GET /api/status` exposes remote automation and local verification as separate
objects. The dashboard primarily consumes this shape while retaining display
compatibility with the older `pipeline`, `pipeline_status`, and `nodes` fields:

```json
{
  "remote_pipeline": {
    "configured": true,
    "status": "healthy",
    "pipeline_status": "healthy",
    "stale": false,
    "generated_at": "TIMESTAMP",
    "age_seconds": 120,
    "fetched_at": "TIMESTAMP",
    "verify": {
      "total": 100,
      "verified": 100,
      "alive": 80,
      "dead": 20,
      "unverified": 0,
      "tier1_alive": 90,
      "tier2_passed": 80,
      "completed": true
    }
  },
  "local_verification": {
    "status": "attention",
    "total": 100,
    "verified": 20,
    "alive": 18,
    "dead": 2,
    "unverified": 80,
    "tier1_alive": 18,
    "tier2_passed": 0,
    "completed": false,
    "updated_at": "TIMESTAMP",
    "age_seconds": 60
  }
}
```

Remote automation is fail-closed in the UI: an unconfigured source, unknown
freshness, or stale snapshot is labelled explicitly and is not promoted to a
successful state. Production serving keeps its own badge based on the live
serving probe. Local `attention` only describes the candidate pool. Endpoint,
exit-IP, and purity jobs are on-demand diagnostics and do not rewrite either
production or remote automation status. Stable `remote_pipeline.error` codes
are translated to operator-facing Traditional Chinese descriptions rather than
rendered as raw backend identifiers.

## IP Checks

`endpoint` resolves the node endpoint, rejects private/reserved addresses, and
tests TCP reachability. `exit` additionally starts an isolated one-node Mihomo
process bound to an authenticated loopback SOCKS port and queries fixed HTTPS
IP-echo endpoints. Results distinguish pass, partial provider response, rotating
egress, direct-connection bypass, failure, and cancellation.

`purity` first performs the full exit-IP check, then submits only the canonical
public exit IP to three fixed HTTPS reputation adapters. It normalizes proxy,
VPN, Tor, datacenter, abuse, and provider risk-score signals before
computing a reproducible 0-100 purity score. Results include an A-F grade,
confidence, provider coverage, and stable reason codes. Higher scores are
cleaner. Provider disagreement lowers confidence instead of treating one
provider as authoritative. A job item with `status=passed` means the query
completed; the grade and score describe reputation.

Reputation responses are cached by exit IP for 24 hours. Provider hosts, paths,
and methods are hard-coded, redirects are rejected, responses are size-bounded,
and provider concurrency is capped. Raw provider documents are neither returned
to the browser nor persisted.

The reputation stage is configured under `ip_checker` in
`config/dashboard.yaml`:

```yaml
purity_timeout_seconds: 8       # reputation-stage deadline, 1-30 seconds
purity_cache_seconds: 86400     # per-exit-IP cache, 0-604800 seconds
purity_provider_concurrency: 2  # global reputation requests, 1-3
```

These limits do not change the endpoint or exit-IP timeout. A provider timeout,
quota response, or malformed document is recorded as a stable error code; a
partial reputation response lowers coverage and confidence without changing
the node's existing liveness result.

Proxy configuration is serialized through stdin. Raw subscription URIs, UUIDs,
passwords, and other credentials are never returned by the HTTP API, written to
checker configuration files, or included in persisted check results.

## Local API

- `GET /api/status`
- `GET /api/sources`
- `GET /api/nodes?query=&status=&proto=&source=&published=&offset=&limit=`
- `POST /api/ip-checks` with `{"node_ids": ["SHA256_ID"], "mode": "endpoint"}`
  where mode is `endpoint`, `exit`, or `purity`
- `GET /api/ip-checks/{job_id}`
- `POST /api/ip-checks/{job_id}/cancel`

API responses are non-cacheable. The browser submits opaque node IDs only; the
server resolves credentials from the local database when a check begins.
