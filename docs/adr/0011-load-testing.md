# ADR 0011: Load testing

**Status:** Accepted

## Context

VaultGate makes performance claims it hasn't measured. The gateway streams, so its
memory should stay flat whatever the transfer sizes. The gateway scales out on CPU
(M7). The scanner keeps up with uploads. M8 measures these and publishes the numbers.
It also keeps a short run in CI, so a change that breaks the claims shows up on its PR.

## Decision

**Locust scenarios (`loadtest/`) against the local k3d cluster, as many distinct load
users, judged with Prometheus's view of the same minutes.**

- **Against the k3d cluster** (ADR 0009, 0010): the deployment shape, with the
  gateway's CPU autoscaler active and Prometheus recording memory, CPU and latency per
  pod. Results come from one machine, a laptop or a CI runner, and the report says
  which. They measure VaultGate's own behaviour (flat memory, scaling, where it
  saturates), not what production hardware would do.
- **Many distinct users through a local-only login client.** Real logins use the
  browser PKCE flow, which a load tool can't drive at scale. The local realm gets a
  second client, `vaultgate-load`, with the password grant enabled, and 50 users in the
  `/load` group, in their own import file (`infra/keycloak/vaultgate-users-0.json`).
  Their tokens are like any other, so nothing in the API or the gateway changes.
  - **Why not the three seed users?** All the load would then come from two ordinary
    users. Their per-user caps (20 open uploads each, the share limits) would be
    reached long before the gateway is under real pressure, and the test would partly
    measure those caps. Raising the caps for load runs only would test a setup that
    differs from the defaults.
  - **What it costs:** a weaker login flow (password grant) in the local realm,
    limited to a client that exists only there. The web client stays PKCE-only.
- **Three kinds of user:**
  - **Transfers:** streaming uploads of 256 KiB to 128 MiB, the wait for the scan, and
    the download back, checked by size.
  - **ControlPlane:** the API's small requests: who am I, listing and reading files,
    download intents (policy and quarantine checks).
  - **Documents:** PDF and Office files and 8 MiB text files, timed from the end of the
    upload to the verdict. This measures the scanner's throughput as its queue fills.

  The scan wait is reported as its own request type (`SCAN`), so its percentiles sit
  next to the HTTP ones.
- **Pass or fail is decided outside Locust** (`loadtest/check.py`). It checks:
  - no failed request: errors, short downloads, and scans with no verdict all count;
  - every scenario did its work;
  - no gateway pod above 90% of its 256 MiB memory limit, according to Prometheus;
  - no VaultGate pod restarted during the run.
- **CI:** after `k3d-check`, `make load-smoke` runs 6 users for 90 seconds, with uploads
  up to 32 MiB, against the same cluster, and applies those thresholds.
- **The published report** (`docs/load-testing.md`, `make load-report`): 20 users for
  6 minutes, with uploads up to 128 MiB. `loadtest/report.py` builds it from Locust's
  results and from Prometheus's view of the same minutes (gateway memory, CPU and pods,
  throughput, scans in progress), with charts drawn as plain SVG. A workflow
  (`load-report`) runs it on a fresh cluster whenever the load tests change, or by hand,
  and the report says where it was measured.
- **Local-only cleanup:** VaultGate has no file deletion yet. Each Transfers object is
  removed from LocalStack once its download checked out. These are unsigned requests,
  which only LocalStack accepts, and they remove every version, since the bucket is
  versioned. Without this, a full run would keep gigabytes of ciphertext in the
  runner's memory and disk. The make targets turn it on (`VAULTGATE_LOAD_CLEANUP=1`).

## Consequences

- Each PR shows that transfers, API calls and scans still work under concurrent load,
  and that the gateway's memory stays flat. The smoke run adds a few minutes to
  `k3d-e2e`.
- Load users and their data stay in the cluster's database. Only the Transfers objects
  are removed from the bucket. Runs are meant for a throwaway cluster
  (`make k3d-down` afterwards).
- The report is regenerated from a run, never edited by hand. Each run's numbers vary
  with the machine it ran on.
- No latency threshold gates CI: a shared runner's latency varies too much. Latency and
  throughput are reported, not enforced.
