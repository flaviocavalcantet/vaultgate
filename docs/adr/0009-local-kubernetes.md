# ADR 0009: The local Kubernetes cluster (k3d, Argo CD)

**Status:** Accepted

## Context

Until M7, VaultGate ran only under docker compose. The Helm chart existed, but nothing
showed that it deploys a working system. M7 asks for the whole system on Kubernetes,
deployed the GitOps way (Argo CD syncing this repo), with the gateway scaling
horizontally. It has to run on a laptop and in CI, at no cost.

## Decision

**A k3d cluster, `make k3d-up`, where Argo CD syncs everything from this repo: the
dependencies and VaultGate. The images are built locally and pushed to the cluster's
own registry.**

- **k3d (k3s in Docker):** a single-node cluster that starts in under a minute. It has
  what the chart needs: a NetworkPolicy controller (so the internal-port policy is
  enforced, not just accepted), metrics-server for the autoscaler, and local-path
  volumes. Traefik is turned off; see host access below.
- **The dependencies in the cluster** (`deploy/k3d/deps`, namespace `vaultgate-deps`):
  PostgreSQL, LocalStack (S3, KMS, SQS), Keycloak with the same realm compose imports,
  and Mailpit. They are plain manifests for local use only, synced by Argo CD like
  everything else. The cluster is self-contained; compose isn't needed alongside it.
- **GitOps with local images:** Argo CD deploys what is in git at
  `VAULTGATE_REVISION` (the current branch by default, a commit SHA in CI), never the
  working tree. An app of apps (`deploy/argocd/local`) passes the revision to every
  application, so a branch can be tried before it is merged. The images are the one
  exception: they are built from the working tree, pushed to the cluster's registry,
  and pulled again when a pod restarts. Publishing them from CI to GHCR, with the chart
  pinned to them, is on the roadmap (M11).
- **Host access through NodePorts, on compose's ports:** the API on 8000, the gateway
  on 8888, Keycloak on 8080, LocalStack on 4566 and Mailpit on 8025, all on loopback.
  The scripts, the e2e check and the walkthroughs then work unchanged against either
  stack. Keycloak keeps `KC_HOSTNAME=http://localhost:8080`, as under compose, so
  tokens carry the same issuer from the host and from pods. The chart puts a node port
  on its own Service with the public port only, so the internal and metrics ports never
  get one. A real deployment uses the chart's Ingress, with TLS.
- **Autoscaling on CPU:** the gateway's HorizontalPodAutoscaler (from the chart, 1 to 3
  pods locally). The checks show that it reads CPU utilization. Scaling on transfers
  in progress (KEDA) comes later, judged against the M8 load tests (M11).
- **Argo CD from its official manifest,** pinned to a release, with two settings merged
  in: kustomize may read the realm from `infra/keycloak` (one copy for both stacks),
  and the UI runs over plain HTTP for `kubectl port-forward`.

## Consequences

- `make k3d-up` then `make k3d-check` runs the vault end-to-end check against the
  cluster, plus cluster checks:
  - Argo CD reports every application Synced and Healthy;
  - the autoscaler reads CPU;
  - a pod other than the gateway and the scanner is refused on the API's internal port
    but reaches its public port.

  CI runs both on every PR (`k3d-e2e`), syncing the PR's commit from GitHub.
- Compose and the cluster use the same host ports, so only one of them runs at a time.
- LocalStack keeps its state in the pod. After it restarts, `make tf-local` recreates
  the bucket, key and queues; `make k3d-up` does this itself. PostgreSQL keeps its data
  on a local-path volume until `make k3d-down`.
- Local changes need two steps to reach the cluster: push for what Argo CD syncs
  (chart, manifests), and `make k3d-images` for the code.
- The cluster's observability (Prometheus Operator, Grafana, Loki, Tempo, Alloy,
  Alertmanager) is the next M7 step. Until then the e2e check skips traces in the
  cluster.
