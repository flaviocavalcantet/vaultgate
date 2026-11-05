# ADR 0010: Observability on the local cluster

**Status:** Accepted

## Context

Under docker compose, VaultGate has Prometheus with alert rules, Loki through Alloy,
Tempo, and Grafana with dashboards (M1.5, M6). The local k3d cluster (ADR 0009) had
none of it. It also had no Alertmanager: firing alerts were only visible in the
Prometheus UI, and the README promised routing with M7.

The cluster should be observable the way a real one is: an operator-managed Prometheus
that finds services through ServiceMonitors, and Alertmanager routing alerts somewhere.
Both stacks should also show the same thing: the same rules, dashboards and data
sources. Two copies would drift.

## Decision

**kube-prometheus-stack for metrics, alerting and Grafana. VaultGate's own pieces in a
small local chart that reads compose's files. All of it synced by Argo CD into
`monitoring`.**

- **kube-prometheus-stack** (upstream chart, pinned to 92.21.1;
  `deploy/k3d/kube-prometheus-stack.yaml`): the Prometheus Operator, Prometheus,
  Alertmanager, Grafana, kube-state-metrics and node-exporter, with the Kubernetes
  dashboards and rules. Prometheus selects every ServiceMonitor and PrometheusRule in
  the cluster, so the VaultGate chart's ServiceMonitors (M7, `metrics.serviceMonitor`)
  and the local chart's rules are picked up as they are. What k3s runs inside a single
  process (etcd, the scheduler, the controller manager, kube-proxy) is not scraped, so
  its rules don't fire forever as "target down". The operator's admission webhook is
  off on this throwaway cluster.
- **Loki, Tempo and Alloy as plain workloads** in a local chart
  (`deploy/k3d/observability`), on the same images and configs as compose, not their
  upstream charts. Grafana's Tempo single-binary chart is deprecated. The current Loki
  chart is a distributed system to configure, for one process here. One config each,
  read by both stacks, is easier to keep right. Alloy gets its own cluster config
  (`observability/alloy/kubernetes.alloy`): a DaemonSet that reads the node's pod log
  files and forwards OTLP to Tempo. Its processing stages are the compose ones.
- **One copy of every file:** the local chart's `files/` links to `observability/`, and
  Argo CD follows links inside the repo:
  - `rules.yml` becomes a PrometheusRule;
  - the dashboards become ConfigMaps for Grafana's sidecar;
  - `datasources.yml` becomes the data sources, with the same UIDs;
  - `loki.yml` and `tempo.yml` become the configs.

  An alias Service `prometheus` keeps the data source URL that compose uses.
- **Alertmanager mails Mailpit:**
  - VaultGate's alerts go to `oncall@vaultgate.local`, resolved ones too;
  - Watchdog, which always fires, goes to `heartbeat@vaultgate.local`, which shows that
    rules, routing and SMTP work end to end;
  - a critical alert inhibits the warning with the same name and job.

  Locally that is as far as alerts should go. A real deployment replaces the receivers
  (chat, paging) in the same values file.
- **Host access as with compose:** Grafana on 3000, Prometheus on 9090, Loki on 3100,
  Tempo on 3200, plus Alertmanager on 9093. Each is a NodePort Service with that one
  port.

## Consequences

- `make k3d-check` now covers the cluster's observability:
  - every scrape target (API, gateway, scanner, Loki, Tempo, Alloy) is up;
  - Grafana has the VaultGate dashboards and the three data sources;
  - Alertmanager's heartbeat mail is in Mailpit;
  - the vault end-to-end check runs in full, including the upload's trace in Tempo and
    its log lines from all three services in Loki.
- A change to a rule, dashboard or config reaches both stacks.
- The cluster's VaultGate dashboards are in Grafana's General folder, next to the
  Kubernetes ones, not in a VaultGate folder as under compose.
- Loki and Tempo keep their data on local-path volumes, lost with `make k3d-down`.
  A real deployment would run them against object storage, with their own charts.
- The rules come from compose, where one Prometheus scrapes a fixed list of targets. On
  Kubernetes, a service with no pods has no targets left, so `VaultGateTargetDown`
  (`up == 0`) can't fire for it. `VaultGateTargetMissing` covers that case: no API,
  gateway or scanner target at all for five minutes. It never fires under compose. It
  can fire once on a fresh cluster, if VaultGate takes more than five minutes to come
  up after Prometheus.
