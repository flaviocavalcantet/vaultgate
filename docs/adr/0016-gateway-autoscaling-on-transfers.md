# ADR 0016: Gateway autoscaling on transfers in progress

**Status:** Accepted

## Context

The gateway has scaled on CPU since M7: a HorizontalPodAutoscaler at 70% of the CPU
request. CPU follows the bytes the gateway encrypts and decrypts, so it sees fast
transfers well. It misses slow ones. A client on a slow link holds its connection, its
buffers and its place under the transfer limits (M10) for as long as the transfer
lasts, at almost no CPU. Many of them fill a pod that the autoscaler takes for idle.

The gateway already counts what is in progress
(`vaultgate_gateway_uploads_in_progress`, `vaultgate_gateway_downloads_in_progress`),
and Prometheus scrapes it. The built-in autoscaler can't read Prometheus.

## Decision

**KEDA scales the gateway on two signals, CPU and the transfers in progress, whichever
asks for more pods.**

- **One autoscaler, two triggers.** A Deployment can have only one
  HorizontalPodAutoscaler, so "next to" the CPU autoscaler means in the same one. With
  `gateway.autoscaling.transfers.enabled`, the chart renders a KEDA `ScaledObject` in
  place of its own HorizontalPodAutoscaler, with a `cpu` trigger (the same 70%) and a
  `prometheus` trigger. KEDA creates and manages the HorizontalPodAutoscaler
  (`keda-hpa-<release>-gateway`), which takes the larger of the two answers. Without
  the option, the chart's CPU-only autoscaler is unchanged, and KEDA isn't needed.
- **The signal:** uploads plus downloads in progress over all the gateway pods of the
  release's namespace, divided by the pods (`AverageValue`), against
  `transfers.perPod`. The default is 8; the local cluster uses 4, low enough for the
  load tests' 20 users to pass it.
- **Scale-down as before:** one pod a minute after five quiet minutes, passed through
  to the HorizontalPodAutoscaler. A stopping pod still gets two minutes to finish its
  transfers.
- **KEDA from its upstream chart**, pinned, as an Argo CD application of the local
  cluster (`deploy/argocd/local`), in its own namespace. Its images are in the
  third-party scan. Why KEDA and not the Prometheus adapter: KEDA keeps the query next
  to the workload, in one object the chart renders, where the adapter needs
  cluster-wide rules that name each workload's metrics; and KEDA can later scale the
  scanner on its queue's length with the same mechanism.
- **Judged against the load tests** (ADR 0011). The report
  ([docs/load-testing.md](../load-testing.md)) charts the transfers in progress per pod
  and CPU per pod, each against its target, and says which of the two passed it during
  the run.

## Consequences

- The gateway adds pods for slow transfers that CPU never showed.
- Scaling now depends on Prometheus and on KEDA. If Prometheus doesn't answer, the
  transfers signal is missing: the autoscaler still scales out on CPU, and scales
  nothing in until the signal is back. If KEDA is down, no external metric is served,
  with the same effect. Neither removes pods that are serving.
- The count lags: the scrape interval, then KEDA's polling (15 seconds). A burst
  shorter than that isn't seen, and doesn't need pods.
- `perPod` is a judgement per deployment: what one pod holds comfortably, from its
  memory limit and the transfer limits. The load report is where to check it.
- The API's and the scanner's replicas are still fixed. The scanner on queue length is
  the natural next use.
- Scaling in still ends transfers that outlast the two minutes a stopping pod gets, as
  before: the client starts that transfer again.
