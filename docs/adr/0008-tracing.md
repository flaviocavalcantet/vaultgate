# ADR 0008: Distributed tracing (OpenTelemetry, Alloy, Tempo)

**Status:** Accepted

## Context

One user action crosses three services and a queue. An upload goes to the gateway,
which asks the API to consume the intent, has KMS make a key and streams parts to S3,
then reports to the API. The API sends a scan request to SQS, and the scanner worker
fetches the job, unwraps the key and reads the object. Finally it reports the verdict.
Request IDs tie log lines together within one request, but they don't follow the work
across the queue, and they don't show where the time went or which hop failed.

Traces answer both, if they don't become a second place where sensitive data leaks.
A trace store is one more copy of what the system did, read by more people than the
audit log, and spans are easy to fill with URLs, error messages and payloads.

## Decision

**OpenTelemetry in all three services, exported over OTLP/HTTP to Grafana Alloy,
which forwards to Grafana Tempo. Trace IDs go in every log line, so Grafana links
traces and logs both ways.**

- **Standard configuration:** tracing is on when `OTEL_EXPORTER_OTLP_ENDPOINT` (or
  `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`) is set and off otherwise, and
  `OTEL_SDK_DISABLED=true` turns it off. Without an endpoint nothing is recorded, as
  in the unit tests. Trace context is still passed on, which costs nothing.
- **One collector:** the services only know Alloy, which already ships the logs. The
  trace store can change (Tempo, a vendor, an OpenTelemetry Collector in the cluster)
  without touching the services. The Helm chart takes the endpoint as
  `tracing.otlpEndpoint`.
- **Where traces start:** only where work comes in: a request (SERVER span), a message
  sent to start work elsewhere (PRODUCER), or a message received (CONSUMER). A database
  query or AWS call with no request around it, from the sweeper, the resender or the
  audit anchor, is not recorded. Background loops would otherwise fill the store with
  single-query traces. A resent scan request is itself where work starts, so it begins
  a trace, and the scan continues it.
- **Whose context is trusted:** the public API and the gateway start a new trace for
  every request and ignore any `traceparent` a client sends. A client must not attach
  its requests to someone else's trace or force them to be kept. The API's internal
  port, which only the gateway and the scanner reach, continues their traces.
- **Across the queue:** the API puts the W3C trace context in the SQS message
  attributes (`traceparent`). The scanner continues it, so one trace runs from the
  upload to the scan's verdict.
- **What spans carry:** identifiers and outcomes: route templates, paths (file and scan
  IDs, never query strings), status codes, request IDs, byte counts, failure reasons,
  and the SQL text of database calls. Values in that text are always bound parameters,
  which are not captured. Never tokens, headers, personal data or file contents.
  Error descriptions and exception events are dropped before export in all three
  services, because a driver's or parser's message can quote the value it refused.
  Client addresses stay in the logs and the audit log, which have their own rules.
- **Library choices:** spans for requests and for the calls between services are
  written by hand in each service, a few dozen lines each. The contrib integrations are
  used only for the driver-level calls. They would record query strings, trust any
  incoming context or, for the gateway's streamed uploads, lose the request's context
  in Tornado's body callbacks:
  - API: asyncpg for the database. SQLAlchemy's own instrumentation lags its releases.
    FastAPI's built-in telemetry is turned off, so that only one request span exists
    and it follows the rules above.
  - Gateway: botocore for KMS and S3.
  - Scanner: one span per scan step. The object is read with many small range
    requests, so their number is an attribute, not one span each.
- **Logs:** every log line written inside a sampled span carries `trace_id` and
  `span_id`. Alloy stores `trace_id` in Loki as structured metadata, like `request_id`.
  Grafana opens a trace from a log line and the logs from a span.

## Consequences

- One query finds everything about an upload: the gateway's request with its KMS and
  S3 calls, the API's checks and queries, the queue hop and the scanner's steps. The
  end-to-end check (`make vault-check`) asserts this chain in Tempo, and Loki's lines
  from all three services under the same trace ID.
- Every request is sampled. That suits the local stack and is what the e2e check
  needs. Under load (M8) a ratio will be needed; the entry-point sampler is where it
  goes.
- Local retention is seven days, like the metrics. Tempo runs as a single binary on a
  local volume; a deployment would point it at object storage.
- The scanner's object reads appear only as a count, not one span each.
- Background work (the upload sweep, the audit anchor) shows in logs and metrics, not
  in traces.
