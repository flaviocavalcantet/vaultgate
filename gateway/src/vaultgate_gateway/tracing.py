"""OpenTelemetry tracing for the gateway (ADR 0008).

The same rules as the API's (vaultgate_api.tracing): off unless an OTLP endpoint is
configured (`OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`;
`OTEL_SDK_DISABLED=true` turns it off), traces start only at a request, a client's
own trace context is ignored, and no error text, personal data, token or query string
is exported.

Each upload or download is one SERVER span (vaultgate_gateway.app.BaseHandler), with
the calls it makes as children: the API's internal routes (which continue the trace on
their side), and KMS and S3 through the botocore instrumentation.
"""

import os
from collections.abc import Sequence

from opentelemetry import propagate, trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SpanExporter,
    SpanExportResult,
    SpanProcessor,
)
from opentelemetry.sdk.trace.sampling import Decision, ParentBased, Sampler, SamplingResult
from opentelemetry.trace import SpanKind, Status

SERVICE = "gateway"
VERSION = "0.1.0"

tracer = trace.get_tracer("vaultgate.gateway")


class EntryPoints(Sampler):
    """Samples a root span only if it is where work comes in (a request); ParentBased
    decides for every span that has a parent."""

    KINDS = frozenset({SpanKind.SERVER, SpanKind.PRODUCER, SpanKind.CONSUMER})

    def should_sample(self, parent_context, trace_id, name, kind=None, attributes=None, *_, **__):
        decision = Decision.RECORD_AND_SAMPLE if kind in self.KINDS else Decision.DROP
        return SamplingResult(decision, attributes if decision.is_sampled() else None)

    def get_description(self) -> str:
        return "EntryPoints"


class RedactingExporter(SpanExporter):
    """Exports spans without error descriptions or events: an instrumentation's error
    text can quote data it was given."""

    def __init__(self, inner: SpanExporter) -> None:
        self.inner = inner

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        return self.inner.export([redacted(span) for span in spans])

    def shutdown(self) -> None:
        self.inner.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self.inner.force_flush(timeout_millis)


def redacted(span: ReadableSpan) -> ReadableSpan:
    if span.status.description is None and not span.events:
        return span
    return ReadableSpan(
        name=span.name,
        context=span.context,
        parent=span.parent,
        resource=span.resource,
        attributes=span.attributes,
        events=(),
        links=span.links,
        kind=span.kind,
        status=Status(span.status.status_code),
        start_time=span.start_time,
        end_time=span.end_time,
        instrumentation_scope=span.instrumentation_scope,
    )


def enabled() -> bool:
    if os.getenv("OTEL_SDK_DISABLED", "").strip().lower() == "true":
        return False
    return bool(
        os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    )


def make_provider(processor: SpanProcessor) -> TracerProvider:
    provider = TracerProvider(
        resource=Resource.create(
            {"service.name": SERVICE, "service.namespace": "vaultgate", "service.version": VERSION}
        ),
        sampler=ParentBased(root=EntryPoints()),
    )
    provider.add_span_processor(processor)
    return provider


def configure_tracing() -> bool:
    """Install the exporter and the KMS/S3 instrumentation; returns whether tracing is on."""
    if not enabled():
        return False
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.botocore import BotocoreInstrumentor

    trace.set_tracer_provider(
        make_provider(BatchSpanProcessor(RedactingExporter(OTLPSpanExporter())))
    )
    BotocoreInstrumentor().instrument()
    return True


def inject(headers: dict[str, str]) -> dict[str, str]:
    """Add the current trace context to outgoing request headers."""
    propagate.inject(headers)
    return headers
