"""OpenTelemetry tracing for the API (ADR 0008).

Off unless an OTLP endpoint is configured (`OTEL_EXPORTER_OTLP_ENDPOINT` or
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, the standard variables; `OTEL_SDK_DISABLED=true`
turns it off again). Spans go over OTLP/HTTP, locally to Alloy, which forwards them to
Tempo.

- A trace starts only where work comes in: a request (SERVER) or a message sent to
  start work elsewhere (PRODUCER). Everything else (database queries, ...) is recorded
  only inside one, so background loops do not fill the trace store with stray queries.
- The public API starts a new trace for every request and ignores any trace context the
  client sends; the internal API, which only the gateway and the scanner reach,
  continues theirs. Scan requests carry the context to the scanner in SQS message
  attributes.
- Spans carry identifiers (route, file and scan IDs, status), never personal data,
  tokens or query strings. Database spans carry the SQL text, whose values are always
  bound parameters, never the parameters. Error descriptions and exception events are
  dropped before export (`RedactingExporter`): driver messages can quote the values
  they refused.
- FastAPI's own telemetry is off (FASTAPI_TELEMETRY): it would add a second request
  span that always continues the caller's trace and records query strings.
- Log lines written inside a span carry its trace_id and span_id (vaultgate_api.logs),
  which links the logs in Loki to the trace in Tempo.
"""

import os
from collections.abc import Sequence

from opentelemetry import propagate, trace
from opentelemetry.context import Context
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SpanExporter,
    SpanExportResult,
    SpanProcessor,
)
from opentelemetry.sdk.trace.sampling import Decision, ParentBased, Sampler, SamplingResult
from opentelemetry.trace import SpanKind, Status, StatusCode
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from vaultgate_api.logs import REQUEST_ID_HEADER
from vaultgate_api.metrics import route_template

SERVICE = "api"
VERSION = "0.1.0"

tracer = trace.get_tracer("vaultgate.api")

# Probes are called every few seconds and say nothing about a user's request.
UNTRACED_PATHS = frozenset({"/healthz", "/readyz"})

# For FastAPI(telemetry=...): TracingMiddleware is the only source of request spans.
FASTAPI_TELEMETRY = {"tracing": False, "metrics": False, "logs": False}


class EntryPoints(Sampler):
    """Samples a root span only if it is where work comes in (see the module docstring);
    ParentBased decides for every span that has a parent."""

    KINDS = frozenset({SpanKind.SERVER, SpanKind.PRODUCER, SpanKind.CONSUMER})

    def should_sample(self, parent_context, trace_id, name, kind=None, attributes=None, *_, **__):
        decision = Decision.RECORD_AND_SAMPLE if kind in self.KINDS else Decision.DROP
        return SamplingResult(decision, attributes if decision.is_sampled() else None)

    def get_description(self) -> str:
        return "EntryPoints"


class RedactingExporter(SpanExporter):
    """Exports spans without error descriptions or events: an instrumentation's error
    text (a database driver's, for one) can quote the value that was refused."""

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
    """Install the exporter and the database instrumentation; returns whether tracing
    is on."""
    if not enabled():
        return False
    # Imported here: the exporter and instrumentation are only loaded when used.
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.asyncpg import AsyncPGInstrumentor

    trace.set_tracer_provider(
        make_provider(BatchSpanProcessor(RedactingExporter(OTLPSpanExporter())))
    )
    # At the driver: SQLAlchemy's own instrumentation lags its releases. Parameters
    # are not captured (the default).
    AsyncPGInstrumentor().instrument()
    return True


class TracingMiddleware:
    """One SERVER span per request, named after the matched route.

    `trust_incoming` continues a trace context sent by the caller (the internal API);
    otherwise every request starts a new trace (the public API: a client must not be
    able to attach its requests to someone else's trace or force them to be kept).
    """

    def __init__(self, app: ASGIApp, *, trust_incoming: bool = False) -> None:
        self.app = app
        self.trust_incoming = trust_incoming

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in UNTRACED_PATHS:
            await self.app(scope, receive, send)
            return

        if self.trust_incoming:
            carrier = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]}
            parent = propagate.extract(carrier)
        else:
            parent = Context()
        method = scope["method"]
        with tracer.start_as_current_span(
            method,
            context=parent,
            kind=SpanKind.SERVER,
            attributes={"http.request.method": method, "url.path": scope["path"]},
            # Recorded below without the message, which may quote request data.
            record_exception=False,
            set_status_on_exception=False,
        ) as span:

            async def send_traced(message: Message) -> None:
                if message["type"] == "http.response.start":
                    status = message["status"]
                    span.set_attribute("http.response.status_code", status)
                    if status >= 500:
                        span.set_status(StatusCode.ERROR)
                    for name, value in message.get("headers", ()):
                        if name.decode("latin-1").lower() == REQUEST_ID_HEADER:
                            span.set_attribute("vaultgate.request_id", value.decode("latin-1"))
                await send(message)

            try:
                await self.app(scope, receive, send_traced)
            except Exception as exc:
                span.set_attribute("error.type", type(exc).__qualname__)
                span.set_status(StatusCode.ERROR)
                raise
            finally:
                route = route_template(scope)
                span.set_attribute("http.route", route)
                span.update_name(f"{method} {route}")


def sqs_trace_attributes() -> dict[str, dict[str, str]]:
    """The current trace context as SQS message attributes, for the scanner to continue."""
    carrier: dict[str, str] = {}
    propagate.inject(carrier)
    return {k: {"DataType": "String", "StringValue": v} for k, v in carrier.items()}
