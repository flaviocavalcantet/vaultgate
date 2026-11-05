"""Traces (ADR 0008): where they start, what crosses a hop, and what never leaves."""

import io
import json
import logging
import uuid

import boto3
import httpx
import pytest
from moto import mock_aws
from opentelemetry import trace
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, Status, StatusCode

from vaultgate_api import scans, tracing
from vaultgate_api.internal import internal_app
from vaultgate_api.logs import JsonFormatter
from vaultgate_api.main import app

_exporter = InMemorySpanExporter()
_provider = tracing.make_provider(SimpleSpanProcessor(tracing.RedactingExporter(_exporter)))

# A remote parent, as the gateway would send it (sampled).
PARENT_TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
PARENT_SPAN = "00f067aa0ba902b7"
TRACEPARENT = f"00-{PARENT_TRACE}-{PARENT_SPAN}-01"


@pytest.fixture
def spans(monkeypatch) -> InMemorySpanExporter:
    # The global provider can be set only once per process; the tracer is swapped
    # instead, so other tests run with tracing off as in a default deployment.
    monkeypatch.setattr(tracing, "tracer", _provider.get_tracer("vaultgate.api"))
    _exporter.clear()
    return _exporter


def server_spans(exporter: InMemorySpanExporter) -> list[ReadableSpan]:
    return [s for s in exporter.get_finished_spans() if s.kind is SpanKind.SERVER]


def client(asgi_app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=asgi_app), base_url="http://t")


async def test_a_request_is_one_span_named_after_its_route(spans):
    async with client(app) as c:
        response = await c.get("/me?token=secret")
    [span] = server_spans(spans)
    assert span.name == "GET /me"
    assert span.attributes["http.route"] == "/me"
    assert span.attributes["http.response.status_code"] == response.status_code == 401
    assert span.attributes["vaultgate.request_id"] == response.headers["x-request-id"]
    # Path only, like the access log: query strings may carry tokens.
    assert "secret" not in json.dumps(dict(span.attributes))
    assert span.status.status_code is StatusCode.UNSET  # a 4xx is the client's error


async def test_fastapi_adds_no_request_span_of_its_own(spans, monkeypatch):
    """FastAPI's built-in telemetry would add a span that trusts a client's trace
    context and records query strings; it is off in both apps."""
    monkeypatch.setattr(trace, "get_tracer_provider", lambda: _provider)
    for asgi_app, path in ((app, "/me?q=1"), (internal_app, "/internal/intents/consume")):
        async with client(asgi_app) as c:
            await c.post(path, json={}, headers={"traceparent": TRACEPARENT})
    assert [s.instrumentation_scope.name for s in spans.get_finished_spans()] == [
        "vaultgate.api",
        "vaultgate.api",
    ]


async def test_probes_are_not_traced(spans):
    async with client(app) as c:
        await c.get("/healthz")
    assert server_spans(spans) == []


async def test_the_public_api_ignores_a_clients_trace_context(spans):
    async with client(app) as c:
        await c.get("/me", headers={"traceparent": TRACEPARENT})
    [span] = server_spans(spans)
    assert span.parent is None
    assert f"{span.context.trace_id:032x}" != PARENT_TRACE


async def test_the_internal_api_continues_the_callers_trace(spans):
    async with client(internal_app) as c:
        await c.post("/internal/intents/consume", json={}, headers={"traceparent": TRACEPARENT})
    [span] = server_spans(spans)
    assert f"{span.context.trace_id:032x}" == PARENT_TRACE
    assert f"{span.parent.span_id:016x}" == PARENT_SPAN
    assert span.name == "POST /internal/intents/consume"


async def test_log_lines_carry_the_trace_id(spans):
    out = io.StringIO()
    handler = logging.StreamHandler(out)
    handler.setFormatter(JsonFormatter("api"))
    access = logging.getLogger("vaultgate.access")
    access.addHandler(handler)
    previous = access.level
    access.setLevel(logging.INFO)
    try:
        async with client(app) as c:
            await c.get("/me")
    finally:
        access.removeHandler(handler)
        access.setLevel(previous)
    [span] = server_spans(spans)
    [line] = [json.loads(line) for line in out.getvalue().splitlines()]
    assert line["trace_id"] == f"{span.context.trace_id:032x}"
    assert line["span_id"] == f"{span.context.span_id:016x}"


def test_log_lines_outside_a_trace_have_no_trace_id():
    record = logging.makeLogRecord({"name": "t", "levelname": "INFO", "msg": "m"})
    assert "trace_id" not in json.loads(JsonFormatter("api").format(record))


async def test_scan_requests_carry_the_trace_to_the_scanner(spans):
    with mock_aws():
        sqs = boto3.client("sqs", region_name="ap-northeast-1")
        url = sqs.create_queue(QueueName="scans")["QueueUrl"]
        file_id, scan_id = uuid.uuid4(), uuid.uuid4()
        with tracing.tracer.start_as_current_span("POST /internal/files", kind=SpanKind.SERVER):
            await scans.SqsScanQueue(url, sqs).send(file_id, scan_id)
        [message] = sqs.receive_message(QueueUrl=url, MessageAttributeNames=["All"])["Messages"]
    request, send = spans.get_finished_spans()[::-1]
    assert send.kind is SpanKind.PRODUCER and send.parent.span_id == request.context.span_id
    assert send.attributes["vaultgate.scan_id"] == str(scan_id)
    _, trace_id, span_id, flags = message["MessageAttributes"]["traceparent"]["StringValue"].split(
        "-"
    )
    assert (trace_id, span_id) == (f"{send.context.trace_id:032x}", f"{send.context.span_id:016x}")
    assert int(flags, 16) & 1  # sampled: the scanner keeps its part


async def test_a_resend_starts_its_own_trace(spans):
    """The resender has no request around it: the send itself is where work starts."""
    with mock_aws():
        sqs = boto3.client("sqs", region_name="ap-northeast-1")
        url = sqs.create_queue(QueueName="scans")["QueueUrl"]
        await scans.SqsScanQueue(url, sqs).send(uuid.uuid4(), uuid.uuid4())
    [send] = spans.get_finished_spans()
    assert send.parent is None and send.context.trace_flags.sampled


@pytest.mark.parametrize(
    ("kind", "kept"),
    [
        (SpanKind.SERVER, True),
        (SpanKind.PRODUCER, True),
        (SpanKind.CONSUMER, True),
        (SpanKind.CLIENT, False),  # e.g. a query from a background loop
        (SpanKind.INTERNAL, False),
    ],
)
def test_traces_start_only_where_work_comes_in(spans, kind, kept):
    with (
        tracing.tracer.start_as_current_span("root", kind=kind) as root,
        tracing.tracer.start_as_current_span("child", kind=SpanKind.CLIENT) as child,
    ):
        pass
    assert root.get_span_context().trace_flags.sampled is kept
    assert child.get_span_context().trace_flags.sampled is kept


def test_error_text_never_leaves_the_process(spans):
    with tracing.tracer.start_as_current_span("POST /files", kind=SpanKind.SERVER) as span:
        span.add_event("exception", {"exception.message": "bob@example.com refused"})
        span.set_status(Status(StatusCode.ERROR, 'invalid input value "bob@example.com"'))
    [exported] = spans.get_finished_spans()
    assert exported.status.status_code is StatusCode.ERROR
    assert exported.status.description is None
    assert exported.events == ()


def test_tracing_is_off_without_an_endpoint(monkeypatch):
    for name in ("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"):
        monkeypatch.delenv(name, raising=False)
    assert tracing.enabled() is False
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://alloy:4318")
    assert tracing.enabled() is True
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    assert tracing.enabled() is False


def test_the_global_provider_is_untouched_in_tests():
    # Sanity check for the fixture's approach: nothing above installed a provider.
    assert not isinstance(trace.get_tracer_provider(), type(_provider))
