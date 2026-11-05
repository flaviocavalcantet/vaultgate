"""Traces (ADR 0008): one span per upload or download, with its calls as children."""

import io
import json
import logging
import uuid

from opentelemetry.instrumentation.botocore import BotocoreInstrumentor
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, Status, StatusCode
from tornado.testing import gen_test

from tests.test_api_client import SECRET, InternalApiTest
from tests.test_app import TOKEN, GatewayCase, MiB
from vaultgate_gateway import tracing
from vaultgate_gateway.api_client import InternalApi
from vaultgate_gateway.logs import JsonFormatter

_exporter = InMemorySpanExporter()
_provider = tracing.make_provider(SimpleSpanProcessor(tracing.RedactingExporter(_exporter)))

TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


class Traced:
    """Swaps in a recording tracer (the global provider stays unset, as in a deployment
    without an OTLP endpoint) and instruments boto3 against it."""

    def setUp(self) -> None:
        self._tracer = tracing.tracer
        tracing.tracer = _provider.get_tracer("vaultgate.gateway")
        BotocoreInstrumentor().instrument(tracer_provider=_provider)
        _exporter.clear()
        super().setUp()

    def tearDown(self) -> None:
        super().tearDown()
        BotocoreInstrumentor().uninstrument()
        tracing.tracer = self._tracer

    def spans(self, kind: SpanKind | None = None) -> list[ReadableSpan]:
        return [s for s in _exporter.get_finished_spans() if kind is None or s.kind is kind]


class GatewayTracingTest(Traced, GatewayCase):
    def test_an_upload_is_one_span_with_its_storage_calls_inside(self) -> None:
        payload = b"x" * (6 * MiB)  # two S3 parts, uploaded while the body arrives
        file_id = self.api.grant(len(payload))
        assert self.put(file_id, payload).code == 201

        [request] = self.spans(SpanKind.SERVER)
        assert request.name == "PUT /uploads/{upload_id}"
        assert request.attributes["vaultgate.file_id"] == str(file_id)
        assert request.attributes["http.response.status_code"] == 201
        assert request.attributes["vaultgate.bytes_in"] == len(payload)
        calls = {s.name for s in self.spans(SpanKind.CLIENT)}
        assert {"KMS.GenerateDataKey", "S3.UploadPart", "S3.CompleteMultipartUpload"} <= calls
        # Parts are uploaded from data_received, outside the request's coroutine: they
        # still belong to the request.
        for span in self.spans(SpanKind.CLIENT):
            assert span.context.trace_id == request.context.trace_id
            assert span.parent.span_id == request.context.span_id

    def test_a_download_records_what_it_sent(self) -> None:
        payload = b"y" * 1000
        file_id = self.api.grant(len(payload))
        self.put(file_id, payload)
        _exporter.clear()
        token = self.api.grant_download(file_id)
        response = self.fetch(f"/downloads/{file_id}", headers={"Authorization": f"Bearer {token}"})
        assert response.code == 200
        [request] = self.spans(SpanKind.SERVER)
        assert request.name == "GET /downloads/{download_id}"
        assert request.attributes["vaultgate.bytes_out"] == len(payload)
        assert "KMS.Decrypt" in {s.name for s in self.spans(SpanKind.CLIENT)}

    def test_a_refusal_records_why(self) -> None:
        assert self.put(uuid.uuid4(), b"abc", token="nope").code == 403
        [request] = self.spans(SpanKind.SERVER)
        assert request.attributes["vaultgate.failure"] == "intent_refused"
        assert request.attributes["http.response.status_code"] == 403
        assert request.status.status_code is StatusCode.UNSET

    def test_an_unavailable_api_marks_the_span_failed(self) -> None:
        file_id = self.api.grant(3)
        self.api.down = True
        assert self.put(file_id, b"abc").code == 503
        [request] = self.spans(SpanKind.SERVER)
        assert request.status.status_code is StatusCode.ERROR
        assert request.attributes["vaultgate.failure"] == "api_unavailable"

    def test_a_clients_trace_context_is_ignored(self) -> None:
        file_id = self.api.grant(3)
        self.put(file_id, b"abc", headers={"traceparent": TRACEPARENT})
        [request] = self.spans(SpanKind.SERVER)
        assert request.parent is None
        assert f"{request.context.trace_id:032x}" not in TRACEPARENT

    def test_probes_are_not_traced(self) -> None:
        self.fetch("/healthz")
        assert self.spans() == []

    def test_log_lines_carry_the_trace_id(self) -> None:
        out = io.StringIO()
        handler = logging.StreamHandler(out)
        handler.setFormatter(JsonFormatter("gateway"))
        access = logging.getLogger("vaultgate.access")
        access.addHandler(handler)
        previous = access.level
        access.setLevel(logging.INFO)
        try:
            self.put(self.api.grant(3), b"abc")
        finally:
            access.removeHandler(handler)
            access.setLevel(previous)
        [request] = self.spans(SpanKind.SERVER)
        [line] = [json.loads(line) for line in out.getvalue().splitlines()]
        assert line["trace_id"] == f"{request.context.trace_id:032x}"


class ApiClientTracingTest(Traced, InternalApiTest):
    @gen_test
    async def test_calls_to_the_api_carry_the_trace(self) -> None:
        with tracing.tracer.start_as_current_span("PUT /uploads", kind=SpanKind.SERVER) as parent:
            await InternalApi(self.get_url(""), SECRET).consume_upload(TOKEN, uuid.uuid4(), None)
        [call] = self.spans(SpanKind.CLIENT)
        assert call.name == "api consume upload"
        assert call.parent.span_id == parent.get_span_context().span_id
        assert call.attributes["http.response.status_code"] == 200
        [headers] = self._app.settings["headers"]
        assert headers["traceparent"].split("-")[1:3] == [
            f"{call.context.trace_id:032x}",
            f"{call.context.span_id:016x}",
        ]


def test_error_text_never_leaves_the_process() -> None:
    _exporter.clear()
    tracer = _provider.get_tracer("t")
    with tracer.start_as_current_span("PUT /uploads", kind=SpanKind.SERVER) as span:
        span.add_event("exception", {"exception.message": "bucket vault refused"})
        span.set_status(Status(StatusCode.ERROR, "AccessDenied for files/..."))
    [exported] = _exporter.get_finished_spans()
    assert exported.status.status_code is StatusCode.ERROR
    assert exported.status.description is None
    assert exported.events == ()
