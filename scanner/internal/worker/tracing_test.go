package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/flaviocavalcantet/vaultgate/scanner/internal/tracing"
)

// As the API sends it with a scan request (sampled).
const senderTrace = "4bf92f3577b34da6a3ce929d0e0e4736"
const senderSpan = "00f067aa0ba902b7"

func recorded(t *testing.T) (*tracetest.SpanRecorder, trace.Tracer) {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	return rec, tracing.NewProvider(rec, "test").Tracer(tracing.Name)
}

func byName(spans []sdktrace.ReadOnlySpan) map[string]sdktrace.ReadOnlySpan {
	out := map[string]sdktrace.ReadOnlySpan{}
	for _, s := range spans {
		out[s.Name()] = s
	}
	return out
}

func attr(s sdktrace.ReadOnlySpan, key string) attribute.Value {
	for _, kv := range s.Attributes() {
		if string(kv.Key) == key {
			return kv.Value
		}
	}
	return attribute.Value{}
}

func TestAScanContinuesTheSendersTrace(t *testing.T) {
	rec, tracer := recorded(t)
	f := newFixture(t, []byte("nothing to see here\n"))
	f.worker.Tracer = tracer
	loop := &Loop{Worker: f.worker, Queue: &fakeQueue{extended: map[string]int{}}, Visibility: time.Minute, JobTimeout: time.Minute}
	loop.process(context.Background(), Delivery{Body: f.body, Handle: "h", Trace: map[string]string{
		"traceparent": "00-" + senderTrace + "-" + senderSpan + "-01",
	}})

	spans := byName(rec.Ended())
	scan, ok := spans["scan"]
	if !ok {
		t.Fatalf("no scan span among %v", spans)
	}
	if scan.SpanKind() != trace.SpanKindConsumer || scan.SpanContext().TraceID().String() != senderTrace ||
		scan.Parent().SpanID().String() != senderSpan {
		t.Fatalf("scan span %v does not continue the sender's trace", scan.SpanContext())
	}
	if got := attr(scan, "vaultgate.outcome").AsString(); got != string(Clean) {
		t.Fatalf("outcome %q, want clean", got)
	}
	for _, name := range []string{"unwrap key", "open object", "read and detect"} {
		s, ok := spans[name]
		if !ok || s.Parent().SpanID() != scan.SpanContext().SpanID() {
			t.Fatalf("%q is not a step of the scan: %v", name, spans)
		}
	}
	if reads := attr(spans["read and detect"], "vaultgate.reads").AsInt64(); reads < 1 {
		t.Fatalf("reads = %d, want at least one", reads)
	}
}

func TestAScanWithoutTraceContextStartsItsOwn(t *testing.T) {
	rec, tracer := recorded(t)
	f := newFixture(t, []byte("text\n"))
	f.worker.Tracer = tracer
	f.worker.Handle(context.Background(), f.body)
	scan := byName(rec.Ended())["scan"]
	if scan == nil || scan.Parent().IsValid() || !scan.SpanContext().IsSampled() {
		t.Fatal("want a sampled root span for the scan")
	}
}

func TestAScanLeftForRetryIsAnError(t *testing.T) {
	rec, tracer := recorded(t)
	f := newFixture(t, []byte("text\n"))
	f.worker.Tracer = tracer
	f.api.jobErr = errors.New("API down: connection refused to 10.0.0.1")
	if got := f.worker.Handle(context.Background(), f.body); got != Retry {
		t.Fatalf("outcome %q, want retry", got)
	}
	scan := byName(rec.Ended())["scan"]
	if scan.Status().Code != codes.Error || scan.Status().Description != "" {
		t.Fatalf("status %+v, want an error without text", scan.Status())
	}
}

func TestScanLogLinesCarryTheTraceID(t *testing.T) {
	rec, tracer := recorded(t)
	f := newFixture(t, []byte("text\n"))
	f.worker.Tracer = tracer
	var out bytes.Buffer
	f.worker.Logger = slog.New(slog.NewJSONHandler(&out, nil))
	f.worker.Handle(context.Background(), f.body)
	scan := byName(rec.Ended())["scan"]
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) == 0 {
		t.Fatal("nothing logged")
	}
	for _, line := range lines {
		var entry map[string]any
		_ = json.Unmarshal([]byte(line), &entry)
		if entry["trace_id"] != scan.SpanContext().TraceID().String() {
			t.Fatalf("line %s has no trace_id of the scan", line)
		}
	}
}

func TestHTTPAPIPassesTheTraceOn(t *testing.T) {
	rec, tracer := recorded(t)
	var traceparent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceparent = r.Header.Get("traceparent")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	api := NewHTTPAPI(srv.URL, "secret")
	api.Tracer = tracer
	ctx, parent := tracer.Start(context.Background(), "scan", trace.WithSpanKind(trace.SpanKindConsumer))
	if _, err := api.Job(ctx, uuid.New()); !errors.Is(err, ErrGone) {
		t.Fatalf("err = %v, want ErrGone", err)
	}
	parent.End()
	call := byName(rec.Ended())["api scan job"]
	if call == nil || call.Parent().SpanID() != parent.SpanContext().SpanID() {
		t.Fatal("the call is not a child of the scan")
	}
	want := "00-" + call.SpanContext().TraceID().String() + "-" + call.SpanContext().SpanID().String() + "-01"
	if traceparent != want {
		t.Fatalf("traceparent %q, want %q", traceparent, want)
	}
	if call.Status().Code == codes.Error {
		t.Fatal("a scan that is no longer pending is not an error")
	}
}
