// Package tracing sets up OpenTelemetry for the scanner worker (ADR 0008), with the
// same rules as the Python services: off unless an OTLP endpoint is configured
// (OTEL_EXPORTER_OTLP_ENDPOINT or OTEL_EXPORTER_OTLP_TRACES_ENDPOINT; OTEL_SDK_DISABLED=true
// turns it off), spans carry identifiers and outcomes but never personal data or error
// text, and log lines written for a scan carry its trace_id.
//
// A scan continues the trace of the request that sent it: the API puts the W3C trace
// context in the SQS message's attributes (Extract), and the scanner passes it on to
// the API's internal routes in the traceparent header (Inject).
package tracing

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Name is the instrumentation scope of the scanner's spans.
const Name = "vaultgate/scanner"

// Propagator is the W3C trace context, the one format all three services use.
var Propagator = propagation.TraceContext{}

// Enabled says whether an OTLP endpoint is configured.
func Enabled() bool {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("OTEL_SDK_DISABLED")), "true") {
		return false
	}
	return os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" || os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != ""
}

// Setup returns the tracer the worker uses and a function that flushes and stops it.
// Without an endpoint the tracer records nothing (trace context is still passed on).
func Setup(ctx context.Context, version string) (trace.Tracer, func(context.Context) error, error) {
	if !Enabled() {
		return noop.NewTracerProvider().Tracer(Name), func(context.Context) error { return nil }, nil
	}
	exporter, err := otlptracehttp.New(ctx) // endpoint and options from OTEL_* variables
	if err != nil {
		return nil, nil, err
	}
	provider := NewProvider(sdktrace.NewBatchSpanProcessor(Redacting{exporter}), version)
	return provider.Tracer(Name), provider.Shutdown, nil
}

// NewProvider returns a provider for the scanner's resource. The default sampler
// (parent-based, sampling roots) suits it: its only roots are scans, which is where
// its work comes in.
func NewProvider(processor sdktrace.SpanProcessor, version string) *sdktrace.TracerProvider {
	return sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(processor),
		sdktrace.WithResource(resource.NewSchemaless(
			attribute.String("service.name", "scanner"),
			attribute.String("service.namespace", "vaultgate"),
			attribute.String("service.version", version),
		)),
	)
}

// Redacting exports spans without status descriptions or events: error text (an
// HTTP client's, a parser's) can quote what it was given.
type Redacting struct{ sdktrace.SpanExporter }

func (r Redacting) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	out := make([]sdktrace.ReadOnlySpan, len(spans))
	for i, s := range spans {
		if s.Status().Description == "" && len(s.Events()) == 0 {
			out[i] = s
			continue
		}
		stub := tracetest.SpanStubFromReadOnlySpan(s)
		stub.Status.Description = ""
		stub.Events = nil
		out[i] = stub.Snapshot()
	}
	return r.SpanExporter.ExportSpans(ctx, out)
}

// LogAttrs are the span's IDs for log lines, if it is one that is kept.
func LogAttrs(span trace.Span) []any {
	sc := span.SpanContext()
	if !sc.IsValid() || !sc.IsSampled() {
		return nil
	}
	return []any{slog.String("trace_id", sc.TraceID().String()), slog.String("span_id", sc.SpanID().String())}
}
