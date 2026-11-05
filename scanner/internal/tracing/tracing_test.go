package tracing

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestErrorTextNeverLeavesTheProcess(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	provider := NewProvider(sdktrace.NewSimpleSpanProcessor(Redacting{exp}), "test")
	_, span := provider.Tracer(Name).Start(context.Background(), "scan")
	span.RecordError(errors.New("reading bob@example.com.pdf failed"))
	span.SetStatus(codes.Error, "cpf 123.456.789-09 rejected")
	span.End()
	got := exp.GetSpans()
	if len(got) != 1 || got[0].Status.Code != codes.Error || got[0].Status.Description != "" || len(got[0].Events) != 0 {
		t.Fatalf("exported %+v, want an error status with no text and no events", got)
	}
}

func TestEnabledOnlyWithAnEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	if Enabled() {
		t.Fatal("enabled without an endpoint")
	}
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://alloy:4318")
	if !Enabled() {
		t.Fatal("not enabled with an endpoint")
	}
	t.Setenv("OTEL_SDK_DISABLED", "true")
	if Enabled() {
		t.Fatal("enabled although OTEL_SDK_DISABLED=true")
	}
}
