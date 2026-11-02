package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/flaviocavalcantet/vaultgate/scanner/internal/extract"
)

func TestRunLogsCountsButNeverValues(t *testing.T) {
	var out, logs bytes.Buffer
	input := "Contact ana@example.com, CPF 529.982.247-25"
	if err := run(strings.NewReader(input), &out, newLogger(&logs, "info")); err != nil {
		t.Fatal(err)
	}

	if got := strings.Count(out.String(), "\n"); got != 2 {
		t.Fatalf("want 2 findings on stdout, got %d: %s", got, out.String())
	}

	var entry map[string]any
	if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
		t.Fatalf("log line is not JSON: %v: %s", err, logs.String())
	}
	for key, want := range map[string]any{"level": "info", "service": "scanner", "msg": "scan complete", "findings": 2.0} {
		if entry[key] != want {
			t.Errorf("log %s = %v, want %v", key, entry[key], want)
		}
	}
	if _, ok := entry["ts"]; !ok {
		t.Error("log line has no ts field")
	}
	for _, secret := range []string{"ana@example.com", "529.982.247-25"} {
		if strings.Contains(logs.String()+out.String(), secret) {
			t.Errorf("matched value %q leaked into output", secret)
		}
	}
}

func TestLoggerLevelFilter(t *testing.T) {
	var logs bytes.Buffer
	logger := newLogger(&logs, "warn")
	logger.Info("hidden")
	logger.Warn("shown")
	if strings.Contains(logs.String(), "hidden") || !strings.Contains(logs.String(), `"level":"warn"`) {
		t.Fatalf("unexpected log output: %s", logs.String())
	}
}

func TestScanDocumentExtractsBeforeScanning(t *testing.T) {
	var out, logs bytes.Buffer
	e := &extract.Extractor{Limits: extract.DefaultLimits()}
	data, err := os.ReadFile("../../internal/extract/testdata/report.docx")
	if err != nil {
		t.Fatal(err)
	}
	if err := scanDocument(e, bytes.NewReader(data), int64(len(data)), &out, newLogger(&logs, "info")); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{`"kind":"payment_card"`, `"kind":"br_cpf"`, `"kind":"email"`} {
		if !strings.Contains(out.String(), kind) {
			t.Errorf("no %s finding in %s", kind, out.String())
		}
	}
	if !strings.Contains(logs.String(), `"format":"office"`) {
		t.Errorf("format not logged: %s", logs.String())
	}
	for _, secret := range []string{"4111", "529.982", "ana@example.com"} {
		if strings.Contains(out.String()+logs.String(), secret) {
			t.Errorf("matched value %q leaked into output", secret)
		}
	}
}

func TestScanDocumentReportsUnscannableFiles(t *testing.T) {
	var out, logs bytes.Buffer
	e := &extract.Extractor{Limits: extract.DefaultLimits()} // no PDF support configured
	err := scanDocument(e, strings.NewReader("%PDF-1.7 not really"), 19, &out, newLogger(&logs, "info"))
	if !errors.Is(err, extract.ErrUnscannable) {
		t.Fatalf("got %v, want ErrUnscannable", err)
	}
}
