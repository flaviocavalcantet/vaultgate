// Command scanner prints the PII findings in a file, or in text on stdin, as JSON
// lines.
//
//	scanner report.pdf     PDF, Word, Excel, PowerPoint, OpenDocument, zip or text
//	scanner < notes.txt    text on stdin
//
// For a file, the format comes from its content, and positions are offsets in the
// extracted text. A file that cannot be scanned completely (encrypted, damaged, over
// a limit) exits with status 3, never as a clean result.
//
// Today this is a CLI so the detectors can be exercised in isolation. The roadmap
// turns it into a worker that consumes "file uploaded" events, streams the object
// from storage, and reports a verdict back to the API.
//
// Findings go to stdout; logs go to stderr as JSON, in the same shape as the
// Python services' logs, so the log pipeline can collect them alongside.
package main

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/flaviocavalcantet/vaultgate/scanner/internal/detect"
	"github.com/flaviocavalcantet/vaultgate/scanner/internal/extract"
)

// Exit status for a file that could not be scanned completely.
const exitUnscannable = 3

type result struct {
	Kind  detect.Kind `json:"kind"`
	Start int         `json:"start"`
	End   int         `json:"end"`
}

func main() {
	logger := newLogger(os.Stderr, os.Getenv("VAULTGATE_LOG_LEVEL"))
	var err error
	if len(os.Args) > 1 {
		err = scanFile(os.Args[1], os.Stdout, logger)
	} else {
		err = run(os.Stdin, os.Stdout, logger)
	}
	switch {
	case errors.Is(err, extract.ErrUnscannable):
		logger.Warn("file cannot be scanned", "reason", err.Error())
		os.Exit(exitUnscannable)
	case err != nil:
		logger.Error("scan failed", "error", err)
		os.Exit(1)
	}
}

func scanFile(name string, out io.Writer, logger *slog.Logger) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	pdf, err := extract.NewPDFium(1, 512<<20, time.Minute)
	if err != nil {
		return err
	}
	defer pdf.Close()
	e := &extract.Extractor{Limits: extract.DefaultLimits(), PDF: pdf}
	return scanDocument(e, f, info.Size(), out, logger)
}

// scanDocument extracts the text and scans it as it comes out, through a pipe, so a
// large document's text is never held whole.
func scanDocument(e *extract.Extractor, r io.ReaderAt, size int64, out io.Writer, logger *slog.Logger) error {
	text, sink := io.Pipe()
	done := make(chan extract.Report, 1)
	go func() {
		report, err := e.Extract(r, size, sink)
		_ = sink.CloseWithError(err) // nil closes cleanly
		done <- report
	}()
	err := run(text, out, logger)
	_ = text.CloseWithError(err) // unblocks the extraction if scanning stopped early
	report := <-done
	if err == nil {
		logger.Info("document read", "format", report.Format, "parts", report.Parts, "text_bytes", report.Bytes)
	}
	return err
}

func run(in io.Reader, out io.Writer, logger *slog.Logger) error {
	enc := json.NewEncoder(out)
	counts := map[detect.Kind]int{}
	findings := 0
	var writeErr error
	// Streamed: memory stays at one window whatever the input size.
	n, err := detect.ScanReader(in, func(f detect.Finding) {
		counts[f.Kind]++
		findings++
		if writeErr == nil {
			// Positions only: matched values never leave the scanner.
			writeErr = enc.Encode(result{f.Kind, f.Start, f.End})
		}
	})
	if err != nil {
		return err
	}
	if writeErr != nil {
		return writeErr
	}
	logger.Info("scan complete", "bytes", n, "findings", findings, "by_kind", counts)
	return nil
}

// newLogger writes JSON lines with the field names the Python services use
// (ts, level, msg, service), so one log query works across all three.
func newLogger(w io.Writer, level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(strings.ToUpper(level))); err != nil {
		lvl = slog.LevelInfo
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: lvl,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) > 0 {
				return a
			}
			switch a.Key {
			case slog.TimeKey:
				a.Key = "ts"
			case slog.LevelKey:
				a.Value = slog.StringValue(strings.ToLower(a.Value.String()))
			}
			return a
		},
	})
	return slog.New(h).With("service", "scanner")
}
