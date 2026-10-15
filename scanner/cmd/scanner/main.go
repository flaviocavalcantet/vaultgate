// Command scanner reads text on stdin and prints PII findings as JSON lines.
//
// Today this is a CLI so the detectors can be exercised in isolation. The roadmap
// turns it into a worker that consumes "file uploaded" events, streams the object
// from storage, and reports a verdict back to the API.
//
// Findings go to stdout; logs go to stderr as JSON, in the same shape as the
// Python services' logs, so the log pipeline can collect them alongside.
package main

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/flaviocavalcantet/vaultgate/scanner/internal/detect"
)

type result struct {
	Kind  detect.Kind `json:"kind"`
	Start int         `json:"start"`
	End   int         `json:"end"`
}

func main() {
	logger := newLogger(os.Stderr, os.Getenv("VAULTGATE_LOG_LEVEL"))
	if err := run(os.Stdin, os.Stdout, logger); err != nil {
		logger.Error("scan failed", "error", err)
		os.Exit(1)
	}
}

func run(in io.Reader, out io.Writer, logger *slog.Logger) error {
	data, err := io.ReadAll(bufio.NewReader(in))
	if err != nil {
		return err
	}
	findings := detect.Scan(string(data))
	enc := json.NewEncoder(out)
	counts := map[detect.Kind]int{}
	for _, f := range findings {
		counts[f.Kind]++
		// Positions only: matched values never leave the scanner.
		if err := enc.Encode(result{f.Kind, f.Start, f.End}); err != nil {
			return err
		}
	}
	logger.Info("scan complete", "bytes", len(data), "findings", len(findings), "by_kind", counts)
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
