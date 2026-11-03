// Package logging writes JSON log lines with the field names the Python services use
// (ts, level, msg, service), so one log query works across all three.
package logging

import (
	"io"
	"log/slog"
	"strings"
)

// New returns a logger for the scanner at the given level (debug, info, warn, error;
// default info).
func New(w io.Writer, level string) *slog.Logger {
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
