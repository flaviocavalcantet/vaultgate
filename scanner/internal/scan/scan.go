// Package scan runs the detectors over a document's text as it is extracted, through
// a pipe, so a large document's text is never held whole. The CLI and the worker
// share it.
package scan

import (
	"io"

	"github.com/flaviocavalcantet/vaultgate/scanner/internal/detect"
	"github.com/flaviocavalcantet/vaultgate/scanner/internal/extract"
)

// Document extracts the text of the document (size bytes readable through r) and
// calls found for every match. It returns what was extracted and how many bytes of
// text were scanned. An error wrapping extract.ErrUnscannable means the document
// could not be read completely: what was found before is not a full result.
func Document(e *extract.Extractor, r io.ReaderAt, size int64, found func(detect.Finding)) (extract.Report, int64, error) {
	text, sink := io.Pipe()
	done := make(chan extract.Report, 1)
	go func() {
		report, err := e.Extract(r, size, sink)
		_ = sink.CloseWithError(err) // nil closes cleanly
		done <- report
	}()
	// Streamed: memory stays at one window whatever the text size.
	n, err := detect.ScanReader(text, found)
	_ = text.CloseWithError(err) // unblocks the extraction if scanning stopped early
	report := <-done
	return report, n, err
}
