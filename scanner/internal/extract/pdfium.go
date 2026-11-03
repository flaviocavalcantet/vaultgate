package extract

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/klippa-app/go-pdfium"
	pdfiumerrors "github.com/klippa-app/go-pdfium/errors"
	"github.com/klippa-app/go-pdfium/references"
	"github.com/klippa-app/go-pdfium/requests"
	"github.com/klippa-app/go-pdfium/webassembly"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
)

// PDFium extracts PDF text with PDFium, the PDF engine in Chrome, compiled to
// WebAssembly and run by wazero inside this process. Parsing untrusted PDFs happens
// in a memory-isolated sandbox with its own memory cap, each document in a fresh
// instance, and a document that takes too long is stopped and reported unscannable.
type PDFium struct {
	pool    pdfium.Pool
	timeout time.Duration
	// After a timeout, how long to wait for the stopped instance to return. A kill
	// interrupts PDFium's own code, but not a call blocked in Go (reading the file).
	killGrace time.Duration
}

// NewPDFium compiles PDFium (a few seconds, once per process). maxMemory caps each
// instance's memory; timeout bounds the work on one document.
func NewPDFium(workers int, maxMemory int64, timeout time.Duration) (*PDFium, error) {
	pool, err := webassembly.Init(webassembly.Config{
		MinIdle:  1,
		MaxIdle:  workers,
		MaxTotal: workers,
		// go-pdfium's own runtime config plus our limits; PDFium needs exception handling.
		RuntimeConfig: wazero.NewRuntimeConfig().
			WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesExceptionHandling).
			WithMemoryLimitPages(uint32(maxMemory / 65536)). // WebAssembly pages are 64 KiB
			WithCloseOnContextDone(true),                    // so a killed instance stops running
	})
	if err != nil {
		return nil, fmt.Errorf("starting PDFium: %w", err)
	}
	return &PDFium{pool: pool, timeout: timeout, killGrace: 5 * time.Second}, nil
}

func (p *PDFium) Close() error { return p.pool.Close() }

// Text writes the text of every page to w, pages separated by a line break, and
// returns the attached files.
func (p *PDFium) Text(r io.ReadSeeker, size int64, w io.Writer, maxAttachments int64) ([]Attachment, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()
	instance, err := p.pool.GetInstanceWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("no PDFium instance: %w", err) // busy: retry later, not a verdict
	}
	out := &guardedWriter{w: w}
	type result struct {
		attachments []Attachment
		err         error
	}
	done := make(chan result, 1)
	go func() {
		attachments, err := read(instance, r, size, out, maxAttachments)
		done <- result{attachments, err}
	}()
	select {
	case res := <-done:
		_ = instance.Close()
		return res.attachments, res.err
	case <-ctx.Done():
		out.close() // nothing more reaches w, even if the instance keeps going
		_ = instance.Kill()
		select {
		case <-done:
		case <-time.After(p.killGrace):
		}
		return nil, unscannable("PDF took longer than %v", p.timeout)
	}
}

// guardedWriter stops passing writes on once closed.
type guardedWriter struct {
	mu     sync.Mutex
	w      io.Writer
	closed bool
}

func (g *guardedWriter) Write(b []byte) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return 0, errors.New("PDF extraction was stopped")
	}
	return g.w.Write(b)
}

func (g *guardedWriter) close() {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
}

func read(instance pdfium.Pdfium, r io.ReadSeeker, size int64, w io.Writer, maxAttachments int64) ([]Attachment, error) {
	doc, err := instance.OpenDocument(&requests.OpenDocument{FileReader: r, FileReaderSize: size})
	if err != nil {
		switch {
		case errors.Is(err, pdfiumerrors.ErrFormat):
			return nil, fmt.Errorf("%w: %w", ErrUnscannable, ErrNotPDF)
		case errors.Is(err, pdfiumerrors.ErrPassword), errors.Is(err, pdfiumerrors.ErrSecurity):
			return nil, unscannable("PDF is encrypted")
		default:
			return nil, unscannable("PDF cannot be opened: %v", err)
		}
	}
	defer instance.FPDF_CloseDocument(&requests.FPDF_CloseDocument{Document: doc.Document})
	count, err := instance.FPDF_GetPageCount(&requests.FPDF_GetPageCount{Document: doc.Document})
	if err != nil {
		return nil, unscannable("PDF page count: %v", err)
	}
	for i := 0; i < count.PageCount; i++ {
		text, err := instance.GetPageText(&requests.GetPageText{
			Page: requests.Page{ByIndex: &requests.PageByIndex{Document: doc.Document, Index: i}},
		})
		if err != nil {
			return nil, unscannable("PDF page %d: %v", i+1, err)
		}
		if _, err := io.WriteString(w, text.Text+"\n"); err != nil {
			return nil, err
		}
	}
	return attachments(instance, doc.Document, maxAttachments)
}

// attachments returns the files embedded in a PDF, at most max bytes in total.
func attachments(instance pdfium.Pdfium, doc references.FPDF_DOCUMENT, max int64) ([]Attachment, error) {
	count, err := instance.FPDFDoc_GetAttachmentCount(&requests.FPDFDoc_GetAttachmentCount{Document: doc})
	if err != nil {
		return nil, unscannable("PDF attachments: %v", err)
	}
	var out []Attachment
	var total int64
	for i := 0; i < count.AttachmentCount; i++ {
		a, err := instance.FPDFDoc_GetAttachment(&requests.FPDFDoc_GetAttachment{Document: doc, Index: i})
		if err != nil {
			return nil, unscannable("PDF attachment %d: %v", i+1, err)
		}
		name := fmt.Sprintf("attachment %d", i+1)
		if n, err := instance.FPDFAttachment_GetName(&requests.FPDFAttachment_GetName{Attachment: a.Attachment}); err == nil {
			name = n.Name
		}
		file, err := instance.FPDFAttachment_GetFile(&requests.FPDFAttachment_GetFile{Attachment: a.Attachment})
		if err != nil || file.Contents == nil {
			return nil, unscannable("PDF attachment %q cannot be read", name)
		}
		total += int64(len(file.Contents))
		if total > max {
			return nil, unscannable("PDF attachments are over the %d-byte limit", max)
		}
		out = append(out, Attachment{Name: name, Data: file.Contents})
	}
	return out, nil
}
