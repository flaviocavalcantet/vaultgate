// Package extract turns an uploaded file into the text the detectors scan.
//
// The format comes from the content, never from the file name or declared type:
//
//   - PDF ("%PDF-" in the first KiB, where PDF readers accept it): the text of every
//     page, through PDFium;
//   - Office Open XML (Word, Excel, PowerPoint) and OpenDocument: the text of their
//     XML parts, with line breaks only at paragraph, cell and row ends, so a number
//     Word splits across text runs stays whole;
//   - any other zip archive: each entry, recursively. Zip tools find an archive from
//     the end of a file, so a zip appended to other data is found the same way;
//   - anything else: the bytes as they are (plain text, CSV, JSON, ...).
//
// Detection leans towards opening a file: a PDF or zip scanned as raw bytes would
// hide its compressed content. The one exception is a text file that merely
// mentions "%PDF-" after its first byte: when PDFium says it is not a PDF, it is
// scanned as text instead of being refused.
//
// Documents inside documents (an Excel sheet embedded in Word, a CSV in a zip) are
// opened too, up to Limits.MaxDepth, so packing a file does not hide it.
//
// Every limit fails closed: a file that exceeds one, is encrypted, or cannot be
// parsed returns an error wrapping ErrUnscannable, and the caller must treat it as
// not scanned, never as clean. Decompressed sizes are counted as bytes come out, not
// taken from archive headers, which an attacker controls.
package extract

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// ErrUnscannable means the file could not be scanned completely: an empty verdict
// would be a guess. Wrapped errors say why.
var ErrUnscannable = errors.New("extract: file cannot be scanned")

// ErrNotPDF is what a PDFText implementation wraps (with ErrUnscannable) when the
// data is not a PDF at all, as opposed to an encrypted or damaged one.
var ErrNotPDF = errors.New("not a PDF")

// Format is what a file was recognized as.
type Format string

const (
	FormatText         Format = "text"
	FormatPDF          Format = "pdf"
	FormatOfficeXML    Format = "office"
	FormatOpenDocument Format = "opendocument"
	FormatZip          Format = "zip"
)

// Limits bound the work one file can cause.
type Limits struct {
	// PDFs and archives larger than this are not opened (they need random access).
	MaxDocumentBytes int64
	// Total bytes decompressed or extracted from one file, across all nesting.
	MaxExtractedBytes int64
	// Total archive entries visited, across all nesting.
	MaxEntries int
	// Containers (PDFs, archives) inside each other: a zip in a zip is depth 2. The
	// text inside the deepest one does not count.
	MaxDepth int
}

// DefaultLimits suit uploads of up to 5 GiB: text streams through without a size
// limit; containers are capped.
func DefaultLimits() Limits {
	return Limits{
		MaxDocumentBytes:  100 << 20,
		MaxExtractedBytes: 1 << 30,
		MaxEntries:        10000,
		MaxDepth:          3,
	}
}

// PDFText writes the text of a PDF's pages to w.
type PDFText interface {
	Text(r io.ReadSeeker, size int64, w io.Writer) error
}

// Extractor extracts text within its limits.
type Extractor struct {
	Limits Limits
	PDF    PDFText
}

// Report says what was extracted.
type Report struct {
	Format Format // of the file itself
	Parts  int    // documents and archive entries read, the file included
	Bytes  int64  // bytes written to the scan
}

// Extract writes the text of the file (size bytes readable through r) to w.
func (e *Extractor) Extract(r io.ReaderAt, size int64, w io.Writer) (Report, error) {
	run := &run{e: e, w: &countingWriter{w: w}}
	format, err := run.document(r, size, 1)
	return Report{Format: format, Parts: run.parts, Bytes: run.w.n}, err
}

type run struct {
	e       *Extractor
	w       *countingWriter
	parts   int
	entries int
	budget  int64 // bytes decompressed so far
}

func unscannable(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnscannable, fmt.Sprintf(format, args...))
}

func (x *run) document(r io.ReaderAt, size int64, depth int) (Format, error) {
	x.parts++
	head := make([]byte, min(size, 1024))
	n, _ := r.ReadAt(head, 0)
	if at := bytes.Index(head[:n], []byte("%PDF-")); at >= 0 {
		err := x.pdf(r, size, depth)
		if !(at > 0 && errors.Is(err, ErrNotPDF)) {
			return FormatPDF, err
		}
	}
	// Reading the archive index costs only the end of the file, whatever its size.
	if zr, err := zip.NewReader(r, size); err == nil && len(zr.File) > 0 {
		if err := x.container(FormatZip, size, depth); err != nil {
			return FormatZip, err
		}
		return x.archive(zr, depth)
	}
	if _, err := io.Copy(x.w, io.NewSectionReader(r, 0, size)); err != nil {
		return FormatText, err
	}
	return FormatText, x.separate()
}

func (x *run) pdf(r io.ReaderAt, size int64, depth int) error {
	if err := x.container(FormatPDF, size, depth); err != nil {
		return err
	}
	if x.e.PDF == nil {
		return unscannable("no PDF support configured")
	}
	if err := x.e.PDF.Text(io.NewSectionReader(r, 0, size), size, x.w); err != nil {
		return err
	}
	return x.separate()
}

// container checks the limits on opening a PDF or an archive.
func (x *run) container(format Format, size int64, depth int) error {
	if depth > x.e.Limits.MaxDepth {
		return unscannable("%s nested deeper than %d containers", format, x.e.Limits.MaxDepth)
	}
	if size > x.e.Limits.MaxDocumentBytes {
		return unscannable("%s of %d bytes is over the %d-byte limit", format, size, x.e.Limits.MaxDocumentBytes)
	}
	return nil
}

// separate ends one part's text, so the last word of one part and the first of the
// next never join into a match.
func (x *run) separate() error {
	_, err := io.WriteString(x.w, "\n")
	return err
}

func (x *run) archive(zr *zip.Reader, depth int) (Format, error) {
	format := FormatZip
	for _, f := range zr.File {
		switch {
		case f.Name == "[Content_Types].xml":
			format = FormatOfficeXML
		case f.Name == "mimetype" && format == FormatZip:
			if mime, err := x.small(f, 256); err == nil &&
				strings.HasPrefix(string(mime), "application/vnd.oasis.opendocument") {
				format = FormatOpenDocument
			}
		}
	}
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			continue // directory
		}
		x.entries++
		if x.entries > x.e.Limits.MaxEntries {
			return format, unscannable("more than %d archive entries", x.e.Limits.MaxEntries)
		}
		if f.Flags&0x1 != 0 {
			return format, unscannable("encrypted archive entry %q", f.Name)
		}
		if err := x.entry(f, format, depth); err != nil {
			return format, err
		}
	}
	return format, nil
}

// entry reads one archive entry. In Office and OpenDocument files the XML parts hold
// the text; other entries are media or embedded documents. In a plain zip archive
// every entry is a document. Names do not decide what is skipped: the uploader
// chooses them. An entry is skipped only when its first bytes are an image, audio,
// video or font; anything else, whatever it is called, is opened as a document.
func (x *run) entry(f *zip.File, container Format, depth int) error {
	if container != FormatZip {
		switch ext := path.Ext(strings.ToLower(f.Name)); {
		case ext == ".xml" || ext == ".rels": // parts and their relationships
			return x.xmlText(f)
		}
	}
	head, err := x.head(f, 64)
	if err != nil {
		return err
	}
	if isMedia(head) {
		return nil
	}
	data, err := x.small(f, x.e.Limits.MaxDocumentBytes)
	if err != nil {
		return err
	}
	_, err = x.document(bytes.NewReader(data), int64(len(data)), depth+1)
	return err
}

// head reads the first n bytes of an entry, charged to the budget like the rest.
func (x *run) head(f *zip.File, n int) ([]byte, error) {
	rc, err := x.open(f)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	buf := make([]byte, n)
	got, err := io.ReadFull(rc, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return buf[:got], nil
}

// isMedia recognizes the binary media Office files embed, by their magic numbers.
// Text hidden after a media file's own data is not looked for.
func isMedia(head []byte) bool {
	for _, magic := range [][]byte{
		[]byte("\x89PNG\r\n\x1a\n"), []byte("\xff\xd8\xff"), []byte("GIF87a"), []byte("GIF89a"),
		[]byte("II*\x00"), []byte("MM\x00*"), []byte("\xd7\xcd\xc6\x9a"), // TIFF, WMF
		[]byte("\x00\x01\x00\x00"), []byte("OTTO"), []byte("wOFF"), []byte("wOF2"), // fonts
		[]byte("ID3"), []byte("OggS"), []byte("fLaC"), []byte("\x1aE\xdf\xa3"), // audio, Matroska
	} {
		if bytes.HasPrefix(head, magic) {
			return true
		}
	}
	switch {
	case len(head) >= 12 && string(head[4:8]) == "ftyp": // MP4, MOV, M4A, HEIC
		return true
	case len(head) >= 12 && string(head[:4]) == "RIFF" &&
		(string(head[8:12]) == "WAVE" || string(head[8:12]) == "AVI " || string(head[8:12]) == "WEBP"):
		return true
	case len(head) >= 44 && head[0] == 1 && string(head[40:44]) == " EMF":
		return true
	}
	return false
}

// open returns an entry's decompressed bytes as they come out, charged to the run's
// budget whatever the archive header claims.
func (x *run) open(f *zip.File) (io.ReadCloser, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, unscannable("archive entry %q: %v", f.Name, err)
	}
	return &budgetReader{rc: rc, run: x, name: f.Name}, nil
}

// small reads a whole entry, refusing one larger than limit.
func (x *run) small(f *zip.File, limit int64) ([]byte, error) {
	rc, err := x.open(f)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, unscannable("archive entry %q is over the %d-byte limit", f.Name, limit)
	}
	return data, nil
}

// Elements that end a paragraph, a cell or a row in Word, Excel, PowerPoint and
// OpenDocument. Text runs inside them are joined without a separator: Word splits
// words and numbers across runs.
var breakElements = map[string]bool{
	"p": true, "h": true, "br": true, "cr": true, "tab": true, // paragraphs, breaks
	"tc": true, "tr": true, "c": true, "row": true, "si": true, "is": true, // tables, cells
	"table-cell": true, "table-row": true, "line-break": true, "list-item": true, // OpenDocument
}

// xmlText writes the text of an XML part: character data, and also attribute values,
// comments and processing instructions, each followed by a break, since a crafted
// part can put anything there. Go's XML decoder does not load external entities or
// expand custom ones, so no entity tricks apply.
func (x *run) xmlText(f *zip.File) error {
	rc, err := x.open(f)
	if err != nil {
		return err
	}
	defer rc.Close()
	dec := xml.NewDecoder(rc)
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return x.separate()
		}
		if err != nil {
			if errors.Is(err, ErrUnscannable) {
				return err
			}
			return unscannable("XML part %q: %v", f.Name, err)
		}
		switch t := tok.(type) {
		case xml.CharData:
			if _, err := x.w.Write(t); err != nil {
				return err
			}
		case xml.StartElement:
			for _, attr := range t.Attr {
				if err := x.apart([]byte(attr.Value)); err != nil {
					return err
				}
			}
		case xml.Comment:
			if err := x.apart(t); err != nil {
				return err
			}
		case xml.ProcInst:
			if err := x.apart(t.Inst); err != nil {
				return err
			}
		case xml.EndElement:
			if breakElements[t.Name.Local] {
				if err := x.separate(); err != nil {
					return err
				}
			}
		}
	}
}

// apart writes text set off from what surrounds it.
func (x *run) apart(text []byte) error {
	if err := x.separate(); err != nil {
		return err
	}
	if _, err := x.w.Write(text); err != nil {
		return err
	}
	return x.separate()
}

type budgetReader struct {
	rc   io.ReadCloser
	run  *run
	name string
}

func (b *budgetReader) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	b.run.budget += int64(n)
	if b.run.budget > b.run.e.Limits.MaxExtractedBytes {
		return n, unscannable("archive expands beyond %d bytes (at %q)", b.run.e.Limits.MaxExtractedBytes, b.name)
	}
	if err != nil && err != io.EOF {
		return n, unscannable("archive entry %q: %v", b.name, err)
	}
	return n, err
}

func (b *budgetReader) Close() error { return b.rc.Close() }

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
