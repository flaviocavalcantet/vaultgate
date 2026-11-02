// Package extract turns an uploaded file into the text the detectors scan.
//
// The format comes from the content, never from the file name or declared type:
//
//   - PDF ("%PDF-" in the first KiB, where PDF readers accept it): the text of every
//     page, through PDFium, and every attached file as a document of its own;
//   - Office Open XML (Word, Excel, PowerPoint) and OpenDocument: the text of their
//     XML parts, with line breaks only at paragraph, cell and row ends, so a number
//     Word splits across text runs stays whole;
//   - any other zip archive: each entry, recursively. Zip tools find an archive from
//     the end of a file, so a zip appended to other data is found the same way,
//     a PDF included: a file that is both is scanned as both;
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
	"regexp"
	"strconv"
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

// PDFText writes the text of a PDF's pages to w and returns the files attached to
// it, refusing (ErrUnscannable) attachments larger than maxAttachments in total.
type PDFText interface {
	Text(r io.ReadSeeker, size int64, w io.Writer, maxAttachments int64) ([]Attachment, error)
}

// Attachment is a file embedded in a PDF.
type Attachment struct {
	Name string
	Data []byte
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
	format := FormatText
	head := make([]byte, min(size, 1024))
	n, _ := r.ReadAt(head, 0)
	if at := bytes.Index(head[:n], []byte("%PDF-")); at >= 0 {
		switch err := x.pdf(r, size, depth); {
		case err == nil:
			format = FormatPDF
		case at > 0 && errors.Is(err, ErrNotPDF): // text that mentions the header
		default:
			return FormatPDF, err
		}
	}
	// Reading the archive index costs only the end of the file, whatever its size. A
	// PDF is probed too: one with a zip appended opens in zip tools as well.
	if zr, err := zip.NewReader(r, size); err == nil && len(zr.File) > 0 {
		if err := x.container(FormatZip, size, depth); err != nil {
			return FormatZip, err
		}
		archive, err := x.archive(zr, depth)
		if format == FormatPDF {
			return format, err
		}
		return archive, err
	}
	if format == FormatPDF {
		return format, nil
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
	attachments, err := x.e.PDF.Text(io.NewSectionReader(r, 0, size), size, x.w, x.e.Limits.MaxDocumentBytes)
	if err != nil {
		return err
	}
	if err := x.separate(); err != nil {
		return err
	}
	// Attachments are documents of their own, scanned once PDFium has let go of this
	// one (an attached PDF needs an instance of its own).
	for _, a := range attachments {
		x.budget += int64(len(a.Data))
		if x.budget > x.e.Limits.MaxExtractedBytes {
			return unscannable("PDF attachments expand beyond %d bytes (at %q)", x.e.Limits.MaxExtractedBytes, a.Name)
		}
		if _, err := x.document(bytes.NewReader(a.Data), int64(len(a.Data)), depth+1); err != nil {
			return err
		}
	}
	return nil
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
// the text; in a plain zip archive every entry is a document. Nothing is skipped as
// "media": the uploader chooses names and first bytes alike, and an image read as
// text yields nothing but costs little.
//
// An entry that fits under MaxDocumentBytes is a document of its own (a nested PDF or
// archive is opened). A larger one is streamed as text, so it cannot be opened as a
// container; holding one anyway (a zip after padding, say) makes the file
// unscannable instead of hiding what is inside.
func (x *run) entry(f *zip.File, container Format, depth int) error {
	if container != FormatZip {
		switch path.Ext(strings.ToLower(f.Name)) {
		case ".xml", ".rels": // parts and their relationships
			return x.xmlText(f)
		}
	}
	rc, err := x.open(f)
	if err != nil {
		return err
	}
	defer rc.Close()
	limit := x.e.Limits.MaxDocumentBytes
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) <= limit {
		_, err = x.document(bytes.NewReader(data), int64(len(data)), depth+1)
		return err
	}
	x.parts++
	sniff := &containerSniffer{w: x.w, name: f.Name}
	if _, err := io.Copy(sniff, io.MultiReader(bytes.NewReader(data), rc)); err != nil {
		return err
	}
	return x.separate()
}

// containerSniffer passes text on, refusing it once it holds the start of a zip
// entry or a PDF header: streamed text cannot be opened as a container.
type containerSniffer struct {
	w    io.Writer
	name string
	tail []byte // the end of the previous write, for signatures across writes
}

var containerSignatures = [][]byte{[]byte("PK\x03\x04"), []byte("%PDF-")}

func (c *containerSniffer) Write(p []byte) (int, error) {
	window := append(c.tail, p...)
	for _, sig := range containerSignatures {
		if bytes.Contains(window, sig) {
			return 0, unscannable("archive entry %q is over the size limit and holds an archive or PDF", c.name)
		}
	}
	keep := min(len(window), 4) // longest signature minus one
	c.tail = append(c.tail[:0], window[len(window)-keep:]...)
	return c.w.Write(p)
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

// xmlText writes the text of an XML part as a reader sees it: character data, and
// also attribute values, comments, processing instructions and declarations, each
// set apart, since a crafted part can put anything there.
//
// Entities declared in the part's DOCTYPE are expanded, as office suites do, so a
// number split across entities ("529.982.&a;-25") comes out whole. External entities
// are never loaded. Go substitutes entity values without parsing them again, so
// nesting cannot multiply them, and the text written is charged to the expansion
// budget, so repetition ("&big;" thousands of times) cannot either.
func (x *run) xmlText(f *zip.File) error {
	rc, err := x.open(f)
	if err != nil {
		return err
	}
	defer rc.Close()
	dec := xml.NewDecoder(rc)
	dec.Strict = false
	dec.Entity = map[string]string{}
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
			if err := x.charge(len(t), f.Name); err != nil {
				return err
			}
			if _, err := x.w.Write(t); err != nil {
				return err
			}
		case xml.Directive:
			for _, m := range entityDecl.FindAllSubmatch(t, -1) {
				value := m[2]
				if value == nil {
					value = m[3]
				}
				dec.Entity[string(m[1])] = string(charRefs(value))
			}
			if err := x.apart(charRefs(t)); err != nil {
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

// An internal general entity: <!ENTITY name "value"> or 'value'. Parameter entities
// (%) and external ones (SYSTEM, PUBLIC) do not match and are never expanded.
var entityDecl = regexp.MustCompile(`<!ENTITY\s+([^\s%"'>]+)\s+(?:"([^"]*)"|'([^']*)')\s*>`)

var charRef = regexp.MustCompile(`&#(x[0-9A-Fa-f]{1,6}|[0-9]{1,7});`)

// charRefs decodes numeric character references (&#53; &#x35;), which are allowed in
// entity values and would otherwise hide what they spell.
func charRefs(b []byte) []byte {
	return charRef.ReplaceAllFunc(b, func(ref []byte) []byte {
		digits, base := string(ref[2:len(ref)-1]), 10
		if digits[0] == 'x' {
			digits, base = digits[1:], 16
		}
		n, err := strconv.ParseUint(digits, base, 32)
		if err != nil || n > 0x10FFFF {
			return ref
		}
		return []byte(string(rune(n)))
	})
}

// charge counts text produced from a part against the expansion budget.
func (x *run) charge(n int, name string) error {
	x.budget += int64(n)
	if x.budget > x.e.Limits.MaxExtractedBytes {
		return unscannable("%q expands beyond %d bytes", name, x.e.Limits.MaxExtractedBytes)
	}
	return nil
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
