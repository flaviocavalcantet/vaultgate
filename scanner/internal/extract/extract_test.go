package extract

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/flaviocavalcantet/vaultgate/scanner/internal/detect"
)

// One PDFium for the package: compiling it takes a few seconds.
var pdf *PDFium

func TestMain(m *testing.M) {
	var err error
	pdf, err = NewPDFium(2, 256<<20, 30*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	_ = pdf.Close()
	os.Exit(code)
}

func extractor() *Extractor { return &Extractor{Limits: DefaultLimits(), PDF: pdf} }

// scan extracts data and returns the findings as "kind=value", sorted.
func scan(t *testing.T, e *Extractor, data []byte) ([]string, Report, error) {
	t.Helper()
	var text bytes.Buffer
	report, err := e.Extract(bytes.NewReader(data), int64(len(data)), &text)
	var found []string
	for _, f := range detect.Scan(text.String()) {
		found = append(found, string(f.Kind)+"="+f.Value)
	}
	sort.Strings(found)
	return found, report, err
}

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func expect(t *testing.T, name string, got []string, want ...string) {
	t.Helper()
	sort.Strings(want)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("%s: found %q, want %q", name, got, want)
	}
}

func TestDocuments(t *testing.T) {
	cases := []struct {
		file   string
		format Format
		want   []string
	}{
		// The card spans two Word text runs; the email is in the page header.
		{"report.docx", FormatOfficeXML, []string{
			"payment_card=4111 1111 1111 1111", "br_cpf=529.982.247-25", "email=ana@example.com"}},
		{"clean.docx", FormatOfficeXML, nil},
		// A CPF as text and as a number; four cells of "4111 1111 1111 1111" are not a card.
		{"clients.xlsx", FormatOfficeXML, []string{"br_cpf=529.982.247-25", "br_cpf=52998224725"}},
		{"slides.pptx", FormatOfficeXML, []string{"payment_card=5555 5555 5555 4444"}},
		{"notes.odt", FormatOpenDocument, []string{"br_cpf=529.982.247-25"}},
		// Embedded font with a ToUnicode map, accents, two pages.
		{"report.pdf", FormatPDF, []string{
			"payment_card=4111 1111 1111 1111", "br_cpf=529.982.247-25", "email=ana@example.com"}},
	}
	for _, c := range cases {
		found, report, err := scan(t, extractor(), testdata(t, c.file))
		if err != nil {
			t.Errorf("%s: %v", c.file, err)
			continue
		}
		if report.Format != c.format {
			t.Errorf("%s: format %s, want %s", c.file, report.Format, c.format)
		}
		expect(t, c.file, found, c.want...)
	}
}

func TestPDFKeepsAccents(t *testing.T) {
	var text bytes.Buffer
	data := testdata(t, "report.pdf")
	if _, err := extractor().Extract(bytes.NewReader(data), int64(len(data)), &text); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "Relatório de clientes, São Paulo") {
		t.Errorf("accents lost: %q", text.String())
	}
}

func assertUnscannable(t *testing.T, name string, e *Extractor, data []byte) {
	t.Helper()
	_, _, err := scan(t, e, data)
	if !errors.Is(err, ErrUnscannable) {
		t.Errorf("%s: got %v, want ErrUnscannable", name, err)
	}
}

func TestBrokenAndEncryptedPDFsAreUnscannable(t *testing.T) {
	assertUnscannable(t, "encrypted.pdf", extractor(), testdata(t, "encrypted.pdf"))
	assertUnscannable(t, "truncated.pdf", extractor(), testdata(t, "truncated.pdf"))
	assertUnscannable(t, "fake PDF", extractor(), []byte("%PDF-1.7\nnot really a PDF, CPF 529.982.247-25"))
}

// PDF readers accept the header anywhere in the first KiB, so junk in front must not
// turn a PDF into raw (compressed) bytes the detectors cannot read.
func TestPDFAfterJunkIsStillAPDF(t *testing.T) {
	data := append([]byte("junk before the header\n"), testdata(t, "report.pdf")...)
	found, report, err := scan(t, extractor(), data)
	if err != nil || report.Format != FormatPDF {
		t.Fatalf("format %s, err %v", report.Format, err)
	}
	expect(t, "junk+report.pdf", found,
		"payment_card=4111 1111 1111 1111", "br_cpf=529.982.247-25", "email=ana@example.com")
}

// A text file that only mentions the PDF header is scanned as text, not refused.
func TestTextMentioningAPDFHeaderIsText(t *testing.T) {
	found, report, err := scan(t, extractor(), []byte("Files start with %PDF-1.7. CPF 529.982.247-25"))
	if err != nil || report.Format != FormatText {
		t.Fatalf("format %s, err %v", report.Format, err)
	}
	expect(t, "text", found, "br_cpf=529.982.247-25")
}

type entry struct {
	name  string
	data  []byte
	flags uint16
}

func zipOf(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: zip.Deflate, Flags: e.flags})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestArchivesAreOpened(t *testing.T) {
	inner := zipOf(t,
		entry{name: "export.csv", data: []byte("name;cpf\nAna;529.982.247-25\n")},
		entry{name: "clients.xlsx", data: testdata(t, "clients.xlsx")},
		entry{name: "report.pdf", data: testdata(t, "report.pdf")},
	)
	outer := zipOf(t, entry{name: "inner.zip", data: inner}, entry{name: "readme.txt", data: []byte("hi")})
	found, report, err := scan(t, extractor(), outer)
	if err != nil {
		t.Fatal(err)
	}
	if report.Format != FormatZip || report.Parts != 6 {
		t.Errorf("report %+v, want zip with 6 parts", report)
	}
	expect(t, "nested zip", found,
		"br_cpf=529.982.247-25", "br_cpf=529.982.247-25", "br_cpf=52998224725",
		"payment_card=4111 1111 1111 1111", "br_cpf=529.982.247-25", "email=ana@example.com")
}

// Zip tools find an archive from its end, so one appended to other data still opens.
func TestZipAfterOtherDataIsFound(t *testing.T) {
	data := append(bytes.Repeat([]byte("not a zip "), 1000),
		zipOf(t, entry{name: "export.csv", data: []byte("CPF 529.982.247-25")})...)
	found, report, err := scan(t, extractor(), data)
	if err != nil || report.Format != FormatZip {
		t.Fatalf("format %s, err %v", report.Format, err)
	}
	expect(t, "appended zip", found, "br_cpf=529.982.247-25")
}

// smallContainers opens archives of a few KiB but streams any entry over 4 KiB as text.
func smallContainers() *Extractor {
	e := extractor()
	e.Limits.MaxDocumentBytes = 4096
	return e
}

func TestLimits(t *testing.T) {
	csv := entry{name: "a.csv", data: []byte("CPF 529.982.247-25")}
	nest := func(levels int) []byte {
		data := zipOf(t, csv)
		for i := 1; i < levels; i++ {
			data = zipOf(t, entry{name: "inner.zip", data: data})
		}
		return data
	}
	// Containers count, the text inside them does not: three zips is the default limit.
	if _, _, err := scan(t, extractor(), nest(3)); err != nil {
		t.Errorf("zip > zip > zip > CSV: %v", err)
	}
	assertUnscannable(t, "four zips deep", extractor(), nest(4))

	small := extractor()
	small.Limits.MaxExtractedBytes = 10 << 20
	bomb := zipOf(t, entry{name: "zeros.csv", data: make([]byte, 50<<20)}) // about 50 KiB compressed
	if len(bomb) > 1<<20 {
		t.Fatalf("bomb is %d bytes; expected it to compress", len(bomb))
	}
	assertUnscannable(t, "zip bomb", small, bomb)

	few := extractor()
	few.Limits.MaxEntries = 5
	var many []entry
	for i := 0; i < 6; i++ {
		many = append(many, entry{name: fmt.Sprintf("%d.txt", i), data: []byte("x")})
	}
	assertUnscannable(t, "too many entries", few, zipOf(t, many...))
	if _, _, err := scan(t, few, zipOf(t, many[:5]...)); err != nil {
		t.Errorf("5 entries: %v", err)
	}

	// An entry over the container limit is streamed as text, so it cannot be opened as
	// a container: one holding a zip or PDF anywhere is refused instead.
	bigText := append(bytes.Repeat([]byte("filler "), 1000), []byte("CPF 529.982.247-25")...)
	bigFound, _, err := scan(t, smallContainers(), zipOf(t, entry{name: "big.csv", data: bigText}))
	if err != nil {
		t.Errorf("big text entry: %v", err)
	}
	expect(t, "big text entry", bigFound, "br_cpf=529.982.247-25")
	hidden := append(bytes.Repeat([]byte("filler "), 1000), zipOf(t, csv)...)
	assertUnscannable(t, "zip hidden after padding in a big entry", smallContainers(),
		zipOf(t, entry{name: "padding.bin", data: hidden}))
	hiddenPDF := append(bytes.Repeat([]byte("filler "), 1000), testdata(t, "report.pdf")...)
	assertUnscannable(t, "PDF after padding in a big entry", smallContainers(),
		zipOf(t, entry{name: "padding.bin", data: hiddenPDF}))

	assertUnscannable(t, "encrypted entry", extractor(),
		zipOf(t, entry{name: "secret.csv", data: []byte("x"), flags: 0x1}))

	tight := extractor()
	tight.Limits.MaxDocumentBytes = 1000
	assertUnscannable(t, "PDF over the size limit", tight, testdata(t, "report.pdf"))
	assertUnscannable(t, "zip over the size limit", tight, testdata(t, "clients.xlsx"))
	// Plain text streams through: no size limit.
	text := append(bytes.Repeat([]byte("lorem ipsum "), 1000), []byte("CPF 529.982.247-25")...)
	found, _, err := scan(t, tight, text)
	if err != nil {
		t.Fatalf("large text: %v", err)
	}
	expect(t, "large text", found, "br_cpf=529.982.247-25")
}

// A file that starts like a zip but cannot be opened is a damaged archive: recovery
// tools may still extract it, so scanning its compressed bytes is not a verdict.
func TestDamagedZipIsUnscannable(t *testing.T) {
	assertUnscannable(t, "zip header without an index", extractor(), []byte("PK\x03\x04 broken, CPF 529.982.247-25"))
	whole := zipOf(t, entry{name: "export.csv", data: []byte("CPF 529.982.247-25")})
	assertUnscannable(t, "zip with its end cut off", extractor(), whole[:len(whole)-10])
}

// blockingReader stalls inside PDFium's file reads until released, like a PDF that
// never finishes; PDFium cannot interrupt a call that is waiting in Go.
type blockingReader struct{ release chan struct{} }

func (b blockingReader) Read([]byte) (int, error) { <-b.release; return 0, io.EOF }
func (b blockingReader) Seek(int64, int) (int64, error) {
	<-b.release
	return 0, nil
}

func TestPDFTimeoutIsUnscannableAndBounded(t *testing.T) {
	slow, err := NewPDFium(1, 64<<20, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	slow.killGrace = 500 * time.Millisecond
	reader := blockingReader{release: make(chan struct{})}
	defer close(reader.release)

	started := time.Now()
	var out bytes.Buffer
	_, err = slow.Text(reader, 1000, &out, 1<<20)
	if !errors.Is(err, ErrUnscannable) {
		t.Fatalf("got %v, want ErrUnscannable", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("Text took %v; the timeout and kill grace should bound it", elapsed)
	}
}

// The uploader chooses entry names and content alike: an entry is skipped as media
// only when its bytes are media, and XML is read in full, attributes included.
func TestCraftedOfficeFilesCannotHidePII(t *testing.T) {
	office := func(extra ...entry) []byte {
		return zipOf(t, append([]entry{{name: "[Content_Types].xml", data: []byte("<Types/>")}}, extra...)...)
	}
	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 64)...)
	cases := []struct {
		name string
		data []byte
		want []string
	}{
		{"CSV named as an image", office(entry{name: "word/media/customers.png",
			data: []byte("cpf\n529.982.247-25\n")}), []string{"br_cpf=529.982.247-25"}},
		{"CSV named as relationships", office(entry{name: "_rels/x.rels",
			data: []byte("529.982.247-25")}), []string{"br_cpf=529.982.247-25"}},
		{"PDF named as a font", office(entry{name: "word/fonts/font1.odttf",
			data: testdata(t, "report.pdf")}), []string{
			"payment_card=4111 1111 1111 1111", "br_cpf=529.982.247-25", "email=ana@example.com"}},
		{"PII in an XML attribute", office(entry{name: "word/document.xml",
			data: []byte(`<doc><x v="529.982.247-25"/></doc>`)}), []string{"br_cpf=529.982.247-25"}},
		{"PII in an XML comment", office(entry{name: "word/document.xml",
			data: []byte(`<doc><!-- 4111 1111 1111 1111 --></doc>`)}), []string{"payment_card=4111 1111 1111 1111"}},
		{"a real image yields nothing", office(entry{name: "word/media/image1.png", data: png}), nil},
		// A media signature in front proves nothing either: nothing is skipped.
		{"CSV behind a PNG signature", office(entry{name: "data.csv",
			data: append(bytes.Clone(png[:8]), []byte("\n529.982.247-25\n")...)}), []string{"br_cpf=529.982.247-25"}},
		{"CSV whose first column is ID3", zipOf(t, entry{name: "export.csv",
			data: []byte("ID3;cpf\n1;529.982.247-25\n")}), []string{"br_cpf=529.982.247-25"}},
	}
	for _, c := range cases {
		found, _, err := scan(t, extractor(), c.data)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		expect(t, c.name, found, c.want...)
	}
}

func TestContainerSnifferSeesSignaturesAcrossWrites(t *testing.T) {
	for _, sig := range containerSignatures {
		for split := 0; split <= len(sig); split++ {
			var out bytes.Buffer
			c := &containerSniffer{w: &out, name: "x"}
			_, err1 := c.Write(append([]byte("text before "), sig[:split]...))
			_, err2 := c.Write(append(bytes.Clone(sig[split:]), []byte(" text after")...))
			if !errors.Is(err1, ErrUnscannable) && !errors.Is(err2, ErrUnscannable) {
				t.Errorf("%q split at %d was not noticed", sig, split)
			}
		}
	}
	var out bytes.Buffer
	c := &containerSniffer{w: &out, name: "x"}
	for _, piece := range []string{"PK is a ", "fine word; so is %PD", "F without the dash"} {
		if _, err := c.Write([]byte(piece)); err != nil {
			t.Fatalf("plain text refused: %v", err)
		}
	}
}

// A file can be a PDF and a zip at once: PDF readers start at the header, zip tools at
// the index at the end. Both must be scanned.
func TestPDFWithAZipAppendedIsScannedAsBoth(t *testing.T) {
	data := append(testdata(t, "report.pdf"),
		zipOf(t, entry{name: "customers.csv", data: []byte("cpf\n111.444.777-35\n")})...)
	found, report, err := scan(t, extractor(), data)
	if err != nil || report.Format != FormatPDF {
		t.Fatalf("format %s, err %v", report.Format, err)
	}
	expect(t, "PDF + zip", found, "payment_card=4111 1111 1111 1111", "br_cpf=529.982.247-25",
		"email=ana@example.com", "br_cpf=111.444.777-35")
}

// Files attached to a PDF are not page text; they are documents of their own.
func TestPDFAttachmentsAreScanned(t *testing.T) {
	found, report, err := scan(t, extractor(), testdata(t, "attached.pdf"))
	if err != nil || report.Format != FormatPDF {
		t.Fatalf("format %s, err %v", report.Format, err)
	}
	expect(t, "attached.pdf", found, "payment_card=5555 5555 5555 4444")
	if report.Parts != 2 {
		t.Errorf("parts %d, want 2 (the PDF and its attachment)", report.Parts)
	}
}

func TestPDFAttachmentLimits(t *testing.T) {
	data := testdata(t, "big_attachment.pdf") // a few KiB, with a 1 MiB attachment
	found, _, err := scan(t, extractor(), data)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, "big attachment", found, "payment_card=4111 1111 1111 1111")

	small := extractor()
	small.Limits.MaxDocumentBytes = 64 << 10 // the PDF fits, its attachment does not
	if int64(len(data)) > small.Limits.MaxDocumentBytes {
		t.Fatalf("the PDF itself is %d bytes", len(data))
	}
	assertUnscannable(t, "attachment over the size limit", small, data)
	budget := extractor()
	budget.Limits.MaxExtractedBytes = 512 << 10
	assertUnscannable(t, "attachment over the expansion budget", budget, data)
}

// XML can declare its own entities; office suites expand them, so the scan must see
// the text as a reader does, including a number split across entities.
func TestXMLEntitiesAreExpanded(t *testing.T) {
	odt := func(content string) []byte {
		return zipOf(t,
			entry{name: "mimetype", data: []byte("application/vnd.oasis.opendocument.text")},
			entry{name: "content.xml", data: []byte(content)})
	}
	cases := map[string]string{
		"entity holding a CPF": `<!DOCTYPE doc [<!ENTITY cpf "529.982.247-25">]><doc><p>&cpf;</p></doc>`,
		"CPF split across entities": `<!DOCTYPE doc [<!ENTITY a "247"><!ENTITY b '&#53;&#50;&#57;'>]>` +
			`<doc><p>&b;.982.&a;-25</p></doc>`,
	}
	for name, content := range cases {
		found, _, err := scan(t, extractor(), odt(content))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		// Each place the whole number appears counts: the declaration and the body,
		// or only the body when it is split across entities.
		want := []string{"br_cpf=529.982.247-25"}
		if name == "entity holding a CPF" {
			want = append(want, "br_cpf=529.982.247-25")
		}
		expect(t, name, found, want...)
	}

	// Expansion is charged to the budget: repeating a large entity is a bomb.
	bomb := `<!DOCTYPE doc [<!ENTITY big "` + strings.Repeat("x", 100_000) + `">]><doc><p>` +
		strings.Repeat("&big;", 2000) + `</p></doc>` // 200 MB of text from a 110 KB part
	small := extractor()
	small.Limits.MaxExtractedBytes = 4 << 20 // small, so little text is scanned before refusal
	assertUnscannable(t, "entity expansion bomb", small, odt(bomb))
}

// Expansion is bounded before memory is used, not after: a 1 MiB entity referenced
// 100,000 times (100 GB) in an attribute or in text is refused without building it.
func TestEntityBombsAreRefusedBeforeTheyExpand(t *testing.T) {
	entity := `<!DOCTYPE doc [<!ENTITY big "` + strings.Repeat("x", 1<<20) + `">]>`
	refs := strings.Repeat("&big;", 100_000)
	small := extractor()
	small.Limits.MaxExtractedBytes = 4 << 20 // small, so little text is scanned before refusal
	for name, body := range map[string]string{
		"in text":         `<doc><p>` + refs + `</p></doc>`,
		"in an attribute": `<doc><p v="` + refs + `"/></doc>`,
	} {
		odt := zipOf(t,
			entry{name: "mimetype", data: []byte("application/vnd.oasis.opendocument.text")},
			entry{name: "content.xml", data: []byte(entity + body)})
		assertUnscannable(t, "entity bomb "+name, small, odt)
	}
}
