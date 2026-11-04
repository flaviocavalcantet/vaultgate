package extract

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// Well-known test values, valid by their check digits.
const (
	card = "card=4111 1111 1111 1111"
	cpf  = "br_cpf=529.982.247-25"
	text = "Card 4111 1111 1111 1111, CPF 529.982.247-25."
)

func encodeUTF16(s string, bigEndian, bom bool) []byte {
	var order binary.ByteOrder = binary.LittleEndian
	if bigEndian {
		order = binary.BigEndian
	}
	units := utf16.Encode([]rune(s))
	if bom {
		units = append([]uint16{0xFEFF}, units...)
	}
	out := make([]byte, 2*len(units))
	for i, u := range units {
		order.PutUint16(out[2*i:], u)
	}
	return out
}

// The detector's kinds, as scan() reports them.
func pii(values ...string) []string {
	var out []string
	for _, v := range values {
		kind, value, _ := strings.Cut(v, "=")
		if kind == "card" {
			kind = "payment_card"
		}
		out = append(out, kind+"="+value)
	}
	return out
}

func TestUTF16TextIsDecoded(t *testing.T) {
	long := strings.Repeat("Nome\tValor\r\n", 100) + text
	for name, data := range map[string][]byte{
		"little-endian with BOM":    encodeUTF16(text, false, true),
		"big-endian with BOM":       encodeUTF16(text, true, true),
		"little-endian without BOM": encodeUTF16(long, false, false),
		"big-endian without BOM":    encodeUTF16(long, true, false),
	} {
		found, report, err := scan(t, extractor(), data)
		if err != nil || report.Format != FormatText {
			t.Fatalf("%s: %v, %s", name, err, report.Format)
		}
		expect(t, name, found, pii(card, cpf)...)
	}
}

// ASCII text, or binary data with some NULs, is not mistaken for UTF-16.
func TestOnlyUTF16IsDecodedAsUTF16(t *testing.T) {
	found, _, _ := scan(t, extractor(), []byte(text))
	expect(t, "ASCII", found, pii(card, cpf)...)
	binaryish := append(bytes.Repeat([]byte{0, 1, 2, 'a', 0, 0xFF}, 200), text...)
	found, _, _ = scan(t, extractor(), binaryish)
	expect(t, "binary then text", found, pii(card, cpf)...)
}

func TestUTF16InALargeArchiveEntryIsDecoded(t *testing.T) {
	small := extractor()
	small.Limits.MaxDocumentBytes = 4096 // the entry is streamed as text
	data := encodeUTF16(strings.Repeat("x ", 4000)+text, false, true)
	found, _, err := scan(t, small, zipOf(t, entry{name: "export.txt", data: data}))
	if err != nil {
		t.Fatal(err)
	}
	expect(t, "large UTF-16 entry", found, pii(card, cpf)...)
}

func TestCharacterReferencesAreDecoded(t *testing.T) {
	html := `<p>Card &#52;111&#x20;1111&nbsp;1111&#32;1111, CPF 529&#46;982&period;247&ndash;25.</p>`
	found, _, err := scan(t, extractor(), []byte(html))
	if err != nil {
		t.Fatal(err)
	}
	expect(t, "references", found, pii(card, cpf)...)
	// Not references: left as they are.
	for _, s := range []string{"a & b", "&#;", "&#xZZ;", "&#0;", "&#55296;", "&unknown;", "&#52", "&" + strings.Repeat("a", 40) + ";"} {
		var out bytes.Buffer
		tw := newTextWriter(&out)
		_, _ = tw.Write([]byte(s))
		_ = tw.Close()
		if out.String() != s {
			t.Errorf("%q became %q", s, out.String())
		}
	}
}

// A reference split across writes is still decoded.
func TestCharacterReferencesAcrossWrites(t *testing.T) {
	var out bytes.Buffer
	tw := newTextWriter(&out)
	in := strings.Repeat("x", headBytes) + "4111 1111 1111 111&#" + "49;"
	for i := 0; i < len(in); i += 7 {
		_, _ = tw.Write([]byte(in[i:min(i+7, len(in))]))
	}
	_ = tw.Close()
	if !strings.HasSuffix(out.String(), "4111 1111 1111 1111") {
		t.Fatalf("got ...%q", out.String()[len(out.String())-30:])
	}
}

func TestRTFTextIsExtracted(t *testing.T) {
	rtf := `{\rtf1\ansi\deff0{\fonttbl{\f0 Arial;}}` +
		`{\*\generator Test 1.0;}` +
		`\pard Card \'34111 1111 1111 1111\par ` +
		`CPF \u53?\u50?9.982.247-25\par ` +
		`{\pict\pngblip 41111111111111114111111111111111}` +
		`\bin5 4111 tail 529\-.982\~247-25}`
	found, report, err := scan(t, extractor(), []byte(rtf))
	if err != nil || report.Format != FormatRTF {
		t.Fatalf("%v, %s", err, report.Format)
	}
	// The picture's hex is not text; the CPF after \bin5 is split by \- (optional
	// hyphen, no text) and \~ (a space), so it reads 529.982 247-25: not a CPF.
	expect(t, "RTF", found, pii(card, cpf)...)
}

func TestDeeplyNestedRTFIsUnscannable(t *testing.T) {
	deep := `{\rtf1 ` + strings.Repeat("{", maxRTFDepth+1) + "x" + strings.Repeat("}", maxRTFDepth+1) + "}"
	assertUnscannable(t, "nested groups", extractor(), []byte(deep))
	ok := `{\rtf1 ` + strings.Repeat("{", 50) + "Card 4111 1111 1111 1111" + strings.Repeat("}", 50) + "}"
	found, _, err := scan(t, extractor(), []byte(ok))
	if err != nil {
		t.Fatal(err)
	}
	expect(t, "50 levels", found, pii(card)...)
}

func TestRTFWithAnEmbeddedObjectIsUnscannable(t *testing.T) {
	rtf := `{\rtf1 Hello {\object\objemb{\*\objdata 01050000020000000b0000}}}`
	assertUnscannable(t, "RTF object", extractor(), []byte(rtf))
}

func email(parts ...string) string {
	head := "From: Alice <alice@example.com>\r\nTo: bob@example.com\r\nSubject: =?utf-8?q?Relat=C3=B3rio?=\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n" +
		"This is a multi-part message. CPF 111.444.777-35\r\n"
	for _, p := range parts {
		head += "--b1\r\n" + p + "\r\n"
	}
	return head + "--b1--\r\nEpilogue: card 5555 5555 5555 4444\r\n"
}

func b64Lines(data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	return b.String() + enc
}

func TestEmailsAreDecodedPartByPart(t *testing.T) {
	msg := email(
		// A quoted-printable soft line break in the middle of a CPF.
		"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nCPF 529.982.=\r\n247-25 ol=C3=A1",
		// A base64 text attachment with a card.
		"Content-Type: text/csv\r\nContent-Disposition: attachment; filename=a.csv\r\nContent-Transfer-Encoding: base64\r\n\r\n"+
			b64Lines([]byte("nome,cartao\nana,4111 1111 1111 1111\n")),
		// A Word document attached: opened like any document.
		"Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\nContent-Transfer-Encoding: base64\r\n\r\n"+
			b64Lines(testdata(t, "report.docx")),
	)
	found, report, err := scan(t, extractor(), []byte(msg))
	if err != nil || report.Format != FormatEmail {
		t.Fatalf("%v, %s", err, report.Format)
	}
	want := map[string]bool{
		"br_cpf=111.444.777-35":            true, // preamble
		"payment_card=5555 5555 5555 4444": true, // epilogue
		"br_cpf=529.982.247-25":            true, // quoted-printable part
		"payment_card=4111 1111 1111 1111": true, // base64 attachment
		"email=alice@example.com":          true, // header
	}
	got := map[string]bool{}
	for _, f := range found {
		got[f] = true
	}
	for w := range want {
		if !got[w] {
			t.Errorf("missing %s in %q", w, found)
		}
	}
	// The Word attachment's own findings (report.docx has a CPF and an email too).
	if report.Parts < 4 {
		t.Errorf("parts %d: the attachment was not opened", report.Parts)
	}
}

func TestNestedEmailsAreRead(t *testing.T) {
	inner := "From: x@example.com\r\nTo: y@example.com\r\nSubject: fwd\r\n\r\nCard 4111 1111 1111 1111\r\n"
	msg := email("Content-Type: message/rfc822\r\n\r\n" + inner)
	found, _, err := scan(t, extractor(), []byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(found, "|"), "payment_card=4111 1111 1111 1111") {
		t.Fatalf("found %q", found)
	}
}

func TestMalformedEmailsAreUnscannable(t *testing.T) {
	for name, part := range map[string]string{
		"bad base64":         "Content-Transfer-Encoding: base64\r\n\r\n!!!not base64!!!",
		"unknown encoding":   "Content-Transfer-Encoding: x-uuencode\r\n\r\nbegin 644 a",
		"multipart no bound": "Content-Type: multipart/mixed\r\n\r\nhello",
	} {
		assertUnscannable(t, name, extractor(), []byte(email(part)))
	}
}

// Text that merely starts with a "Key: value" line is text, read in full.
func TestTextWithAColonIsNotAnEmail(t *testing.T) {
	for _, s := range []string{
		"Note: call back\n\n" + text,
		"Name: Ana\nCPF: 529.982.247-25\nCard: 4111 1111 1111 1111\n",
	} {
		found, report, err := scan(t, extractor(), []byte(s))
		if err != nil || report.Format != FormatText {
			t.Fatalf("%q: %v, %s", s, err, report.Format)
		}
		expect(t, s, found, pii(card, cpf)...)
	}
}

// Large entries are streamed as text, which would skip RTF escapes and email
// decoding: such an entry is refused instead.
func TestLargeRTFOrEmailEntriesAreUnscannable(t *testing.T) {
	small := extractor()
	small.Limits.MaxDocumentBytes = 4096
	padding := strings.Repeat("filler ", 1000)
	bigEmail := "From: a@example.com\r\nTo: b@example.com\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		b64Lines([]byte(padding+text))
	bigRTF := `{\rtf1 ` + padding + `Card \'34111 1111 1111 1111}`
	assertUnscannable(t, "large email entry", small, zipOf(t, entry{name: "big.eml", data: []byte(bigEmail)}))
	assertUnscannable(t, "large RTF entry", small, zipOf(t, entry{name: "big.rtf", data: []byte(bigRTF)}))
	// Large plain text is still streamed and scanned.
	found, _, err := scan(t, small, zipOf(t, entry{name: "big.txt", data: []byte(padding + text)}))
	if err != nil {
		t.Fatal(err)
	}
	expect(t, "large text entry", found, pii(card, cpf)...)
}
