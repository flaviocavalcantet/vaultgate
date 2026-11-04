package extract

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/ianaindex"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// Text can hide digits from the detectors without being a container: UTF-16 puts a
// NUL between every ASCII character, and HTML or XML can write "4" as "&#52;". Text
// is decoded before it is scanned, so what a viewer would show is what is scanned.

// textWriter decodes text written to it: UTF-16 (decided from its first bytes) to
// UTF-8, then character references. Close flushes it.
type textWriter struct {
	w    io.Writer
	head []byte         // buffered until the encoding is decided
	out  io.WriteCloser // nil until then
}

// headBytes is how much text decides whether it is UTF-16.
const headBytes = 1024

func newTextWriter(w io.Writer) *textWriter { return &textWriter{w: w} }

func (t *textWriter) Write(p []byte) (int, error) {
	if t.out != nil {
		return t.out.Write(p)
	}
	t.head = append(t.head, p...)
	if len(t.head) < headBytes {
		return len(p), nil
	}
	if err := t.start(); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *textWriter) start() error {
	decoders := []transform.Transformer{}
	if order, bom, ok := utf16Order(t.head); ok {
		policy := unicode.IgnoreBOM
		if bom {
			policy = unicode.ExpectBOM
		}
		decoders = append(decoders, unicode.UTF16(order, policy).NewDecoder())
	}
	decoders = append(decoders, &refDecoder{})
	t.out = transform.NewWriter(t.w, transform.Chain(decoders...))
	head := t.head
	t.head = nil
	_, err := t.out.Write(head)
	return err
}

func (t *textWriter) Close() error {
	if t.out == nil {
		if err := t.start(); err != nil {
			return err
		}
	}
	return t.out.Close()
}

// utf16Order says whether text is UTF-16, and in which byte order: from a byte order
// mark, or, without one, when nearly every pair of bytes is an ASCII character and a
// NUL. Excel's "Unicode text" export has a mark; other tools leave it out.
func utf16Order(head []byte) (order unicode.Endianness, bom, ok bool) {
	switch {
	case bytes.HasPrefix(head, []byte{0xFF, 0xFE}) && !bytes.HasPrefix(head, []byte{0xFF, 0xFE, 0, 0}):
		return unicode.LittleEndian, true, true
	case bytes.HasPrefix(head, []byte{0xFE, 0xFF}):
		return unicode.BigEndian, true, true
	}
	pairs := len(head) / 2
	if pairs < 16 {
		return unicode.LittleEndian, false, false
	}
	var little, big int
	for i := 0; i+1 < len(head); i += 2 {
		switch {
		case head[i+1] == 0 && textByte(head[i]):
			little++
		case head[i] == 0 && textByte(head[i+1]):
			big++
		}
	}
	switch {
	case little*10 >= pairs*9:
		return unicode.LittleEndian, false, true
	case big*10 >= pairs*9:
		return unicode.BigEndian, false, true
	}
	return unicode.LittleEndian, false, false
}

func textByte(b byte) bool { return b == '\t' || b == '\n' || b == '\r' || (b >= 0x20 && b < 0x7F) }

// refDecoder replaces HTML and XML character references with the characters they
// stand for, as a browser does: numeric ones in decimal or hex with any number of
// leading zeros and with or without the closing ';' (&#52;, &#x34, &#00000052;), named
// ones that matter between digits (&nbsp;, &period;, &ndash;...), and the legacy names
// browsers decode even without ';' (&nbsp1111). Invalid numbers become U+FFFD, as in a
// browser. Anything else passes through unchanged.
//
// It reads byte by byte and keeps its state across calls, so a reference split across
// writes, or padded with any number of zeros, needs no lookahead.
type refDecoder struct {
	state   refState
	raw     []byte // the reference so far, to write back if it is none (capped)
	name    []byte // letters of a named reference
	value   rune
	digits  bool // at least one digit seen
	invalid bool // out of range
}

type refState int

const (
	refText refState = iota
	refAmp           // after '&'
	refName          // after '&' and a letter
	refHash          // after "&#"
	refDec           // decimal digits
	refHex           // after "&#x"
)

// Raw text kept for a reference that turns out not to be one, and the longest name.
const (
	maxRefRaw  = 64
	maxRefName = 32
)

var namedRefs = map[string]rune{
	"amp": '&', "lt": '<', "gt": '>', "quot": '"', "apos": '\'',
	"nbsp": ' ', "ensp": ' ', "emsp": ' ', "thinsp": ' ',
	"hyphen": '-', "dash": '-', "ndash": '-', "minus": '-', "period": '.', "sol": '/',
}

// Names browsers decode without ';', longest first for prefix matching.
var legacyRefs = []string{"nbsp", "quot", "amp", "lt", "gt"}

func (d *refDecoder) Reset() { *d = refDecoder{} }

// maxStepOut bounds what one byte can produce: a reference given back as text, the
// rest of a name, and the byte itself.
const maxStepOut = maxRefRaw + maxRefName + 2*utf8.UTFMax

func (d *refDecoder) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	var out []byte
	for nSrc < len(src) {
		// Room first: a step changes the state, so it must not be undone for lack of space.
		if len(dst)-nDst < maxStepOut {
			return nDst, nSrc, transform.ErrShortDst
		}
		out = d.step(src[nSrc], out[:0])
		nDst += copy(dst[nDst:], out)
		nSrc++
	}
	if atEOF && d.state != refText {
		if len(dst)-nDst < maxStepOut {
			return nDst, nSrc, transform.ErrShortDst
		}
		out = d.finish(out[:0])
		nDst += copy(dst[nDst:], out)
	}
	return nDst, nSrc, nil
}

func (d *refDecoder) keep(c byte) {
	if len(d.raw) < maxRefRaw {
		d.raw = append(d.raw, c)
	}
}

// step takes one byte and appends what it produces to out.
func (d *refDecoder) step(c byte, out []byte) []byte {
	switch d.state {
	case refText:
		if c == '&' {
			d.state, d.raw = refAmp, append(d.raw[:0], c)
			return out
		}
		return append(out, c)
	case refAmp:
		switch {
		case c == '#':
			d.state, d.value, d.digits, d.invalid = refHash, 0, false, false
			d.keep(c)
			return out
		case isLetter(c):
			d.state, d.name = refName, append(d.name[:0], c)
			d.keep(c)
			return out
		}
	case refName:
		switch {
		case (isLetter(c) || (c >= '0' && c <= '9')) && len(d.name) < maxRefName:
			d.name = append(d.name, c)
			d.keep(c)
			return out
		case c == ';':
			if r, ok := namedRefs[string(d.name)]; ok {
				d.state = refText
				return utf8.AppendRune(out, r)
			}
		}
		return d.step(c, d.finishName(out))
	case refHash:
		switch {
		case c == 'x' || c == 'X':
			d.state = refHex
			d.keep(c)
			return out
		case c >= '0' && c <= '9':
			d.state = refDec
			return d.step(c, out)
		}
	case refDec, refHex:
		if digit, ok := refDigit(c, d.state == refHex); ok {
			d.keep(c) // past the cap (leading zeros, say) digits are not kept, nor needed
			d.digits = true
			base := rune(10)
			if d.state == refHex {
				base = 16
			}
			if !d.invalid {
				d.value = d.value*base + digit
				if d.value > utf8.MaxRune {
					d.invalid = true
				}
			}
			return out
		}
		if c == ';' && d.digits {
			return d.finish(out)
		}
		return d.step(c, d.finish(out))
	}
	// Not a reference after all: the text so far, then this byte as text.
	out = d.flush(out)
	return d.step(c, out)
}

// finish ends whatever reference is in progress and appends what it stands for.
func (d *refDecoder) finish(out []byte) []byte {
	switch d.state {
	case refDec, refHex:
		if !d.digits {
			return d.flush(out)
		}
		r := d.value
		if d.invalid || r == 0 || (r >= 0xD800 && r <= 0xDFFF) {
			r = utf8.RuneError
		}
		d.state = refText
		return utf8.AppendRune(out, r)
	case refName:
		return d.finishName(out)
	}
	return d.flush(out)
}

// finishName ends a named reference that had no ';': a legacy name at its start is
// decoded and the rest of the letters follow as text, as a browser does.
func (d *refDecoder) finishName(out []byte) []byte {
	name := string(d.name)
	for _, legacy := range legacyRefs {
		if strings.HasPrefix(name, legacy) {
			d.state = refText
			out = utf8.AppendRune(out, namedRefs[legacy])
			return append(out, name[len(legacy):]...)
		}
	}
	return d.flush(out)
}

func (d *refDecoder) flush(out []byte) []byte {
	d.state = refText
	return append(out, d.raw...)
}

func refDigit(c byte, hex bool) (rune, bool) {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0'), true
	case hex && c >= 'a' && c <= 'f':
		return rune(c-'a') + 10, true
	case hex && c >= 'A' && c <= 'F':
		return rune(c-'A') + 10, true
	}
	return 0, false
}

// --- RTF ---------------------------------------------------------------------------

func isRTF(head []byte) bool {
	head = bytes.TrimLeft(bytes.TrimPrefix(head, []byte("\xEF\xBB\xBF")), " \t\r\n")
	return bytes.HasPrefix(head, []byte(`{\rtf`))
}

// rtf writes the text of an RTF document. Control words are dropped except those that
// stand for text: \'hh (a byte in the document's ANSI code page, Windows-1252
// assumed), \uN (a Unicode character, whose ANSI fallback is then skipped), and line,
// cell and paragraph breaks. Every group is read, the "ignorable" ones too, except
// pictures, whose hex data is no text. An embedded object (\objdata) holds a document
// in a format the scanner does not read, so the file is unscannable.
func (x *run) rtf(r io.Reader) error {
	in := bufio.NewReader(r)
	out := bufio.NewWriter(x.w)
	type group struct {
		skip bool // inside a picture
		uc   int  // fallback characters after \uN
	}
	stack := []group{{uc: 1}}
	fallback := 0 // characters still to skip after \uN
	emit := func(r rune) error {
		if stack[len(stack)-1].skip {
			return nil
		}
		if fallback > 0 {
			fallback--
			return nil
		}
		_, err := out.WriteRune(r)
		return err
	}
	ansi := func(b byte) rune { return charmap.Windows1252.DecodeByte(b) }
	for {
		c, err := in.ReadByte()
		if err == io.EOF {
			return out.Flush()
		}
		if err != nil {
			return err
		}
		switch c {
		case '{':
			if len(stack) > maxRTFDepth {
				return unscannable("RTF groups nested deeper than %d", maxRTFDepth)
			}
			stack = append(stack, stack[len(stack)-1])
			continue
		case '}':
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			continue
		case '\r', '\n':
			continue // line breaks in the file are not text
		case '\\':
		default:
			if err := emit(ansi(c)); err != nil {
				return err
			}
			continue
		}
		c, err = in.ReadByte()
		if err == io.EOF {
			return out.Flush()
		}
		if err != nil {
			return err
		}
		switch {
		case c == '\'':
			hex := make([]byte, 2)
			if _, err := io.ReadFull(in, hex); err != nil {
				return out.Flush()
			}
			if b, err := strconv.ParseUint(string(hex), 16, 8); err == nil {
				err = emit(ansi(byte(b)))
				if err != nil {
					return err
				}
			}
		case c == '\\' || c == '{' || c == '}':
			if err := emit(rune(c)); err != nil {
				return err
			}
		case c == '~':
			if err := emit(' '); err != nil {
				return err
			}
		case c == '_':
			if err := emit('-'); err != nil {
				return err
			}
		case c == '\r' || c == '\n': // "\" at the end of a line is a paragraph
			if err := emit('\n'); err != nil {
				return err
			}
		case isLetter(c):
			word, param, hasParam, err := controlWord(in, c)
			if err != nil {
				return out.Flush()
			}
			top := &stack[len(stack)-1]
			switch word {
			case "par", "line", "row", "sect", "page":
				err = emit('\n')
			case "tab", "cell":
				err = emit('\t')
			case "u":
				if hasParam {
					if param < 0 {
						param += 65536
					}
					err = emit(rune(param))
					fallback = top.uc
				}
			case "uc":
				if hasParam && param >= 0 && param < 10 {
					top.uc = param
				}
			case "bin": // raw bytes follow, no text
				if hasParam && param > 0 {
					if _, err := in.Discard(param); err != nil {
						return out.Flush()
					}
				}
			case "pict":
				top.skip = true
			case "objdata", "objemb", "object":
				return unscannable("RTF with an embedded object")
			}
			if err != nil {
				return err
			}
		}
	}
}

// maxRTFDepth bounds nested RTF groups; real documents stay far below it, and each
// level costs memory.
const maxRTFDepth = 1000

func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// controlWord reads the rest of a control word that starts with first: letters, an
// optional signed number, and the space that may end it.
func controlWord(in *bufio.Reader, first byte) (word string, param int, hasParam bool, err error) {
	var name, num []byte
	name = append(name, first)
	for {
		c, err := in.ReadByte()
		if err != nil {
			return string(name), 0, false, err
		}
		switch {
		case isLetter(c) && len(name) < 32 && len(num) == 0:
			name = append(name, c)
		case (c == '-' && len(num) == 0) || (c >= '0' && c <= '9' && len(num) < 10):
			num = append(num, c)
		default:
			if c != ' ' {
				_ = in.UnreadByte()
			}
			if len(num) > 0 && string(num) != "-" {
				n, err := strconv.Atoi(string(num))
				return string(name), n, err == nil, nil
			}
			return string(name), 0, false, nil
		}
	}
}

// --- Email ---------------------------------------------------------------------------

// A header field name is an RFC 7230 token, directly followed by ':'. JSON lines
// ({"id":...) or prose with a colon do not qualify.
var headerLine = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+:")

// emailHeadMax is how much of a file is read to tell whether it starts with an email
// header. Mail clients accept any fields in any order, so the decision takes the whole
// header block, not just its first lines.
const emailHeadMax = 64 << 10

// isEmail says whether a file (size bytes readable through r) starts with an email's
// header: only header lines up to the first blank line, and fields an email has. A
// header block that runs past emailHeadMax counts as an email, so its parts are
// decoded rather than read as text: padding cannot push the telling fields out of view.
func isEmail(r io.ReaderAt, size int64) bool {
	head := make([]byte, min(size, emailHeadMax))
	n, _ := r.ReadAt(head, 0)
	head = head[:n]
	cut := int64(n) < size // the last line may be cut
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	if cut {
		lines = lines[:len(lines)-1]
	}
	fields := map[string]bool{}
	blank := false
header:
	for _, line := range lines {
		switch {
		case line == "":
			blank = true
			break header
		case line[0] == ' ' || line[0] == '\t':
			if len(fields) == 0 {
				return false
			}
		case headerLine.MatchString(line):
			fields[strings.ToLower(line[:strings.IndexByte(line, ':')])] = true
		default:
			return false
		}
	}
	if !blank && cut && len(fields) > 0 {
		return true
	}
	if fields["mime-version"] || fields["content-type"] || fields["content-transfer-encoding"] {
		return true
	}
	return fields["from"] && (fields["to"] || fields["date"] || fields["subject"] || fields["received"] || fields["message-id"])
}

// maxMultipartDepth bounds multiparts within multiparts in one email.
const maxMultipartDepth = 10

// email reads a message: its header, then every MIME part, decoded from base64 or
// quoted-printable, as a document of its own (an attached Word file is opened).
// Multipart preambles and epilogues, which mail clients hide, are scanned as text.
func (x *run) email(r io.ReaderAt, size int64, depth int) error {
	if err := x.container(FormatEmail, size, depth); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.NewSectionReader(r, 0, size))
	if err != nil {
		return err
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return unscannable("malformed email: %v", err)
	}
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return err
	}
	return x.entity(textproto.MIMEHeader(msg.Header), body, depth, 0)
}

// entity reads one MIME entity: the message itself or a part.
func (x *run) entity(header textproto.MIMEHeader, body []byte, depth, nesting int) error {
	if err := x.headers(header); err != nil {
		return err
	}
	data, err := transferDecode(header.Get("Content-Transfer-Encoding"), body)
	if err != nil {
		return err
	}
	mediaType, params, _ := mime.ParseMediaType(header.Get("Content-Type"))
	if !strings.HasPrefix(mediaType, "multipart/") {
		x.budget += int64(len(data))
		if x.budget > x.e.Limits.MaxExtractedBytes {
			return unscannable("email parts expand beyond %d bytes", x.e.Limits.MaxExtractedBytes)
		}
		_, err := x.document(bytes.NewReader(data), int64(len(data)), depth+1)
		return err
	}
	if nesting >= maxMultipartDepth {
		return unscannable("multipart nested deeper than %d", maxMultipartDepth)
	}
	boundary := params["boundary"]
	if boundary == "" {
		return unscannable("multipart without a boundary")
	}
	if err := x.outside(data, boundary); err != nil {
		return err
	}
	mr := multipart.NewReader(bytes.NewReader(data), boundary)
	for {
		part, err := mr.NextRawPart() // raw: decoded here, the same way for every part
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return unscannable("malformed multipart: %v", err)
		}
		x.entries++
		if x.entries > x.e.Limits.MaxEntries {
			return unscannable("more than %d email parts and archive entries", x.e.Limits.MaxEntries)
		}
		partBody, err := io.ReadAll(part)
		if err != nil {
			return unscannable("malformed multipart: %v", err)
		}
		if err := x.entity(part.Header, partBody, depth, nesting+1); err != nil {
			return err
		}
	}
}

func transferDecode(encoding string, body []byte) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "7bit", "8bit", "binary":
		return body, nil
	case "base64": // line breaks are ignored by the decoder
		out, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(bytes.TrimSpace(body))))
		if err != nil {
			return nil, unscannable("email part with invalid base64")
		}
		return out, nil
	case "quoted-printable":
		out, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(body)))
		if err != nil {
			return nil, unscannable("email part with invalid quoted-printable")
		}
		return out, nil
	default:
		return nil, unscannable("email part in transfer encoding %q", encoding)
	}
}

var wordDecoder = &mime.WordDecoder{CharsetReader: charsetReader}

// charsetReader decodes the charset an encoded header word names (any IANA charset Go
// knows: ISO-8859-*, Windows-125*, GB2312, Shift_JIS, UTF-16...). An unknown one gives
// the word's bytes as they are, already decoded from base64 or Q: digits are ASCII in
// nearly every charset, so they are still seen. The header is never left encoded.
func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	if enc, err := ianaindex.MIME.Encoding(charset); err == nil && enc != nil {
		return enc.NewDecoder().Reader(input), nil
	}
	if enc, err := ianaindex.IANA.Encoding(charset); err == nil && enc != nil {
		return enc.NewDecoder().Reader(input), nil
	}
	return input, nil
}

// headers writes header fields as text, with encoded words (=?utf-8?b?...?=) decoded.
func (x *run) headers(header textproto.MIMEHeader) error {
	keys := make([]string, 0, len(header))
	for k := range header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		for _, v := range header[k] {
			if decoded, err := wordDecoder.DecodeHeader(v); err == nil {
				v = decoded
			}
			b.WriteString(k + ": " + v + "\n")
		}
	}
	if _, err := io.WriteString(x.w, b.String()); err != nil {
		return err
	}
	return x.separate()
}

// outside writes the text of a multipart body before its first boundary (the
// preamble) and after its last (the epilogue).
func (x *run) outside(body []byte, boundary string) error {
	delimiter := []byte("--" + boundary)
	first := bytes.Index(body, delimiter)
	if first < 0 {
		return unscannable("multipart without its boundary")
	}
	text := body[:first]
	if end := bytes.LastIndex(body, append(delimiter, '-', '-')); end >= 0 {
		text = append(append(append([]byte{}, text...), '\n'), body[end+len(delimiter)+2:]...)
	}
	if len(bytes.TrimSpace(text)) == 0 {
		return nil
	}
	tw := newTextWriter(x.w)
	if _, err := tw.Write(text); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return x.separate()
}
