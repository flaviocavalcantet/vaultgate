package extract

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
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
	decoders = append(decoders, refDecoder{})
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

// refDecoder replaces HTML and XML character references (&#52;, &#x34;, and the named
// ones that matter between digits) with the characters they stand for. Anything else
// passes through unchanged.
type refDecoder struct{ transform.NopResetter }

// The longest reference decoded: "&#x0010FFFF;" fits.
const maxRef = 16

var namedRefs = map[string]rune{
	"amp": '&', "lt": '<', "gt": '>', "quot": '"', "apos": '\'',
	"nbsp": ' ', "ensp": ' ', "emsp": ' ', "thinsp": ' ',
	"hyphen": '-', "dash": '-', "ndash": '-', "minus": '-', "period": '.', "sol": '/',
}

func (refDecoder) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	for nSrc < len(src) {
		amp := bytes.IndexByte(src[nSrc:], '&')
		if amp < 0 {
			amp = len(src) - nSrc
		}
		if amp > 0 { // plain text up to the next '&'
			n := copy(dst[nDst:], src[nSrc:nSrc+amp])
			nDst += n
			nSrc += n
			if n < amp {
				return nDst, nSrc, transform.ErrShortDst
			}
			continue
		}
		r, size, complete := parseRef(src[nSrc:])
		if !complete && !atEOF {
			return nDst, nSrc, transform.ErrShortSrc
		}
		if size == 0 { // not a reference: the '&' itself
			r, size = '&', 1
		}
		if len(dst)-nDst < utf8.UTFMax {
			return nDst, nSrc, transform.ErrShortDst
		}
		nDst += utf8.EncodeRune(dst[nDst:], r)
		nSrc += size
	}
	return nDst, nSrc, nil
}

// parseRef reads a reference at the start of b (which starts with '&'). It returns the
// character and the reference's length, a zero length if b does not start with one,
// and complete=false if b ends before that can be told.
func parseRef(b []byte) (r rune, size int, complete bool) {
	end := bytes.IndexByte(b[:min(len(b), maxRef)], ';')
	if end < 0 {
		return 0, 0, len(b) >= maxRef // a ';' may still come
	}
	name := string(b[1:end])
	if strings.HasPrefix(name, "#") {
		base, digits := 10, name[1:]
		if strings.HasPrefix(digits, "x") || strings.HasPrefix(digits, "X") {
			base, digits = 16, digits[1:]
		}
		n, err := strconv.ParseUint(digits, base, 32)
		if err != nil || digits == "" || digits[0] == '+' || n == 0 || n > utf8.MaxRune || (n >= 0xD800 && n <= 0xDFFF) {
			return 0, 0, true
		}
		return rune(n), end + 1, true
	}
	if r, ok := namedRefs[name]; ok {
		return r, end + 1, true
	}
	return 0, 0, true
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

var headerLine = regexp.MustCompile(`^[!-9;-~]+:`)

// isEmail says whether a file starts with an email's header: only header lines up to
// the first blank line (or the end of what was read), and fields an email has.
func isEmail(head []byte) bool {
	fields := map[string]bool{}
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	if len(head) == headBytes { // the last line may be cut
		lines = lines[:len(lines)-1]
	}
header:
	for _, line := range lines {
		switch {
		case line == "":
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
	if fields["mime-version"] || fields["content-type"] {
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

// charsetReader decodes the legacy charsets of encoded header words; others fail and
// the header is scanned as written.
func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(charset) {
	case "iso-8859-1", "latin1", "windows-1252", "cp1252":
		return charmap.Windows1252.NewDecoder().Reader(input), nil
	case "iso-8859-15":
		return charmap.ISO8859_15.NewDecoder().Reader(input), nil
	}
	return nil, errors.New("unsupported charset")
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
