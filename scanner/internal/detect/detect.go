// Package detect finds personally identifiable information (PII) in text.
//
// Detectors are deliberately conservative: a regex match alone is not a finding.
// Where a format carries a checksum (CPF, payment card numbers) the checksum must
// also validate, which keeps false positives low enough to block uploads on.
package detect

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"sort"
	"strconv"
)

// Kind identifies the type of PII found.
type Kind string

const (
	KindEmail       Kind = "email"
	KindCPF         Kind = "br_cpf"
	KindPaymentCard Kind = "payment_card"
)

// Finding is one PII match. Value is never logged or persisted; only Kind,
// Start and End leave the scanner.
type Finding struct {
	Kind  Kind
	Start int
	End   int
	Value string
}

var (
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	cpfRe   = regexp.MustCompile(`\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b`)
	// 13 to 19 digits, optionally grouped by single spaces or hyphens, and not part
	// of a longer number.
	cardRe = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)
)

// Scan returns every PII finding in text, ordered by position.
func Scan(text string) []Finding {
	var out []Finding
	for _, loc := range emailRe.FindAllStringIndex(text, -1) {
		out = append(out, Finding{KindEmail, loc[0], loc[1], text[loc[0]:loc[1]]})
	}
	for _, loc := range cpfRe.FindAllStringIndex(text, -1) {
		if v := text[loc[0]:loc[1]]; ValidCPF(v) {
			out = append(out, Finding{KindCPF, loc[0], loc[1], v})
		}
	}
	for _, loc := range cardRe.FindAllStringIndex(text, -1) {
		if v := text[loc[0]:loc[1]]; ValidPaymentCard(v) {
			out = append(out, Finding{KindPaymentCard, loc[0], loc[1], v})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

const (
	// ChunkSize is how much ScanReader reads at a time.
	ChunkSize = 64 * 1024
	// MaxMatch is the longest match ScanReader is guaranteed to find whole when it
	// spans a chunk boundary. Card numbers and CPFs are far shorter; e-mail addresses
	// longer than this could be missed at a boundary.
	MaxMatch = 1024
)

// The sizes ScanReader uses; tests shrink them to cross many boundaries quickly.
var chunkSize, maxMatch = ChunkSize, MaxMatch

// ScanReader scans a stream without holding it in memory, calling found for each
// finding in order of position. Start and End are byte offsets in the stream.
//
// It scans windows of up to ChunkSize new bytes plus the last MaxMatch bytes of the
// previous window, and reports a match only once: a match that starts in those last
// MaxMatch bytes is left for the next window, which sees it whole. One more byte is
// kept before them, so a number that started earlier is not mistaken for one that
// starts at the window's edge, and a match carried over that starts inside one
// already reported (the tail of a card number, say) is not reported again.
func ScanReader(r io.Reader, found func(Finding)) (int64, error) {
	buf := make([]byte, 0, chunkSize+maxMatch+1)
	chunk := make([]byte, chunkSize)
	var base, total, reportedEnd int64 // stream offset of buf[0]; bytes read; end of last finding
	lead, carried := 0, 0              // bytes at the start of buf: context only; carried over
	for {
		n, err := io.ReadFull(r, chunk)
		total += int64(n)
		buf = append(buf, chunk[:n]...)
		eof := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
		if err != nil && !eof {
			return total, err
		}
		cut := len(buf)
		if !eof && cut > lead+maxMatch {
			cut -= maxMatch
		}
		for _, f := range Scan(string(buf)) {
			if f.Start >= cut {
				break // next window sees it whole
			}
			start, end := base+int64(f.Start), base+int64(f.End)
			if f.Start < lead || (f.Start < carried && start < reportedEnd) {
				continue // reported by the previous window
			}
			f.Start, f.End = int(start), int(end)
			found(f)
			reportedEnd = max(reportedEnd, end)
		}
		if eof {
			return total, nil
		}
		keep := cut - 1 // one byte of context before what is carried over
		base += int64(keep)
		buf = append(buf[:0], buf[keep:]...)
		lead, carried = 1, len(buf)
	}
}

// ValidCPF checks a Brazilian CPF number, with or without punctuation,
// against its two check digits.
func ValidCPF(s string) bool {
	d := digits(s)
	if len(d) != 11 || allSame(d) {
		return false // 000.000.000-00, 111.111.111-11 ... pass the checksum but are invalid
	}
	return checkDigit(d[:9], 10) == d[9] && checkDigit(d[:10], 11) == d[10]
}

func checkDigit(digits []int, weight int) int {
	sum := 0
	for i, x := range digits {
		sum += x * (weight - i)
	}
	r := (sum * 10) % 11
	if r == 10 {
		return 0
	}
	return r
}

// A card network's number range: numbers whose first len(lo) digits are in
// [lo, hi], with one of the given lengths.
type cardRange struct {
	lo, hi  string
	lengths []int
}

// Issuer ranges of the networks common in Brazil and internationally. A number
// that passes Luhn but fits no network is not reported: Luhn alone accepts one
// random number in ten.
var cardRanges = []cardRange{
	{"4", "4", []int{13, 16, 19}},                 // Visa (and Elo ranges inside 4)
	{"51", "55", []int{16}},                       // Mastercard
	{"2221", "2720", []int{16}},                   // Mastercard 2-series
	{"34", "34", []int{15}},                       // American Express
	{"37", "37", []int{15}},                       // American Express
	{"6011", "6011", []int{16, 17, 18, 19}},       // Discover
	{"644", "649", []int{16, 17, 18, 19}},         // Discover
	{"65", "65", []int{16, 17, 18, 19}},           // Discover, Elo
	{"300", "305", []int{14, 15, 16, 17, 18, 19}}, // Diners Club
	{"36", "36", []int{14, 15, 16, 17, 18, 19}},   // Diners Club
	{"38", "39", []int{16, 17, 18, 19}},           // Diners Club; Hipercard 3841
	{"3528", "3589", []int{16, 17, 18, 19}},       // JCB
	{"62", "62", []int{16, 17, 18, 19}},           // UnionPay; Elo 6277
	{"5041", "5041", []int{16}},                   // Elo
	{"5066", "5067", []int{16}},                   // Elo
	{"509", "509", []int{16}},                     // Elo
	{"606282", "606282", []int{16, 19}},           // Hipercard
	{"6362", "6363", []int{16}},                   // Elo
}

// ValidPaymentCard checks a payment card number, with or without spaces or
// hyphens: 13 to 19 digits, a known network's range and length, and the Luhn check
// digit.
func ValidPaymentCard(s string) bool {
	d := digits(s)
	if len(d) < 13 || len(d) > 19 || allSame(d) || !luhn(d) {
		return false
	}
	number := string(digitBytes(d))
	for _, r := range cardRanges {
		if !contains(r.lengths, len(d)) {
			continue
		}
		prefix, _ := strconv.Atoi(number[:len(r.lo)])
		lo, _ := strconv.Atoi(r.lo)
		hi, _ := strconv.Atoi(r.hi)
		if prefix >= lo && prefix <= hi {
			return true
		}
	}
	return false
}

func luhn(d []int) bool {
	sum := 0
	for i := range d {
		x := d[len(d)-1-i]
		if i%2 == 1 {
			x *= 2
			if x > 9 {
				x -= 9
			}
		}
		sum += x
	}
	return sum%10 == 0
}

func digits(s string) []int {
	d := make([]int, 0, len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			d = append(d, int(r-'0'))
		}
	}
	return d
}

func digitBytes(d []int) []byte {
	var b bytes.Buffer
	for _, x := range d {
		b.WriteByte(byte('0' + x))
	}
	return b.Bytes()
}

func allSame(d []int) bool {
	for _, x := range d[1:] {
		if x != d[0] {
			return false
		}
	}
	return true
}

func contains(xs []int, x int) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
