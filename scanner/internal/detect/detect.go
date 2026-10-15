// Package detect finds personally identifiable information (PII) in text.
//
// Detectors are deliberately conservative: a regex match alone is not a finding.
// Where a format carries a checksum (CPF, payment card numbers) the checksum must
// also validate, which keeps false positives low enough to block uploads on.
package detect

import "regexp"

// Kind identifies the type of PII found.
type Kind string

const (
	KindEmail Kind = "email"
	KindCPF   Kind = "br_cpf"
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
)

// Scan returns every PII finding in text, in order of appearance per detector.
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
	return out
}

// ValidCPF checks a Brazilian CPF number, with or without punctuation,
// against its two check digits.
func ValidCPF(s string) bool {
	d := make([]int, 0, 11)
	for _, r := range s {
		if r >= '0' && r <= '9' {
			d = append(d, int(r-'0'))
		}
	}
	if len(d) != 11 {
		return false
	}
	allSame := true
	for _, x := range d[1:] {
		if x != d[0] {
			allSame = false
			break
		}
	}
	if allSame {
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
