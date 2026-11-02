package detect

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestValidCPF(t *testing.T) {
	cases := map[string]bool{
		"529.982.247-25": true,
		"52998224725":    true,
		"529.982.247-24": false, // wrong check digit
		"111.111.111-11": false, // repeated digits
		"123":            false,
	}
	for in, want := range cases {
		if got := ValidCPF(in); got != want {
			t.Errorf("ValidCPF(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestScan(t *testing.T) {
	text := "Contact ana@example.com, CPF 529.982.247-25, ref 529.982.247-24."
	got := Scan(text)
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(got), got)
	}
	if got[0].Kind != KindEmail || got[0].Value != "ana@example.com" {
		t.Errorf("unexpected email finding: %+v", got[0])
	}
	if got[1].Kind != KindCPF || got[1].Value != "529.982.247-25" {
		t.Errorf("unexpected CPF finding: %+v", got[1])
	}
}

func TestValidPaymentCard(t *testing.T) {
	valid := []string{
		"4111111111111111",    // Visa
		"4111 1111 1111 1111", // grouped by spaces
		"4111-1111-1111-1111", // grouped by hyphens
		"4222222222222",       // Visa, 13 digits
		"5555555555554444",    // Mastercard
		"2223003122003222",    // Mastercard 2-series
		"378282246310005",     // American Express
		"6011111111111117",    // Discover
		"3530111333300000",    // JCB
		"30569309025904",      // Diners Club
		"6362970000457013",    // Elo
		"6062825624254001",    // Hipercard
	}
	for _, s := range valid {
		if !ValidPaymentCard(s) {
			t.Errorf("ValidPaymentCard(%q) = false, want true", s)
		}
	}
	invalid := []string{
		"4111111111111112",      // Luhn fails
		"1234567812345670",      // Luhn passes, but no network starts with 1
		"378282246310005" + "1", // Amex prefix with 16 digits
		"0000000000000000",      // repeated digits
		"411111111111",          // too short
		"41111111111111111111",  // too long
	}
	for _, s := range invalid {
		if ValidPaymentCard(s) {
			t.Errorf("ValidPaymentCard(%q) = true, want false", s)
		}
	}
}

func TestScanFindsCards(t *testing.T) {
	text := "Card 4111 1111 1111 1111, invoice 1234567812345670, order 4111111111111111111111111."
	got := Scan(text)
	if len(got) != 1 || got[0].Kind != KindPaymentCard || got[0].Value != "4111 1111 1111 1111" {
		t.Fatalf("want one card finding, got %+v", got)
	}
}

// A card next to another number, separated by a space or hyphen, is still found:
// cards are looked for at every group boundary of a run of digits, not only from
// its start.
func TestScanFindsCardsNextToOtherNumbers(t *testing.T) {
	cases := map[string]string{
		"Qty 12 4111111111111111":            "4111111111111111",
		"2024-05 4111 1111 1111 1111":        "4111 1111 1111 1111",
		"3 4111-1111-1111-1111":              "4111-1111-1111-1111",
		"4111111111111111 12":                "4111111111111111",
		"4111 1111 1111 1111 2024-05-01":     "4111 1111 1111 1111",
		"100 378282246310005 200":            "378282246310005",
		"ref 9 8 7 4111 1111 1111 1111 x":    "4111 1111 1111 1111",
		"total 1.234 4111111111111111 BRL 5": "4111111111111111",
	}
	for text, want := range cases {
		got := Scan(text)
		if len(got) != 1 || got[0].Kind != KindPaymentCard || got[0].Value != want {
			t.Errorf("Scan(%q) = %+v, want one card %q", text, got, want)
		}
	}
}

func TestScanFindsAdjacentCardsSeparately(t *testing.T) {
	got := Scan("4111 1111 1111 1111 5555 5555 5555 4444")
	if len(got) != 2 || got[0].Value != "4111 1111 1111 1111" || got[1].Value != "5555 5555 5555 4444" {
		t.Fatalf("want two cards, got %+v", got)
	}
}

// Single digits and short numbers in a table must not combine into a card, and a
// card never starts or ends inside a group of digits.
func TestScanIgnoresCardsMadeOfShortGroupsOrInsideNumbers(t *testing.T) {
	for _, text := range []string{
		"4 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1",      // a Visa number, one digit per column
		"41 11 11 11 11 11 11 11",              // two digits per group
		"0000004111111111111111",               // inside a longer number
		"4111111111111111111111111",            // 25 digits
		"12345 4111111111111111111111111 6789", // inside a longer number, among others
	} {
		if got := Scan(text); len(got) != 0 {
			t.Errorf("Scan(%q) = %+v, want nothing", text, got)
		}
	}
}

func TestScanOrdersFindingsByPosition(t *testing.T) {
	got := Scan("4111111111111111 then ana@example.com then 529.982.247-25")
	kinds := []Kind{}
	for _, f := range got {
		kinds = append(kinds, f.Kind)
	}
	want := []Kind{KindPaymentCard, KindEmail, KindCPF}
	if fmt.Sprint(kinds) != fmt.Sprint(want) {
		t.Fatalf("kinds = %v, want %v", kinds, want)
	}
}

// ScanReader must report exactly what Scan reports on the whole text, wherever the
// window boundaries fall, with no duplicates and no matches cut in half. Small
// windows exercise the same arithmetic as the real ones, much faster.
func TestScanReaderMatchesScanAcrossBoundaries(t *testing.T) {
	for _, size := range [][2]int{{256, 64}, {300, 97}, {ChunkSize, MaxMatch}} {
		chunkSize, maxMatch = size[0], size[1]
		checkBoundaries(t, size == [2]int{ChunkSize, MaxMatch})
	}
	chunkSize, maxMatch = ChunkSize, MaxMatch
}

func checkBoundaries(t *testing.T, quick bool) {
	t.Helper()
	samples := []string{
		"4111 1111 1111 1111",
		"529.982.247-25",
		"ana.maria@example.com",
		"4111111111111111111111111",               // 25 digits: not a card, whole or cut
		"0000004111111111111111",                  // a card's digits inside a longer number
		"406 4111111111111111",                    // a 19-digit card whose last 16 digits are a card too
		"Qty 12 4111111111111111",                 // a card after another number
		"7 88 999 4111 1111 1111 1111 10 2024-05", // a card inside a run of numbers
	}
	var boundaries []int
	for k := 1; k <= 3; k++ {
		boundaries = append(boundaries, k*chunkSize, k*chunkSize-maxMatch, k*(chunkSize-maxMatch))
	}
	for _, sample := range samples {
		shifts := []int{}
		for shift := -len(sample) - 2; shift <= 2; shift++ {
			shifts = append(shifts, shift)
		}
		if quick { // the real sizes: a few straddling positions at the first cut and end
			boundaries, shifts = boundaries[:2], []int{-len(sample) / 2, -1, 0}
		}
		for _, b := range boundaries {
			for _, shift := range shifts {
				at := b + shift
				if at < 1 {
					continue
				}
				// Enough text after the sample for one more window to follow it.
				text := strings.Repeat("x", at) + " " + sample + " " + strings.Repeat("y", 2*maxMatch)
				want := Scan(text)
				var got []Finding
				n, err := ScanReader(strings.NewReader(text), func(f Finding) { got = append(got, f) })
				if err != nil || n != int64(len(text)) {
					t.Fatalf("ScanReader: n=%d err=%v", n, err)
				}
				if fmt.Sprint(got) != fmt.Sprint(want) {
					t.Fatalf("window %d+%d, sample %q at %d: got %+v, want %+v",
						chunkSize, maxMatch, sample, at, got, want)
				}
			}
		}
	}
}

func TestScanReaderSeesEveryMatchInALongStream(t *testing.T) {
	var b strings.Builder
	const cards = 2000 // about 70 KiB of text per 2000 lines: several windows
	for i := 0; i < cards; i++ {
		fmt.Fprintf(&b, "line %d: card 4111 1111 1111 1111 and filler text\n", i)
	}
	count := 0
	if _, err := ScanReader(strings.NewReader(b.String()), func(f Finding) {
		if f.Kind == KindPaymentCard && b.String()[f.Start:f.End] == "4111 1111 1111 1111" {
			count++
		}
	}); err != nil {
		t.Fatal(err)
	}
	if count != cards {
		t.Fatalf("found %d cards, want %d", count, cards)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("disk on fire") }

func TestScanReaderReturnsReadErrors(t *testing.T) {
	if _, err := ScanReader(failingReader{}, func(Finding) {}); err == nil {
		t.Fatal("want the read error")
	}
}
