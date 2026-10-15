package detect

import "testing"

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
