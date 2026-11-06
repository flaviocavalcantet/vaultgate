package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretFromTheDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vaultgate_scanner_token"), []byte("from-openbao\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULTGATE_SCANNER_TOKEN", "")
	t.Setenv("VAULTGATE_SECRETS_DIR", dir)
	if got := secret("VAULTGATE_SCANNER_TOKEN"); got != "from-openbao" {
		t.Fatalf("got %q", got)
	}
	t.Setenv("VAULTGATE_SCANNER_TOKEN", "from-env")
	if got := secret("VAULTGATE_SCANNER_TOKEN"); got != "from-env" {
		t.Fatalf("the variable should win, got %q", got)
	}
	t.Setenv("VAULTGATE_SCANNER_TOKEN", "")
	t.Setenv("VAULTGATE_SECRETS_DIR", "")
	if got := secret("VAULTGATE_SCANNER_TOKEN"); got != "" {
		t.Fatalf("got %q without either", got)
	}
}
