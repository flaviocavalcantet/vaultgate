package tlsreload

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// selfSigned returns a PEM certificate and key for localhost.
func selfSigned(t *testing.T, name string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func write(t *testing.T, path string, data []byte, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

// serves reports whether a TLS server with this reloader presents the certificate a
// client trusting only `trusted` accepts.
func serves(t *testing.T, r *Reloader, trusted []byte) bool {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", r.ServerConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if conn, err := ln.Accept(); err == nil {
			_ = conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(trusted)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", ln.Addr().String(),
		&tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func setup(t *testing.T) (r *Reloader, certFile, keyFile string, first []byte) {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	cert, key := selfSigned(t, "first")
	start := time.Unix(1_000_000_000, 0)
	write(t, certFile, cert, start)
	write(t, keyFile, key, start)
	r, err := New(certFile, keyFile, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return r, certFile, keyFile, cert
}

func TestUnchangedFilesAreNotReloaded(t *testing.T) {
	r, _, _, first := setup(t)
	if r.Check() {
		t.Fatal("reloaded unchanged files")
	}
	if !serves(t, r, first) {
		t.Fatal("does not serve the first certificate")
	}
}

func TestRenewedCertificateIsServed(t *testing.T) {
	r, certFile, keyFile, first := setup(t)
	cert, key := selfSigned(t, "second")
	later := time.Unix(2_000_000_000, 0)
	write(t, certFile, cert, later)
	write(t, keyFile, key, later)
	if !r.Check() {
		t.Fatal("did not reload")
	}
	if !serves(t, r, cert) || serves(t, r, first) {
		t.Fatal("does not serve the renewed certificate only")
	}
	if r.Check() {
		t.Fatal("reloaded twice")
	}
}

func TestMismatchedPairKeepsTheLoadedCertificate(t *testing.T) {
	r, certFile, keyFile, first := setup(t)
	cert, key := selfSigned(t, "second")
	write(t, certFile, cert, time.Unix(2_000_000_000, 0)) // the key is still the first one
	if r.Check() {
		t.Fatal("loaded a certificate with the wrong key")
	}
	if !serves(t, r, first) {
		t.Fatal("stopped serving the loaded certificate")
	}
	write(t, keyFile, key, time.Unix(3_000_000_000, 0)) // the pair is complete: tried again
	if !r.Check() || !serves(t, r, cert) {
		t.Fatal("did not load the complete pair")
	}
}

func TestMissingFilesKeepTheLoadedCertificate(t *testing.T) {
	r, certFile, _, first := setup(t)
	if err := os.Remove(certFile); err != nil {
		t.Fatal(err)
	}
	if r.Check() || !serves(t, r, first) {
		t.Fatal("lost the loaded certificate")
	}
}

func TestNewFailsWithoutAPair(t *testing.T) {
	if _, err := New("/nonexistent.crt", "/nonexistent.key", slog.Default()); err == nil {
		t.Fatal("New succeeded without files")
	}
}
