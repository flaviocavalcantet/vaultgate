// Package tlsreload serves a certificate that renews while the server runs (M9, ADR 0012).
//
// cert-manager renews the scanner's certificate long before it expires (they last a day)
// and Kubernetes swaps the mounted files in place. A Reloader checks the files every so
// often and, when they changed and the new pair loads, serves it to new connections. A
// pair that doesn't load (a key that doesn't match, a half-written file) is skipped and
// tried again, and the loaded one stays in use.
package tlsreload

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Reloader holds the current certificate for tls.Config.GetCertificate.
type Reloader struct {
	certFile, keyFile string
	logger            *slog.Logger

	mu     sync.RWMutex
	cert   *tls.Certificate
	loaded [2]fileState
}

type fileState struct {
	modTime time.Time
	size    int64
}

// New loads the pair once; it fails if that first load does.
func New(certFile, keyFile string, logger *slog.Logger) (*Reloader, error) {
	r := &Reloader{certFile: certFile, keyFile: keyFile, logger: logger}
	state, err := r.state()
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tls certificate: %w", err)
	}
	r.cert, r.loaded = &cert, state
	return r, nil
}

func (r *Reloader) state() ([2]fileState, error) {
	var state [2]fileState
	for i, name := range []string{r.certFile, r.keyFile} {
		info, err := os.Stat(name) // follows the mounted Secret's symlinks
		if err != nil {
			return state, err
		}
		state[i] = fileState{info.ModTime(), info.Size()}
	}
	return state, nil
}

// Check loads the pair again if its files changed; it reports whether it did.
func (r *Reloader) Check() bool {
	state, err := r.state()
	if err != nil {
		r.logger.Warn("tls certificate unreadable, keeping the loaded one", "error", err)
		return false
	}
	r.mu.RLock()
	unchanged := state == r.loaded
	r.mu.RUnlock()
	if unchanged {
		return false
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		r.logger.Warn("tls certificate not reloaded, keeping the loaded one", "error", err)
		return false
	}
	r.mu.Lock()
	r.cert, r.loaded = &cert, state
	r.mu.Unlock()
	r.logger.Info("tls certificate reloaded", "cert_file", r.certFile)
	return true
}

// Run checks every interval until ctx ends.
func (r *Reloader) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.Check()
		}
	}
}

// GetCertificate is for tls.Config: the pair loaded last.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// ServerConfig is a TLS 1.3 server configuration serving the reloaded certificate:
// TLS 1.3 only, as on every hop (ADR 0012).
func (r *Reloader) ServerConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: r.GetCertificate}
}

// GetClientCertificate is for a client's tls.Config: the pair loaded last, presented
// to any server that asks for a client certificate.
func (r *Reloader) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// ClientConfig is a TLS 1.3 client configuration presenting the reloaded certificate
// (mutual TLS); servers are verified against the system's roots, which SSL_CERT_FILE
// replaces.
func (r *Reloader) ClientConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, GetClientCertificate: r.GetClientCertificate}
}
