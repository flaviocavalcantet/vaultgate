package worker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// HTTPAPI calls the API's internal scanner routes with the scanner's secret.
type HTTPAPI struct {
	BaseURL string // the internal API, e.g. http://api:8001
	Token   string
	Client  *http.Client
}

// NewHTTPAPI returns a client with a request timeout.
func NewHTTPAPI(baseURL, token string) *HTTPAPI {
	return &HTTPAPI{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, Client: &http.Client{Timeout: 15 * time.Second}}
}

func (a *HTTPAPI) Job(ctx context.Context, scanID uuid.UUID) (Job, error) {
	var body struct {
		FileID     uuid.UUID `json:"file_id"`
		StorageKey string    `json:"storage_key"`
		Size       int64     `json:"size"`
		WrappedKey string    `json:"wrapped_key"`
		KMSKeyID   string    `json:"kms_key_id"`
	}
	if err := a.call(ctx, http.MethodGet, "/internal/scans/"+scanID.String(), nil, &body); err != nil {
		return Job{}, err
	}
	wrapped, err := base64.StdEncoding.DecodeString(body.WrappedKey)
	if err != nil {
		return Job{}, fmt.Errorf("scan job: wrapped key is not base64: %w", err)
	}
	return Job{body.FileID, body.StorageKey, body.Size, wrapped, body.KMSKeyID}, nil
}

func (a *HTTPAPI) Report(ctx context.Context, scanID uuid.UUID, r Result) (string, error) {
	var body struct {
		Verdict string `json:"verdict"`
	}
	err := a.call(ctx, http.MethodPost, "/internal/scans/"+scanID.String()+"/result", r, &body)
	return body.Verdict, err
}

func (a *HTTPAPI) call(ctx context.Context, method, path string, in, out any) error {
	var payload io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.BaseURL+path, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusConflict:
		return ErrGone
	case resp.StatusCode != http.StatusOK:
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, bytes.TrimSpace(detail))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}
