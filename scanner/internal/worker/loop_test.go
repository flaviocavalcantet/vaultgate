package worker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
)

func TestHTTPAPI(t *testing.T) {
	scanID, fileID := uuid.New(), uuid.New()
	var gotResult Result
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /internal/scans/" + scanID.String():
			_ = json.NewEncoder(w).Encode(map[string]any{
				"file_id": fileID, "storage_key": "files/x", "size": 5, "content_type": "text/plain",
				"wrapped_key": base64.StdEncoding.EncodeToString([]byte("wrapped")), "kms_key_id": "k",
			})
		case "POST /internal/scans/" + scanID.String() + "/result":
			_ = json.NewDecoder(r.Body).Decode(&gotResult)
			_, _ = w.Write([]byte(`{"verdict": "quarantined"}`))
		case "GET /internal/scans/" + uuid.Nil.String():
			w.WriteHeader(http.StatusConflict)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	api := NewHTTPAPI(server.URL+"/", "secret")

	job, err := api.Job(context.Background(), scanID)
	if err != nil || job.FileID != fileID || job.StorageKey != "files/x" || job.Size != 5 ||
		string(job.WrappedKey) != "wrapped" || job.KMSKeyID != "k" {
		t.Fatalf("job %+v, %v", job, err)
	}
	result := Result{Outcome: "scanned", Findings: []Finding{{"payment_card", 1}}}
	verdict, err := api.Report(context.Background(), scanID, result)
	if err != nil || verdict != "quarantined" || gotResult.Findings[0] != result.Findings[0] {
		t.Fatalf("verdict %q, %v, sent %+v", verdict, err, gotResult)
	}
	if _, err := api.Job(context.Background(), uuid.New()); !errors.Is(err, ErrGone) {
		t.Fatalf("404: %v", err)
	}
	if _, err := api.Job(context.Background(), uuid.Nil); !errors.Is(err, ErrGone) {
		t.Fatalf("409: %v", err)
	}
	wrong := NewHTTPAPI(server.URL, "wrong")
	if _, err := wrong.Job(context.Background(), scanID); err == nil || errors.Is(err, ErrGone) {
		t.Fatalf("401 must be an error to retry: %v", err)
	}
}

// Empty results report a JSON array, never null: the API expects a list.
func TestResultsAlwaysHaveAFindingsList(t *testing.T) {
	b, _ := json.Marshal(unscannable(nil, "x"))
	var decoded map[string]any
	_ = json.Unmarshal(b, &decoded)
	if _, ok := decoded["findings"].([]any); !ok {
		t.Fatalf("got %s", b)
	}
}

type fakeQueue struct {
	mu       sync.Mutex
	pending  []Delivery
	deleted  []string
	extended map[string]int
	failures int // Receive calls to fail first
}

func (q *fakeQueue) Receive(ctx context.Context, max int) ([]Delivery, error) {
	q.mu.Lock()
	if q.failures > 0 {
		q.failures--
		q.mu.Unlock()
		return nil, errors.New("queue unavailable")
	}
	n := min(max, len(q.pending))
	out := q.pending[:n]
	q.pending = q.pending[n:]
	q.mu.Unlock()
	if n == 0 {
		select { // long polling
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return out, nil
}

func (q *fakeQueue) Delete(_ context.Context, d Delivery) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.deleted = append(q.deleted, d.Handle)
	return nil
}

func (q *fakeQueue) Extend(_ context.Context, d Delivery, _ time.Duration) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.extended[d.Handle]++
	return nil
}

// stubAPI answers by scan: done, gone, failing, or slow.
type stubAPI struct {
	slow  uuid.UUID
	fail  uuid.UUID
	gone  uuid.UUID
	delay time.Duration
}

func (a *stubAPI) Job(ctx context.Context, scanID uuid.UUID) (Job, error) {
	switch scanID {
	case a.gone:
		return Job{}, ErrGone
	case a.fail:
		return Job{}, errors.New("API down")
	case a.slow:
		time.Sleep(a.delay)
	}
	return Job{}, ErrGone // the job itself is not the point here
}

func (a *stubAPI) Report(context.Context, uuid.UUID, Result) (string, error) { return "", nil }

func request(scanID uuid.UUID) string {
	b, _ := json.Marshal(Request{FileID: uuid.New(), ScanID: scanID})
	return string(b)
}

func TestLoopDeletesHandledMessagesAndKeepsTheRest(t *testing.T) {
	api := &stubAPI{slow: uuid.New(), fail: uuid.New(), gone: uuid.New(), delay: 250 * time.Millisecond}
	q := &fakeQueue{extended: map[string]int{}, failures: 2, pending: []Delivery{
		{Body: request(api.gone), Handle: "gone"},
		{Body: request(api.fail), Handle: "fail"},
		{Body: request(api.slow), Handle: "slow"},
		{Body: "garbage", Handle: "garbage"},
	}}
	loop := &Loop{
		Worker: &Worker{API: api, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Metrics: NewMetrics(prometheus.NewRegistry())},
		Queue:       q,
		Concurrency: 2,
		Visibility:  90 * time.Millisecond, // extended every 30 ms
		JobTimeout:  time.Minute,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { loop.Run(ctx); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		q.mu.Lock()
		handled := len(q.pending) == 0 && len(q.deleted) == 2
		q.mu.Unlock()
		if handled || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	deleted := map[string]bool{}
	for _, h := range q.deleted {
		deleted[h] = true
	}
	if !deleted["gone"] || !deleted["slow"] || deleted["fail"] || deleted["garbage"] {
		t.Fatalf("deleted %v; want gone and slow only", q.deleted)
	}
	if q.extended["slow"] == 0 {
		t.Fatal("the slow message's visibility was never extended")
	}
}

func TestLoopFinishesScansInProgressWhenStopped(t *testing.T) {
	api := &stubAPI{slow: uuid.New(), delay: 300 * time.Millisecond}
	q := &fakeQueue{extended: map[string]int{}, pending: []Delivery{{Body: request(api.slow), Handle: "slow"}}}
	loop := &Loop{
		Worker: &Worker{API: api, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Metrics: NewMetrics(prometheus.NewRegistry())},
		Queue: q, Concurrency: 1, Visibility: time.Minute, JobTimeout: time.Minute,
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	loop.Run(ctx) // returns only after the slow scan finished
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.deleted) != 1 {
		t.Fatalf("deleted %v", q.deleted)
	}
}
