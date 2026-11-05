// Package worker scans stored files for personal data: it takes scan requests from
// the queue, reads the object the request names, and reports what it found to the
// API (vaultgate_api.scans).
//
// For each request it asks the API for the scan job (where the object is and its
// KMS-wrapped data key), unwraps the key with KMS, and reads the object from S3
// through vge1.ReaderAt: chunks are fetched with range requests and decrypted in
// memory as the extraction reads them, so plaintext never touches disk. Text goes
// through the detectors as it is extracted; only the kinds and counts of matches are
// reported.
//
// Failures are of two kinds. A verdict on the file (it can't be read, or the stored
// object is not authentic) is reported as unscannable. Anything else (the API, KMS or
// S3 unreachable, a timeout) leaves the message in the queue to be delivered again;
// after the queue's redrive limit it moves to the dead-letter queue, and the API's
// resender eventually marks the file unscannable. Either way nothing becomes clean
// without a complete scan.
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/flaviocavalcantet/vaultgate/scanner/internal/detect"
	"github.com/flaviocavalcantet/vaultgate/scanner/internal/extract"
	"github.com/flaviocavalcantet/vaultgate/scanner/internal/scan"
	"github.com/flaviocavalcantet/vaultgate/scanner/internal/tracing"
	"github.com/flaviocavalcantet/vaultgate/scanner/internal/vge1"
)

// Request is a queue message, as the API sends it.
type Request struct {
	FileID uuid.UUID `json:"file_id"`
	ScanID uuid.UUID `json:"scan_id"`
}

// Job is what the API says about a pending scan.
type Job struct {
	FileID     uuid.UUID
	StorageKey string
	Size       int64 // of the plaintext
	WrappedKey []byte
	KMSKeyID   string
}

// Finding is how many matches of one kind were found.
type Finding struct {
	Kind  detect.Kind `json:"kind"`
	Count int         `json:"count"`
}

// Result is what is reported for a scan.
type Result struct {
	Outcome  string    `json:"outcome"` // scanned or unscannable
	Findings []Finding `json:"findings"`
	Reason   string    `json:"reason,omitempty"`
}

// ErrGone means the scan is no longer pending: it already has a result, or a newer
// request replaced it. The message is done with.
var ErrGone = errors.New("scan is no longer pending")

// API is the API's internal scanner routes.
type API interface {
	Job(ctx context.Context, scanID uuid.UUID) (Job, error)
	// Report records a result and returns the verdict.
	Report(ctx context.Context, scanID uuid.UUID, r Result) (string, error)
}

// Objects opens stored objects for random access.
type Objects interface {
	Open(ctx context.Context, key string) (io.ReaderAt, int64, error)
}

// Keys unwraps data keys.
type Keys interface {
	Unwrap(ctx context.Context, fileID uuid.UUID, wrapped []byte, kmsKeyID string) ([]byte, error)
}

// Outcome of handling one message.
type Outcome string

const (
	Clean       Outcome = "clean"
	Quarantined Outcome = "quarantined"
	Unscannable Outcome = "unscannable"
	Stale       Outcome = "stale"   // the scan was no longer pending
	Retry       Outcome = "retry"   // left in the queue, to be delivered again
	Invalid     Outcome = "invalid" // not a scan request; left for the dead-letter queue
)

// Done says whether the message can be deleted.
func (o Outcome) Done() bool { return o != Retry && o != Invalid }

// Worker handles scan requests.
type Worker struct {
	API       API
	Objects   Objects
	Keys      Keys
	Extractor *extract.Extractor
	Logger    *slog.Logger
	Metrics   *Metrics
	// Tracer records each scan as a span (internal/tracing); nil records nothing.
	Tracer trace.Tracer
}

const maxReason = 500

func (w *Worker) tracer() trace.Tracer {
	if w.Tracer == nil {
		return noop.NewTracerProvider().Tracer(tracing.Name)
	}
	return w.Tracer
}

// Handle processes one message body. ctx carries the trace context of the request
// that sent the message, if any: the scan's span continues that trace.
func (w *Worker) Handle(ctx context.Context, body string) Outcome {
	start := time.Now()
	w.Metrics.inProgress.Inc()
	defer w.Metrics.inProgress.Dec()
	ctx, span := w.tracer().Start(ctx, "scan", trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(attribute.String("messaging.system", "aws_sqs")))
	defer span.End()
	var req Request
	if err := json.Unmarshal([]byte(body), &req); err != nil || req.ScanID == uuid.Nil {
		w.Logger.Error("not a scan request", append([]any{"error", err}, tracing.LogAttrs(span)...)...)
		w.Metrics.jobs.WithLabelValues(string(Invalid)).Inc()
		endScan(span, Invalid)
		return Invalid
	}
	span.SetAttributes(attribute.String("vaultgate.file_id", req.FileID.String()), attribute.String("vaultgate.scan_id", req.ScanID.String()))
	log := w.Logger.With("file_id", req.FileID, "scan_id", req.ScanID).With(tracing.LogAttrs(span)...)
	outcome := w.handle(ctx, req, log)
	w.Metrics.jobs.WithLabelValues(string(outcome)).Inc()
	w.Metrics.duration.Observe(time.Since(start).Seconds())
	endScan(span, outcome)
	return outcome
}

// endScan records the outcome; one that leaves the message in the queue is an error
// (the verdicts, unscannable included, are results).
func endScan(span trace.Span, o Outcome) {
	span.SetAttributes(attribute.String("vaultgate.outcome", string(o)))
	if !o.Done() {
		span.SetStatus(codes.Error, "")
	}
}

func (w *Worker) handle(ctx context.Context, req Request, log *slog.Logger) Outcome {
	job, err := w.API.Job(ctx, req.ScanID)
	if errors.Is(err, ErrGone) {
		log.Info("scan no longer pending")
		return Stale
	}
	if err != nil {
		log.Warn("scan job unavailable", "error", err)
		return Retry
	}
	if job.FileID != req.FileID {
		log.Warn("request names another file than its scan", "job_file_id", job.FileID)
		log = log.With("file_id", job.FileID)
	}
	result, err := w.scan(ctx, job, log)
	if err != nil {
		log.Warn("scan not finished; it will be retried", "error", err)
		return Retry
	}
	verdict, err := w.API.Report(ctx, req.ScanID, result)
	if errors.Is(err, ErrGone) {
		log.Info("scan got a result elsewhere")
		return Stale
	}
	if err != nil {
		log.Warn("result not recorded; it will be retried", "error", err)
		return Retry
	}
	log.Info("scan reported", "verdict", verdict, "findings", counts(result.Findings), "reason", result.Reason)
	switch verdict {
	case string(Clean), string(Quarantined), string(Unscannable):
		return Outcome(verdict)
	default:
		return Unscannable // pending would be the API's bug; never counted as clean
	}
}

// scan reads the object and returns the result to report, or an error when the scan
// did not finish for a reason that is not about the file (to be retried).
func (w *Worker) scan(ctx context.Context, job Job, log *slog.Logger) (Result, error) {
	key, err := step(w, ctx, "unwrap key", func(ctx context.Context) ([]byte, error) {
		return w.Keys.Unwrap(ctx, job.FileID, job.WrappedKey, job.KMSKeyID)
	})
	if err != nil {
		return Result{}, err
	}
	defer clear(key)
	var size int64
	src, err := step(w, ctx, "open object", func(ctx context.Context) (io.ReaderAt, error) {
		src, n, err := w.Objects.Open(ctx, job.StorageKey)
		size = n
		return src, err
	})
	if err != nil {
		return Result{}, err
	}
	plain, err := vge1.NewReaderAt(src, size, key, job.FileID)
	if errors.Is(err, vge1.ErrNotAuthentic) {
		log.Error("stored object is not authentic", "error", err)
		return unscannable(nil, "stored object is not authentic"), nil
	}
	if err != nil {
		return Result{}, err
	}
	if plain.Size() != job.Size {
		log.Error("stored object does not match its recorded size", "stored", plain.Size(), "recorded", job.Size)
		return unscannable(nil, "stored object does not match its recorded size"), nil
	}
	// The extraction turns some read errors into "damaged document"; the recorder
	// keeps the real one, which decides.
	rec := &recorder{r: plain}
	found := map[detect.Kind]int{}
	// One span for the whole read: each range request would be a span of its own,
	// thousands for a large file. Their number is an attribute instead.
	_, read := w.tracer().Start(ctx, "read and detect")
	report, n, err := scan.Document(w.Extractor, rec, plain.Size(), func(f detect.Finding) { found[f.Kind]++ })
	read.SetAttributes(
		attribute.String("vaultgate.format", string(report.Format)),
		attribute.Int("vaultgate.parts", report.Parts),
		attribute.Int64("vaultgate.text_bytes", n),
		attribute.Int64("vaultgate.reads", rec.reads.Load()),
	)
	read.End()
	w.Metrics.textBytes.Add(float64(n))
	if readErr := rec.Err(); readErr != nil {
		if errors.Is(readErr, vge1.ErrNotAuthentic) {
			log.Error("stored object is not authentic", "error", readErr)
			return unscannable(nil, "stored object is not authentic"), nil
		}
		return Result{}, readErr
	}
	log.Info("document read", "format", report.Format, "parts", report.Parts, "text_bytes", n)
	switch {
	case errors.Is(err, extract.ErrUnscannable):
		reason := strings.TrimPrefix(err.Error(), extract.ErrUnscannable.Error()+": ")
		return unscannable(found, reason), nil
	case err != nil:
		return Result{}, err // e.g. no PDF engine free
	}
	return Result{Outcome: "scanned", Findings: findings(found)}, nil
}

func unscannable(found map[detect.Kind]int, reason string) Result {
	if len(reason) > maxReason {
		reason = reason[:maxReason]
	}
	return Result{Outcome: "unscannable", Findings: findings(found), Reason: reason}
}

func findings(found map[detect.Kind]int) []Finding {
	out := []Finding{}
	for kind, count := range found {
		out = append(out, Finding{kind, count})
	}
	return out
}

func counts(fs []Finding) map[detect.Kind]int {
	out := map[detect.Kind]int{}
	for _, f := range fs {
		out[f.Kind] = f.Count
	}
	return out
}

// step runs one part of a scan in a span of its own.
func step[T any](w *Worker, ctx context.Context, name string, fn func(context.Context) (T, error)) (T, error) {
	ctx, span := w.tracer().Start(ctx, name)
	defer span.End()
	v, err := fn(ctx)
	if err != nil {
		span.SetStatus(codes.Error, "")
	}
	return v, err
}

// recorder keeps the first read error other than EOF, and counts reads.
type recorder struct {
	r     io.ReaderAt
	mu    sync.Mutex
	err   error
	reads atomic.Int64
}

func (c *recorder) ReadAt(p []byte, off int64) (int, error) {
	c.reads.Add(1)
	n, err := c.r.ReadAt(p, off)
	if err != nil && err != io.EOF {
		c.mu.Lock()
		if c.err == nil {
			c.err = err
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *recorder) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}
