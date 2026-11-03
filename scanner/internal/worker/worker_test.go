package worker

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/flaviocavalcantet/vaultgate/scanner/internal/detect"
	"github.com/flaviocavalcantet/vaultgate/scanner/internal/extract"
)

var pdf *extract.PDFium

func TestMain(m *testing.M) {
	var err error
	pdf, err = extract.NewPDFium(2, 256<<20, 30*time.Second)
	if err != nil {
		panic(err)
	}
	code := m.Run()
	_ = pdf.Close()
	os.Exit(code)
}

// encrypt writes VGE1 as the gateway does (ADR 0003), with 64 KiB chunks.
func encrypt(t *testing.T, key []byte, fileID uuid.UUID, plain []byte) []byte {
	t.Helper()
	const chunkSize = 65536
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	header := append([]byte("VGE1"), 1)
	header = binary.BigEndian.AppendUint32(header, chunkSize)
	prefix := make([]byte, 7)
	_, _ = rand.Read(prefix)
	header = append(header, prefix...)
	aad := append(bytes.Clone(header), fileID[:]...)
	out := bytes.Clone(header)
	for i := 0; ; i++ {
		n := min(chunkSize, len(plain))
		last := len(plain) <= chunkSize
		nonce := binary.BigEndian.AppendUint32(bytes.Clone(prefix), uint32(i))
		if last {
			nonce = append(nonce, 1)
		} else {
			nonce = append(nonce, 0)
		}
		out = aead.Seal(out, nonce, plain[:n], aad)
		plain = plain[n:]
		if last {
			return out
		}
	}
}

// fakeAPI keeps one scan, records the result reported, and gives the API's verdict.
type fakeAPI struct {
	mu        sync.Mutex
	job       Job
	jobErr    error
	reportErr error
	reported  []Result
}

func (a *fakeAPI) Job(_ context.Context, _ uuid.UUID) (Job, error) {
	return a.job, a.jobErr
}

func (a *fakeAPI) Report(_ context.Context, _ uuid.UUID, r Result) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.reportErr != nil {
		return "", a.reportErr
	}
	a.reported = append(a.reported, r)
	if r.Outcome == "unscannable" {
		return "unscannable", nil
	}
	for _, f := range r.Findings {
		if f.Kind == detect.KindPaymentCard || f.Kind == detect.KindCPF {
			return "quarantined", nil
		}
	}
	return "clean", nil
}

type fakeObjects struct {
	data map[string][]byte
	wrap func(io.ReaderAt) io.ReaderAt
	err  error
}

func (o *fakeObjects) Open(_ context.Context, key string) (io.ReaderAt, int64, error) {
	if o.err != nil {
		return nil, 0, o.err
	}
	data, ok := o.data[key]
	if !ok {
		return nil, 0, errors.New("NoSuchKey")
	}
	var r io.ReaderAt = bytes.NewReader(data)
	if o.wrap != nil {
		r = o.wrap(r)
	}
	return r, int64(len(data)), nil
}

type fakeKeys struct {
	key []byte
	err error
}

func (k *fakeKeys) Unwrap(_ context.Context, _ uuid.UUID, _ []byte, _ string) ([]byte, error) {
	return bytes.Clone(k.key), k.err
}

type fixture struct {
	worker  *Worker
	api     *fakeAPI
	objects *fakeObjects
	keys    *fakeKeys
	body    string
	stored  []byte
}

// newFixture stores plain encrypted, with a pending scan for it.
func newFixture(t *testing.T, plain []byte) *fixture {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	fileID, scanID := uuid.New(), uuid.New()
	stored := encrypt(t, key, fileID, plain)
	f := &fixture{
		api: &fakeAPI{job: Job{
			FileID: fileID, StorageKey: "files/" + fileID.String(), Size: int64(len(plain)),
			WrappedKey: []byte("wrapped"), KMSKeyID: "alias/test",
		}},
		objects: &fakeObjects{data: map[string][]byte{"files/" + fileID.String(): stored}},
		keys:    &fakeKeys{key: key},
		stored:  stored,
	}
	body, _ := json.Marshal(Request{FileID: fileID, ScanID: scanID})
	f.body = string(body)
	f.worker = &Worker{
		API: f.api, Objects: f.objects, Keys: f.keys,
		Extractor: &extract.Extractor{Limits: extract.DefaultLimits(), PDF: pdf},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics:   NewMetrics(prometheus.NewRegistry()),
	}
	return f
}

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../extract/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (f *fixture) only(t *testing.T) Result {
	t.Helper()
	if len(f.api.reported) != 1 {
		t.Fatalf("want one result reported, got %+v", f.api.reported)
	}
	r := f.api.reported[0]
	slices.SortFunc(r.Findings, func(a, b Finding) int { return bytes.Compare([]byte(a.Kind), []byte(b.Kind)) })
	return r
}

func TestScansAndReportsFindings(t *testing.T) {
	for _, tc := range []struct {
		name     string
		plain    []byte
		outcome  Outcome
		findings []Finding
	}{
		{"clean text", []byte("nothing to see here\n"), Clean, []Finding{}},
		{"empty file", []byte{}, Clean, []Finding{}},
		{"email only", []byte("write to alice@example.com\n"), Clean, []Finding{{detect.KindEmail, 1}}},
		{"card in text", []byte("card 4111 1111 1111 1111 and 4111 1111 1111 1111"), Quarantined,
			[]Finding{{detect.KindPaymentCard, 2}}},
		{"Word document", nil, Quarantined, []Finding{
			{detect.KindCPF, 1}, {detect.KindEmail, 1}, {detect.KindPaymentCard, 1}}},
		{"PDF", nil, Quarantined, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plain := tc.plain
			switch tc.name {
			case "Word document":
				plain = testdata(t, "report.docx")
			case "PDF":
				plain = testdata(t, "report.pdf")
			}
			f := newFixture(t, plain)
			if got := f.worker.Handle(context.Background(), f.body); got != tc.outcome {
				t.Fatalf("outcome %s, want %s", got, tc.outcome)
			}
			r := f.only(t)
			if r.Outcome != "scanned" {
				t.Fatalf("got %+v", r)
			}
			if tc.findings != nil && !slices.Equal(r.Findings, tc.findings) {
				t.Fatalf("findings %+v, want %+v", r.Findings, tc.findings)
			}
		})
	}
}

func TestUnreadableFilesAreUnscannableWithTheReason(t *testing.T) {
	f := newFixture(t, testdata(t, "encrypted.pdf"))
	if got := f.worker.Handle(context.Background(), f.body); got != Unscannable {
		t.Fatalf("outcome %s", got)
	}
	if r := f.only(t); r.Outcome != "unscannable" || r.Reason != "PDF is encrypted" {
		t.Fatalf("got %+v", r)
	}
}

func TestStoredObjectsThatAreNotAuthenticAreUnscannable(t *testing.T) {
	big := bytes.Repeat([]byte("lorem ipsum "), 300_000) // several groups of chunks
	for name, change := range map[string]func(f *fixture){
		"tampered chunk": func(f *fixture) { f.stored[40] ^= 1 },
		"truncated": func(f *fixture) {
			for k, v := range f.objects.data {
				f.objects.data[k] = v[:len(v)-1]
			}
		},
		"wrong key":     func(f *fixture) { f.keys.key[0] ^= 1 },
		"size mismatch": func(f *fixture) { f.api.job.Size++ },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, big)
			change(f)
			if got := f.worker.Handle(context.Background(), f.body); got != Unscannable {
				t.Fatalf("outcome %s", got)
			}
			if r := f.only(t); r.Outcome != "unscannable" || r.Reason == "" {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

type failAfter struct {
	r     io.ReaderAt
	reads int
	mu    sync.Mutex
}

func (f *failAfter) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	f.reads--
	fail := f.reads < 0
	f.mu.Unlock()
	if fail {
		return 0, errors.New("connection reset")
	}
	return f.r.ReadAt(p, off)
}

// Nothing is reported unless the scan finished, or failed because of the file.
func TestFailuresOutsideTheFileAreRetried(t *testing.T) {
	for name, change := range map[string]func(f *fixture){
		"API down":       func(f *fixture) { f.api.jobErr = errors.New("connection refused") },
		"KMS down":       func(f *fixture) { f.keys.err = errors.New("KMS unavailable") },
		"S3 down":        func(f *fixture) { f.objects.err = errors.New("S3 unavailable") },
		"result refused": func(f *fixture) { f.api.reportErr = errors.New("500") },
		// The read fails inside the zip: the extraction alone would call the
		// document damaged, which would wrongly be a verdict.
		"read fails mid-document": func(f *fixture) {
			f.objects.wrap = func(r io.ReaderAt) io.ReaderAt { return &failAfter{r: r, reads: 2} }
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, bigZip(t))
			change(f)
			if got := f.worker.Handle(context.Background(), f.body); got != Retry || got.Done() {
				t.Fatalf("outcome %s, want retry", got)
			}
			if len(f.api.reported) != 0 {
				t.Fatalf("reported %+v", f.api.reported)
			}
		})
	}
}

// bigZip is a zip larger than one read group, so reading its entries needs more reads
// after the index at the end.
func bigZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	noise := make([]byte, 3<<20)
	_, _ = rand.Read(noise)
	w, _ := zw.CreateHeader(&zip.FileHeader{Name: "noise.bin", Method: zip.Store})
	_, _ = w.Write(noise)
	w, _ = zw.Create("card.txt")
	_, _ = w.Write([]byte("4111 1111 1111 1111"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestScansNoLongerPendingAreDone(t *testing.T) {
	f := newFixture(t, []byte("x"))
	f.api.jobErr = ErrGone
	if got := f.worker.Handle(context.Background(), f.body); got != Stale || !got.Done() {
		t.Fatalf("outcome %s", got)
	}
	f = newFixture(t, []byte("x"))
	f.api.reportErr = ErrGone
	if got := f.worker.Handle(context.Background(), f.body); got != Stale {
		t.Fatalf("outcome %s", got)
	}
}

func TestMessagesThatAreNotScanRequestsAreLeftForTheDeadLetterQueue(t *testing.T) {
	f := newFixture(t, []byte("x"))
	for _, body := range []string{"", "not json", `{"file_id": "x"}`, `{"scan_id": "00000000-0000-0000-0000-000000000000"}`} {
		if got := f.worker.Handle(context.Background(), body); got != Invalid || got.Done() {
			t.Fatalf("%q: outcome %s", body, got)
		}
	}
	if len(f.api.reported) != 0 {
		t.Fatal("reported a result")
	}
}
