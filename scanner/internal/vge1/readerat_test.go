package vge1

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	mrand "math/rand/v2"
	"testing"

	"github.com/google/uuid"
)

func openAt(t *testing.T, key []byte, fileID uuid.UUID, c []byte) (*ReaderAt, error) {
	t.Helper()
	return NewReaderAt(bytes.NewReader(c), int64(len(c)), key, fileID)
}

func TestReaderAtReadsTheGatewayVectors(t *testing.T) {
	key, fileID, _, vectors := loadVectors(t)
	for _, v := range vectors {
		r, err := openAt(t, key, fileID, v.ciphertext)
		if err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		got, err := io.ReadAll(io.NewSectionReader(r, 0, r.Size()))
		if err != nil || !bytes.Equal(got, v.plain) {
			t.Errorf("%s: got %x, %v; want %x", v.name, got, err, v.plain)
		}
	}
}

// Random reads anywhere, of any length, return exactly the plaintext there. Small
// chunks make reads cross chunk and group boundaries.
func TestReaderAtRandomReads(t *testing.T) {
	key := make([]byte, keySize)
	_, _ = rand.Read(key)
	fileID := uuid.New()
	for _, chunkSize := range []int{1, 7, 4096, 65536} {
		// Over a group (1 MiB) for the large chunks, so reads cross groups too.
		for _, size := range []int{0, 1, chunkSize, chunkSize + 1, 3*chunkSize + 5, 300 * chunkSize} {
			plain := make([]byte, size)
			_, _ = rand.Read(plain)
			r, err := openAt(t, key, fileID, encrypt(t, key, fileID, chunkSize, plain))
			if err != nil {
				t.Fatalf("chunk %d size %d: %v", chunkSize, size, err)
			}
			if r.Size() != int64(size) {
				t.Fatalf("size %d, want %d", r.Size(), size)
			}
			for range 100 {
				off := mrand.IntN(size + 2)
				p := make([]byte, mrand.IntN(3*chunkSize+2))
				n, err := r.ReadAt(p, int64(off))
				want := plain[min(off, size):min(off+len(p), size)]
				if !bytes.Equal(p[:n], want) {
					t.Fatalf("chunk %d size %d: read at %d of %d differs", chunkSize, size, off, len(p))
				}
				if n < len(p) && err != io.EOF {
					t.Fatalf("short read without EOF: %v", err)
				}
				if n == len(p) && err != nil {
					t.Fatalf("full read with error: %v", err)
				}
			}
		}
	}
}

func TestReaderAtRefusesWrongLengthKeyOrFile(t *testing.T) {
	key, fileID, chunkSize, vectors := loadVectors(t)
	sealed := chunkSize + tagSize
	for _, v := range vectors {
		c := v.ciphertext
		cases := map[string][]byte{
			"byte appended": append(bytes.Clone(c), 0),
			"last byte cut": c[:len(c)-1],
		}
		if len(c) >= headerSize+2*sealed {
			cases["cut at a chunk"] = c[:headerSize+sealed]
		}
		for name, changed := range cases {
			if _, err := openAt(t, key, fileID, changed); !errors.Is(err, ErrNotAuthentic) {
				t.Errorf("%s, %s: got %v, want ErrNotAuthentic", v.name, name, err)
			}
		}
		if _, err := openAt(t, key, uuid.New(), c); !errors.Is(err, ErrNotAuthentic) {
			t.Errorf("%s, wrong file: got %v", v.name, err)
		}
		wrongKey := bytes.Clone(key)
		wrongKey[0] ^= 1
		if _, err := openAt(t, wrongKey, fileID, c); !errors.Is(err, ErrNotAuthentic) {
			t.Errorf("%s, wrong key: got %v", v.name, err)
		}
	}
}

func TestReaderAtRefusesATamperedChunkWhenRead(t *testing.T) {
	key := make([]byte, keySize)
	_, _ = rand.Read(key)
	fileID := uuid.New()
	plain := make([]byte, 3*groupBytes)
	c := encrypt(t, key, fileID, 65536, plain)
	c[headerSize+5] ^= 1 // the first chunk; the final one is intact, so it opens
	r, err := openAt(t, key, fileID, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadAt(make([]byte, 10), int64(len(plain)-10)); err != nil {
		t.Fatalf("an intact chunk failed: %v", err)
	}
	if _, err := r.ReadAt(make([]byte, 10), 0); !errors.Is(err, ErrNotAuthentic) {
		t.Fatalf("got %v, want ErrNotAuthentic", err)
	}
}

type failingAt struct {
	r       io.ReaderAt
	failAt  int64
	failErr error
}

func (f failingAt) ReadAt(p []byte, off int64) (int, error) {
	if off+int64(len(p)) > f.failAt && off < f.failAt+1 {
		return 0, f.failErr
	}
	return f.r.ReadAt(p, off)
}

// A failing source is an error to retry, not a verdict on the object.
func TestReaderAtSourceErrorsAreNotVerdicts(t *testing.T) {
	key := make([]byte, keySize)
	_, _ = rand.Read(key)
	fileID := uuid.New()
	plain := make([]byte, 3*groupBytes)
	c := encrypt(t, key, fileID, 65536, plain)
	reset := errors.New("connection reset")
	src := failingAt{bytes.NewReader(c), headerSize + 10, reset}
	r, err := NewReaderAt(src, int64(len(c)), key, fileID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadAt(make([]byte, 10), 0); !errors.Is(err, reset) || errors.Is(err, ErrNotAuthentic) {
		t.Fatalf("got %v, want the source error", err)
	}
}
