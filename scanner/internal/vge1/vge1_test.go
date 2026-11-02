package vge1

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"testing/iotest"

	"github.com/google/uuid"
)

// The gateway's frozen vectors: the Python implementation defines the format, and
// this decoder must read exactly what it writes.
const vectorsPath = "../../../gateway/tests/vectors/vge1.json"

type vectorFile struct {
	Key       string `json:"key"`
	FileID    string `json:"file_id"`
	ChunkSize int    `json:"chunk_size"`
	Vectors   []struct {
		Name       string `json:"name"`
		Plaintext  string `json:"plaintext"`
		Ciphertext string `json:"ciphertext"`
	} `json:"vectors"`
}

type vector struct {
	name              string
	plain, ciphertext []byte
}

func loadVectors(t *testing.T) ([]byte, uuid.UUID, int, []vector) {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("reading the gateway's vectors: %v", err)
	}
	var f vectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	key := mustHex(t, f.Key)
	fileID := uuid.MustParse(f.FileID)
	var out []vector
	for _, v := range f.Vectors {
		out = append(out, vector{v.Name, mustHex(t, v.Plaintext), mustHex(t, v.Ciphertext)})
	}
	if len(out) < 5 {
		t.Fatalf("expected the gateway's vectors, got %d", len(out))
	}
	return key, fileID, f.ChunkSize, out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decrypt(key []byte, fileID uuid.UUID, src io.Reader) ([]byte, error) {
	r, err := NewReader(src, key, fileID)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestDecryptsTheGatewayVectors(t *testing.T) {
	key, fileID, _, vectors := loadVectors(t)
	for _, v := range vectors {
		for name, wrap := range map[string]func(io.Reader) io.Reader{
			"whole":    func(r io.Reader) io.Reader { return r },
			"one byte": iotest.OneByteReader,
			"halves":   iotest.HalfReader,
		} {
			got, err := decrypt(key, fileID, wrap(bytes.NewReader(v.ciphertext)))
			if err != nil || !bytes.Equal(got, v.plain) {
				t.Errorf("%s (%s): got %x, %v; want %x", v.name, name, got, err, v.plain)
			}
		}
	}
}

func TestReadsInSmallPieces(t *testing.T) {
	key, fileID, _, vectors := loadVectors(t)
	v := vectors[len(vectors)-1] // several chunks
	r, err := NewReader(bytes.NewReader(v.ciphertext), key, fileID)
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	buf := make([]byte, 3)
	for {
		n, err := r.Read(buf)
		got = append(got, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got, v.plain) {
		t.Fatalf("got %x, want %x", got, v.plain)
	}
}

func assertNotAuthentic(t *testing.T, what string, key []byte, fileID uuid.UUID, ciphertext []byte) {
	t.Helper()
	got, err := decrypt(key, fileID, bytes.NewReader(ciphertext))
	if !errors.Is(err, ErrNotAuthentic) {
		t.Fatalf("%s: got %x, %v; want ErrNotAuthentic", what, got, err)
	}
}

// Every attack in ADR 0003's table is refused.
func TestRefusesTamperedObjects(t *testing.T) {
	key, fileID, chunkSize, vectors := loadVectors(t)
	sealed := chunkSize + tagSize
	for _, v := range vectors {
		c := v.ciphertext
		for i := range c {
			changed := bytes.Clone(c)
			changed[i] ^= 0x01
			assertNotAuthentic(t, v.name+": changed byte", key, fileID, changed)
		}
		for n := 0; n < len(c); n++ {
			assertNotAuthentic(t, v.name+": truncated", key, fileID, c[:n])
		}
		assertNotAuthentic(t, v.name+": byte appended", key, fileID, append(bytes.Clone(c), 0))
		assertNotAuthentic(t, v.name+": wrong file", key, uuid.New(), c)
		wrongKey := bytes.Clone(key)
		wrongKey[0] ^= 0x01
		assertNotAuthentic(t, v.name+": wrong key", wrongKey, fileID, c)
		if len(c) >= headerSize+2*sealed { // at least two chunks
			chunk := func(i int) []byte { return c[headerSize+i*sealed : headerSize+(i+1)*sealed] }
			swapped := append(append(append(bytes.Clone(c[:headerSize]), chunk(1)...), chunk(0)...),
				c[headerSize+2*sealed:]...)
			assertNotAuthentic(t, v.name+": chunks reordered", key, fileID, swapped)
			duplicated := append(append(bytes.Clone(c[:headerSize+sealed]), chunk(0)...),
				c[headerSize+sealed:]...)
			assertNotAuthentic(t, v.name+": chunk duplicated", key, fileID, duplicated)
			dropped := append(bytes.Clone(c[:headerSize]), c[headerSize+sealed:]...)
			assertNotAuthentic(t, v.name+": chunk dropped", key, fileID, dropped)
			// Cut at a chunk boundary: what is left is all valid, non-final chunks.
			assertNotAuthentic(t, v.name+": cut at a chunk", key, fileID, c[:headerSize+sealed])
		}
	}
}

func TestRefusesBadHeaders(t *testing.T) {
	key, fileID, _, vectors := loadVectors(t)
	c := vectors[0].ciphertext
	for name, change := range map[string]func([]byte){
		"magic":          func(h []byte) { h[0] = 'X' },
		"version":        func(h []byte) { h[4] = 2 },
		"zero chunks":    func(h []byte) { binary.BigEndian.PutUint32(h[5:9], 0) },
		"huge chunks":    func(h []byte) { binary.BigEndian.PutUint32(h[5:9], maxChunkSize+1) },
		"another prefix": func(h []byte) { h[15] ^= 0x01 },
	} {
		changed := bytes.Clone(c)
		change(changed)
		assertNotAuthentic(t, name, key, fileID, changed)
	}
}

func TestRejectsKeysOfTheWrongSize(t *testing.T) {
	_, err := NewReader(bytes.NewReader(nil), make([]byte, 16), uuid.New())
	if err == nil || errors.Is(err, ErrNotAuthentic) {
		t.Fatalf("want a key size error, got %v", err)
	}
}

// A failing source is an I/O error to retry, not a verdict that the object is bad.
func TestSourceErrorsAreNotVerdicts(t *testing.T) {
	key, fileID, _, vectors := loadVectors(t)
	c := vectors[len(vectors)-1].ciphertext
	broken := io.MultiReader(bytes.NewReader(c[:headerSize+5]), iotest.ErrReader(errors.New("connection reset")))
	_, err := decrypt(key, fileID, broken)
	if err == nil || errors.Is(err, ErrNotAuthentic) {
		t.Fatalf("want the source error, got %v", err)
	}
}

// encrypt writes VGE1 from the spec, for round trips larger than the vectors. The
// format itself is pinned by the gateway's vectors above.
func encrypt(t *testing.T, key []byte, fileID uuid.UUID, chunkSize int, plain []byte) []byte {
	t.Helper()
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	header := append([]byte("VGE1"), version)
	header = binary.BigEndian.AppendUint32(header, uint32(chunkSize))
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

func TestRoundTripsLargeObjects(t *testing.T) {
	key := make([]byte, keySize)
	_, _ = rand.Read(key)
	fileID := uuid.New()
	for _, size := range []int{0, 1, 65536, 65537, 3*65536 + 17, 1 << 20} {
		plain := make([]byte, size)
		_, _ = rand.Read(plain)
		c := encrypt(t, key, fileID, 65536, plain)
		got, err := decrypt(key, fileID, iotest.HalfReader(bytes.NewReader(c)))
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("size %d: %v", size, err)
		}
	}
}
