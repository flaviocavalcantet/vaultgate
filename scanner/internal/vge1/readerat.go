package vge1

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/google/uuid"
)

// ReaderAt gives random access to an object's plaintext, decrypting only the chunks a
// read touches. Documents need it: a zip's index is at the end, and PDF readers jump
// around. Nothing is written to disk; a few groups of decrypted chunks stay in memory.
//
// Every chunk returned is authenticated, and NewReaderAt authenticates the final chunk
// before anything is read, which proves the object has its full length: truncated,
// extended or cut at a chunk boundary, it fails there. Chunks are bound to their
// position by the nonce, so a chunk moved elsewhere fails too.
type ReaderAt struct {
	src        io.ReaderAt
	aead       cipher.AEAD
	aad        []byte
	prefix     []byte
	chunkSize  int64
	chunks     int64 // in the object, the final one included
	size       int64 // of the plaintext
	groupLen   int64 // chunks fetched and decrypted per source read
	mu         sync.Mutex
	cache      map[int64][]byte // group index -> its plaintext
	cacheOrder []int64          // oldest first
}

const (
	// About this much ciphertext is fetched per source read (a range request on S3).
	groupBytes = 1 << 20
	// Decrypted groups kept, so reading the end of a zip and then its entries does not
	// fetch the same chunks again and again.
	cachedGroups = 4
)

// NewReaderAt opens an object of objectSize bytes readable through src, encrypted for
// fileID with key.
func NewReaderAt(src io.ReaderAt, objectSize int64, key []byte, fileID uuid.UUID) (*ReaderAt, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("vge1: data keys are %d bytes, got %d", keySize, len(key))
	}
	header := make([]byte, headerSize)
	if objectSize < headerSize+tagSize {
		return nil, notAuthentic("too short", nil)
	}
	if _, err := src.ReadAt(header, 0); err != nil {
		return nil, err
	}
	if string(header[:4]) != string(magic) || header[4] != version {
		return nil, notAuthentic("not a VGE1 object", nil)
	}
	chunkSize := int64(binary.BigEndian.Uint32(header[5:9]))
	if chunkSize < 1 || chunkSize > maxChunkSize {
		return nil, notAuthentic("invalid chunk size", nil)
	}
	sealed := chunkSize + tagSize
	body := objectSize - headerSize
	chunks := (body + sealed - 1) / sealed
	last := body - (chunks-1)*sealed // sealed length of the final chunk
	if last < tagSize || chunks > maxChunks {
		return nil, notAuthentic("invalid length", nil)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	r := &ReaderAt{
		src:       src,
		aead:      aead,
		aad:       append(append([]byte{}, header...), fileID[:]...),
		prefix:    append([]byte{}, header[9:16]...),
		chunkSize: chunkSize,
		chunks:    chunks,
		size:      body - chunks*tagSize,
		groupLen:  max(1, groupBytes/sealed),
		cache:     map[int64][]byte{},
	}
	// The final chunk proves the length; check it before trusting any read.
	if _, err := r.group(r.groupOf(chunks - 1)); err != nil {
		return nil, err
	}
	return r, nil
}

// Size is the length of the plaintext.
func (r *ReaderAt) Size() int64 { return r.size }

func (r *ReaderAt) groupOf(chunk int64) int64 { return chunk / r.groupLen }

func (r *ReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("vge1: negative offset")
	}
	n := 0
	for n < len(p) {
		pos := off + int64(n)
		if pos >= r.size {
			return n, io.EOF
		}
		g := r.groupOf(pos / r.chunkSize)
		plain, err := r.group(g)
		if err != nil {
			return n, err
		}
		n += copy(p[n:], plain[pos-g*r.groupLen*r.chunkSize:])
	}
	return n, nil
}

// group returns the plaintext of one group of chunks, from the cache or decrypted.
func (r *ReaderAt) group(g int64) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if plain, ok := r.cache[g]; ok {
		return plain, nil
	}
	first := g * r.groupLen
	count := min(r.groupLen, r.chunks-first)
	sealed := r.chunkSize + tagSize
	start := headerSize + first*sealed
	length := count * sealed
	if first+count == r.chunks { // the final chunk may be short
		length = r.size + r.chunks*tagSize - first*sealed
	}
	buf := make([]byte, length)
	if n, err := r.src.ReadAt(buf, start); n < len(buf) {
		if err == nil || errors.Is(err, io.EOF) {
			return nil, notAuthentic("shorter than its size", nil)
		}
		return nil, err // the source failed; not a verdict on the object
	}
	plain := make([]byte, 0, count*r.chunkSize)
	for i := int64(0); i < count; i++ {
		chunk := first + i
		end := min((i+1)*sealed, length)
		opened, err := r.aead.Open(plain[len(plain):], r.nonce(chunk), buf[i*sealed:end], r.aad)
		if err != nil {
			return nil, notAuthentic("chunk failed authentication", nil)
		}
		plain = plain[:len(plain)+len(opened)]
	}
	if len(r.cacheOrder) == cachedGroups {
		delete(r.cache, r.cacheOrder[0])
		r.cacheOrder = r.cacheOrder[1:]
	}
	r.cache[g] = plain
	r.cacheOrder = append(r.cacheOrder, g)
	return plain, nil
}

func (r *ReaderAt) nonce(chunk int64) []byte {
	nonce := make([]byte, 0, 12)
	nonce = append(nonce, r.prefix...)
	nonce = binary.BigEndian.AppendUint32(nonce, uint32(chunk))
	if chunk == r.chunks-1 {
		return append(nonce, 1)
	}
	return append(nonce, 0)
}
