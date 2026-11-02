// Package vge1 decrypts vault objects in the VGE1 format (ADR 0003), the format the
// gateway writes: a 16-byte header, then AES-256-GCM chunks in the STREAM
// construction.
//
//	object  = header || chunk_0 || ... || chunk_n
//	header  = "VGE1" || version=1 (1 B) || chunk_size (uint32 BE) || nonce_prefix (7 B)
//	chunk_i = AES-256-GCM(key, nonce_i, plaintext_i, aad)   -- ciphertext || 16-byte tag
//	nonce_i = nonce_prefix || i (uint32 BE) || last (1 B: 1 for the final chunk, else 0)
//	aad     = header || file_id (16 B)
//
// The gateway's Python implementation is the reference; the tests decrypt its frozen
// vectors (gateway/tests/vectors/vge1.json).
package vge1

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
)

const (
	headerSize   = 16
	tagSize      = 16
	keySize      = 32
	version      = 1
	maxChunkSize = 16 * 1024 * 1024
	maxChunks    = 1 << 32
)

var magic = []byte("VGE1")

// ErrNotAuthentic means the object cannot be trusted: wrong key or file, tampered,
// reordered, truncated, or extended. Plaintext already returned stays authentic, but
// the object as a whole is not: discard any result computed from it.
var ErrNotAuthentic = errors.New("vge1: object is not authentic")

// Reader decrypts one object as it is read, holding one chunk in memory. Read returns
// io.EOF only after the final chunk has been authenticated and nothing follows it;
// any other ending is ErrNotAuthentic (wrapped), never a short but "complete" read.
type Reader struct {
	src       *bufio.Reader
	aead      cipher.AEAD
	aad       []byte
	prefix    []byte
	chunkSize int
	counter   uint64
	sealed    []byte
	plain     []byte // decrypted, not yet returned
	done      bool   // the final chunk has been authenticated
	err       error  // sticky
}

// NewReader reads and checks the header of an object encrypted for fileID with key.
func NewReader(r io.Reader, key []byte, fileID uuid.UUID) (*Reader, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("vge1: data keys are %d bytes, got %d", keySize, len(key))
	}
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, notAuthentic("no header", err)
	}
	if !bytes.Equal(header[:4], magic) || header[4] != version {
		return nil, notAuthentic("not a VGE1 object", nil)
	}
	chunkSize := int(binary.BigEndian.Uint32(header[5:9]))
	if chunkSize < 1 || chunkSize > maxChunkSize {
		return nil, notAuthentic("invalid chunk size", nil)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sealedSize := chunkSize + tagSize
	return &Reader{
		// One byte more than a sealed chunk, to peek whether another chunk follows.
		src:       bufio.NewReaderSize(r, sealedSize+1),
		aead:      aead,
		aad:       append(append([]byte{}, header...), fileID[:]...),
		prefix:    append([]byte{}, header[9:16]...),
		chunkSize: chunkSize,
		sealed:    make([]byte, sealedSize),
	}, nil
}

func (r *Reader) Read(p []byte) (int, error) {
	for len(r.plain) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if r.done {
			return 0, io.EOF
		}
		r.err = r.next()
	}
	n := copy(p, r.plain)
	r.plain = r.plain[n:]
	return n, nil
}

// next authenticates one chunk. A chunk is the final one when the stream ends with
// it: shorter than a full sealed chunk, or full with nothing after it.
func (r *Reader) next() error {
	n, err := io.ReadFull(r.src, r.sealed)
	switch {
	case err == nil:
		if _, peek := r.src.Peek(1); peek == io.EOF {
			return r.open(r.sealed, true)
		} else if peek != nil {
			return peek
		}
		return r.open(r.sealed, false)
	case errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF):
		if n < tagSize {
			return notAuthentic("truncated: no final chunk", nil)
		}
		return r.open(r.sealed[:n], true)
	default:
		return err // the source failed; not a verdict on the object
	}
}

func (r *Reader) open(sealed []byte, last bool) error {
	if r.counter >= maxChunks {
		return notAuthentic("too many chunks", nil)
	}
	nonce := make([]byte, 0, 12)
	nonce = append(nonce, r.prefix...)
	nonce = binary.BigEndian.AppendUint32(nonce, uint32(r.counter))
	if last {
		nonce = append(nonce, 1)
	} else {
		nonce = append(nonce, 0)
	}
	plain, err := r.aead.Open(nil, nonce, sealed, r.aad)
	if err != nil {
		return notAuthentic("chunk failed authentication", nil)
	}
	r.counter++
	r.plain = plain
	r.done = last
	return nil
}

func notAuthentic(reason string, cause error) error {
	if cause != nil {
		return fmt.Errorf("%w: %s (%v)", ErrNotAuthentic, reason, cause)
	}
	return fmt.Errorf("%w: %s", ErrNotAuthentic, reason)
}
