package proxy

import (
	"bytes"
	"sync"
)

const BufferSize = 32 * 1024 // 32 KB I/O copy buffer

var (
	// bufferPool reuses 32 KB byte slices for io.CopyBuffer
	bufferPool = sync.Pool{
		New: func() any {
			b := make([]byte, BufferSize)
			return &b
		},
	}

	// bytesBufferPool reuses bytes.Buffer instances for header and body rewriting
	bytesBufferPool = sync.Pool{
		New: func() any {
			return bytes.NewBuffer(make([]byte, 0, 4096))
		},
	}
)

// GetCopyBuffer retrieves a 32 KB byte slice from the pool.
func GetCopyBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

// PutCopyBuffer returns a 32 KB byte slice back to the pool after securely zeroing contents.
func PutCopyBuffer(b *[]byte) {
	if b != nil && len(*b) == BufferSize {
		// Zero the buffer before returning to pool to prevent residual plaintext data leakage (VULN-07 fix)
		for i := range *b {
			(*b)[i] = 0
		}
		bufferPool.Put(b)
	}
}

// GetBytesBuffer retrieves an empty bytes.Buffer from the pool.
func GetBytesBuffer() *bytes.Buffer {
	buf := bytesBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

// PutBytesBuffer returns a bytes.Buffer back to the pool after zeroing and resetting.
func PutBytesBuffer(buf *bytes.Buffer) {
	if buf != nil {
		// Securely wipe underlying buffer memory before recycling
		b := buf.Bytes()
		for i := range b {
			b[i] = 0
		}
		buf.Reset()
		bytesBufferPool.Put(buf)
	}
}
