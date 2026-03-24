package util

import (
	"bytes"
	"sync"
)

// BufferPool is a shared pool of bytes.Buffer objects to reduce GC pressure
// in hot paths such as streaming response handling and request translation.
var BufferPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

// GetBuffer retrieves a buffer from the pool and resets it.
func GetBuffer() *bytes.Buffer {
	buf := BufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

// PutBuffer returns a buffer to the pool.
// Buffers larger than 1MB are discarded to avoid holding excessive memory.
func PutBuffer(buf *bytes.Buffer) {
	if buf == nil {
		return
	}
	if buf.Cap() > 1<<20 {
		return // discard oversized buffers
	}
	BufferPool.Put(buf)
}
