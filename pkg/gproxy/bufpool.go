package gproxy

import "sync"

// BufferPool is a sync.Pool wrapper for reusable byte buffers.
type BufferPool struct {
	pool       sync.Pool
	bufferSize int
}

// NewBufferPool creates a new buffer pool with the given buffer size.
func NewBufferPool(size int) *BufferPool {
	bp := &BufferPool{bufferSize: size}
	bp.pool.New = func() any {
		buf := make([]byte, size)
		return &buf
	}
	return bp
}

// Get retrieves a buffer from the pool.
// The returned buffer may contain stale data - caller should slice or overwrite.
func (bp *BufferPool) Get() *[]byte {
	return bp.pool.Get().(*[]byte)
}

// Put returns a buffer to the pool.
// The buffer should not be used after calling Put.
func (bp *BufferPool) Put(buf *[]byte) {
	bp.pool.Put(buf)
}
