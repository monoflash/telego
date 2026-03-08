package gproxy

import (
	"encoding/binary"
	"sync"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

// Buffer size for batching - balances throughput vs memory
// 64KB allows batching 4 TLS records (16KB each) while limiting memory per connection
const relayBufSize = 64 * 1024 // 64KB for batching

// Buffer pools for relay operations to avoid allocations in hot path
var (
	// relayBufPool for decrypt/encrypt buffers (up to 16KB TLS record)
	relayBufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, faketls.MaxRecordPayload)
			return &buf
		},
	}

	// dcBufPool for batching writes - 64KB for reduced syscalls
	// Used for both Client->DC batching and DC->Client TLS wrapping
	// Sized to hold 64KB data + TLS header overhead (5 bytes per 16KB = ~20 bytes)
	dcBufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, relayBufSize+256)
			return &buf
		},
	}
)

// handleRelay processes data from the client and forwards to DC.
// Implements flow control: pauses client processing when DC is slow.
func (h *ProxyHandler) handleRelay(c gnet.Conn, ctx *ConnContext) gnet.Action {
	// Lock-free read of relay context
	relay := ctx.Relay()
	if relay == nil {
		// DC connection not ready yet
		return gnet.None
	}

	dcConn := relay.DCConn
	decryptor := relay.Decryptor
	dcEncrypt := relay.DCEncrypt

	dcBuffered := dcConn.OutboundBuffered()
	clientBuffered := c.InboundBuffered()

	// HARD LIMIT: Close if total buffered data exceeds hard limit
	if dcBuffered+clientBuffered > h.maxWriteBuffer {
		h.logger.Warn("[%s] DC %d: buffers exceeded %dMB (dc=%dKB, client=%dKB), closing",
			ctx.LogPrefix(), ctx.DCID(), h.maxWriteBuffer/1024/1024,
			dcBuffered/1024, clientBuffered/1024)
		return gnet.Close
	}

	// SOFT LIMIT: Pause client processing when DC buffer is full
	// Leave data in client's inbound buffer, TCP will backpressure upstream
	if dcBuffered > h.softLimit {
		// Don't process - data stays in client buffer
		return gnet.None
	}

	// Calculate how much we can send without exceeding soft limit
	available := h.softLimit - dcBuffered

	data, _ := c.Peek(-1)
	if len(data) < faketls.RecordHeaderSize {
		return gnet.None
	}

	// Get pooled buffer for batching writes to DC
	batchBufPtr := dcBufPool.Get().(*[]byte)
	batchBuf := *batchBufPtr

	batchOffset := 0

	// Process complete TLS records (limited by available space)
	consumed := 0
	for len(data) >= faketls.RecordHeaderSize && batchOffset < available {
		// Parse TLS record header
		recordType := data[0]
		payloadLen := int(binary.BigEndian.Uint16(data[3:5]))
		recordLen := faketls.RecordHeaderSize + payloadLen

		if len(data) < recordLen {
			// Incomplete record, wait for more data
			break
		}

		// Only process ApplicationData records
		if recordType == faketls.RecordTypeApplicationData {
			// Extract payload
			payload := data[faketls.RecordHeaderSize:recordLen]

			// Check if we'd exceed available space
			if batchOffset+len(payload) > available {
				break // Stop processing, leave remaining for next call
			}

			// Check if batch buffer has space
			if batchOffset+len(payload) > len(batchBuf) {
				// Flush current batch
				if batchOffset > 0 {
					if _, err := dcConn.Write(batchBuf[:batchOffset]); err != nil {
						dcBufPool.Put(batchBufPtr)
						return gnet.Close
					}
					batchOffset = 0
				}
			}

			// Decrypt from client, encrypt for DC directly into batch buffer
			decryptor.XORKeyStream(batchBuf[batchOffset:batchOffset+len(payload)], payload)
			dcEncrypt.XORKeyStream(batchBuf[batchOffset:batchOffset+len(payload)], batchBuf[batchOffset:batchOffset+len(payload)])
			batchOffset += len(payload)
		}

		consumed += recordLen
		data = data[recordLen:]
	}

	// Check if there's more client data we couldn't process
	hasMoreClientData := len(data) >= faketls.RecordHeaderSize

	// Flush remaining batch
	if batchOffset > 0 {
		// Fast path: sync write when no backpressure needed
		// Slow path: async write with wake callback when client has pending data
		if !hasMoreClientData {
			// Normal case - sync write
			_, err := dcConn.Write(batchBuf[:batchOffset])
			dcBufPool.Put(batchBufPtr)
			if err != nil {
				return gnet.Close
			}
		} else {
			// Backpressure case - async write with wake callback
			clientConn := c
			resumeAt := h.resumeThreshold // Low watermark for hysteresis

			err := dcConn.AsyncWrite(batchBuf[:batchOffset], func(dc gnet.Conn, err error) error {
				dcBufPool.Put(batchBufPtr)
				// Wake client when DC buffer drops below low watermark (prevents thrashing)
				if err == nil && dc.OutboundBuffered() < resumeAt {
					clientConn.Wake(nil)
				}
				return nil
			})
			if err != nil {
				dcBufPool.Put(batchBufPtr)
				return gnet.Close
			}
		}
	} else {
		dcBufPool.Put(batchBufPtr)
	}

	if consumed > 0 {
		c.Discard(consumed)
	}

	return gnet.None
}
