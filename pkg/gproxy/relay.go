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
// Implements flow control with rate limiting and wake callbacks.
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

	// Hard limit - OOM protection
	if dcBuffered > h.maxWriteBuffer {
		h.logger.Warn("[%s] DC %d: DC buffer exceeded %dMB (%dKB), closing",
			ctx.LogPrefix(), ctx.DCID(), h.maxWriteBuffer/1024/1024,
			dcBuffered/1024)
		return gnet.Close
	}

	data, _ := c.Peek(-1)
	if len(data) < faketls.RecordHeaderSize {
		return gnet.None
	}

	// Flow control parameters
	softLimit := h.maxWriteBuffer / 2 // 2MB for 4MB hard limit
	resumeAt := softLimit / 2         // 1MB - resume when below this

	// Rate limiting: process less when buffer is filling up
	var maxProcess int
	if dcBuffered > softLimit {
		// Above soft limit: small chunks only
		maxProcess = 64 * 1024
		h.logger.Info("[%s] backpressure: DC buffer %dKB > soft limit, throttling to 64KB chunks",
			ctx.LogPrefix(), dcBuffered/1024)
	} else if dcBuffered > resumeAt {
		// Between resume and soft: medium chunks
		maxProcess = 256 * 1024
	} else {
		// Full speed - process everything
		maxProcess = len(data)
	}

	// Get pooled buffer for batching writes to DC
	batchBufPtr := dcBufPool.Get().(*[]byte)
	batchBuf := *batchBufPtr

	batchOffset := 0
	processed := 0
	rateLimited := false // Track if we stopped due to rate limiting vs incomplete record

	// Process complete TLS records
	consumed := 0
	for len(data) >= faketls.RecordHeaderSize {
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
			payload := data[faketls.RecordHeaderSize:recordLen]

			// Check if we'd exceed maxProcess (but always process at least one record)
			if processed > 0 && processed+len(payload) > maxProcess {
				rateLimited = true
				break
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
			processed += len(payload)
		}

		consumed += recordLen
		data = data[recordLen:]
	}

	// Flush remaining batch - always use sync write
	if batchOffset > 0 {
		_, err := dcConn.Write(batchBuf[:batchOffset])
		dcBufPool.Put(batchBufPtr)
		if err != nil {
			return gnet.Close
		}
	} else {
		dcBufPool.Put(batchBufPtr)
	}

	// Only wake if we rate-limited and there's more data to process
	// Don't wake for incomplete records - gnet will call OnTraffic when more data arrives
	if rateLimited {
		c.Wake(nil)
	}

	if consumed > 0 {
		c.Discard(consumed)
	}

	return gnet.None
}
