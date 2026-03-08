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

	data, _ := c.Peek(-1)
	if len(data) < faketls.RecordHeaderSize {
		return gnet.None
	}

	// Get pooled buffer for batching writes to DC
	batchBufPtr := dcBufPool.Get().(*[]byte)
	batchBuf := *batchBufPtr

	batchOffset := 0

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
			// Extract payload
			payload := data[faketls.RecordHeaderSize:recordLen]

			// Check if batch buffer has space
			if batchOffset+len(payload) > len(batchBuf) {
				// Flush current batch - Write() copies so no extra buffer needed
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

	// Flush remaining batch - Write() copies so we can return buffer immediately
	if batchOffset > 0 {
		_, err := dcConn.Write(batchBuf[:batchOffset])
		dcBufPool.Put(batchBufPtr)
		if err != nil {
			return gnet.Close
		}
	} else {
		dcBufPool.Put(batchBufPtr)
	}

	if consumed > 0 {
		c.Discard(consumed)
	}

	return gnet.None
}
