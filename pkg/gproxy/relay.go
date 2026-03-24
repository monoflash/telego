package gproxy

import (
	"encoding/binary"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
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

	data, _ := c.Peek(-1)
	if len(data) < faketls.RecordHeaderSize {
		return gnet.None
	}

	// Flow control parameters
	softLimit := h.maxWriteBuffer / 2 // 2MB for 4MB hard limit
	resumeAt := softLimit / 2         // 1MB - resume when below this

	// Rate limiting: process less when buffer is filling up
	// No hard disconnects - let TCP flow control + idle timeout handle stuck DCs
	var maxProcess int
	if dcBuffered > h.maxWriteBuffer {
		// Above hard limit: trickle mode
		maxProcess = 16 * 1024
		h.logger.Debug("[%s] backpressure: DC buffer %dMB > hard limit, trickle mode",
			ctx.LogPrefix(), dcBuffered/1024/1024)
	} else if dcBuffered > softLimit {
		// Above soft limit: small chunks only
		maxProcess = 64 * 1024
		h.logger.Debug("[%s] backpressure: DC buffer %dKB > soft limit, throttling",
			ctx.LogPrefix(), dcBuffered/1024)
	} else if dcBuffered > resumeAt {
		// Between resume and soft: medium chunks
		maxProcess = 256 * 1024
	} else {
		// Full speed - process everything
		maxProcess = len(data)
	}

	// Get pooled buffer for batching writes to DC
	batchBufPtr := h.dcBufPool.Get()
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

		// Check for desync (abnormally large frame indicates crypto state divergence)
		if CheckFrameSize(payloadLen) {
			h.desyncDetector.Report(ctx, payloadLen, "c2dc", h.logger)
			h.dcBufPool.Put(batchBufPtr)
			return gnet.Close
		}

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
				// Flush current batch via AsyncWrite (cross-event-loop safe)
				if batchOffset > 0 {
					flushBuf := batchBufPtr
					flushData := batchBuf[:batchOffset]
					err := dcConn.AsyncWrite(flushData, func(_ gnet.Conn, _ error) error {
						h.dcBufPool.Put(flushBuf)
						return nil
					})
					if err != nil {
						h.dcBufPool.Put(flushBuf)
						return gnet.Close
					}
					// Get fresh buffer for continued processing
					batchBufPtr = h.dcBufPool.Get()
					batchBuf = *batchBufPtr
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

	// Flush remaining batch via AsyncWrite (cross-event-loop safe)
	if batchOffset > 0 {
		poolRef := batchBufPtr
		err := dcConn.AsyncWrite(batchBuf[:batchOffset], func(_ gnet.Conn, _ error) error {
			h.dcBufPool.Put(poolRef)
			return nil
		})
		if err != nil {
			h.dcBufPool.Put(poolRef)
			return gnet.Close
		}
	} else {
		h.dcBufPool.Put(batchBufPtr)
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
