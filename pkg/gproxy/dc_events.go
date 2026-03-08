package gproxy

import (
	"crypto/cipher"
	"errors"
	"io"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

// dcEventHandler handles events from DC connections.
type dcEventHandler struct {
	gnet.BuiltinEventEngine
	proxy *ProxyHandler
}

// DCConnContext holds per-DC-connection state.
type DCConnContext struct {
	// Link back to client connection
	ClientConn gnet.Conn

	// Client context for state access
	ClientCtx *ConnContext

	// DC ciphers (proxy <-> DC)
	DCEncrypt cipher.Stream
	DCDecrypt cipher.Stream

	// Client ciphers (cached from relay context)
	ClientEncrypt cipher.Stream // encrypt TO client

	// Flow control: DC connection reference for wake mechanism
	DCConn gnet.Conn
}

// OnTraffic handles data arriving from DC.
func (h *dcEventHandler) OnTraffic(c gnet.Conn) gnet.Action {
	ctx, ok := c.Context().(*DCConnContext)
	if !ok || ctx == nil {
		return gnet.Close
	}
	return h.proxy.handleDCTraffic(c, ctx)
}

// OnClose handles DC connection close.
func (h *dcEventHandler) OnClose(c gnet.Conn, err error) gnet.Action {
	ctx, ok := c.Context().(*DCConnContext)
	if !ok || ctx == nil {
		return gnet.None
	}

	// Log DC disconnect with details for debugging
	if ctx.ClientCtx != nil {
		prefix := ctx.ClientCtx.LogPrefix()
		dcID := ctx.ClientCtx.DCID()
		duration := time.Since(ctx.ClientCtx.connTime)

		isRealError := err != nil && !errors.Is(err, io.EOF)
		if isRealError {
			h.proxy.logger.Warn("[%s] DC %d disconnected (%v): %v", prefix, dcID, duration.Round(time.Millisecond), err)
		} else {
			h.proxy.logger.Debug("[%s] DC %d disconnected (%v)", prefix, dcID, duration.Round(time.Millisecond))
		}
	}

	if ctx.ClientConn != nil {
		ctx.ClientConn.Close()
	}
	return gnet.None
}

// handleDCTraffic processes data from DC and forwards to client.
// Implements flow control: pauses DC when client is slow, resumes when caught up.
func (h *ProxyHandler) handleDCTraffic(dcConn gnet.Conn, dcCtx *DCConnContext) gnet.Action {
	clientConn := dcCtx.ClientConn
	clientCtx := dcCtx.ClientCtx

	// Check client is still in relay state
	if clientCtx.State() != StateRelaying {
		return gnet.Close
	}

	clientBuffered := clientConn.OutboundBuffered()
	dcBuffered := dcConn.InboundBuffered()

	// HARD LIMIT: Close if total buffered data exceeds hard limit
	// This is the last resort to prevent memory exhaustion
	if clientBuffered+dcBuffered > h.maxWriteBuffer {
		h.logger.Warn("[%s] DC %d: buffers exceeded %dMB (client=%dKB, dc=%dKB), closing",
			clientCtx.LogPrefix(), clientCtx.DCID(), h.maxWriteBuffer/1024/1024,
			clientBuffered/1024, dcBuffered/1024)
		return gnet.Close
	}

	// SOFT LIMIT: Pause DC processing when client buffer is full
	// Leave data in DC's inbound buffer, TCP will backpressure upstream
	if clientBuffered > h.softLimit {
		// Don't process - data stays in DC buffer
		// Will be woken when client buffer drains (via AsyncWrite callback)
		return gnet.None
	}

	// Calculate how much we can send without exceeding soft limit
	available := h.softLimit - clientBuffered
	if available <= 0 {
		return gnet.None
	}

	// Read available data from DC (limited to what we can accept)
	data, _ := dcConn.Peek(-1)
	if len(data) == 0 {
		return gnet.None
	}

	// Limit processing to available space (with some headroom for TLS overhead)
	// TLS adds ~5 bytes per 16KB, so ~0.03% overhead - negligible
	if len(data) > available {
		data = data[:available]
	}

	// Calculate TLS output size
	numRecords := (len(data) + faketls.MaxRecordPayload - 1) / faketls.MaxRecordPayload
	tlsSize := len(data) + numRecords*faketls.RecordHeaderSize

	// Get buffer from pool
	tlsBufPtr := dcBufPool.Get().(*[]byte)
	var tlsBuf []byte
	if tlsSize <= len(*tlsBufPtr) {
		tlsBuf = (*tlsBufPtr)[:tlsSize]
	} else {
		// Large data - allocate (rare)
		dcBufPool.Put(tlsBufPtr)
		tlsBufPtr = nil
		tlsBuf = make([]byte, tlsSize)
	}

	// Decrypt from DC, encrypt for client, wrap in TLS - all in one pass
	srcOffset := 0
	dstOffset := 0
	for srcOffset < len(data) {
		chunk := min(faketls.MaxRecordPayload, len(data)-srcOffset)

		// Write TLS header
		tlsBuf[dstOffset] = faketls.RecordTypeApplicationData
		tlsBuf[dstOffset+1] = 0x03
		tlsBuf[dstOffset+2] = 0x03
		tlsBuf[dstOffset+3] = byte(chunk >> 8)
		tlsBuf[dstOffset+4] = byte(chunk)
		dstOffset += faketls.RecordHeaderSize

		// Decrypt from DC into TLS payload
		dcCtx.DCDecrypt.XORKeyStream(tlsBuf[dstOffset:dstOffset+chunk], data[srcOffset:srcOffset+chunk])

		// Encrypt for client (in-place)
		dcCtx.ClientEncrypt.XORKeyStream(tlsBuf[dstOffset:dstOffset+chunk], tlsBuf[dstOffset:dstOffset+chunk])

		dstOffset += chunk
		srcOffset += chunk
	}

	// Discard only what we processed from DC buffer
	dcConn.Discard(len(data))

	// Check if there's more data in DC buffer that we couldn't process
	hasMoreDCData := dcConn.InboundBuffered() > 0

	// Fast path: sync write when no backpressure needed
	// Slow path: async write with wake callback when DC has pending data
	if !hasMoreDCData {
		// Normal case - sync write, return buffer immediately
		_, err := clientConn.Write(tlsBuf)
		if tlsBufPtr != nil {
			dcBufPool.Put(tlsBufPtr)
		}
		if err != nil {
			return gnet.Close
		}
	} else {
		// Backpressure case - async write with wake callback
		resumeAt := h.resumeThreshold // Low watermark for hysteresis
		err := clientConn.AsyncWrite(tlsBuf, func(c gnet.Conn, err error) error {
			if tlsBufPtr != nil {
				dcBufPool.Put(tlsBufPtr)
			}
			// Wake DC when client buffer drops below low watermark (prevents thrashing)
			if err == nil && c.OutboundBuffered() < resumeAt {
				dcCtx.DCConn.Wake(nil)
			}
			return nil
		})
		if err != nil {
			if tlsBufPtr != nil {
				dcBufPool.Put(tlsBufPtr)
			}
			return gnet.Close
		}
	}

	return gnet.None
}
