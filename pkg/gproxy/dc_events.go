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
// Implements flow control with rate limiting and wake callbacks.
func (h *ProxyHandler) handleDCTraffic(dcConn gnet.Conn, dcCtx *DCConnContext) gnet.Action {
	clientConn := dcCtx.ClientConn
	clientCtx := dcCtx.ClientCtx

	// Check client is still in relay state
	if clientCtx.State() != StateRelaying {
		return gnet.Close
	}

	clientBuffered := clientConn.OutboundBuffered()

	data, _ := dcConn.Peek(-1)
	if len(data) == 0 {
		return gnet.None
	}

	// Flow control parameters
	softLimit := h.maxWriteBuffer / 2 // 2MB for 4MB hard limit
	resumeAt := softLimit / 2         // 1MB - resume when below this

	// Rate limiting: process less when buffer is filling up
	// No hard disconnects - let TCP flow control + idle timeout handle stuck clients
	maxProcess := len(data) // Default: full speed
	if clientBuffered > h.maxWriteBuffer {
		// Above hard limit: trickle mode - keep alive but minimal throughput
		// TCP backpressure will naturally slow DC, idle timeout catches truly stuck clients
		maxProcess = 16 * 1024
		if maxProcess > len(data) {
			maxProcess = len(data)
		}
		h.logger.Debug("[%s] backpressure: client buffer %dMB > hard limit, trickle mode",
			clientCtx.LogPrefix(), clientBuffered/1024/1024)
	} else if clientBuffered > softLimit {
		// Above soft limit: small chunks only
		maxProcess = 64 * 1024
		if maxProcess > len(data) {
			maxProcess = len(data)
		}
		h.logger.Debug("[%s] backpressure: client buffer %dKB > soft limit, throttling",
			clientCtx.LogPrefix(), clientBuffered/1024)
	} else if clientBuffered > resumeAt {
		// Between resume and soft: medium chunks
		maxProcess = 256 * 1024
		if maxProcess > len(data) {
			maxProcess = len(data)
		}
	}
	// else: full speed - process all available data

	// Limit data to what we'll process
	processData := data[:maxProcess]

	// Calculate TLS output size
	numRecords := (len(processData) + faketls.MaxRecordPayload - 1) / faketls.MaxRecordPayload
	tlsSize := len(processData) + numRecords*faketls.RecordHeaderSize

	// Get buffer from pool
	tlsBufPtr := h.dcBufPool.Get()
	var tlsBuf []byte
	if tlsSize <= len(*tlsBufPtr) {
		tlsBuf = (*tlsBufPtr)[:tlsSize]
	} else {
		// Large data - allocate (rare)
		h.dcBufPool.Put(tlsBufPtr)
		tlsBufPtr = nil
		tlsBuf = make([]byte, tlsSize)
	}

	// Decrypt from DC, encrypt for client, wrap in TLS - all in one pass
	srcOffset := 0
	dstOffset := 0
	for srcOffset < len(processData) {
		chunk := min(faketls.MaxRecordPayload, len(processData)-srcOffset)

		// Write TLS header
		tlsBuf[dstOffset] = faketls.RecordTypeApplicationData
		tlsBuf[dstOffset+1] = 0x03
		tlsBuf[dstOffset+2] = 0x03
		tlsBuf[dstOffset+3] = byte(chunk >> 8)
		tlsBuf[dstOffset+4] = byte(chunk)
		dstOffset += faketls.RecordHeaderSize

		// Decrypt from DC into TLS payload
		dcCtx.DCDecrypt.XORKeyStream(tlsBuf[dstOffset:dstOffset+chunk], processData[srcOffset:srcOffset+chunk])

		// Encrypt for client (in-place)
		dcCtx.ClientEncrypt.XORKeyStream(tlsBuf[dstOffset:dstOffset+chunk], tlsBuf[dstOffset:dstOffset+chunk])

		dstOffset += chunk
		srcOffset += chunk
	}

	// Discard what we processed
	dcConn.Discard(len(processData))

	// Always use sync write - simpler and proven to work
	_, err := clientConn.Write(tlsBuf)
	if tlsBufPtr != nil {
		h.dcBufPool.Put(tlsBufPtr)
	}
	if err != nil {
		return gnet.Close
	}

	// If we rate-limited and there's more data, wake self to continue
	// This keeps processing without cross-event-loop Wake issues
	if dcConn.InboundBuffered() > 0 {
		dcConn.Wake(nil)
	}

	return gnet.None
}
