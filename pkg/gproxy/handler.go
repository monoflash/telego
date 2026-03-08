package gproxy

import (
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/tlsfront"
)

// Buffer limits for flow control (follows Envoy's watermark pattern)
const (
	// Soft limit (high watermark): pause processing when buffer exceeds this
	// This allows TCP backpressure to slow down sender without closing
	defaultSoftLimit = 512 * 1024 // 512KB

	// Resume threshold (low watermark): resume when buffer drops below this
	// Set to 50% of soft limit to prevent rapid pause/resume thrashing
	// (Envoy uses same 50% ratio)
	defaultResumeThreshold = 256 * 1024 // 256KB

	// Hard limit: close connection when buffers exceed this
	// This is the last resort to prevent memory exhaustion
	defaultMaxWriteBuffer = 4 * 1024 * 1024 // 4MB
)

// ProxyHandler implements gnet.EventHandler for the MTProxy server.
type ProxyHandler struct {
	gnet.BuiltinEventEngine

	// Configuration
	config *Config

	// DC client for outgoing connections
	dcClient *gnet.Client

	// Our public IP (detected via STUN, used for logging)
	publicIP string

	// Replay cache for anti-replay protection
	replayCache *ReplayCache

	// Connection limiter (nil if disabled)
	connLimiter *ConnLimiter

	// TLS fronting
	certFetcher *tlsfront.CertFetcher

	// Logger
	logger Logger

	// Metrics
	activeConns int64

	// Cached config values for hot path (flow control watermarks)
	softLimit       int // High watermark: pause when exceeded
	resumeThreshold int // Low watermark: resume when below (50% of soft)
	maxWriteBuffer  int // Hard limit: close when exceeded
}

// NewProxyHandler creates a new gnet proxy handler.
func NewProxyHandler(cfg *Config, logger Logger) *ProxyHandler {
	if logger == nil {
		logger = defaultLogger{}
	}

	// Set buffer limits with defaults (follows Envoy's watermark pattern)
	// High watermark (soft limit): pause when exceeded
	// Low watermark (resume threshold): resume when below (50% of high, prevents thrashing)
	// Hard limit: close connection to prevent OOM
	maxWriteBuf := cfg.MaxWriteBuffer
	if maxWriteBuf <= 0 {
		maxWriteBuf = defaultMaxWriteBuffer
	}
	softLim := maxWriteBuf / 8
	if softLim < defaultSoftLimit {
		softLim = defaultSoftLimit
	}
	resumeAt := softLim / 2 // 50% hysteresis like Envoy
	if resumeAt < defaultResumeThreshold {
		resumeAt = defaultResumeThreshold
	}

	h := &ProxyHandler{
		config:          cfg,
		replayCache:     NewReplayCache(1000000, 10*time.Minute),
		logger:          logger,
		softLimit:       softLim,
		resumeThreshold: resumeAt,
		maxWriteBuffer:  maxWriteBuf,
	}

	// Initialize connection limiter if configured
	if cfg.MaxConnectionsPerIP > 0 {
		h.connLimiter = NewConnLimiter(cfg.MaxConnectionsPerIP)
		logger.Info("Connection limiter enabled: max %d per IP+secret", cfg.MaxConnectionsPerIP)
	}

	logger.Info("Flow control: soft=%dKB hard=%dMB per connection", softLim/1024, maxWriteBuf/1024/1024)

	return h
}

// OnBoot is called when the gnet engine starts.
func (h *ProxyHandler) OnBoot(eng gnet.Engine) gnet.Action {
	h.logger.Info("gnet proxy started on %s", h.config.BindAddr)
	return gnet.None
}

// OnShutdown is called when the gnet engine shuts down.
func (h *ProxyHandler) OnShutdown(eng gnet.Engine) {
	h.logger.Info("gnet proxy shutting down")
	if h.dcClient != nil {
		h.dcClient.Stop()
	}
}

// OnOpen is called when a new connection is accepted.
func (h *ProxyHandler) OnOpen(c gnet.Conn) ([]byte, gnet.Action) {
	ctx := NewConnContext()

	// Start with PROXY protocol parsing if enabled
	if h.config.ProxyProtocol {
		ctx.SetState(StateReadProxyProto)
	}

	c.SetContext(ctx)

	conns := atomic.AddInt64(&h.activeConns, 1)
	h.logger.Debug("[#%d] new connection from %s (active: %d)", ctx.id, c.RemoteAddr(), conns)

	// Set read deadline for handshake
	c.SetReadDeadline(time.Now().Add(30 * time.Second))

	return nil, gnet.None
}

// OnClose is called when a connection is closed.
func (h *ProxyHandler) OnClose(c gnet.Conn, err error) gnet.Action {
	conns := atomic.AddInt64(&h.activeConns, -1)

	ctx, ok := c.Context().(*ConnContext)
	if !ok || ctx == nil {
		h.logger.Debug("[?] connection closed without context (active: %d)", conns)
		return gnet.None
	}

	// Close DC connection if active
	if relay := ctx.Relay(); relay != nil && relay.DCConn != nil {
		relay.DCConn.Close()
	}

	// Close splice connection if active
	if spliceConn := ctx.SpliceConn(); spliceConn != nil {
		spliceConn.Close()
	}

	// Release connection limit slot and check if authenticated
	ctx.mu.Lock()
	authenticated := ctx.secret != nil
	if ctx.limitTracked && h.connLimiter != nil {
		h.connLimiter.Release(ctx.limitKey)
		ctx.limitTracked = false
	}
	ctx.mu.Unlock()

	// Log closure with DC info for debugging
	duration := time.Since(ctx.connTime)
	prefix := ctx.LogPrefix()
	dcID := ctx.DCID()

	// Determine if this is a real error (not just EOF/normal close)
	isRealError := err != nil && !errors.Is(err, io.EOF)

	if authenticated {
		if isRealError {
			h.logger.Warn("[%s] DC %d closed (%v): %v (active: %d)", prefix, dcID, duration.Round(time.Millisecond), err, conns)
		} else {
			h.logger.Info("[%s] DC %d closed (%v) (active: %d)", prefix, dcID, duration.Round(time.Millisecond), conns)
		}
	} else if isRealError {
		h.logger.Debug("[%s] closed (%v): %v (active: %d)", prefix, duration.Round(time.Millisecond), err, conns)
	}

	return gnet.None
}

// OnTraffic is called when data is available to read.
func (h *ProxyHandler) OnTraffic(c gnet.Conn) gnet.Action {
	ctx, ok := c.Context().(*ConnContext)
	if !ok || ctx == nil {
		return gnet.Close
	}

	// Lock-free state read
	switch ctx.State() {
	case StateReadProxyProto:
		return h.handleProxyProto(c, ctx)
	case StateReadTLSHeader:
		return h.handleTLSHeader(c, ctx)
	case StateReadTLSPayload:
		return h.handleTLSPayload(c, ctx)
	case StateReadO2Frame:
		return h.handleO2Frame(c, ctx)
	case StateDialingDC:
		// Still waiting for DC connection, buffer data
		return gnet.None
	case StateRelaying:
		return h.handleRelay(c, ctx)
	case StateSplicing:
		return h.handleSplice(c, ctx)
	case StateClosed:
		return gnet.Close
	}

	return gnet.Close
}

// handleProxyProto parses incoming PROXY protocol header.
func (h *ProxyHandler) handleProxyProto(c gnet.Conn, ctx *ConnContext) gnet.Action {
	data, _ := c.Peek(-1)
	if len(data) == 0 {
		return gnet.None // Need data
	}

	// Quick check: if first byte can't start a PROXY header, skip to TLS immediately
	// This prevents slowloris-style attacks with tiny payloads
	// PROXY v1 starts with 'P' (0x50), v2 starts with 0x0D
	if data[0] != 'P' && data[0] != 0x0D {
		ctx.SetState(StateReadTLSHeader)
		return h.handleTLSHeader(c, ctx)
	}

	// Need minimum bytes to determine protocol type
	// v1: need 6 bytes for "PROXY " prefix
	// v2: need 12 bytes for signature
	minBytes := 6
	if data[0] == 0x0D {
		minBytes = 12
	}
	if len(data) < minBytes {
		return gnet.None // Need more data to determine
	}

	result, err := ParseProxyProtocol(data)
	if err != nil {
		h.logger.Debug("[#%d] PROXY protocol error: %v", ctx.id, err)
		return gnet.Close
	}

	if result == nil {
		// Not a PROXY protocol header, proceed to TLS
		ctx.SetState(StateReadTLSHeader)
		return h.handleTLSHeader(c, ctx)
	}

	// Discard the PROXY header bytes
	c.Discard(result.HeaderLen)

	// Store real client address if provided
	if result.SrcAddr != nil {
		ctx.SetRealClientAddr(result.SrcAddr)
		h.logger.Debug("[#%d] PROXY protocol: real client %s", ctx.id, result.SrcAddr)
	}

	// Proceed to TLS handshake
	ctx.SetState(StateReadTLSHeader)
	return h.handleTLSHeader(c, ctx)
}

// Logger interface for proxy logging.
type Logger interface {
	Debug(format string, args ...any)
	Info(format string, args ...any)
	Warn(format string, args ...any)
	Error(format string, args ...any)
}

type defaultLogger struct{}

func (defaultLogger) Debug(format string, args ...any) {}
func (defaultLogger) Info(format string, args ...any)  {}
func (defaultLogger) Warn(format string, args ...any)  {}
func (defaultLogger) Error(format string, args ...any) {}
