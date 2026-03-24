package gproxy

import (
	"sync"
	"time"
)

const (
	// desyncDedupWindow is how long to suppress duplicate desync reports for same client.
	desyncDedupWindow = 60 * time.Second

	// maxReasonableFrame is the maximum reasonable frame size.
	// Anything larger likely indicates crypto desync (decryption produced garbage).
	maxReasonableFrame = 64 * 1024 // 64KB
)

// DesyncDetector tracks and reports protocol desynchronization events.
// Desync typically happens when crypto state diverges, causing decryption
// to produce garbage that looks like impossibly large frames.
type DesyncDetector struct {
	mu   sync.Mutex
	seen map[uint64]time.Time // dedup key -> last reported
}

// NewDesyncDetector creates a new desync detector.
func NewDesyncDetector() *DesyncDetector {
	return &DesyncDetector{
		seen: make(map[uint64]time.Time),
	}
}

// CheckFrameSize checks if a frame size indicates desync.
// Returns true if the frame size is abnormally large (likely desync).
func CheckFrameSize(size int) bool {
	return size > maxReasonableFrame
}

// Report reports a potential desync event.
// Returns true if this event was logged (not deduplicated).
// direction is "c2dc" (client to DC) or "dc2c" (DC to client).
func (d *DesyncDetector) Report(
	ctx *ConnContext,
	frameSize int,
	direction string,
	logger Logger,
) bool {
	// Generate dedup key from connection ID + direction
	// This allows one log per direction per connection per window
	key := ctx.ID()
	if direction == "dc2c" {
		key |= 1 << 63 // High bit to distinguish direction
	}

	now := time.Now()

	d.mu.Lock()
	lastSeen, exists := d.seen[key]
	shouldLog := !exists || now.Sub(lastSeen) > desyncDedupWindow

	if shouldLog {
		d.seen[key] = now

		// Cleanup old entries periodically (piggyback on report)
		if len(d.seen) > 1000 {
			for k, t := range d.seen {
				if now.Sub(t) > desyncDedupWindow*2 {
					delete(d.seen, k)
				}
			}
		}
	}
	d.mu.Unlock()

	if shouldLog {
		logger.Warn("[%s] desync detected (%s): frame size %d > %d (likely crypto state divergence)",
			ctx.LogPrefix(), direction, frameSize, maxReasonableFrame)
	}

	return shouldLog
}
