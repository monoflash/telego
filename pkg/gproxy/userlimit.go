package gproxy

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	// Number of shards to reduce lock contention (power of 2)
	userLimiterShards    = 64
	userLimiterShardMask = userLimiterShards - 1

	// Secret key size (16 bytes)
	secretKeySize = 16
)

// UserIPLimiter limits unique IPs per user (secret).
// Uses sharded maps and LRU caches for minimal contention.
type UserIPLimiter struct {
	maxIPsPerUser int
	blockTimeout  time.Duration
	shards        [userLimiterShards]userLimiterShard
}

type userLimiterShard struct {
	mu    sync.Mutex
	users map[[secretKeySize]byte]*userIPState
}

// userIPState tracks IP state for a single user.
type userIPState struct {
	// Secret name for metrics labeling
	secretName string

	// Active IPs with connection count (LRU, size = maxIPsPerUser)
	activeIPs *lru.Cache[string, *int64]

	// Blocked IPs (expirable LRU with TTL)
	blockedIPs *expirable.LRU[string, struct{}]

	// Traffic counters (read via atomic, updated in hot path)
	bytesIn  atomic.Int64
	bytesOut atomic.Int64

	// Block event counter
	blockedTotal atomic.Int64

	// Reference to parent for eviction callback
	parent       *UserIPLimiter
	blockTimeout time.Duration
}

// UserIPStats contains statistics for a single user.
type UserIPStats struct {
	SecretName    string
	ActiveIPs     int
	BlockedIPs    int
	ActiveIPList  []string // List of active IP addresses
	BlockedIPList []string // List of currently blocked IP addresses
	Connections   int64
	BytesIn       int64
	BytesOut      int64
	BlockedTotal  int64
}

// NewUserIPLimiter creates a new user IP limiter.
// Returns nil if maxIPsPerUser <= 0 (limiting disabled).
func NewUserIPLimiter(maxIPsPerUser int, blockTimeout time.Duration) *UserIPLimiter {
	if maxIPsPerUser <= 0 {
		return nil
	}

	l := &UserIPLimiter{
		maxIPsPerUser: maxIPsPerUser,
		blockTimeout:  blockTimeout,
	}

	for i := range l.shards {
		l.shards[i].users = make(map[[secretKeySize]byte]*userIPState)
	}

	return l
}

// getShardIdx returns shard index for a secret key.
func getShardIdx(secret []byte) int {
	if len(secret) == 0 {
		return 0
	}
	return int(secret[0]) & userLimiterShardMask
}

// getOrCreateUserState gets or creates user state for a secret.
// Caller must hold shard lock.
func (l *UserIPLimiter) getOrCreateUserState(shard *userLimiterShard, secretKey [secretKeySize]byte, secretName string) *userIPState {
	state, exists := shard.users[secretKey]
	if exists {
		return state
	}

	// Create new user state
	state = &userIPState{
		secretName:   secretName,
		parent:       l,
		blockTimeout: l.blockTimeout,
	}

	// Create active IPs LRU with eviction callback
	activeIPs, _ := lru.NewWithEvict[string, *int64](l.maxIPsPerUser, func(ip string, _ *int64) {
		// Move evicted IP to blocked list
		state.blockedIPs.Add(ip, struct{}{})
		state.blockedTotal.Add(1)
	})
	state.activeIPs = activeIPs

	// Create blocked IPs expirable LRU
	state.blockedIPs = expirable.NewLRU[string, struct{}](
		l.maxIPsPerUser*10, // Allow tracking more blocked IPs
		nil,
		l.blockTimeout,
	)

	shard.users[secretKey] = state
	return state
}

// TryAcquire attempts to acquire a connection slot for the given IP+secret.
// Returns the key (for Release) and success status.
// secretName is used for metrics labeling.
func (l *UserIPLimiter) TryAcquire(ip net.IP, secret []byte, secretName string) (key string, ok bool) {
	if l == nil || len(secret) < secretKeySize {
		return "", true // Disabled or invalid secret
	}

	var secretKey [secretKeySize]byte
	copy(secretKey[:], secret[:secretKeySize])

	ipStr := ip.String()

	shardIdx := getShardIdx(secret)
	shard := &l.shards[shardIdx]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	state := l.getOrCreateUserState(shard, secretKey, secretName)

	// Check if IP is blocked
	if state.blockedIPs.Contains(ipStr) {
		// Refresh TTL by re-adding
		state.blockedIPs.Add(ipStr, struct{}{})
		return "", false
	}

	// Check if IP is already active
	if countPtr, exists := state.activeIPs.Get(ipStr); exists {
		// Increment connection count
		atomic.AddInt64(countPtr, 1)
		// Build key: secret + IP
		return string(secretKey[:]) + ipStr, true
	}

	// New IP - add to active (may trigger eviction of oldest)
	var count int64 = 1
	state.activeIPs.Add(ipStr, &count)

	return string(secretKey[:]) + ipStr, true
}

// Release releases a connection slot.
func (l *UserIPLimiter) Release(key string) {
	if l == nil || len(key) <= secretKeySize {
		return
	}

	var secretKey [secretKeySize]byte
	copy(secretKey[:], key[:secretKeySize])
	ipStr := key[secretKeySize:]

	shardIdx := getShardIdx(secretKey[:])
	shard := &l.shards[shardIdx]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	state, exists := shard.users[secretKey]
	if !exists {
		return
	}

	countPtr, exists := state.activeIPs.Get(ipStr)
	if !exists {
		return
	}

	// Decrement connection count
	newCount := atomic.AddInt64(countPtr, -1)
	if newCount <= 0 {
		// Keep IP in LRU even at 0 connections - preserves LRU ordering
		// Will be evicted naturally when other IPs need the slot
	}
}

// TrafficCounters returns pointers to traffic counters for a user.
// Used to store in ConnContext for hot-path traffic counting.
func (l *UserIPLimiter) TrafficCounters(secret []byte) (bytesIn, bytesOut *atomic.Int64) {
	if l == nil || len(secret) < secretKeySize {
		return nil, nil
	}

	var secretKey [secretKeySize]byte
	copy(secretKey[:], secret[:secretKeySize])

	shardIdx := getShardIdx(secret)
	shard := &l.shards[shardIdx]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	state, exists := shard.users[secretKey]
	if !exists {
		return nil, nil
	}

	return &state.bytesIn, &state.bytesOut
}

// Stats returns statistics for all users.
func (l *UserIPLimiter) Stats() []UserIPStats {
	if l == nil {
		return nil
	}

	var stats []UserIPStats

	for i := range l.shards {
		shard := &l.shards[i]
		shard.mu.Lock()

		for _, state := range shard.users {
			var totalConns int64
			activeKeys := state.activeIPs.Keys()
			for _, ip := range activeKeys {
				if countPtr, ok := state.activeIPs.Peek(ip); ok {
					totalConns += atomic.LoadInt64(countPtr)
				}
			}

			blockedKeys := state.blockedIPs.Keys()

			stats = append(stats, UserIPStats{
				SecretName:    state.secretName,
				ActiveIPs:     state.activeIPs.Len(),
				BlockedIPs:    state.blockedIPs.Len(),
				ActiveIPList:  activeKeys,
				BlockedIPList: blockedKeys,
				Connections:   totalConns,
				BytesIn:       state.bytesIn.Load(),
				BytesOut:      state.bytesOut.Load(),
				BlockedTotal:  state.blockedTotal.Load(),
			})
		}

		shard.mu.Unlock()
	}

	return stats
}

// Close stops any background goroutines.
func (l *UserIPLimiter) Close() {
	// expirable.LRU runs its own cleanup goroutine
	// Purge all to stop cleanup timers
	if l == nil {
		return
	}

	for i := range l.shards {
		shard := &l.shards[i]
		shard.mu.Lock()
		for _, state := range shard.users {
			state.blockedIPs.Purge()
		}
		shard.mu.Unlock()
	}
}
