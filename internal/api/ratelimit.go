package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// rateLimiter is a simple per-client-IP token-bucket rate limiter. It is used
// to throttle expensive and security-sensitive endpoints (certificate
// issuance, which forwards a client-supplied token to motley_cue) so that a
// single source cannot brute-force tokens or exhaust the upstream.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket

	// rate is the steady-state number of allowed requests per second
	// (bucket refill rate); burst is the maximum number of tokens.
	rate  float64
	burst float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

// newRateLimiter creates a limiter allowing up to burst requests immediately
// and rate requests per second sustained, per client IP. A background
// goroutine evicts idle buckets to bound memory.
func newRateLimiter(rate, burst float64) *rateLimiter {
	rl := &rateLimiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
	}

	go rl.cleanupLoop()

	return rl
}

// allow reports whether a request from the given key (client IP) may proceed,
// consuming one token if so.
func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		rl.buckets[key] = &bucket{tokens: rl.burst - 1, last: now}
		return true
	}

	// Refill based on elapsed time, capped at burst.
	b.tokens += now.Sub(b.last).Seconds() * rl.rate
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.last = now

	if b.tokens < 1 {
		return false
	}

	b.tokens--
	return true
}

// cleanupLoop periodically removes buckets that have been idle long enough to
// have fully refilled, to prevent unbounded growth of the map.
func (rl *rateLimiter) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, b := range rl.buckets {
			if now.Sub(b.last) > 10*time.Minute {
				delete(rl.buckets, key)
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimitMiddleware returns a Gin middleware that throttles requests per
// client IP using a token bucket. burst requests are allowed immediately and
// rate requests per second are sustained thereafter.
func RateLimitMiddleware(rate, burst float64) gin.HandlerFunc {
	rl := newRateLimiter(rate, burst)

	return func(c *gin.Context) {
		// c.ClientIP honours trusted proxy headers as configured on the
		// gin engine, falling back to the remote address.
		if !rl.allow(c.ClientIP()) {
			Error(c, http.StatusTooManyRequests, ERR_RATE_LIMITED)
			c.Abort()
			return
		}

		c.Next()
	}
}
