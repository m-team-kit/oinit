package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRateLimiterBurstAndRefill(t *testing.T) {
	// 10 tokens/sec, burst of 3.
	rl := newRateLimiter(10, 3)

	// The burst should be allowed immediately, then the next request denied.
	assert.True(t, rl.allow("1.2.3.4"))
	assert.True(t, rl.allow("1.2.3.4"))
	assert.True(t, rl.allow("1.2.3.4"))
	assert.False(t, rl.allow("1.2.3.4"))

	// After ~110ms at 10/sec, ~1 token is refilled and one more is allowed.
	time.Sleep(110 * time.Millisecond)
	assert.True(t, rl.allow("1.2.3.4"))
	assert.False(t, rl.allow("1.2.3.4"))
}

func TestRateLimiterIsolatesKeys(t *testing.T) {
	rl := newRateLimiter(1, 1)

	// Exhaust the bucket for one IP.
	assert.True(t, rl.allow("10.0.0.1"))
	assert.False(t, rl.allow("10.0.0.1"))

	// A different IP has its own independent bucket.
	assert.True(t, rl.allow("10.0.0.2"))
	assert.False(t, rl.allow("10.0.0.2"))
}
