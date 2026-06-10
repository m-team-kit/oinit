package util

import (
	"sync"
	"testing"
	"time"
)

func TestTimedCache_Get(t *testing.T) {
	cache := NewTimedCache[string, int]()

	t.Run("Non-existing key", func(t *testing.T) {
		value, exists := cache.Get("key1")
		if exists {
			t.Errorf("Expected 'exists' to be false, but got true")
		}
		if value != 0 {
			t.Errorf("Expected value to be 0, but got %d", value)
		}
	})

	cache.Set("key2", 42, time.Duration(1))

	t.Run("Existing key with unexpired value", func(t *testing.T) {
		value, exists := cache.Get("key2")
		if !exists {
			t.Errorf("Expected 'exists' to be true, but got false")
		}
		if value != 42 {
			t.Errorf("Expected value to be 42, but got %d", value)
		}
	})

	t.Run("Existing key with expired value", func(t *testing.T) {
		// Sleep for more than 2 seconds to simulate expiration
		time.Sleep(2 * time.Second)
		value, exists := cache.Get("key2")
		if exists {
			t.Errorf("Expected 'exists' to be false, but got true")
		}
		if value != 0 {
			t.Errorf("Expected value to be 0, but got %d", value)
		}
	})
}

func TestTimedCache_Set(t *testing.T) {
	cache := NewTimedCache[string, int]()
	cache.Set("key1", 42, time.Duration(1))

	// Check that the value is set correctly
	value, exists := cache.Get("key1")
	if !exists {
		t.Errorf("Expected 'exists' to be true, but got false")
	}
	if value != 42 {
		t.Errorf("Expected value to be 42, but got %d", value)
	}

	// Check that the value expires after the specified duration
	time.Sleep(2 * time.Second)
	value, exists = cache.Get("key1")
	if exists {
		t.Errorf("Expected 'exists' to be false, but got true")
	}
	if value != 0 {
		t.Errorf("Expected value to be 0, but got %d", value)
	}
}

// TestTimedCache_Concurrent exercises the cache from many goroutines at once.
// Before locking was added this reliably triggered a "concurrent map writes"
// fatal panic, which an attacker could provoke remotely via the CA's host
// cache. Run with -race for full coverage.
func TestTimedCache_Concurrent(t *testing.T) {
	cache := NewTimedCache[int, int]()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				cache.Set(n%8, n, time.Duration(10))
				cache.Get(n % 8)
			}
		}(i)
	}
	wg.Wait()
}

func TestTimedCache_SetWithNegativeDuration(t *testing.T) {
	cache := NewTimedCache[string, int]()

	t.Run("Setting with negative duration", func(t *testing.T) {
		cache.Set("key1", 42, time.Duration(-1))

		// Check that the value is not added to the cache
		value, exists := cache.Get("key1")
		if exists {
			t.Errorf("Expected 'exists' to be false, but got true")
		}
		if value != 0 {
			t.Errorf("Expected value to be 0, but got %d", value)
		}
	})
}
