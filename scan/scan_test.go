package scan

import (
	"sync"
	"testing"
)

// These run without a network so they execute under -short in CI.

// The pool must bound live goroutines rather than the work list, which is what
// keeps a large zone transfer from costing a goroutine per name.
func TestPoolBoundsConcurrency(t *testing.T) {
	const (
		limit = 4
		jobs  = 500
	)
	var (
		mu       sync.Mutex
		live     int
		peak     int
		finished int
	)
	p := newPool(limit)
	for i := 0; i < jobs; i++ {
		p.run(func() {
			mu.Lock()
			live++
			if live > peak {
				peak = live
			}
			mu.Unlock()

			mu.Lock()
			live--
			finished++
			mu.Unlock()
		})
	}
	p.wait()

	if finished != jobs {
		t.Errorf("ran %d jobs, expected %d", finished, jobs)
	}
	if peak > limit {
		t.Errorf("peak concurrency %d exceeded the pool limit %d", peak, limit)
	}
}
