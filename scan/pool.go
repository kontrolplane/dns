package scan

import "sync"

// pool runs functions on a bounded number of goroutines. Work is handed to it
// one call at a time and run blocks while the pool is full, so the number of
// live goroutines is the pool size rather than the size of the work list —
// a zone transfer that returns tens of thousands of names costs nothing
// beyond the slice holding them.
type pool struct {
	sem chan struct{}
	wg  sync.WaitGroup
}

// newPool builds a pool that runs at most n functions at once.
func newPool(n int) *pool {
	return &pool{sem: make(chan struct{}, n)}
}

// run blocks until a slot is free, then executes f on its own goroutine.
func (p *pool) run(f func()) {
	p.wg.Add(1)
	p.sem <- struct{}{}
	go func() {
		defer p.wg.Done()
		defer func() { <-p.sem }()
		f()
	}()
}

// wait blocks until every function handed to run has returned.
func (p *pool) wait() { p.wg.Wait() }
