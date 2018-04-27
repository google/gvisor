// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tmutex

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBasicLock(t *testing.T) {
	var m Mutex
	m.Init()

	m.Lock()

	// Try blocking lock the mutex from a different goroutine. This must
	// not block because the mutex is held.
	ch := make(chan struct{}, 1)
	go func() {
		m.Lock()
		ch <- struct{}{}
		m.Unlock()
		ch <- struct{}{}
	}()

	select {
	case <-ch:
		t.Fatalf("Lock succeeded on locked mutex")
	case <-time.After(100 * time.Millisecond):
	}

	// Unlock the mutex and make sure that the goroutine waiting on Lock()
	// unblocks and succeeds.
	m.Unlock()

	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Lock failed to acquire unlocked mutex")
	}

	// Make sure we can lock and unlock again.
	m.Lock()
	m.Unlock()
}

func TestTryLock(t *testing.T) {
	var m Mutex
	m.Init()

	// Try to lock. It should succeed.
	if !m.TryLock() {
		t.Fatalf("TryLock failed on unlocked mutex")
	}

	// Try to lock again, it should now fail.
	if m.TryLock() {
		t.Fatalf("TryLock succeeded on locked mutex")
	}

	// Try blocking lock the mutex from a different goroutine. This must
	// not block because the mutex is held.
	ch := make(chan struct{}, 1)
	go func() {
		m.Lock()
		ch <- struct{}{}
		m.Unlock()
	}()

	select {
	case <-ch:
		t.Fatalf("Lock succeeded on locked mutex")
	case <-time.After(100 * time.Millisecond):
	}

	// Unlock the mutex and make sure that the goroutine waiting on Lock()
	// unblocks and succeeds.
	m.Unlock()

	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Lock failed to acquire unlocked mutex")
	}
}

func TestMutualExclusion(t *testing.T) {
	var m Mutex
	m.Init()

	// Test mutual exclusion by running "gr" goroutines concurrently, and
	// have each one increment a counter "iters" times within the critical
	// section established by the mutex.
	//
	// If at the end the counter is not gr * iters, then we know that
	// goroutines ran concurrently within the critical section.
	//
	// If one of the goroutines doesn't complete, it's likely a bug that
	// causes to it to wait forever.
	const gr = 1000
	const iters = 100000
	v := 0
	var wg sync.WaitGroup
	for i := 0; i < gr; i++ {
		wg.Add(1)
		go func() {
			for j := 0; j < iters; j++ {
				m.Lock()
				v++
				m.Unlock()
			}
			wg.Done()
		}()
	}

	wg.Wait()

	if v != gr*iters {
		t.Fatalf("Bad count: got %v, want %v", v, gr*iters)
	}
}

func TestMutualExclusionWithTryLock(t *testing.T) {
	var m Mutex
	m.Init()

	// Similar to the previous, with the addition of some goroutines that
	// only increment the count if TryLock succeeds.
	const gr = 1000
	const iters = 100000
	total := int64(gr * iters)
	var tryTotal int64
	v := int64(0)
	var wg sync.WaitGroup
	for i := 0; i < gr; i++ {
		wg.Add(2)
		go func() {
			for j := 0; j < iters; j++ {
				m.Lock()
				v++
				m.Unlock()
			}
			wg.Done()
		}()
		go func() {
			local := int64(0)
			for j := 0; j < iters; j++ {
				if m.TryLock() {
					v++
					m.Unlock()
					local++
				}
			}
			atomic.AddInt64(&tryTotal, local)
			wg.Done()
		}()
	}

	wg.Wait()

	t.Logf("tryTotal = %d", tryTotal)
	total += tryTotal

	if v != total {
		t.Fatalf("Bad count: got %v, want %v", v, total)
	}
}

// BenchmarkTmutex is equivalent to TestMutualExclusion, with the following
// differences:
//
// - The number of goroutines is variable, with the maximum value depending on
// GOMAXPROCS.
//
// - The number of iterations per benchmark is controlled by the benchmarking
// framework.
//
// - Care is taken to ensure that all goroutines participating in the benchmark
// have been created before the benchmark begins.
func BenchmarkTmutex(b *testing.B) {
	for n, max := 1, 4*runtime.GOMAXPROCS(0); n > 0 && n <= max; n *= 2 {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			var m Mutex
			m.Init()

			var ready sync.WaitGroup
			begin := make(chan struct{})
			var end sync.WaitGroup
			for i := 0; i < n; i++ {
				ready.Add(1)
				end.Add(1)
				go func() {
					ready.Done()
					<-begin
					for j := 0; j < b.N; j++ {
						m.Lock()
						m.Unlock()
					}
					end.Done()
				}()
			}

			ready.Wait()
			b.ResetTimer()
			close(begin)
			end.Wait()
		})
	}
}

// BenchmarkSyncMutex is equivalent to BenchmarkTmutex, but uses sync.Mutex as
// a comparison point.
func BenchmarkSyncMutex(b *testing.B) {
	for n, max := 1, 4*runtime.GOMAXPROCS(0); n > 0 && n <= max; n *= 2 {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			var m sync.Mutex

			var ready sync.WaitGroup
			begin := make(chan struct{})
			var end sync.WaitGroup
			for i := 0; i < n; i++ {
				ready.Add(1)
				end.Add(1)
				go func() {
					ready.Done()
					<-begin
					for j := 0; j < b.N; j++ {
						m.Lock()
						m.Unlock()
					}
					end.Done()
				}()
			}

			ready.Wait()
			b.ResetTimer()
			close(begin)
			end.Wait()
		})
	}
}
