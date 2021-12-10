// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sleep

import (
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ZeroWakerNotAsserted tests that a zero-value waker is in non-asserted state.
func ZeroWakerNotAsserted(t *testing.T) {
	var w Waker
	if w.IsAsserted() {
		t.Fatalf("Zero waker is asserted")
	}

	if w.Clear() {
		t.Fatalf("Zero waker is asserted")
	}
}

// AssertedWakerAfterAssert tests that a waker properly reports its state as
// asserted once its Assert() method is called.
func AssertedWakerAfterAssert(t *testing.T) {
	var w Waker
	w.Assert()
	if !w.IsAsserted() {
		t.Fatalf("Asserted waker is not reported as such")
	}

	if !w.Clear() {
		t.Fatalf("Asserted waker is not reported as such")
	}
}

// AssertedWakerAfterTwoAsserts tests that a waker properly reports its state as
// asserted once its Assert() method is called twice.
func AssertedWakerAfterTwoAsserts(t *testing.T) {
	var w Waker
	w.Assert()
	w.Assert()
	if !w.IsAsserted() {
		t.Fatalf("Asserted waker is not reported as such")
	}

	if !w.Clear() {
		t.Fatalf("Asserted waker is not reported as such")
	}
}

// NotAssertedWakerWithSleeper tests that a waker properly reports its state as
// not asserted after a sleeper is associated with it.
func NotAssertedWakerWithSleeper(t *testing.T) {
	var w Waker
	var s Sleeper
	s.AddWaker(&w)
	if w.IsAsserted() {
		t.Fatalf("Non-asserted waker is reported as asserted")
	}

	if w.Clear() {
		t.Fatalf("Non-asserted waker is reported as asserted")
	}
}

// NotAssertedWakerAfterWake tests that a waker properly reports its state as
// not asserted after a previous assert is consumed by a sleeper. That is, tests
// the "edge-triggered" behavior.
func NotAssertedWakerAfterWake(t *testing.T) {
	var w Waker
	var s Sleeper
	s.AddWaker(&w)
	w.Assert()
	s.Fetch(true)
	if w.IsAsserted() {
		t.Fatalf("Consumed waker is reported as asserted")
	}

	if w.Clear() {
		t.Fatalf("Consumed waker is reported as asserted")
	}
}

// AssertedWakerBeforeAdd tests that a waker causes a sleeper to not sleep if
// it's already asserted before being added.
func AssertedWakerBeforeAdd(t *testing.T) {
	var w Waker
	var s Sleeper
	w.Assert()
	s.AddWaker(&w)

	if s.Fetch(false) != &w {
		t.Fatalf("Fetch did not match waker")
	}
}

// ClearedWaker tests that a waker properly reports its state as not asserted
// after it is cleared.
func ClearedWaker(t *testing.T) {
	var w Waker
	w.Assert()
	w.Clear()
	if w.IsAsserted() {
		t.Fatalf("Cleared waker is reported as asserted")
	}

	if w.Clear() {
		t.Fatalf("Cleared waker is reported as asserted")
	}
}

// ClearedWakerWithSleeper tests that a waker properly reports its state as
// not asserted when it is cleared while it has a sleeper associated with it.
func ClearedWakerWithSleeper(t *testing.T) {
	var w Waker
	var s Sleeper
	s.AddWaker(&w)
	w.Clear()
	if w.IsAsserted() {
		t.Fatalf("Cleared waker is reported as asserted")
	}

	if w.Clear() {
		t.Fatalf("Cleared waker is reported as asserted")
	}
}

// ClearedWakerAssertedWithSleeper tests that a waker properly reports its state
// as not asserted when it is cleared while it has a sleeper associated with it
// and has been asserted.
func ClearedWakerAssertedWithSleeper(t *testing.T) {
	var w Waker
	var s Sleeper
	s.AddWaker(&w)
	w.Assert()
	w.Clear()
	if w.IsAsserted() {
		t.Fatalf("Cleared waker is reported as asserted")
	}

	if w.Clear() {
		t.Fatalf("Cleared waker is reported as asserted")
	}
}

// TestBlock tests that a sleeper actually blocks waiting for the waker to
// assert its state.
func TestBlock(t *testing.T) {
	var w Waker
	var s Sleeper

	s.AddWaker(&w)

	// Assert waker after one second.
	before := time.Now()
	time.AfterFunc(time.Second, w.Assert)

	// Fetch the result and make sure it took at least 500ms.
	if s.Fetch(true) != &w {
		t.Fatalf("Fetch did not match waker")
	}
	if d := time.Now().Sub(before); d < 500*time.Millisecond {
		t.Fatalf("Duration was too short: %v", d)
	}

	// Check that already-asserted waker completes inline.
	w.Assert()
	if s.Fetch(true) != &w {
		t.Fatalf("Fetch did not match waker")
	}

	// Check that fetch sleeps if waker had been asserted but was reset
	// before Fetch is called.
	w.Assert()
	w.Clear()
	before = time.Now()
	time.AfterFunc(time.Second, w.Assert)

	if s.Fetch(true) != &w {
		t.Fatalf("Fetch did not match waker")
	}
	if d := time.Now().Sub(before); d < 500*time.Millisecond {
		t.Fatalf("Duration was too short: %v", d)
	}
}

// TestNonBlock checks that a sleeper won't block if waker isn't asserted.
func TestNonBlock(t *testing.T) {
	var w Waker
	var s Sleeper

	// Don't block when there's no waker.
	if s.Fetch(false) != nil {
		t.Fatalf("Fetch succeeded when there is no waker")
	}

	// Don't block when waker isn't asserted.
	s.AddWaker(&w)
	if s.Fetch(false) != nil {
		t.Fatalf("Fetch succeeded when waker was not asserted")
	}

	// Don't block when waker was asserted, but isn't anymore.
	w.Assert()
	w.Clear()
	if s.Fetch(false) != nil {
		t.Fatalf("Fetch succeeded when waker was not asserted anymore")
	}

	// Don't block when waker was consumed by previous Fetch().
	w.Assert()
	if s.Fetch(false) != &w {
		t.Fatalf("Fetch failed even though waker was asserted")
	}

	if s.Fetch(false) != nil {
		t.Fatalf("Fetch succeeded when waker had been consumed")
	}
}

// TestMultiple checks that a sleeper can wait for and receives notifications
// from multiple wakers.
func TestMultiple(t *testing.T) {
	s := Sleeper{}
	w1 := Waker{}
	w2 := Waker{}

	s.AddWaker(&w1)
	s.AddWaker(&w2)

	w1.Assert()
	w2.Assert()

	v := s.Fetch(false)
	if v == nil {
		t.Fatalf("Fetch failed when there are asserted wakers")
	}
	if v != &w1 && v != &w2 {
		t.Fatalf("Unexpected waker: %v", v)
	}

	want := &w1
	if v == want {
		want = &w2 // Other waiter.
	}
	v = s.Fetch(false)
	if v == nil {
		t.Fatalf("Fetch failed when there is an asserted waker")
	}
	if v != want {
		t.Fatalf("Unexpected waker, got %v, want %v", v, want)
	}
}

// TestDoneFunction tests if calling Done() on a sleeper works properly.
func TestDoneFunction(t *testing.T) {
	// Trivial case of no waker.
	s := Sleeper{}
	s.Done()

	// Cases when the sleeper has n wakers, but none are asserted.
	for n := 1; n < 20; n++ {
		s := Sleeper{}
		w := make([]Waker, n)
		for j := 0; j < n; j++ {
			s.AddWaker(&w[j])
		}
		s.Done()
	}

	// Cases when the sleeper has n wakers, and only the i-th one is
	// asserted.
	for n := 1; n < 20; n++ {
		for i := 0; i < n; i++ {
			s := Sleeper{}
			w := make([]Waker, n)
			for j := 0; j < n; j++ {
				s.AddWaker(&w[j])
			}
			w[i].Assert()
			s.Done()
		}
	}

	// Cases when the sleeper has n wakers, and the i-th one is asserted
	// and cleared.
	for n := 1; n < 20; n++ {
		for i := 0; i < n; i++ {
			s := Sleeper{}
			w := make([]Waker, n)
			for j := 0; j < n; j++ {
				s.AddWaker(&w[j])
			}
			w[i].Assert()
			w[i].Clear()
			s.Done()
		}
	}

	// Cases when the sleeper has n wakers, with a random number of them
	// asserted.
	for n := 1; n < 20; n++ {
		for iters := 0; iters < 1000; iters++ {
			s := Sleeper{}
			w := make([]Waker, n)
			for j := 0; j < n; j++ {
				s.AddWaker(&w[j])
			}

			// Pick the number of asserted elements, then assert
			// random wakers.
			asserted := rand.Int() % (n + 1)
			for j := 0; j < asserted; j++ {
				w[rand.Int()%n].Assert()
			}
			s.Done()
		}
	}
}

// TestAssertFetch tests basic assert fetch functionality.
func TestAssertFetch(t *testing.T) {
	const sleeperWakers = 100
	const wakeRequests = 1000
	const seedAsserts = 10

	ws := make([]Waker, sleeperWakers)
	ss := make([]Sleeper, sleeperWakers)
	for i := 0; i < sleeperWakers; i++ {
		ss[i].AddWaker(&ws[i])
	}
	defer func() {
		for i := 0; i < sleeperWakers; i++ {
			defer ss[i].Done()
		}
	}()
	var (
		count int32
		wg    sync.WaitGroup
	)
	for i := 0; i < sleeperWakers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ss[i].Fetch(true /* block */)
			w := &ws[(i+1)%sleeperWakers]
			for n := 0; n < wakeRequests; n++ {
				atomic.AddInt32(&count, 1)
				ss[i].AssertAndFetch(w)
			}
			w.Assert() // Final wake-up.
		}(i)
	}

	// Fire the first assertion.
	ws[0].Assert()
	wg.Wait()

	// Check what we got.
	if want := int32(sleeperWakers * wakeRequests); count != want {
		t.Errorf("unexpected count: got %d, wanted %d", count, want)
	}
}

// TestRace tests that multiple wakers can continuously send wake requests to
// the sleeper.
func TestRace(t *testing.T) {
	const wakers = 100
	const wakeRequests = 10000

	counts := make(map[*Waker]int, wakers)
	s := Sleeper{}

	// Associate each waker and start goroutines that will assert them.
	for i := 0; i < wakers; i++ {
		var w Waker
		s.AddWaker(&w)
		go func() {
			n := 0
			for n < wakeRequests {
				if !w.IsAsserted() {
					w.Assert()
					n++
				} else {
					runtime.Gosched()
				}
			}
		}()
	}

	// Wait for all wake up notifications from all wakers.
	for i := 0; i < wakers*wakeRequests; i++ {
		v := s.Fetch(true)
		counts[v]++
	}

	// Check that we got the right number for each.
	if got := len(counts); got != wakers {
		t.Errorf("Got %d wakers, wanted %d", got, wakers)
	}
	for _, count := range counts {
		if count != wakeRequests {
			t.Errorf("Waker only got %d wakes, wanted %d", count, wakeRequests)
		}
	}
}

// TestRaceInOrder tests that multiple wakers can continuously send wake requests to
// the sleeper and that the wakers are retrieved in the order asserted.
func TestRaceInOrder(t *testing.T) {
	w := make([]Waker, 10000)
	s := Sleeper{}

	// Associate each waker and start goroutines that will assert them.
	for i := range w {
		s.AddWaker(&w[i])
	}
	go func() {
		for i := range w {
			w[i].Assert()
		}
	}()

	// Wait for all wake up notifications from all wakers.
	for i := range w {
		got := s.Fetch(true)
		if want := &w[i]; got != want {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

// BenchmarkSleeperMultiSelect measures how long it takes to fetch a wake up
// from 4 wakers when at least one is already asserted.
func BenchmarkSleeperMultiSelect(b *testing.B) {
	const count = 4
	s := Sleeper{}
	w := make([]Waker, count)
	for i := range w {
		s.AddWaker(&w[i])
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w[count-1].Assert()
		s.Fetch(true)
	}
}

// BenchmarkGoMultiSelect measures how long it takes to fetch a zero-length
// struct from one of 4 channels when at least one is ready.
func BenchmarkGoMultiSelect(b *testing.B) {
	const count = 4
	ch := make([]chan struct{}, count)
	for i := range ch {
		ch[i] = make(chan struct{}, 1)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch[count-1] <- struct{}{}
		select {
		case <-ch[0]:
		case <-ch[1]:
		case <-ch[2]:
		case <-ch[3]:
		}
	}
}

// BenchmarkSleeperSingleSelect measures how long it takes to fetch a wake up
// from one waker that is already asserted.
func BenchmarkSleeperSingleSelect(b *testing.B) {
	s := Sleeper{}
	w := Waker{}
	s.AddWaker(&w)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Assert()
		s.Fetch(true)
	}
}

// BenchmarkGoSingleSelect measures how long it takes to fetch a zero-length
// struct from a channel that already has it buffered.
func BenchmarkGoSingleSelect(b *testing.B) {
	ch := make(chan struct{}, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch <- struct{}{}
		<-ch
	}
}

// BenchmarkSleeperAssertNonWaiting measures how long it takes to assert a
// channel that is already asserted.
func BenchmarkSleeperAssertNonWaiting(b *testing.B) {
	w := Waker{}
	w.Assert()
	for i := 0; i < b.N; i++ {
		w.Assert()
	}

}

// BenchmarkGoAssertNonWaiting measures how long it takes to write to a channel
// that has already something written to it.
func BenchmarkGoAssertNonWaiting(b *testing.B) {
	ch := make(chan struct{}, 1)
	ch <- struct{}{}
	for i := 0; i < b.N; i++ {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// BenchmarkSleeperWaitOnSingleSelect measures how long it takes to wait on one
// waker channel while another goroutine wakes up the sleeper.
func BenchmarkSleeperWaitOnSingleSelect(b *testing.B) {
	var (
		s  Sleeper
		w  Waker
		ns Sleeper
		nw Waker
	)
	ns.AddWaker(&nw)
	s.AddWaker(&w)
	go func() {
		for i := 0; i < b.N; i++ {
			ns.Fetch(true)
			w.Assert()
		}
	}()
	for i := 0; i < b.N; i++ {
		nw.Assert()
		s.Fetch(true)
	}
}

// BenchmarkSleeperWaitOnSingleSelectSync is a modification of the similarly
// named benchmark, except it uses the synchronous AssertAndFetch.
func BenchmarkSleeperWaitOnSingleSelectSync(b *testing.B) {
	var (
		s  Sleeper
		w  Waker
		ns Sleeper
		nw Waker
	)
	ns.AddWaker(&nw)
	s.AddWaker(&w)
	go func() {
		ns.Fetch(true)
		defer w.Assert()
		for i := 0; i < b.N-1; i++ {
			ns.AssertAndFetch(&w)
		}
	}()
	for i := 0; i < b.N; i++ {
		s.AssertAndFetch(&nw)
	}
}

// BenchmarkGoWaitOnSingleSelect measures how long it takes to wait on one
// channel while another goroutine wakes up the sleeper.
func BenchmarkGoWaitOnSingleSelect(b *testing.B) {
	ch := make(chan struct{}, 1)
	nch := make(chan struct{}, 1)
	go func() {
		for i := 0; i < b.N; i++ {
			<-nch
			ch <- struct{}{}
		}
	}()
	for i := 0; i < b.N; i++ {
		nch <- struct{}{}
		<-ch
	}
}

// BenchmarkSleeperWaitOnMultiSelect measures how long it takes to wait on 4
// wakers while another goroutine wakes up the sleeper.
func BenchmarkSleeperWaitOnMultiSelect(b *testing.B) {
	const count = 4
	var (
		s  Sleeper
		ns Sleeper
		nw Waker
	)
	ns.AddWaker(&nw)
	w := make([]Waker, count)
	for i := range w {
		s.AddWaker(&w[i])
	}

	b.ResetTimer()
	go func() {
		for i := 0; i < b.N; i++ {
			ns.Fetch(true)
			w[count-1].Assert()
		}
	}()
	for i := 0; i < b.N; i++ {
		nw.Assert()
		s.Fetch(true)
	}
}

// BenchmarkSleeperWaitOnMultiSelectSync is a modification of the similarly
// named benchmark, except it uses the synchronous AssertAndFetch.
func BenchmarkSleeperWaitOnMultiSelectSync(b *testing.B) {
	const count = 4
	var (
		s  Sleeper
		ns Sleeper
		nw Waker
	)
	ns.AddWaker(&nw)
	w := make([]Waker, count)
	for i := range w {
		s.AddWaker(&w[i])
	}

	b.ResetTimer()
	go func() {
		ns.Fetch(true)
		defer w[count-1].Assert()
		for i := 0; i < b.N-1; i++ {
			ns.AssertAndFetch(&w[count-1])
		}
	}()
	for i := 0; i < b.N; i++ {
		s.AssertAndFetch(&nw)
	}
}

// BenchmarkGoWaitOnMultiSelect measures how long it takes to wait on 4 channels
// while another goroutine wakes up the sleeper.
func BenchmarkGoWaitOnMultiSelect(b *testing.B) {
	const count = 4
	ch := make([]chan struct{}, count)
	nch := make([]chan struct{}, count)
	for i := range ch {
		ch[i] = make(chan struct{}, 1)
		nch[i] = make(chan struct{}, 1)
	}

	b.ResetTimer()
	go func() {
		for i := 0; i < b.N; i++ {
			select {
			case <-nch[0]:
			case <-nch[1]:
			case <-nch[2]:
			case <-nch[3]:
			}
			ch[count-1] <- struct{}{}
		}
	}()
	for i := 0; i < b.N; i++ {
		nch[count-1] <- struct{}{}
		select {
		case <-ch[0]:
		case <-ch[1]:
		case <-ch[2]:
		case <-ch[3]:
		}
	}
}
