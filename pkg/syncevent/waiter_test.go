// Copyright 2020 The gVisor Authors.
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

package syncevent

import (
	"fmt"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/sync"
)

func TestWaiterAlreadyPending(t *testing.T) {
	var w Waiter
	w.Init()
	want := Set(1)
	w.Notify(want)
	if got := w.Wait(); got != want {
		t.Errorf("Waiter.Wait: got %#x, wanted %#x", got, want)
	}
}

func TestWaiterAsyncNotify(t *testing.T) {
	var w Waiter
	w.Init()
	want := Set(1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		w.Notify(want)
	}()
	if got := w.Wait(); got != want {
		t.Errorf("Waiter.Wait: got %#x, wanted %#x", got, want)
	}
}

func TestWaiterWaitFor(t *testing.T) {
	var w Waiter
	w.Init()
	evWaited := Set(1)
	evOther := Set(2)
	w.Notify(evOther)
	notifiedEvent := atomicbitops.FromUint32(0)
	go func() {
		time.Sleep(100 * time.Millisecond)
		notifiedEvent.Store(1)
		w.Notify(evWaited)
	}()
	if got, want := w.WaitFor(evWaited), evWaited|evOther; got != want {
		t.Errorf("Waiter.WaitFor: got %#x, wanted %#x", got, want)
	}
	if notifiedEvent.Load() == 0 {
		t.Errorf("Waiter.WaitFor returned before goroutine notified waited-for event")
	}
}

func TestWaiterWaitAndAckAll(t *testing.T) {
	var w Waiter
	w.Init()
	w.Notify(AllEvents)
	if got := w.WaitAndAckAll(); got != AllEvents {
		t.Errorf("Waiter.WaitAndAckAll: got %#x, wanted %#x", got, AllEvents)
	}
	if got := w.Pending(); got != NoEvents {
		t.Errorf("Waiter.WaitAndAckAll did not ack all events: got %#x, wanted 0", got)
	}
}

// BenchmarkWaiterX, BenchmarkSleeperX, and BenchmarkChannelX benchmark usage
// pattern X (described in terms of Waiter) with Waiter, sleep.Sleeper, and
// buffered chan struct{} respectively. When the maximum number of event
// sources is relevant, we use 3 event sources because this is representative
// of the kernel.Task.block() use case: an interrupt source, a timeout source,
// and the actual event source being waited on.

// Event set used by most benchmarks.
const evBench Set = 1

// BenchmarkXxxNotifyRedundant measures how long it takes to notify a Waiter of
// an event that is already pending.

func BenchmarkWaiterNotifyRedundant(b *testing.B) {
	var w Waiter
	w.Init()
	w.Notify(evBench)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Notify(evBench)
	}
}

func BenchmarkSleeperNotifyRedundant(b *testing.B) {
	var s sleep.Sleeper
	var w sleep.Waker
	s.AddWaker(&w)
	w.Assert()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Assert()
	}
}

func BenchmarkChannelNotifyRedundant(b *testing.B) {
	ch := make(chan struct{}, 1)
	ch <- struct{}{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// BenchmarkXxxNotifyWaitAck measures how long it takes to notify a Waiter an
// event, return that event using a blocking check, and then unset the event as
// pending.

func BenchmarkWaiterNotifyWaitAck(b *testing.B) {
	var w Waiter
	w.Init()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Notify(evBench)
		w.Wait()
		w.Ack(evBench)
	}
}

func BenchmarkSleeperNotifyWaitAck(b *testing.B) {
	var s sleep.Sleeper
	var w sleep.Waker
	s.AddWaker(&w)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Assert()
		s.Fetch(true)
	}
}

func BenchmarkChannelNotifyWaitAck(b *testing.B) {
	ch := make(chan struct{}, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// notify
		select {
		case ch <- struct{}{}:
		default:
		}

		// wait + ack
		<-ch
	}
}

// BenchmarkSleeperMultiNotifyWaitAck is equivalent to
// BenchmarkSleeperNotifyWaitAck, but also includes allocation of a
// temporary sleep.Waker. This is necessary when multiple goroutines may wait
// for the same event, since each sleep.Waker can wake only a single
// sleep.Sleeper.
//
// The syncevent package does not require a distinct object for each
// waiter-waker relationship, so BenchmarkWaiterNotifyWaitAck and
// BenchmarkWaiterMultiNotifyWaitAck would be identical. The analogous state
// for channels, runtime.sudog, is inescapably runtime-allocated, so
// BenchmarkChannelNotifyWaitAck and BenchmarkChannelMultiNotifyWaitAck would
// also be identical.

func BenchmarkSleeperMultiNotifyWaitAck(b *testing.B) {
	var s sleep.Sleeper
	// The sleep package doesn't provide sync.Pool allocation of Wakers;
	// we do for a fairer comparison.
	wakerPool := sync.Pool{
		New: func() any {
			return &sleep.Waker{}
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := wakerPool.Get().(*sleep.Waker)
		s.AddWaker(w)
		w.Assert()
		s.Fetch(true)
		s.Done()
		wakerPool.Put(w)
	}
}

// BenchmarkXxxTempNotifyWaitAck is equivalent to NotifyWaitAck, but also
// includes allocation of a temporary Waiter. This models the case where a
// goroutine not already associated with a Waiter needs one in order to block.
//
// The analogous state for channels is built into runtime.g, so
// BenchmarkChannelNotifyWaitAck and BenchmarkChannelTempNotifyWaitAck would be
// identical.

func BenchmarkWaiterTempNotifyWaitAck(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := GetWaiter()
		w.Notify(evBench)
		w.Wait()
		w.Ack(evBench)
		PutWaiter(w)
	}
}

func BenchmarkSleeperTempNotifyWaitAck(b *testing.B) {
	// The sleep package doesn't provide sync.Pool allocation of Sleepers;
	// we do for a fairer comparison.
	sleeperPool := sync.Pool{
		New: func() any {
			return &sleep.Sleeper{}
		},
	}
	var w sleep.Waker

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := sleeperPool.Get().(*sleep.Sleeper)
		s.AddWaker(&w)
		w.Assert()
		s.Fetch(true)
		s.Done()
		sleeperPool.Put(s)
	}
}

// BenchmarkXxxNotifyWaitMultiAck is equivalent to NotifyWaitAck, but allows
// for multiple event sources.

func BenchmarkWaiterNotifyWaitMultiAck(b *testing.B) {
	var w Waiter
	w.Init()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Notify(evBench)
		if e := w.Wait(); e != evBench {
			b.Fatalf("Wait: got %#x, wanted %#x", e, evBench)
		}
		w.Ack(evBench)
	}
}

func BenchmarkSleeperNotifyWaitMultiAck(b *testing.B) {
	var s sleep.Sleeper
	var ws [3]sleep.Waker
	for i := range ws {
		s.AddWaker(&ws[i])
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ws[0].Assert()
		if v := s.Fetch(true); v != &ws[0] {
			b.Fatalf("Fetch: got %v, wanted %v", v, &ws[0])
		}
	}
}

func BenchmarkChannelNotifyWaitMultiAck(b *testing.B) {
	ch0 := make(chan struct{}, 1)
	ch1 := make(chan struct{}, 1)
	ch2 := make(chan struct{}, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// notify
		select {
		case ch0 <- struct{}{}:
		default:
		}

		// wait + clear
		select {
		case <-ch0:
			// ok
		case <-ch1:
			b.Fatalf("received from ch1")
		case <-ch2:
			b.Fatalf("received from ch2")
		}
	}
}

// BenchmarkXxxPingPong exchanges control between two goroutines.

func BenchmarkWaiterPingPong(b *testing.B) {
	var w1, w2 Waiter
	w1.Init()
	w2.Init()
	var wg sync.WaitGroup
	defer wg.Wait()

	w1.Notify(evBench)
	b.ResetTimer()
	go func() {
		for i := 0; i < b.N; i++ {
			w1.Wait()
			w1.Ack(evBench)
			w2.Notify(evBench)
		}
	}()
	for i := 0; i < b.N; i++ {
		w2.Wait()
		w2.Ack(evBench)
		w1.Notify(evBench)
	}
}

func BenchmarkSleeperPingPong(b *testing.B) {
	var (
		s1 sleep.Sleeper
		w1 sleep.Waker
		s2 sleep.Sleeper
		w2 sleep.Waker
	)
	s1.AddWaker(&w1)
	s2.AddWaker(&w2)
	var wg sync.WaitGroup
	defer wg.Wait()

	w1.Assert()
	wg.Add(1)
	b.ResetTimer()
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			s1.Fetch(true)
			w2.Assert()
		}
	}()
	for i := 0; i < b.N; i++ {
		s2.Fetch(true)
		w1.Assert()
	}
}

func BenchmarkChannelPingPong(b *testing.B) {
	ch1 := make(chan struct{}, 1)
	ch2 := make(chan struct{}, 1)
	var wg sync.WaitGroup
	defer wg.Wait()

	ch1 <- struct{}{}
	wg.Add(1)
	b.ResetTimer()
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			<-ch1
			ch2 <- struct{}{}
		}
	}()
	for i := 0; i < b.N; i++ {
		<-ch2
		ch1 <- struct{}{}
	}
}

// BenchmarkXxxPingPongMulti is equivalent to PingPong, but allows each
// goroutine to receive from multiple event sources (although only one is ever
// signaled).

func BenchmarkWaiterPingPongMulti(b *testing.B) {
	var w1, w2 Waiter
	w1.Init()
	w2.Init()
	var wg sync.WaitGroup
	defer wg.Wait()

	w1.Notify(evBench)
	wg.Add(1)
	b.ResetTimer()
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			if e := w1.Wait(); e != evBench {
				// b.Fatalf() can only be called from the main goroutine.
				panic(fmt.Sprintf("Wait: got %#x, wanted %#x", e, evBench))
			}
			w1.Ack(evBench)
			w2.Notify(evBench)
		}
	}()
	for i := 0; i < b.N; i++ {
		if e := w2.Wait(); e != evBench {
			b.Fatalf("Wait: got %#x, wanted %#x", e, evBench)
		}
		w2.Ack(evBench)
		w1.Notify(evBench)
	}
}

func BenchmarkSleeperPingPongMulti(b *testing.B) {
	var (
		s1           sleep.Sleeper
		w1, w1a, w1b sleep.Waker
		s2           sleep.Sleeper
		w2, w2a, w2b sleep.Waker
	)
	s1.AddWaker(&w1)
	s1.AddWaker(&w1a)
	s1.AddWaker(&w1b)
	s2.AddWaker(&w2)
	s2.AddWaker(&w2a)
	s2.AddWaker(&w2b)
	var wg sync.WaitGroup
	defer wg.Wait()

	w1.Assert()
	wg.Add(1)
	b.ResetTimer()
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			if w := s1.Fetch(true); w != &w1 {
				// b.Fatalf() can only be called from the main goroutine.
				panic(fmt.Sprintf("Fetch: got %p, wanted %p", w, &w1))
			}
			w2.Assert()
		}
	}()
	for i := 0; i < b.N; i++ {
		if w := s2.Fetch(true); w != &w2 {
			b.Fatalf("Fetch: got %p, wanted %p", w, &w2)
		}
		w1.Assert()
	}
}

func BenchmarkChannelPingPongMulti(b *testing.B) {
	ch1 := make(chan struct{}, 1)
	ch1a := make(chan struct{}, 1)
	ch1b := make(chan struct{}, 1)
	ch2 := make(chan struct{}, 1)
	ch2a := make(chan struct{}, 1)
	ch2b := make(chan struct{}, 1)
	var wg sync.WaitGroup
	defer wg.Wait()

	ch1 <- struct{}{}
	wg.Add(1)
	b.ResetTimer()
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			select {
			case <-ch1:
			case <-ch1a:
				panic("received from ch1a")
			case <-ch1b:
				panic("received from ch1a")
			}
			ch2 <- struct{}{}
		}
	}()
	for i := 0; i < b.N; i++ {
		select {
		case <-ch2:
		case <-ch2a:
			panic("received from ch2a")
		case <-ch2b:
			panic("received from ch2a")
		}
		ch1 <- struct{}{}
	}
}
