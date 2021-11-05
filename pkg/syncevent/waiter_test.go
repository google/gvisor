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
	"sync/atomic"
	"testing"
	"time"

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
	notifiedEvent := uint32(0)
	go func() {
		time.Sleep(100 * time.Millisecond)
		atomic.StoreUint32(&notifiedEvent, 1)
		w.Notify(evWaited)
	}()
	if got, want := w.WaitFor(evWaited), evWaited|evOther; got != want {
		t.Errorf("Waiter.WaitFor: got %#x, wanted %#x", got, want)
	}
	if atomic.LoadUint32(&notifiedEvent) == 0 {
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
		New: func() interface{} {
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
		New: func() interface{} {
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

// BenchmarkXxxNotifyAsyncWaitAck measures how long it takes to wait for an
// event while another goroutine signals the event. This assumes that a new
// goroutine doesn't run immediately (i.e. the creator of a new goroutine is
// allowed to go to sleep before the new goroutine has a chance to run).

func BenchmarkWaiterNotifyAsyncWaitAck(b *testing.B) {
	var w Waiter
	w.Init()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		go func() {
			w.Notify(1)
		}()
		w.Wait()
		w.Ack(evBench)
	}
}

func BenchmarkSleeperNotifyAsyncWaitAck(b *testing.B) {
	var s sleep.Sleeper
	var w sleep.Waker
	s.AddWaker(&w)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		go func() {
			w.Assert()
		}()
		s.Fetch(true)
	}
}

func BenchmarkChannelNotifyAsyncWaitAck(b *testing.B) {
	ch := make(chan struct{}, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		go func() {
			select {
			case ch <- struct{}{}:
			default:
			}
		}()
		<-ch
	}
}

// BenchmarkXxxNotifyAsyncWaitMultiAck is equivalent to NotifyAsyncWaitAck, but
// allows for multiple event sources.

func BenchmarkWaiterNotifyAsyncWaitMultiAck(b *testing.B) {
	var w Waiter
	w.Init()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		go func() {
			w.Notify(evBench)
		}()
		if e := w.Wait(); e != evBench {
			b.Fatalf("Wait: got %#x, wanted %#x", e, evBench)
		}
		w.Ack(evBench)
	}
}

func BenchmarkSleeperNotifyAsyncWaitMultiAck(b *testing.B) {
	var s sleep.Sleeper
	var ws [3]sleep.Waker
	for i := range ws {
		s.AddWaker(&ws[i])
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		go func() {
			ws[0].Assert()
		}()
		if v := s.Fetch(true); v != &ws[0] {
			b.Fatalf("Fetch: got %v, expected %v", v, &ws[0])
		}
	}
}

func BenchmarkChannelNotifyAsyncWaitMultiAck(b *testing.B) {
	ch0 := make(chan struct{}, 1)
	ch1 := make(chan struct{}, 1)
	ch2 := make(chan struct{}, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		go func() {
			select {
			case ch0 <- struct{}{}:
			default:
			}
		}()

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
