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

package waiter

import (
	"sync/atomic"
	"testing"
)

type callbackStub struct {
	f func(e *Entry)
}

// Callback implements EntryCallback.Callback.
func (c *callbackStub) Callback(e *Entry) {
	c.f(e)
}

func TestEmptyQueue(t *testing.T) {
	var q Queue

	// Notify the zero-value of a queue.
	q.Notify(EventIn)

	// Register then unregister a waiter, then notify the queue.
	cnt := 0
	e := Entry{Callback: &callbackStub{func(*Entry) { cnt++ }}}
	q.EventRegister(&e, EventIn)
	q.EventUnregister(&e)
	q.Notify(EventIn)
	if cnt != 0 {
		t.Errorf("Callback was called when it shouldn't have been")
	}
}

func TestMask(t *testing.T) {
	// Register a waiter.
	var q Queue
	var cnt int
	e := Entry{Callback: &callbackStub{func(*Entry) { cnt++ }}}
	q.EventRegister(&e, EventIn|EventErr)

	// Notify with an overlapping mask.
	cnt = 0
	q.Notify(EventIn | EventOut)
	if cnt != 1 {
		t.Errorf("Callback wasn't called when it should have been")
	}

	// Notify with a subset mask.
	cnt = 0
	q.Notify(EventIn)
	if cnt != 1 {
		t.Errorf("Callback wasn't called when it should have been")
	}

	// Notify with a superset mask.
	cnt = 0
	q.Notify(EventIn | EventErr | EventOut)
	if cnt != 1 {
		t.Errorf("Callback wasn't called when it should have been")
	}

	// Notify with the exact same mask.
	cnt = 0
	q.Notify(EventIn | EventErr)
	if cnt != 1 {
		t.Errorf("Callback wasn't called when it should have been")
	}

	// Notify with a disjoint mask.
	cnt = 0
	q.Notify(EventOut | EventHUp)
	if cnt != 0 {
		t.Errorf("Callback was called when it shouldn't have been")
	}
}

func TestConcurrentRegistration(t *testing.T) {
	var q Queue
	var cnt int
	const concurrency = 1000

	ch1 := make(chan struct{})
	ch2 := make(chan struct{})
	ch3 := make(chan struct{})

	// Create goroutines that will all register/unregister concurrently.
	for i := 0; i < concurrency; i++ {
		go func() {
			var e Entry
			e.Callback = &callbackStub{func(entry *Entry) {
				cnt++
				if entry != &e {
					t.Errorf("entry = %p, want %p", entry, &e)
				}
			}}

			// Wait for notification, then register.
			<-ch1
			q.EventRegister(&e, EventIn|EventErr)

			// Tell main goroutine that we're done registering.
			ch2 <- struct{}{}

			// Wait for notification, then unregister.
			<-ch3
			q.EventUnregister(&e)

			// Tell main goroutine that we're done unregistering.
			ch2 <- struct{}{}
		}()
	}

	// Let the goroutines register.
	close(ch1)
	for i := 0; i < concurrency; i++ {
		<-ch2
	}

	// Issue a notification.
	q.Notify(EventIn)
	if cnt != concurrency {
		t.Errorf("cnt = %d, want %d", cnt, concurrency)
	}

	// Let the goroutine unregister.
	close(ch3)
	for i := 0; i < concurrency; i++ {
		<-ch2
	}

	// Issue a notification.
	q.Notify(EventIn)
	if cnt != concurrency {
		t.Errorf("cnt = %d, want %d", cnt, concurrency)
	}
}

func TestConcurrentNotification(t *testing.T) {
	var q Queue
	var cnt int32
	const concurrency = 1000
	const waiterCount = 1000

	// Register waiters.
	for i := 0; i < waiterCount; i++ {
		var e Entry
		e.Callback = &callbackStub{func(entry *Entry) {
			atomic.AddInt32(&cnt, 1)
			if entry != &e {
				t.Errorf("entry = %p, want %p", entry, &e)
			}
		}}

		q.EventRegister(&e, EventIn|EventErr)
	}

	// Launch notifiers.
	ch1 := make(chan struct{})
	ch2 := make(chan struct{})
	for i := 0; i < concurrency; i++ {
		go func() {
			<-ch1
			q.Notify(EventIn)
			ch2 <- struct{}{}
		}()
	}

	// Let notifiers go.
	close(ch1)
	for i := 0; i < concurrency; i++ {
		<-ch2
	}

	// Check the count.
	if cnt != concurrency*waiterCount {
		t.Errorf("cnt = %d, want %d", cnt, concurrency*waiterCount)
	}
}
