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

// Package amutex provides the implementation of an abortable mutex. It allows
// the Lock() function to be canceled while it waits to acquire the mutex.
package amutex

import (
	"sync/atomic"
)

// Sleeper must be implemented by users of the abortable mutex to allow for
// cancelation of waits.
type Sleeper interface {
	// SleepStart is called by the AbortableMutex.Lock() function when the
	// mutex is contended and the goroutine is about to sleep.
	//
	// A channel can be returned that causes the sleep to be canceled if
	// it's readable. If no cancelation is desired, nil can be returned.
	SleepStart() <-chan struct{}

	// SleepFinish is called by AbortableMutex.Lock() once a contended mutex
	// is acquired or the wait is aborted.
	SleepFinish(success bool)

	// Interrupted returns true if the wait is aborted.
	Interrupted() bool
}

// NoopSleeper is a stateless no-op implementation of Sleeper for anonymous
// embedding in other types that do not support cancelation.
type NoopSleeper struct{}

// SleepStart implements Sleeper.SleepStart.
func (NoopSleeper) SleepStart() <-chan struct{} {
	return nil
}

// SleepFinish implements Sleeper.SleepFinish.
func (NoopSleeper) SleepFinish(success bool) {}

// Interrupted implements Sleeper.Interrupted.
func (NoopSleeper) Interrupted() bool { return false }

// AbortableMutex is an abortable mutex. It allows Lock() to be aborted while it
// waits to acquire the mutex.
type AbortableMutex struct {
	v  int32
	ch chan struct{}
}

// Init initializes the abortable mutex.
func (m *AbortableMutex) Init() {
	m.v = 1
	m.ch = make(chan struct{}, 1)
}

// Lock attempts to acquire the mutex, returning true on success. If something
// is written to the "c" while Lock waits, the wait is aborted and false is
// returned instead.
func (m *AbortableMutex) Lock(s Sleeper) bool {
	// Uncontended case.
	if atomic.AddInt32(&m.v, -1) == 0 {
		return true
	}

	var c <-chan struct{}
	if s != nil {
		c = s.SleepStart()
	}

	for {
		// Try to acquire the mutex again, at the same time making sure
		// that m.v is negative, which indicates to the owner of the
		// lock that it is contended, which ill force it to try to wake
		// someone up when it releases the mutex.
		if v := atomic.LoadInt32(&m.v); v >= 0 && atomic.SwapInt32(&m.v, -1) == 1 {
			if s != nil {
				s.SleepFinish(true)
			}
			return true
		}

		// Wait for the owner to wake us up before trying again, or for
		// the wait to be aborted by the provided channel.
		select {
		case <-m.ch:
		case <-c:
			// s must be non-nil, otherwise c would be nil and we'd
			// never reach this path.
			s.SleepFinish(false)
			return false
		}
	}
}

// Unlock releases the mutex.
func (m *AbortableMutex) Unlock() {
	if atomic.SwapInt32(&m.v, 1) == 0 {
		// There were no pending waiters.
		return
	}

	// Wake some waiter up.
	select {
	case m.ch <- struct{}{}:
	default:
	}
}
