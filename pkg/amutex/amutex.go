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

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Sleeper must be implemented by users of the abortable mutex to allow for
// cancellation of waits.
type Sleeper = context.ChannelSleeper

// NoopSleeper is a stateless no-op implementation of Sleeper for anonymous
// embedding in other types that do not support cancelation.
type NoopSleeper = context.Context

// Block blocks until either receiving from ch succeeds (in which case it
// returns nil) or sleeper is interrupted (in which case it returns
// syserror.ErrInterrupted).
func Block(sleeper Sleeper, ch <-chan struct{}) error {
	cancel := sleeper.SleepStart()
	select {
	case <-ch:
		sleeper.SleepFinish(true)
		return nil
	case <-cancel:
		sleeper.SleepFinish(false)
		return syserror.ErrInterrupted
	}
}

// AbortableMutex is an abortable mutex. It allows Lock() to be aborted while it
// waits to acquire the mutex.
type AbortableMutex struct {
	// +checkatomic
	v  int32
	ch chan struct{}
}

// Init initializes the abortable mutex.
func (m *AbortableMutex) Init() {
	atomic.StoreInt32(&m.v, 1)
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
