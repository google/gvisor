// Copyright 2018 Google LLC
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

package syscalls

import (
	"syscall"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// PollFD describes a pollable FD.
type PollFD struct {
	FD      kdefs.FD
	Events  waiter.EventMask
	REvents waiter.EventMask
}

// pollState tracks the associated file descriptor and waiter of a PollFD.
type pollState struct {
	file   *fs.File
	waiter waiter.Entry
}

// initReadiness gets the current ready mask for the file represented by the FD
// stored in pfd.FD. If a channel is passed in, the waiter entry in "state" is
// used to register with the file for event notifications, and a reference to
// the file is stored in "state".
func (pfd *PollFD) initReadiness(t *kernel.Task, state *pollState, ch chan struct{}) {
	if pfd.FD < 0 {
		pfd.REvents = 0
		return
	}

	file := t.FDMap().GetFile(pfd.FD)
	if file == nil {
		pfd.REvents = waiter.EventNVal
		return
	}

	if ch == nil {
		defer file.DecRef()
	} else {
		state.file = file
		state.waiter, _ = waiter.NewChannelEntry(ch)
		file.EventRegister(&state.waiter, pfd.Events)
	}

	pfd.REvents = file.Readiness(pfd.Events) & pfd.Events
}

// releaseState releases all the pollState in "state".
func releaseState(state []pollState) {
	for i := range state {
		if state[i].file != nil {
			state[i].file.EventUnregister(&state[i].waiter)
			state[i].file.DecRef()
		}
	}
}

// Poll polls the PollFDs in "pfd" with a bounded time specified in "timeout"
// when "timeout" is greater than zero.
//
// Poll returns the remaining timeout, which is always 0 on a timeout; and 0 or
// positive if interrupted by a signal.
func Poll(t *kernel.Task, pfd []PollFD, timeout time.Duration) (time.Duration, uintptr, error) {
	var ch chan struct{}
	if timeout != 0 {
		ch = make(chan struct{}, 1)
	}

	// Register for event notification in the files involved if we may
	// block (timeout not zero). Once we find a file that has a non-zero
	// result, we stop registering for events but still go through all files
	// to get their ready masks.
	state := make([]pollState, len(pfd))
	defer releaseState(state)
	n := uintptr(0)
	for i := range pfd {
		pfd[i].initReadiness(t, &state[i], ch)
		if pfd[i].REvents != 0 {
			n++
			ch = nil
		}
	}

	if timeout == 0 {
		return timeout, n, nil
	}

	forever := timeout < 0

	for n == 0 {
		var err error
		// Wait for a notification.
		timeout, err = t.BlockWithTimeout(ch, !forever, timeout)
		if err != nil {
			if err == syscall.ETIMEDOUT {
				err = nil
			}
			return timeout, 0, err
		}

		// We got notified, count how many files are ready. If none,
		// then this was a spurious notification, and we just go back
		// to sleep with the remaining timeout.
		for i := range state {
			if state[i].file == nil {
				continue
			}

			ready := state[i].file.Readiness(pfd[i].Events) & pfd[i].Events
			if ready != 0 {
				pfd[i].REvents = ready
				n++
			}
		}
	}

	return timeout, n, nil
}
