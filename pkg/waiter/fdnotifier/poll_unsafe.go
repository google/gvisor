// Copyright 2018 Google Inc.
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

package fdnotifier

import (
	"syscall"
	"unsafe"

	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// NonBlockingPoll polls the given FD in non-blocking fashion. It is used just
// to query the FD's current state.
func NonBlockingPoll(fd int32, mask waiter.EventMask) waiter.EventMask {
	e := struct {
		fd      int32
		events  int16
		revents int16
	}{
		fd:     fd,
		events: int16(mask),
	}

	for {
		n, _, err := syscall.RawSyscall(syscall.SYS_POLL, uintptr(unsafe.Pointer(&e)), 1, 0)
		// Interrupted by signal, try again.
		if err == syscall.EINTR {
			continue
		}
		// If an error occur we'll conservatively say the FD is ready for
		// whatever is being checked.
		if err != 0 {
			return mask
		}

		// If no FDs were returned, it wasn't ready for anything.
		if n == 0 {
			return 0
		}

		// Otherwise we got the ready events in the revents field.
		return waiter.EventMask(e.revents)
	}
}

// epollWait performs a blocking wait on epfd.
//
// Preconditions:
//  * len(events) > 0
func epollWait(epfd int, events []syscall.EpollEvent, msec int) (int, error) {
	if len(events) == 0 {
		panic("Empty events passed to EpollWait")
	}

	// We actually use epoll_pwait with NULL sigmask instead of epoll_wait
	// since that is what the Go >= 1.11 runtime prefers.
	r, _, e := syscall.Syscall6(syscall.SYS_EPOLL_PWAIT, uintptr(epfd), uintptr(unsafe.Pointer(&events[0])), uintptr(len(events)), uintptr(msec), 0, 0)
	if e != 0 {
		return 0, e
	}
	return int(r), nil
}
