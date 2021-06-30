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

package syscalls

import (
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/epoll"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/waiter"
)

// CreateEpoll implements the epoll_create(2) linux syscall.
func CreateEpoll(t *kernel.Task, closeOnExec bool) (int32, error) {
	file := epoll.NewEventPoll(t)
	defer file.DecRef(t)

	fd, err := t.NewFDFrom(0, file, kernel.FDFlags{
		CloseOnExec: closeOnExec,
	})
	if err != nil {
		return 0, err
	}

	return fd, nil
}

// AddEpoll implements the epoll_ctl(2) linux syscall when op is EPOLL_CTL_ADD.
func AddEpoll(t *kernel.Task, epfd int32, fd int32, flags epoll.EntryFlags, mask waiter.EventMask, userData [2]int32) error {
	// Get epoll from the file descriptor.
	epollfile := t.GetFile(epfd)
	if epollfile == nil {
		return linuxerr.EBADF
	}
	defer epollfile.DecRef(t)

	// Get the target file id.
	file := t.GetFile(fd)
	if file == nil {
		return linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Extract the epollPoll operations.
	e, ok := epollfile.FileOperations.(*epoll.EventPoll)
	if !ok {
		return linuxerr.EBADF
	}

	// Try to add the entry.
	return e.AddEntry(epoll.FileIdentifier{file, fd}, flags, mask, userData)
}

// UpdateEpoll implements the epoll_ctl(2) linux syscall when op is EPOLL_CTL_MOD.
func UpdateEpoll(t *kernel.Task, epfd int32, fd int32, flags epoll.EntryFlags, mask waiter.EventMask, userData [2]int32) error {
	// Get epoll from the file descriptor.
	epollfile := t.GetFile(epfd)
	if epollfile == nil {
		return linuxerr.EBADF
	}
	defer epollfile.DecRef(t)

	// Get the target file id.
	file := t.GetFile(fd)
	if file == nil {
		return linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Extract the epollPoll operations.
	e, ok := epollfile.FileOperations.(*epoll.EventPoll)
	if !ok {
		return linuxerr.EBADF
	}

	// Try to update the entry.
	return e.UpdateEntry(epoll.FileIdentifier{file, fd}, flags, mask, userData)
}

// RemoveEpoll implements the epoll_ctl(2) linux syscall when op is EPOLL_CTL_DEL.
func RemoveEpoll(t *kernel.Task, epfd int32, fd int32) error {
	// Get epoll from the file descriptor.
	epollfile := t.GetFile(epfd)
	if epollfile == nil {
		return linuxerr.EBADF
	}
	defer epollfile.DecRef(t)

	// Get the target file id.
	file := t.GetFile(fd)
	if file == nil {
		return linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Extract the epollPoll operations.
	e, ok := epollfile.FileOperations.(*epoll.EventPoll)
	if !ok {
		return linuxerr.EBADF
	}

	// Try to remove the entry.
	return e.RemoveEntry(t, epoll.FileIdentifier{file, fd})
}

// WaitEpoll implements the epoll_wait(2) linux syscall.
func WaitEpoll(t *kernel.Task, fd int32, max int, timeoutInNanos int64) ([]linux.EpollEvent, error) {
	// Get epoll from the file descriptor.
	epollfile := t.GetFile(fd)
	if epollfile == nil {
		return nil, linuxerr.EBADF
	}
	defer epollfile.DecRef(t)

	// Extract the epollPoll operations.
	e, ok := epollfile.FileOperations.(*epoll.EventPoll)
	if !ok {
		return nil, linuxerr.EBADF
	}

	// Try to read events and return right away if we got them or if the
	// caller requested a non-blocking "wait".
	r := e.ReadEvents(max)
	if len(r) != 0 || timeoutInNanos == 0 {
		return r, nil
	}

	// We'll have to wait. Set up the timer if a timeout was specified and
	// and register with the epoll object for readability events.
	var haveDeadline bool
	var deadline ktime.Time
	if timeoutInNanos > 0 {
		timeoutDur := time.Duration(timeoutInNanos) * time.Nanosecond
		deadline = t.Kernel().MonotonicClock().Now().Add(timeoutDur)
		haveDeadline = true
	}

	w, ch := waiter.NewChannelEntry(nil)
	e.EventRegister(&w, waiter.ReadableEvents)
	defer e.EventUnregister(&w)

	// Try to read the events again until we succeed, timeout or get
	// interrupted.
	for {
		r = e.ReadEvents(max)
		if len(r) != 0 {
			return r, nil
		}

		if err := t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
			if linuxerr.Equals(linuxerr.ETIMEDOUT, err) {
				return nil, nil
			}

			return nil, err
		}
	}
}
