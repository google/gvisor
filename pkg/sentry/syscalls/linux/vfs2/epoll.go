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

package vfs2

import (
	"math"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

var sizeofEpollEvent = (*linux.EpollEvent)(nil).SizeBytes()

// EpollCreate1 implements Linux syscall epoll_create1(2).
func EpollCreate1(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	flags := args[0].Int()
	if flags&^linux.EPOLL_CLOEXEC != 0 {
		return 0, nil, syserror.EINVAL
	}

	file, err := t.Kernel().VFS().NewEpollInstanceFD()
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef()

	fd, err := t.NewFDFromVFS2(0, file, kernel.FDFlags{
		CloseOnExec: flags&linux.EPOLL_CLOEXEC != 0,
	})
	if err != nil {
		return 0, nil, err
	}
	return uintptr(fd), nil, nil
}

// EpollCreate implements Linux syscall epoll_create(2).
func EpollCreate(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	size := args[0].Int()

	// "Since Linux 2.6.8, the size argument is ignored, but must be greater
	// than zero" - epoll_create(2)
	if size <= 0 {
		return 0, nil, syserror.EINVAL
	}

	file, err := t.Kernel().VFS().NewEpollInstanceFD()
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef()

	fd, err := t.NewFDFromVFS2(0, file, kernel.FDFlags{})
	if err != nil {
		return 0, nil, err
	}
	return uintptr(fd), nil, nil
}

// EpollCtl implements Linux syscall epoll_ctl(2).
func EpollCtl(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	epfd := args[0].Int()
	op := args[1].Int()
	fd := args[2].Int()
	eventAddr := args[3].Pointer()

	epfile := t.GetFileVFS2(epfd)
	if epfile == nil {
		return 0, nil, syserror.EBADF
	}
	defer epfile.DecRef()
	ep, ok := epfile.Impl().(*vfs.EpollInstance)
	if !ok {
		return 0, nil, syserror.EINVAL
	}
	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()
	if epfile == file {
		return 0, nil, syserror.EINVAL
	}

	var event linux.EpollEvent
	switch op {
	case linux.EPOLL_CTL_ADD:
		if _, err := event.CopyIn(t, eventAddr); err != nil {
			return 0, nil, err
		}
		return 0, nil, ep.AddInterest(file, fd, event)
	case linux.EPOLL_CTL_DEL:
		return 0, nil, ep.DeleteInterest(file, fd)
	case linux.EPOLL_CTL_MOD:
		if _, err := event.CopyIn(t, eventAddr); err != nil {
			return 0, nil, err
		}
		return 0, nil, ep.ModifyInterest(file, fd, event)
	default:
		return 0, nil, syserror.EINVAL
	}
}

// EpollWait implements Linux syscall epoll_wait(2).
func EpollWait(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	epfd := args[0].Int()
	eventsAddr := args[1].Pointer()
	maxEvents := int(args[2].Int())
	timeout := int(args[3].Int())

	var _EP_MAX_EVENTS = math.MaxInt32 / sizeofEpollEvent // Linux: fs/eventpoll.c:EP_MAX_EVENTS
	if maxEvents <= 0 || maxEvents > _EP_MAX_EVENTS {
		return 0, nil, syserror.EINVAL
	}

	epfile := t.GetFileVFS2(epfd)
	if epfile == nil {
		return 0, nil, syserror.EBADF
	}
	defer epfile.DecRef()
	ep, ok := epfile.Impl().(*vfs.EpollInstance)
	if !ok {
		return 0, nil, syserror.EINVAL
	}

	// Use a fixed-size buffer in a loop, instead of make([]linux.EpollEvent,
	// maxEvents), so that the buffer can be allocated on the stack.
	var (
		events       [16]linux.EpollEvent
		total        int
		ch           chan struct{}
		haveDeadline bool
		deadline     ktime.Time
	)
	for {
		batchEvents := len(events)
		if batchEvents > maxEvents {
			batchEvents = maxEvents
		}
		n := ep.ReadEvents(events[:batchEvents])
		maxEvents -= n
		if n != 0 {
			// Copy what we read out.
			copiedBytes, err := linux.CopyEpollEventSliceOut(t, eventsAddr, events[:n])
			copiedEvents := copiedBytes / sizeofEpollEvent // rounded down
			eventsAddr += usermem.Addr(copiedEvents * sizeofEpollEvent)
			total += copiedEvents
			if err != nil {
				if total != 0 {
					return uintptr(total), nil, nil
				}
				return 0, nil, err
			}
			// If we've filled the application's event buffer, we're done.
			if maxEvents == 0 {
				return uintptr(total), nil, nil
			}
			// Loop if we read a full batch, under the expectation that there
			// may be more events to read.
			if n == batchEvents {
				continue
			}
		}
		// We get here if n != batchEvents. If we read any number of events
		// (just now, or in a previous iteration of this loop), or if timeout
		// is 0 (such that epoll_wait should be non-blocking), return the
		// events we've read so far to the application.
		if total != 0 || timeout == 0 {
			return uintptr(total), nil, nil
		}
		// In the first iteration of this loop, register with the epoll
		// instance for readability events, but then immediately continue the
		// loop since we need to retry ReadEvents() before blocking. In all
		// subsequent iterations, block until events are available, the timeout
		// expires, or an interrupt arrives.
		if ch == nil {
			var w waiter.Entry
			w, ch = waiter.NewChannelEntry(nil)
			epfile.EventRegister(&w, waiter.EventIn)
			defer epfile.EventUnregister(&w)
		} else {
			// Set up the timer if a timeout was specified.
			if timeout > 0 && !haveDeadline {
				timeoutDur := time.Duration(timeout) * time.Millisecond
				deadline = t.Kernel().MonotonicClock().Now().Add(timeoutDur)
				haveDeadline = true
			}
			if err := t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
				if err == syserror.ETIMEDOUT {
					err = nil
				}
				// total must be 0 since otherwise we would have returned
				// above.
				return 0, nil, err
			}
		}
	}
}

// EpollPwait implements Linux syscall epoll_pwait(2).
func EpollPwait(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	maskAddr := args[4].Pointer()
	maskSize := uint(args[5].Uint())

	if err := setTempSignalSet(t, maskAddr, maskSize); err != nil {
		return 0, nil, err
	}

	return EpollWait(t, args)
}
