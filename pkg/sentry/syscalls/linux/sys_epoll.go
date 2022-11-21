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

package linux

import (
	"math"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/waiter"
)

var sizeofEpollEvent = (*linux.EpollEvent)(nil).SizeBytes()

// EpollCreate1 implements Linux syscall epoll_create1(2).
func EpollCreate1(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	flags := args[0].Int()
	if flags&^linux.EPOLL_CLOEXEC != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	file, err := t.Kernel().VFS().NewEpollInstanceFD(t)
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef(t)

	fd, err := t.NewFDFrom(0, file, kernel.FDFlags{
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
		return 0, nil, linuxerr.EINVAL
	}

	file, err := t.Kernel().VFS().NewEpollInstanceFD(t)
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef(t)

	fd, err := t.NewFDFrom(0, file, kernel.FDFlags{})
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

	epfile := t.GetFile(epfd)
	if epfile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer epfile.DecRef(t)
	ep, ok := epfile.Impl().(*vfs.EpollInstance)
	if !ok {
		return 0, nil, linuxerr.EINVAL
	}
	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)
	if epfile == file {
		return 0, nil, linuxerr.EINVAL
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
		return 0, nil, linuxerr.EINVAL
	}
}

func waitEpoll(t *kernel.Task, epfd int32, eventsAddr hostarch.Addr, maxEvents int, timeoutInNanos int64) (uintptr, *kernel.SyscallControl, error) {
	var _EP_MAX_EVENTS = math.MaxInt32 / sizeofEpollEvent // Linux: fs/eventpoll.c:EP_MAX_EVENTS
	if maxEvents <= 0 || maxEvents > _EP_MAX_EVENTS {
		return 0, nil, linuxerr.EINVAL
	}

	epfile := t.GetFile(epfd)
	if epfile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer epfile.DecRef(t)
	ep, ok := epfile.Impl().(*vfs.EpollInstance)
	if !ok {
		return 0, nil, linuxerr.EINVAL
	}

	// Allocate space for a few events on the stack for the common case in
	// which we don't have too many events.
	var (
		eventsArr    [16]linux.EpollEvent
		ch           chan struct{}
		haveDeadline bool
		deadline     ktime.Time
	)
	for {
		events := ep.ReadEvents(eventsArr[:0], maxEvents)
		if len(events) != 0 {
			copiedBytes, err := linux.CopyEpollEventSliceOut(t, eventsAddr, events)
			copiedEvents := copiedBytes / sizeofEpollEvent // rounded down
			if copiedEvents != 0 {
				return uintptr(copiedEvents), nil, nil
			}
			return 0, nil, err
		}
		if timeoutInNanos == 0 {
			return 0, nil, nil
		}
		// In the first iteration of this loop, register with the epoll
		// instance for readability events, but then immediately continue the
		// loop since we need to retry ReadEvents() before blocking. In all
		// subsequent iterations, block until events are available, the timeout
		// expires, or an interrupt arrives.
		if ch == nil {
			var w waiter.Entry
			w, ch = waiter.NewChannelEntry(waiter.ReadableEvents)
			if err := epfile.EventRegister(&w); err != nil {
				return 0, nil, err
			}
			defer epfile.EventUnregister(&w)
		} else {
			// Set up the timer if a timeout was specified.
			if timeoutInNanos > 0 && !haveDeadline {
				timeoutDur := time.Duration(timeoutInNanos) * time.Nanosecond
				deadline = t.Kernel().MonotonicClock().Now().Add(timeoutDur)
				haveDeadline = true
			}
			if err := t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
				if linuxerr.Equals(linuxerr.ETIMEDOUT, err) {
					err = nil
				}
				return 0, nil, err
			}
		}
	}

}

// EpollWait implements Linux syscall epoll_wait(2).
func EpollWait(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	epfd := args[0].Int()
	eventsAddr := args[1].Pointer()
	maxEvents := int(args[2].Int())
	timeoutInNanos := int64(args[3].Int()) * 1000000

	return waitEpoll(t, epfd, eventsAddr, maxEvents, timeoutInNanos)
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

// EpollPwait2 implements Linux syscall epoll_pwait(2).
func EpollPwait2(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	epfd := args[0].Int()
	eventsAddr := args[1].Pointer()
	maxEvents := int(args[2].Int())
	timeoutPtr := args[3].Pointer()
	maskAddr := args[4].Pointer()
	maskSize := uint(args[5].Uint())
	haveTimeout := timeoutPtr != 0

	var timeoutInNanos int64 = -1
	if haveTimeout {
		var timeout linux.Timespec
		if _, err := timeout.CopyIn(t, timeoutPtr); err != nil {
			return 0, nil, err
		}
		timeoutInNanos = timeout.ToNsec()
	}

	if err := setTempSignalSet(t, maskAddr, maskSize); err != nil {
		return 0, nil, err
	}

	return waitEpoll(t, epfd, eventsAddr, maxEvents, timeoutInNanos)
}
