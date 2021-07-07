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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/epoll"
	"gvisor.dev/gvisor/pkg/sentry/syscalls"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/waiter"
)

// LINT.IfChange

// EpollCreate1 implements the epoll_create1(2) linux syscall.
func EpollCreate1(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	flags := args[0].Int()
	if flags & ^linux.EPOLL_CLOEXEC != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	closeOnExec := flags&linux.EPOLL_CLOEXEC != 0
	fd, err := syscalls.CreateEpoll(t, closeOnExec)
	if err != nil {
		return 0, nil, err
	}

	return uintptr(fd), nil, nil
}

// EpollCreate implements the epoll_create(2) linux syscall.
func EpollCreate(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	size := args[0].Int()

	if size <= 0 {
		return 0, nil, linuxerr.EINVAL
	}

	fd, err := syscalls.CreateEpoll(t, false)
	if err != nil {
		return 0, nil, err
	}

	return uintptr(fd), nil, nil
}

// EpollCtl implements the epoll_ctl(2) linux syscall.
func EpollCtl(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	epfd := args[0].Int()
	op := args[1].Int()
	fd := args[2].Int()
	eventAddr := args[3].Pointer()

	// Capture the event state if needed.
	flags := epoll.EntryFlags(0)
	mask := waiter.EventMask(0)
	var data [2]int32
	if op != linux.EPOLL_CTL_DEL {
		var e linux.EpollEvent
		if _, err := e.CopyIn(t, eventAddr); err != nil {
			return 0, nil, err
		}

		if e.Events&linux.EPOLLONESHOT != 0 {
			flags |= epoll.OneShot
		}

		if e.Events&linux.EPOLLET != 0 {
			flags |= epoll.EdgeTriggered
		}

		mask = waiter.EventMaskFromLinux(e.Events)
		data = e.Data
	}

	// Perform the requested operations.
	switch op {
	case linux.EPOLL_CTL_ADD:
		// See fs/eventpoll.c.
		mask |= waiter.EventHUp | waiter.EventErr
		return 0, nil, syscalls.AddEpoll(t, epfd, fd, flags, mask, data)
	case linux.EPOLL_CTL_DEL:
		return 0, nil, syscalls.RemoveEpoll(t, epfd, fd)
	case linux.EPOLL_CTL_MOD:
		// Same as EPOLL_CTL_ADD.
		mask |= waiter.EventHUp | waiter.EventErr
		return 0, nil, syscalls.UpdateEpoll(t, epfd, fd, flags, mask, data)
	default:
		return 0, nil, linuxerr.EINVAL
	}
}

func waitEpoll(t *kernel.Task, fd int32, eventsAddr hostarch.Addr, max int, timeoutInNanos int64) (uintptr, *kernel.SyscallControl, error) {
	r, err := syscalls.WaitEpoll(t, fd, max, timeoutInNanos)
	if err != nil {
		return 0, nil, syserr.ConvertIntr(err, linuxerr.EINTR)
	}

	if len(r) != 0 {
		if _, err := linux.CopyEpollEventSliceOut(t, eventsAddr, r); err != nil {
			return 0, nil, err
		}
	}

	return uintptr(len(r)), nil, nil

}

// EpollWait implements the epoll_wait(2) linux syscall.
func EpollWait(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	epfd := args[0].Int()
	eventsAddr := args[1].Pointer()
	maxEvents := int(args[2].Int())
	// Convert milliseconds to nanoseconds.
	timeoutInNanos := int64(args[3].Int()) * 1000000
	return waitEpoll(t, epfd, eventsAddr, maxEvents, timeoutInNanos)
}

// EpollPwait implements the epoll_pwait(2) linux syscall.
func EpollPwait(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	maskAddr := args[4].Pointer()
	maskSize := uint(args[5].Uint())

	if maskAddr != 0 {
		mask, err := CopyInSigSet(t, maskAddr, maskSize)
		if err != nil {
			return 0, nil, err
		}

		oldmask := t.SignalMask()
		t.SetSignalMask(mask)
		t.SetSavedSignalMask(oldmask)
	}

	return EpollWait(t, args)
}

// EpollPwait2 implements the epoll_pwait(2) linux syscall.
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
		timeout, err := copyTimespecIn(t, timeoutPtr)
		if err != nil {
			return 0, nil, err
		}
		timeoutInNanos = timeout.ToNsec()

	}

	if maskAddr != 0 {
		mask, err := CopyInSigSet(t, maskAddr, maskSize)
		if err != nil {
			return 0, nil, err
		}

		oldmask := t.SignalMask()
		t.SetSignalMask(mask)
		t.SetSavedSignalMask(oldmask)
	}

	return waitEpoll(t, epfd, eventsAddr, maxEvents, timeoutInNanos)
}

// LINT.ThenChange(vfs2/epoll.go)
