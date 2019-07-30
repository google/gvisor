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
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/epoll"
	"gvisor.dev/gvisor/pkg/sentry/syscalls"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"
)

// EpollCreate1 implements the epoll_create1(2) linux syscall.
func EpollCreate1(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	flags := args[0].Int()
	if flags & ^linux.EPOLL_CLOEXEC != 0 {
		return 0, nil, syserror.EINVAL
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
		return 0, nil, syserror.EINVAL
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
		if _, err := t.CopyIn(eventAddr, &e); err != nil {
			return 0, nil, err
		}

		if e.Events&linux.EPOLLONESHOT != 0 {
			flags |= epoll.OneShot
		}

		if e.Events&linux.EPOLLET != 0 {
			flags |= epoll.EdgeTriggered
		}

		mask = waiter.EventMaskFromLinux(e.Events)
		data[0] = e.Fd
		data[1] = e.Data
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
		return 0, nil, syserror.EINVAL
	}
}

// copyOutEvents copies epoll events from the kernel to user memory.
func copyOutEvents(t *kernel.Task, addr usermem.Addr, e []epoll.Event) error {
	const itemLen = 12
	buffLen := len(e) * itemLen
	if _, ok := addr.AddLength(uint64(buffLen)); !ok {
		return syserror.EFAULT
	}

	b := t.CopyScratchBuffer(buffLen)
	for i := range e {
		usermem.ByteOrder.PutUint32(b[i*itemLen:], e[i].Events)
		usermem.ByteOrder.PutUint32(b[i*itemLen+4:], uint32(e[i].Data[0]))
		usermem.ByteOrder.PutUint32(b[i*itemLen+8:], uint32(e[i].Data[1]))
	}

	if _, err := t.CopyOutBytes(addr, b); err != nil {
		return err
	}

	return nil
}

// EpollWait implements the epoll_wait(2) linux syscall.
func EpollWait(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	epfd := args[0].Int()
	eventsAddr := args[1].Pointer()
	maxEvents := int(args[2].Int())
	timeout := int(args[3].Int())

	r, err := syscalls.WaitEpoll(t, epfd, maxEvents, timeout)
	if err != nil {
		return 0, nil, syserror.ConvertIntr(err, syserror.EINTR)
	}

	if len(r) != 0 {
		if err := copyOutEvents(t, eventsAddr, r); err != nil {
			return 0, nil, err
		}
	}

	return uintptr(len(r)), nil, nil
}

// EpollPwait implements the epoll_pwait(2) linux syscall.
func EpollPwait(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	maskAddr := args[4].Pointer()
	maskSize := uint(args[5].Uint())

	if maskAddr != 0 {
		mask, err := copyInSigSet(t, maskAddr, maskSize)
		if err != nil {
			return 0, nil, err
		}

		oldmask := t.SignalMask()
		t.SetSignalMask(mask)
		t.SetSavedSignalMask(oldmask)
	}

	return EpollWait(t, args)
}
