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

package linux

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

const (
	// EventMaskWrite contains events that can be triggered on writes.
	//
	// Note that EventHUp is not going to happen for pipes but may for
	// implementations of poll on some sockets, see net/core/datagram.c.
	EventMaskWrite = waiter.EventOut | waiter.EventHUp | waiter.EventErr
)

// Write implements linux syscall write(2).
func Write(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	addr := args[1].Pointer()
	size := args[2].SizeT()

	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	// Check that the file is writable.
	if !file.Flags().Write {
		return 0, nil, syserror.EBADF
	}

	// Check that the size is legitimate.
	si := int(size)
	if si < 0 {
		return 0, nil, syserror.EINVAL
	}

	// Get the source of the write.
	src, err := t.SingleIOSequence(addr, si, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	n, err := writev(t, file, src)
	t.IOUsage().AccountWriteSyscall(n)
	return uintptr(n), nil, handleIOError(t, n != 0, err, kernel.ERESTARTSYS, "write", file)
}

// Pwrite64 implements linux syscall pwrite64(2).
func Pwrite64(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	addr := args[1].Pointer()
	size := args[2].SizeT()
	offset := args[3].Int64()

	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	// Check that the offset is legitimate.
	if offset < 0 {
		return 0, nil, syserror.EINVAL
	}

	// Is writing at an offset supported?
	if !file.Flags().Pwrite {
		return 0, nil, syserror.ESPIPE
	}

	// Check that the file is writable.
	if !file.Flags().Write {
		return 0, nil, syserror.EBADF
	}

	// Check that the size is legitimate.
	si := int(size)
	if si < 0 {
		return 0, nil, syserror.EINVAL
	}

	// Get the source of the write.
	src, err := t.SingleIOSequence(addr, si, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	n, err := pwritev(t, file, src, offset)
	t.IOUsage().AccountWriteSyscall(n)
	return uintptr(n), nil, handleIOError(t, n != 0, err, kernel.ERESTARTSYS, "pwrite64", file)
}

// Writev implements linux syscall writev(2).
func Writev(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	addr := args[1].Pointer()
	iovcnt := int(args[2].Int())

	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	// Check that the file is writable.
	if !file.Flags().Write {
		return 0, nil, syserror.EBADF
	}

	// Read the iovecs that specify the source of the write.
	src, err := t.IovecsIOSequence(addr, iovcnt, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	n, err := writev(t, file, src)
	t.IOUsage().AccountWriteSyscall(n)
	return uintptr(n), nil, handleIOError(t, n != 0, err, kernel.ERESTARTSYS, "writev", file)
}

// Pwritev implements linux syscall pwritev(2).
func Pwritev(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	addr := args[1].Pointer()
	iovcnt := int(args[2].Int())
	offset := args[3].Int64()

	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	// Check that the offset is legitimate.
	if offset < 0 {
		return 0, nil, syserror.EINVAL
	}

	// Is writing at an offset supported?
	if !file.Flags().Pwrite {
		return 0, nil, syserror.ESPIPE
	}

	// Check that the file is writable.
	if !file.Flags().Write {
		return 0, nil, syserror.EBADF
	}

	// Read the iovecs that specify the source of the write.
	src, err := t.IovecsIOSequence(addr, iovcnt, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	n, err := pwritev(t, file, src, offset)
	t.IOUsage().AccountWriteSyscall(n)
	return uintptr(n), nil, handleIOError(t, n != 0, err, kernel.ERESTARTSYS, "pwritev", file)
}

func writev(t *kernel.Task, f *fs.File, src usermem.IOSequence) (int64, error) {
	n, err := f.Writev(t, src)
	if err != syserror.ErrWouldBlock || f.Flags().NonBlocking {
		if n > 0 {
			// Queue notification if we wrote anything.
			f.Dirent.InotifyEvent(linux.IN_MODIFY, 0)
		}
		return n, err
	}

	// Register for notifications.
	w, ch := waiter.NewChannelEntry(nil)
	f.EventRegister(&w, EventMaskWrite)

	total := n
	for {
		// Shorten src to reflect bytes previously written.
		src = src.DropFirst64(n)

		// Issue the request and break out if it completes with
		// anything other than "would block".
		n, err = f.Writev(t, src)
		total += n
		if err != syserror.ErrWouldBlock {
			break
		}

		// Wait for a notification that we should retry.
		if err = t.Block(ch); err != nil {
			break
		}
	}

	f.EventUnregister(&w)

	if total > 0 {
		// Queue notification if we wrote anything.
		f.Dirent.InotifyEvent(linux.IN_MODIFY, 0)
	}

	return total, err
}

func pwritev(t *kernel.Task, f *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
	n, err := f.Pwritev(t, src, offset)
	if err != syserror.ErrWouldBlock || f.Flags().NonBlocking {
		if n > 0 {
			// Queue notification if we wrote anything.
			f.Dirent.InotifyEvent(linux.IN_MODIFY, 0)
		}
		return n, err
	}

	// Register for notifications.
	w, ch := waiter.NewChannelEntry(nil)
	f.EventRegister(&w, EventMaskWrite)

	total := n
	for {
		// Shorten src to reflect bytes previously written.
		src = src.DropFirst64(n)

		// Issue the request and break out if it completes with
		// anything other than "would block".
		n, err = f.Pwritev(t, src, offset+total)
		total += n
		if err != syserror.ErrWouldBlock {
			break
		}

		// Wait for a notification that we should retry.
		if err = t.Block(ch); err != nil {
			break
		}
	}

	f.EventUnregister(&w)

	if total > 0 {
		// Queue notification if we wrote anything.
		f.Dirent.InotifyEvent(linux.IN_MODIFY, 0)
	}

	return total, err
}
