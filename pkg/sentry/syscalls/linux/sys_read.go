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
	// EventMaskRead contains events that can be triggerd on reads.
	EventMaskRead = waiter.EventIn | waiter.EventHUp | waiter.EventErr
)

// Read implements linux syscall read(2).  Note that we try to get a buffer that
// is exactly the size requested because some applications like qemu expect
// they can do large reads all at once.  Bug for bug.  Same for other read
// calls below.
func Read(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	addr := args[1].Pointer()
	size := args[2].SizeT()

	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	// Check that the file is readable.
	if !file.Flags().Read {
		return 0, nil, syserror.EBADF
	}

	// Check that the size is legitimate.
	si := int(size)
	if si < 0 {
		return 0, nil, syserror.EINVAL
	}

	// Get the destination of the read.
	dst, err := t.SingleIOSequence(addr, si, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	n, err := readv(t, file, dst)
	t.IOUsage().AccountReadSyscall(n)
	return uintptr(n), nil, handleIOError(t, n != 0, err, kernel.ERESTARTSYS, "read", file)
}

// Pread64 implements linux syscall pread64(2).
func Pread64(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
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

	// Is reading at an offset supported?
	if !file.Flags().Pread {
		return 0, nil, syserror.ESPIPE
	}

	// Check that the file is readable.
	if !file.Flags().Read {
		return 0, nil, syserror.EBADF
	}

	// Check that the size is legitimate.
	si := int(size)
	if si < 0 {
		return 0, nil, syserror.EINVAL
	}

	// Get the destination of the read.
	dst, err := t.SingleIOSequence(addr, si, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	n, err := preadv(t, file, dst, offset)
	t.IOUsage().AccountReadSyscall(n)
	return uintptr(n), nil, handleIOError(t, n != 0, err, kernel.ERESTARTSYS, "pread64", file)
}

// Readv implements linux syscall readv(2).
func Readv(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := kdefs.FD(args[0].Int())
	addr := args[1].Pointer()
	iovcnt := int(args[2].Int())

	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	// Check that the file is readable.
	if !file.Flags().Read {
		return 0, nil, syserror.EBADF
	}

	// Read the iovecs that specify the destination of the read.
	dst, err := t.IovecsIOSequence(addr, iovcnt, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	n, err := readv(t, file, dst)
	t.IOUsage().AccountReadSyscall(n)
	return uintptr(n), nil, handleIOError(t, n != 0, err, kernel.ERESTARTSYS, "readv", file)
}

// Preadv implements linux syscall preadv(2).
func Preadv(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
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

	// Is reading at an offset supported?
	if !file.Flags().Pread {
		return 0, nil, syserror.ESPIPE
	}

	// Check that the file is readable.
	if !file.Flags().Read {
		return 0, nil, syserror.EBADF
	}

	// Read the iovecs that specify the destination of the read.
	dst, err := t.IovecsIOSequence(addr, iovcnt, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	n, err := preadv(t, file, dst, offset)
	t.IOUsage().AccountReadSyscall(n)
	return uintptr(n), nil, handleIOError(t, n != 0, err, kernel.ERESTARTSYS, "preadv", file)
}

// Preadv2 implements linux syscall preadv2(2).
// TODO: Implement RWF_HIPRI functionality.
func Preadv2(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	// While the syscall is
	// preadv2(int fd, struct iovec* iov, int iov_cnt, off_t offset, int flags)
	// the linux internal call
	// (https://elixir.bootlin.com/linux/v4.18/source/fs/read_write.c#L1248)
	// splits the offset argument into a high/low value for compatibility with
	// 32-bit architectures. The flags argument is the 5th argument.

	fd := kdefs.FD(args[0].Int())
	addr := args[1].Pointer()
	iovcnt := int(args[2].Int())
	offset := args[3].Int64()
	flags := int(args[5].Int())

	file := t.FDMap().GetFile(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	// Check that the offset is legitimate.
	if offset < -1 {
		return 0, nil, syserror.EINVAL
	}

	// Is reading at an offset supported?
	if offset > -1 && !file.Flags().Pread {
		return 0, nil, syserror.ESPIPE
	}

	// Check that the file is readable.
	if !file.Flags().Read {
		return 0, nil, syserror.EBADF
	}

	// Check flags field.
	if flags&^linux.RWF_VALID != 0 {
		return 0, nil, syserror.EOPNOTSUPP
	}

	// Read the iovecs that specify the destination of the read.
	dst, err := t.IovecsIOSequence(addr, iovcnt, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	// If preadv2 is called with an offset of -1, readv is called.
	if offset == -1 {
		n, err := readv(t, file, dst)
		t.IOUsage().AccountReadSyscall(n)
		return uintptr(n), nil, handleIOError(t, n != 0, err, kernel.ERESTARTSYS, "preadv2", file)
	}

	n, err := preadv(t, file, dst, offset)
	t.IOUsage().AccountReadSyscall(n)
	return uintptr(n), nil, handleIOError(t, n != 0, err, kernel.ERESTARTSYS, "preadv2", file)
}

func readv(t *kernel.Task, f *fs.File, dst usermem.IOSequence) (int64, error) {
	n, err := f.Readv(t, dst)
	if err != syserror.ErrWouldBlock || f.Flags().NonBlocking {
		if n > 0 {
			// Queue notification if we read anything.
			f.Dirent.InotifyEvent(linux.IN_ACCESS, 0)
		}
		return n, err
	}

	// Register for notifications.
	w, ch := waiter.NewChannelEntry(nil)
	f.EventRegister(&w, EventMaskRead)

	total := n
	for {
		// Shorten dst to reflect bytes previously read.
		dst = dst.DropFirst64(n)

		// Issue the request and break out if it completes with anything
		// other than "would block".
		n, err = f.Readv(t, dst)
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
		// Queue notification if we read anything.
		f.Dirent.InotifyEvent(linux.IN_ACCESS, 0)
	}

	return total, err
}

func preadv(t *kernel.Task, f *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	n, err := f.Preadv(t, dst, offset)
	if err != syserror.ErrWouldBlock || f.Flags().NonBlocking {
		if n > 0 {
			// Queue notification if we read anything.
			f.Dirent.InotifyEvent(linux.IN_ACCESS, 0)
		}
		return n, err
	}

	// Register for notifications.
	w, ch := waiter.NewChannelEntry(nil)
	f.EventRegister(&w, EventMaskRead)

	total := n
	for {
		// Shorten dst to reflect bytes previously read.
		dst = dst.DropFirst64(n)

		// Issue the request and break out if it completes with anything
		// other than "would block".
		n, err = f.Preadv(t, dst, offset+total)
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
		// Queue notification if we read anything.
		f.Dirent.InotifyEvent(linux.IN_ACCESS, 0)
	}

	return total, err
}
