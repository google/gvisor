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
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// LINT.IfChange

const (
	// EventMaskWrite contains events that can be triggered on writes.
	//
	// Note that EventHUp is not going to happen for pipes but may for
	// implementations of poll on some sockets, see net/core/datagram.c.
	EventMaskWrite = waiter.EventOut | waiter.EventHUp | waiter.EventErr
)

// Write implements linux syscall write(2).
func Write(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	size := args[2].SizeT()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Check that the file is writable.
	if !file.Flags().Write {
		return 0, nil, linuxerr.EBADF
	}

	// Check that the size is legitimate.
	si := int(size)
	if si < 0 {
		return 0, nil, linuxerr.EINVAL
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
	return uintptr(n), nil, handleIOError(t, n != 0, err, syserror.ERESTARTSYS, "write", file)
}

// Pwrite64 implements linux syscall pwrite64(2).
func Pwrite64(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	size := args[2].SizeT()
	offset := args[3].Int64()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Check that the offset is legitimate and does not overflow.
	if offset < 0 || offset+int64(size) < 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Is writing at an offset supported?
	if !file.Flags().Pwrite {
		return 0, nil, syserror.ESPIPE
	}

	// Check that the file is writable.
	if !file.Flags().Write {
		return 0, nil, linuxerr.EBADF
	}

	// Check that the size is legitimate.
	si := int(size)
	if si < 0 {
		return 0, nil, linuxerr.EINVAL
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
	return uintptr(n), nil, handleIOError(t, n != 0, err, syserror.ERESTARTSYS, "pwrite64", file)
}

// Writev implements linux syscall writev(2).
func Writev(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	iovcnt := int(args[2].Int())

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Check that the file is writable.
	if !file.Flags().Write {
		return 0, nil, linuxerr.EBADF
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
	return uintptr(n), nil, handleIOError(t, n != 0, err, syserror.ERESTARTSYS, "writev", file)
}

// Pwritev implements linux syscall pwritev(2).
func Pwritev(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	iovcnt := int(args[2].Int())
	offset := args[3].Int64()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Check that the offset is legitimate.
	if offset < 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Is writing at an offset supported?
	if !file.Flags().Pwrite {
		return 0, nil, syserror.ESPIPE
	}

	// Check that the file is writable.
	if !file.Flags().Write {
		return 0, nil, linuxerr.EBADF
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
	return uintptr(n), nil, handleIOError(t, n != 0, err, syserror.ERESTARTSYS, "pwritev", file)
}

// Pwritev2 implements linux syscall pwritev2(2).
func Pwritev2(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	// While the syscall is
	// pwritev2(int fd, struct iovec* iov, int iov_cnt, off_t offset, int flags)
	// the linux internal call
	// (https://elixir.bootlin.com/linux/v4.18/source/fs/read_write.c#L1354)
	// splits the offset argument into a high/low value for compatibility with
	// 32-bit architectures. The flags argument is the 5th argument.

	fd := args[0].Int()
	addr := args[1].Pointer()
	iovcnt := int(args[2].Int())
	offset := args[3].Int64()
	flags := int(args[5].Int())

	if int(args[4].Int())&0x4 == 1 {
		return 0, nil, linuxerr.EACCES
	}

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Check that the offset is legitimate.
	if offset < -1 {
		return 0, nil, linuxerr.EINVAL
	}

	// Is writing at an offset supported?
	if offset > -1 && !file.Flags().Pwrite {
		return 0, nil, syserror.ESPIPE
	}

	// Note: gVisor does not implement the RWF_HIPRI feature, but the flag is
	// accepted as a valid flag argument for pwritev2.
	if flags&^linux.RWF_VALID != 0 {
		return uintptr(flags), nil, syserror.EOPNOTSUPP
	}

	// Check that the file is writeable.
	if !file.Flags().Write {
		return 0, nil, linuxerr.EBADF
	}

	// Read the iovecs that specify the source of the write.
	src, err := t.IovecsIOSequence(addr, iovcnt, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	// If pwritev2 is called with an offset of -1, writev is called.
	if offset == -1 {
		n, err := writev(t, file, src)
		t.IOUsage().AccountWriteSyscall(n)
		return uintptr(n), nil, handleIOError(t, n != 0, err, syserror.ERESTARTSYS, "pwritev2", file)
	}

	n, err := pwritev(t, file, src, offset)
	t.IOUsage().AccountWriteSyscall(n)
	return uintptr(n), nil, handleIOError(t, n != 0, err, syserror.ERESTARTSYS, "pwritev2", file)
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

	// Sockets support write timeouts.
	var haveDeadline bool
	var deadline ktime.Time
	if s, ok := f.FileOperations.(socket.Socket); ok {
		dl := s.SendTimeout()
		if dl < 0 && err == syserror.ErrWouldBlock {
			return n, err
		}
		if dl > 0 {
			deadline = t.Kernel().MonotonicClock().Now().Add(time.Duration(dl) * time.Nanosecond)
			haveDeadline = true
		}
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
		if err = t.BlockWithDeadline(ch, haveDeadline, deadline); err != nil {
			if linuxerr.Equals(linuxerr.ETIMEDOUT, err) {
				err = syserror.ErrWouldBlock
			}
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

// LINT.ThenChange(vfs2/read_write.go)
