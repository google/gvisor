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
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	slinux "gvisor.dev/gvisor/pkg/sentry/syscalls/linux"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	eventMaskRead  = waiter.EventRdNorm | waiter.EventIn | waiter.EventHUp | waiter.EventErr
	eventMaskWrite = waiter.EventWrNorm | waiter.EventOut | waiter.EventHUp | waiter.EventErr
)

// Read implements Linux syscall read(2).
func Read(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	size := args[2].SizeT()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Check that the size is legitimate.
	si := int(size)
	if si < 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Get the destination of the read.
	dst, err := t.SingleIOSequence(addr, si, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	n, err := read(t, file, dst, vfs.ReadOptions{})
	t.IOUsage().AccountReadSyscall(n)
	return uintptr(n), nil, slinux.HandleIOErrorVFS2(t, n != 0, err, linuxerr.ERESTARTSYS, "read", file)
}

// Readv implements Linux syscall readv(2).
func Readv(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	iovcnt := int(args[2].Int())

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Get the destination of the read.
	dst, err := t.IovecsIOSequence(addr, iovcnt, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	n, err := read(t, file, dst, vfs.ReadOptions{})
	t.IOUsage().AccountReadSyscall(n)
	return uintptr(n), nil, slinux.HandleIOErrorVFS2(t, n != 0, err, linuxerr.ERESTARTSYS, "readv", file)
}

func read(t *kernel.Task, file *vfs.FileDescription, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	n, err := file.Read(t, dst, opts)
	if err != linuxerr.ErrWouldBlock {
		return n, err
	}

	allowBlock, deadline, hasDeadline := blockPolicy(t, file)
	if !allowBlock {
		return n, err
	}

	// Register for notifications.
	w, ch := waiter.NewChannelEntry(eventMaskRead)
	if err := file.EventRegister(&w); err != nil {
		return n, err
	}

	total := n
	for {
		// Shorten dst to reflect bytes previously read.
		dst = dst.DropFirst(int(n))

		// Issue the request and break out if it completes with anything other than
		// "would block".
		n, err = file.Read(t, dst, opts)
		total += n
		if err != linuxerr.ErrWouldBlock {
			break
		}

		// Wait for a notification that we should retry.
		if err = t.BlockWithDeadline(ch, hasDeadline, deadline); err != nil {
			if linuxerr.Equals(linuxerr.ETIMEDOUT, err) {
				err = linuxerr.ErrWouldBlock
			}
			break
		}
	}
	file.EventUnregister(&w)

	return total, err
}

// Pread64 implements Linux syscall pread64(2).
func Pread64(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	size := args[2].SizeT()
	offset := args[3].Int64()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Check that the offset is legitimate and does not overflow.
	if offset < 0 || offset+int64(size) < 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Check that the size is legitimate.
	si := int(size)
	if si < 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Get the destination of the read.
	dst, err := t.SingleIOSequence(addr, si, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	n, err := pread(t, file, dst, offset, vfs.ReadOptions{})
	t.IOUsage().AccountReadSyscall(n)
	return uintptr(n), nil, slinux.HandleIOErrorVFS2(t, n != 0, err, linuxerr.ERESTARTSYS, "pread64", file)
}

// Preadv implements Linux syscall preadv(2).
func Preadv(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	iovcnt := int(args[2].Int())
	offset := args[3].Int64()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Check that the offset is legitimate.
	if offset < 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Get the destination of the read.
	dst, err := t.IovecsIOSequence(addr, iovcnt, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	n, err := pread(t, file, dst, offset, vfs.ReadOptions{})
	t.IOUsage().AccountReadSyscall(n)
	return uintptr(n), nil, slinux.HandleIOErrorVFS2(t, n != 0, err, linuxerr.ERESTARTSYS, "preadv", file)
}

// Preadv2 implements Linux syscall preadv2(2).
func Preadv2(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	// While the glibc signature is
	// preadv2(int fd, struct iovec* iov, int iov_cnt, off_t offset, int flags)
	// the actual syscall
	// (https://elixir.bootlin.com/linux/v5.5/source/fs/read_write.c#L1142)
	// splits the offset argument into a high/low value for compatibility with
	// 32-bit architectures. The flags argument is the 6th argument (index 5).
	fd := args[0].Int()
	addr := args[1].Pointer()
	iovcnt := int(args[2].Int())
	offset := args[3].Int64()
	flags := args[5].Int()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Check that the offset is legitimate.
	if offset < -1 {
		return 0, nil, linuxerr.EINVAL
	}

	// Get the destination of the read.
	dst, err := t.IovecsIOSequence(addr, iovcnt, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	opts := vfs.ReadOptions{
		Flags: uint32(flags),
	}
	var n int64
	if offset == -1 {
		n, err = read(t, file, dst, opts)
	} else {
		n, err = pread(t, file, dst, offset, opts)
	}
	t.IOUsage().AccountReadSyscall(n)
	return uintptr(n), nil, slinux.HandleIOErrorVFS2(t, n != 0, err, linuxerr.ERESTARTSYS, "preadv2", file)
}

func pread(t *kernel.Task, file *vfs.FileDescription, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	n, err := file.PRead(t, dst, offset, opts)
	if err != linuxerr.ErrWouldBlock {
		return n, err
	}

	allowBlock, deadline, hasDeadline := blockPolicy(t, file)
	if !allowBlock {
		return n, err
	}

	// Register for notifications.
	w, ch := waiter.NewChannelEntry(eventMaskRead)
	if err := file.EventRegister(&w); err != nil {
		return n, err
	}
	total := n
	for {
		// Shorten dst to reflect bytes previously read.
		dst = dst.DropFirst(int(n))

		// Issue the request and break out if it completes with anything other than
		// "would block".
		n, err = file.PRead(t, dst, offset+total, opts)
		total += n
		if err != linuxerr.ErrWouldBlock {
			break
		}

		// Wait for a notification that we should retry.
		if err = t.BlockWithDeadline(ch, hasDeadline, deadline); err != nil {
			if linuxerr.Equals(linuxerr.ETIMEDOUT, err) {
				err = linuxerr.ErrWouldBlock
			}
			break
		}
	}
	file.EventUnregister(&w)
	return total, err
}

// Write implements Linux syscall write(2).
func Write(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	size := args[2].SizeT()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

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

	n, err := write(t, file, src, vfs.WriteOptions{})
	t.IOUsage().AccountWriteSyscall(n)
	return uintptr(n), nil, slinux.HandleIOErrorVFS2(t, n != 0, err, linuxerr.ERESTARTSYS, "write", file)
}

// Writev implements Linux syscall writev(2).
func Writev(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	iovcnt := int(args[2].Int())

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Get the source of the write.
	src, err := t.IovecsIOSequence(addr, iovcnt, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	n, err := write(t, file, src, vfs.WriteOptions{})
	t.IOUsage().AccountWriteSyscall(n)
	return uintptr(n), nil, slinux.HandleIOErrorVFS2(t, n != 0, err, linuxerr.ERESTARTSYS, "writev", file)
}

func write(t *kernel.Task, file *vfs.FileDescription, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	n, err := file.Write(t, src, opts)
	if err != linuxerr.ErrWouldBlock {
		return n, err
	}

	allowBlock, deadline, hasDeadline := blockPolicy(t, file)
	if !allowBlock {
		return n, err
	}

	// Register for notifications.
	w, ch := waiter.NewChannelEntry(eventMaskWrite)
	if err := file.EventRegister(&w); err != nil {
		return n, err
	}

	total := n
	for {
		// Shorten src to reflect bytes previously written.
		src = src.DropFirst(int(n))

		// Issue the request and break out if it completes with anything other than
		// "would block".
		n, err = file.Write(t, src, opts)
		total += n
		if err != linuxerr.ErrWouldBlock {
			break
		}

		// Wait for a notification that we should retry.
		if err = t.BlockWithDeadline(ch, hasDeadline, deadline); err != nil {
			if linuxerr.Equals(linuxerr.ETIMEDOUT, err) {
				err = linuxerr.ErrWouldBlock
			}
			break
		}
	}
	file.EventUnregister(&w)
	return total, err
}

// Pwrite64 implements Linux syscall pwrite64(2).
func Pwrite64(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	size := args[2].SizeT()
	offset := args[3].Int64()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Check that the offset is legitimate and does not overflow.
	if offset < 0 || offset+int64(size) < 0 {
		return 0, nil, linuxerr.EINVAL
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

	n, err := pwrite(t, file, src, offset, vfs.WriteOptions{})
	t.IOUsage().AccountWriteSyscall(n)
	return uintptr(n), nil, slinux.HandleIOErrorVFS2(t, n != 0, err, linuxerr.ERESTARTSYS, "pwrite64", file)
}

// Pwritev implements Linux syscall pwritev(2).
func Pwritev(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	iovcnt := int(args[2].Int())
	offset := args[3].Int64()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Check that the offset is legitimate.
	if offset < 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Get the source of the write.
	src, err := t.IovecsIOSequence(addr, iovcnt, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	n, err := pwrite(t, file, src, offset, vfs.WriteOptions{})
	t.IOUsage().AccountReadSyscall(n)
	return uintptr(n), nil, slinux.HandleIOErrorVFS2(t, n != 0, err, linuxerr.ERESTARTSYS, "pwritev", file)
}

// Pwritev2 implements Linux syscall pwritev2(2).
func Pwritev2(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	// While the glibc signature is
	// pwritev2(int fd, struct iovec* iov, int iov_cnt, off_t offset, int flags)
	// the actual syscall
	// (https://elixir.bootlin.com/linux/v5.5/source/fs/read_write.c#L1162)
	// splits the offset argument into a high/low value for compatibility with
	// 32-bit architectures. The flags argument is the 6th argument (index 5).
	fd := args[0].Int()
	addr := args[1].Pointer()
	iovcnt := int(args[2].Int())
	offset := args[3].Int64()
	flags := args[5].Int()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Check that the offset is legitimate.
	if offset < -1 {
		return 0, nil, linuxerr.EINVAL
	}

	// Get the source of the write.
	src, err := t.IovecsIOSequence(addr, iovcnt, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, nil, err
	}

	opts := vfs.WriteOptions{
		Flags: uint32(flags),
	}
	var n int64
	if offset == -1 {
		n, err = write(t, file, src, opts)
	} else {
		n, err = pwrite(t, file, src, offset, opts)
	}
	t.IOUsage().AccountWriteSyscall(n)
	return uintptr(n), nil, slinux.HandleIOErrorVFS2(t, n != 0, err, linuxerr.ERESTARTSYS, "pwritev2", file)
}

func pwrite(t *kernel.Task, file *vfs.FileDescription, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	n, err := file.PWrite(t, src, offset, opts)
	if err != linuxerr.ErrWouldBlock {
		return n, err
	}

	allowBlock, deadline, hasDeadline := blockPolicy(t, file)
	if !allowBlock {
		return n, err
	}

	// Register for notifications.
	w, ch := waiter.NewChannelEntry(eventMaskWrite)
	if err := file.EventRegister(&w); err != nil {
		return n, err
	}

	total := n
	for {
		// Shorten src to reflect bytes previously written.
		src = src.DropFirst(int(n))

		// Issue the request and break out if it completes with anything other than
		// "would block".
		n, err = file.PWrite(t, src, offset+total, opts)
		total += n
		if err != linuxerr.ErrWouldBlock {
			break
		}

		// Wait for a notification that we should retry.
		if err = t.BlockWithDeadline(ch, hasDeadline, deadline); err != nil {
			if linuxerr.Equals(linuxerr.ETIMEDOUT, err) {
				err = linuxerr.ErrWouldBlock
			}
			break
		}
	}
	file.EventUnregister(&w)
	return total, err
}

func blockPolicy(t *kernel.Task, file *vfs.FileDescription) (allowBlock bool, deadline ktime.Time, hasDeadline bool) {
	if file.StatusFlags()&linux.O_NONBLOCK != 0 {
		return false, ktime.Time{}, false
	}
	// Sockets support read/write timeouts.
	if s, ok := file.Impl().(socket.SocketVFS2); ok {
		dl := s.RecvTimeout()
		if dl < 0 {
			return false, ktime.Time{}, false
		}
		if dl > 0 {
			return true, t.Kernel().MonotonicClock().Now().Add(time.Duration(dl) * time.Nanosecond), true
		}
	}
	return true, ktime.Time{}, false
}

// Lseek implements Linux syscall lseek(2).
func Lseek(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	offset := args[1].Int64()
	whence := args[2].Int()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	newoff, err := file.Seek(t, offset, whence)
	return uintptr(newoff), nil, err
}

// Readahead implements readahead(2).
func Readahead(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	offset := args[1].Int64()
	size := args[2].SizeT()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// Check that the file is readable.
	if !file.IsReadable() {
		return 0, nil, linuxerr.EBADF
	}

	// Check that the size is valid.
	if int(size) < 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Check that the offset is legitimate and does not overflow.
	if offset < 0 || offset+int64(size) < 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Return EINVAL; if the underlying file type does not support readahead,
	// then Linux will return EINVAL to indicate as much. In the future, we
	// may extend this function to actually support readahead hints.
	return 0, nil, linuxerr.EINVAL
}
