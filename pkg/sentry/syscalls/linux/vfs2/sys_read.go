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
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/syscalls/linux"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Read implements linux syscall read(2).  Note that we try to get a buffer that
// is exactly the size requested because some applications like qemu expect
// they can do large reads all at once.  Bug for bug.  Same for other read
// calls below.
func Read(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	size := args[2].SizeT()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef()

	// Check that the file is readable.
	if !file.IsReadable() {
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

	n, err := read(t, file, dst, vfs.ReadOptions{})
	t.IOUsage().AccountReadSyscall(n)
	return uintptr(n), nil, linux.HandleIOErrorVFS2(t, n != 0, err, kernel.ERESTARTSYS, "read", file)
}

func read(t *kernel.Task, file *vfs.FileDescription, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	n, err := file.Read(t, dst, opts)
	if err != syserror.ErrWouldBlock {
		return n, err
	}

	// Register for notifications.
	_, ch := waiter.NewChannelEntry(nil)
	// file.EventRegister(&w, EventMaskRead)

	total := n
	for {
		// Shorten dst to reflect bytes previously read.
		dst = dst.DropFirst(int(n))

		// Issue the request and break out if it completes with anything other than
		// "would block".
		n, err := file.Read(t, dst, opts)
		total += n
		if err != syserror.ErrWouldBlock {
			break
		}
		if err := t.Block(ch); err != nil {
			break
		}
	}
	//file.EventUnregister(&w)

	return total, err
}
