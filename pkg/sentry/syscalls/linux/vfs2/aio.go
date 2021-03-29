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

package vfs2

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/eventfd"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	slinux "gvisor.dev/gvisor/pkg/sentry/syscalls/linux"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"

	"gvisor.dev/gvisor/pkg/hostarch"
)

// IoSubmit implements linux syscall io_submit(2).
func IoSubmit(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	id := args[0].Uint64()
	nrEvents := args[1].Int()
	addr := args[2].Pointer()

	if nrEvents < 0 {
		return 0, nil, syserror.EINVAL
	}

	for i := int32(0); i < nrEvents; i++ {
		// Copy in the callback address.
		var cbAddr hostarch.Addr
		switch t.Arch().Width() {
		case 8:
			var cbAddrP primitive.Uint64
			if _, err := cbAddrP.CopyIn(t, addr); err != nil {
				if i > 0 {
					// Some successful.
					return uintptr(i), nil, nil
				}
				// Nothing done.
				return 0, nil, err
			}
			cbAddr = hostarch.Addr(cbAddrP)
		default:
			return 0, nil, syserror.ENOSYS
		}

		// Copy in this callback.
		var cb linux.IOCallback
		if _, err := cb.CopyIn(t, cbAddr); err != nil {
			if i > 0 {
				// Some have been successful.
				return uintptr(i), nil, nil
			}
			// Nothing done.
			return 0, nil, err
		}

		// Process this callback.
		if err := submitCallback(t, id, &cb, cbAddr); err != nil {
			if i > 0 {
				// Partial success.
				return uintptr(i), nil, nil
			}
			// Nothing done.
			return 0, nil, err
		}

		// Advance to the next one.
		addr += hostarch.Addr(t.Arch().Width())
	}

	return uintptr(nrEvents), nil, nil
}

// submitCallback processes a single callback.
func submitCallback(t *kernel.Task, id uint64, cb *linux.IOCallback, cbAddr hostarch.Addr) error {
	if cb.Reserved2 != 0 {
		return syserror.EINVAL
	}

	fd := t.GetFileVFS2(cb.FD)
	if fd == nil {
		return syserror.EBADF
	}
	defer fd.DecRef(t)

	// Was there an eventFD? Extract it.
	var eventFD *vfs.FileDescription
	if cb.Flags&linux.IOCB_FLAG_RESFD != 0 {
		eventFD = t.GetFileVFS2(cb.ResFD)
		if eventFD == nil {
			return syserror.EBADF
		}
		defer eventFD.DecRef(t)

		// Check that it is an eventfd.
		if _, ok := eventFD.Impl().(*eventfd.EventFileDescription); !ok {
			return syserror.EINVAL
		}
	}

	ioseq, err := memoryFor(t, cb)
	if err != nil {
		return err
	}

	// Check offset for reads/writes.
	switch cb.OpCode {
	case linux.IOCB_CMD_PREAD, linux.IOCB_CMD_PREADV, linux.IOCB_CMD_PWRITE, linux.IOCB_CMD_PWRITEV:
		if cb.Offset < 0 {
			return syserror.EINVAL
		}
	}

	// Prepare the request.
	aioCtx, ok := t.MemoryManager().LookupAIOContext(t, id)
	if !ok {
		return syserror.EINVAL
	}
	if err := aioCtx.Prepare(); err != nil {
		return err
	}

	if eventFD != nil {
		// The request is set. Make sure there's a ref on the file.
		//
		// This is necessary when the callback executes on completion,
		// which is also what will release this reference.
		eventFD.IncRef()
	}

	// Perform the request asynchronously.
	fd.IncRef()
	t.QueueAIO(getAIOCallback(t, fd, eventFD, cbAddr, cb, ioseq, aioCtx))
	return nil
}

func getAIOCallback(t *kernel.Task, fd, eventFD *vfs.FileDescription, cbAddr hostarch.Addr, cb *linux.IOCallback, ioseq usermem.IOSequence, aioCtx *mm.AIOContext) kernel.AIOCallback {
	return func(ctx context.Context) {
		// Release references after completing the callback.
		defer fd.DecRef(ctx)
		if eventFD != nil {
			defer eventFD.DecRef(ctx)
		}

		if aioCtx.Dead() {
			aioCtx.CancelPendingRequest()
			return
		}
		ev := &linux.IOEvent{
			Data: cb.Data,
			Obj:  uint64(cbAddr),
		}

		var err error
		switch cb.OpCode {
		case linux.IOCB_CMD_PREAD, linux.IOCB_CMD_PREADV:
			ev.Result, err = fd.PRead(ctx, ioseq, cb.Offset, vfs.ReadOptions{})
		case linux.IOCB_CMD_PWRITE, linux.IOCB_CMD_PWRITEV:
			ev.Result, err = fd.PWrite(ctx, ioseq, cb.Offset, vfs.WriteOptions{})
		case linux.IOCB_CMD_FSYNC, linux.IOCB_CMD_FDSYNC:
			err = fd.Sync(ctx)
		}

		// Update the result.
		if err != nil {
			err = slinux.HandleIOErrorVFS2(ctx, ev.Result != 0 /* partial */, err, nil /* never interrupted */, "aio", fd)
			ev.Result = -int64(kernel.ExtractErrno(err, 0))
		}

		// Queue the result for delivery.
		aioCtx.FinishRequest(ev)

		// Notify the event file if one was specified. This needs to happen
		// *after* queueing the result to avoid racing with the thread we may
		// wake up.
		if eventFD != nil {
			eventFD.Impl().(*eventfd.EventFileDescription).Signal(1)
		}
	}
}

// memoryFor returns appropriate memory for the given callback.
func memoryFor(t *kernel.Task, cb *linux.IOCallback) (usermem.IOSequence, error) {
	bytes := int(cb.Bytes)
	if bytes < 0 {
		// Linux also requires that this field fit in ssize_t.
		return usermem.IOSequence{}, syserror.EINVAL
	}

	// Since this I/O will be asynchronous with respect to t's task goroutine,
	// we have no guarantee that t's AddressSpace will be active during the
	// I/O.
	switch cb.OpCode {
	case linux.IOCB_CMD_PREAD, linux.IOCB_CMD_PWRITE:
		return t.SingleIOSequence(hostarch.Addr(cb.Buf), bytes, usermem.IOOpts{
			AddressSpaceActive: false,
		})

	case linux.IOCB_CMD_PREADV, linux.IOCB_CMD_PWRITEV:
		return t.IovecsIOSequence(hostarch.Addr(cb.Buf), bytes, usermem.IOOpts{
			AddressSpaceActive: false,
		})

	case linux.IOCB_CMD_FSYNC, linux.IOCB_CMD_FDSYNC, linux.IOCB_CMD_NOOP:
		return usermem.IOSequence{}, nil

	default:
		// Not a supported command.
		return usermem.IOSequence{}, syserror.EINVAL
	}
}
