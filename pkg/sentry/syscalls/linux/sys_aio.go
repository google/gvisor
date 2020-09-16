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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/eventfd"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// IoSetup implements linux syscall io_setup(2).
func IoSetup(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	nrEvents := args[0].Int()
	idAddr := args[1].Pointer()

	// Linux uses the native long as the aio ID.
	//
	// The context pointer _must_ be zero initially.
	var idIn uint64
	if _, err := primitive.CopyUint64In(t, idAddr, &idIn); err != nil {
		return 0, nil, err
	}
	if idIn != 0 {
		return 0, nil, syserror.EINVAL
	}

	id, err := t.MemoryManager().NewAIOContext(t, uint32(nrEvents))
	if err != nil {
		return 0, nil, err
	}

	// Copy out the new ID.
	if _, err := primitive.CopyUint64Out(t, idAddr, id); err != nil {
		t.MemoryManager().DestroyAIOContext(t, id)
		return 0, nil, err
	}

	return 0, nil, nil
}

// IoDestroy implements linux syscall io_destroy(2).
func IoDestroy(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	id := args[0].Uint64()

	ctx := t.MemoryManager().DestroyAIOContext(t, id)
	if ctx == nil {
		// Does not exist.
		return 0, nil, syserror.EINVAL
	}

	// Drain completed requests amd wait for pending requests until there are no
	// more.
	for {
		ctx.Drain()

		ch := ctx.WaitChannel()
		if ch == nil {
			// No more requests, we're done.
			return 0, nil, nil
		}
		// The task cannot be interrupted during the wait. Equivalent to
		// TASK_UNINTERRUPTIBLE in Linux.
		t.UninterruptibleSleepStart(true /* deactivate */)
		<-ch
		t.UninterruptibleSleepFinish(true /* activate */)
	}
}

// IoGetevents implements linux syscall io_getevents(2).
func IoGetevents(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	id := args[0].Uint64()
	minEvents := args[1].Int()
	events := args[2].Int()
	eventsAddr := args[3].Pointer()
	timespecAddr := args[4].Pointer()

	// Sanity check arguments.
	if minEvents < 0 || minEvents > events {
		return 0, nil, syserror.EINVAL
	}

	ctx, ok := t.MemoryManager().LookupAIOContext(t, id)
	if !ok {
		return 0, nil, syserror.EINVAL
	}

	// Setup the timeout.
	var haveDeadline bool
	var deadline ktime.Time
	if timespecAddr != 0 {
		d, err := copyTimespecIn(t, timespecAddr)
		if err != nil {
			return 0, nil, err
		}
		if !d.Valid() {
			return 0, nil, syserror.EINVAL
		}
		deadline = t.Kernel().MonotonicClock().Now().Add(d.ToDuration())
		haveDeadline = true
	}

	// Loop over all requests.
	for count := int32(0); count < events; count++ {
		// Get a request, per semantics.
		var v interface{}
		if count >= minEvents {
			var ok bool
			v, ok = ctx.PopRequest()
			if !ok {
				return uintptr(count), nil, nil
			}
		} else {
			var err error
			v, err = waitForRequest(ctx, t, haveDeadline, deadline)
			if err != nil {
				if count > 0 || err == syserror.ETIMEDOUT {
					return uintptr(count), nil, nil
				}
				return 0, nil, syserror.ConvertIntr(err, syserror.EINTR)
			}
		}

		ev := v.(*linux.IOEvent)

		// Copy out the result.
		if _, err := ev.CopyOut(t, eventsAddr); err != nil {
			if count > 0 {
				return uintptr(count), nil, nil
			}
			// Nothing done.
			return 0, nil, err
		}

		// Keep rolling.
		eventsAddr += usermem.Addr(linux.IOEventSize)
	}

	// Everything finished.
	return uintptr(events), nil, nil
}

func waitForRequest(ctx *mm.AIOContext, t *kernel.Task, haveDeadline bool, deadline ktime.Time) (interface{}, error) {
	for {
		if v, ok := ctx.PopRequest(); ok {
			// Request was readily available. Just return it.
			return v, nil
		}

		// Need to wait for request completion.
		done := ctx.WaitChannel()
		if done == nil {
			// Context has been destroyed.
			return nil, syserror.EINVAL
		}
		if err := t.BlockWithDeadline(done, haveDeadline, deadline); err != nil {
			return nil, err
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
		return t.SingleIOSequence(usermem.Addr(cb.Buf), bytes, usermem.IOOpts{
			AddressSpaceActive: false,
		})

	case linux.IOCB_CMD_PREADV, linux.IOCB_CMD_PWRITEV:
		return t.IovecsIOSequence(usermem.Addr(cb.Buf), bytes, usermem.IOOpts{
			AddressSpaceActive: false,
		})

	case linux.IOCB_CMD_FSYNC, linux.IOCB_CMD_FDSYNC, linux.IOCB_CMD_NOOP:
		return usermem.IOSequence{}, nil

	default:
		// Not a supported command.
		return usermem.IOSequence{}, syserror.EINVAL
	}
}

// IoCancel implements linux syscall io_cancel(2).
//
// It is not presently supported (ENOSYS indicates no support on this
// architecture).
func IoCancel(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, syserror.ENOSYS
}

// LINT.IfChange

func getAIOCallback(t *kernel.Task, file *fs.File, cbAddr usermem.Addr, cb *linux.IOCallback, ioseq usermem.IOSequence, actx *mm.AIOContext, eventFile *fs.File) kernel.AIOCallback {
	return func(ctx context.Context) {
		if actx.Dead() {
			actx.CancelPendingRequest()
			return
		}
		ev := &linux.IOEvent{
			Data: cb.Data,
			Obj:  uint64(cbAddr),
		}

		var err error
		switch cb.OpCode {
		case linux.IOCB_CMD_PREAD, linux.IOCB_CMD_PREADV:
			ev.Result, err = file.Preadv(ctx, ioseq, cb.Offset)
		case linux.IOCB_CMD_PWRITE, linux.IOCB_CMD_PWRITEV:
			ev.Result, err = file.Pwritev(ctx, ioseq, cb.Offset)
		case linux.IOCB_CMD_FSYNC:
			err = file.Fsync(ctx, 0, fs.FileMaxOffset, fs.SyncAll)
		case linux.IOCB_CMD_FDSYNC:
			err = file.Fsync(ctx, 0, fs.FileMaxOffset, fs.SyncData)
		}

		// Update the result.
		if err != nil {
			err = handleIOError(t, ev.Result != 0 /* partial */, err, nil /* never interrupted */, "aio", file)
			ev.Result = -int64(kernel.ExtractErrno(err, 0))
		}

		file.DecRef(ctx)

		// Queue the result for delivery.
		actx.FinishRequest(ev)

		// Notify the event file if one was specified. This needs to happen
		// *after* queueing the result to avoid racing with the thread we may
		// wake up.
		if eventFile != nil {
			eventFile.FileOperations.(*eventfd.EventOperations).Signal(1)
			eventFile.DecRef(ctx)
		}
	}
}

// submitCallback processes a single callback.
func submitCallback(t *kernel.Task, id uint64, cb *linux.IOCallback, cbAddr usermem.Addr) error {
	file := t.GetFile(cb.FD)
	if file == nil {
		// File not found.
		return syserror.EBADF
	}
	defer file.DecRef(t)

	// Was there an eventFD? Extract it.
	var eventFile *fs.File
	if cb.Flags&linux.IOCB_FLAG_RESFD != 0 {
		eventFile = t.GetFile(cb.ResFD)
		if eventFile == nil {
			// Bad FD.
			return syserror.EBADF
		}
		defer eventFile.DecRef(t)

		// Check that it is an eventfd.
		if _, ok := eventFile.FileOperations.(*eventfd.EventOperations); !ok {
			// Not an event FD.
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
	ctx, ok := t.MemoryManager().LookupAIOContext(t, id)
	if !ok {
		return syserror.EINVAL
	}
	if ready := ctx.Prepare(); !ready {
		// Context is busy.
		return syserror.EAGAIN
	}

	if eventFile != nil {
		// The request is set. Make sure there's a ref on the file.
		//
		// This is necessary when the callback executes on completion,
		// which is also what will release this reference.
		eventFile.IncRef()
	}

	// Perform the request asynchronously.
	file.IncRef()
	t.QueueAIO(getAIOCallback(t, file, cbAddr, cb, ioseq, ctx, eventFile))

	// All set.
	return nil
}

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
		var cbAddr usermem.Addr
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
			cbAddr = usermem.Addr(cbAddrP)
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
		addr += usermem.Addr(t.Arch().Width())
	}

	return uintptr(nrEvents), nil, nil
}

// LINT.ThenChange(vfs2/aio.go)
