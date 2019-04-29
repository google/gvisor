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
	"encoding/binary"

	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/eventfd"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/mm"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// I/O commands.
const (
	_IOCB_CMD_PREAD   = 0
	_IOCB_CMD_PWRITE  = 1
	_IOCB_CMD_FSYNC   = 2
	_IOCB_CMD_FDSYNC  = 3
	_IOCB_CMD_NOOP    = 6
	_IOCB_CMD_PREADV  = 7
	_IOCB_CMD_PWRITEV = 8
)

// I/O flags.
const (
	_IOCB_FLAG_RESFD = 1
)

// ioCallback describes an I/O request.
//
// The priority field is currently ignored in the implementation below. Also
// note that the IOCB_FLAG_RESFD feature is not supported.
type ioCallback struct {
	Data      uint64
	Key       uint32
	Reserved1 uint32

	OpCode  uint16
	ReqPrio int16
	FD      uint32

	Buf    uint64
	Bytes  uint64
	Offset int64

	Reserved2 uint64
	Flags     uint32

	// eventfd to signal if IOCB_FLAG_RESFD is set in flags.
	ResFD uint32
}

// ioEvent describes an I/O result.
//
// +stateify savable
type ioEvent struct {
	Data    uint64
	Obj     uint64
	Result  int64
	Result2 int64
}

// ioEventSize is the size of an ioEvent encoded.
var ioEventSize = binary.Size(ioEvent{})

// IoSetup implements linux syscall io_setup(2).
func IoSetup(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	nrEvents := args[0].Int()
	idAddr := args[1].Pointer()

	// Linux uses the native long as the aio ID.
	//
	// The context pointer _must_ be zero initially.
	var idIn uint64
	if _, err := t.CopyIn(idAddr, &idIn); err != nil {
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
	if _, err := t.CopyOut(idAddr, &id); err != nil {
		t.MemoryManager().DestroyAIOContext(t, id)
		return 0, nil, err
	}

	return 0, nil, nil
}

// IoDestroy implements linux syscall io_destroy(2).
func IoDestroy(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	id := args[0].Uint64()

	// Destroy the given context.
	if !t.MemoryManager().DestroyAIOContext(t, id) {
		// Does not exist.
		return 0, nil, syserror.EINVAL
	}
	// FIXME(fvoznika): Linux blocks until all AIO to the destroyed context is
	// done.
	return 0, nil, nil
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

		ev := v.(*ioEvent)

		// Copy out the result.
		if _, err := t.CopyOut(eventsAddr, ev); err != nil {
			if count > 0 {
				return uintptr(count), nil, nil
			}
			// Nothing done.
			return 0, nil, err
		}

		// Keep rolling.
		eventsAddr += usermem.Addr(ioEventSize)
	}

	// Everything finished.
	return uintptr(events), nil, nil
}

func waitForRequest(ctx *mm.AIOContext, t *kernel.Task, haveDeadline bool, deadline ktime.Time) (interface{}, error) {
	for {
		if v, ok := ctx.PopRequest(); ok {
			// Request was readly available. Just return it.
			return v, nil
		}

		// Need to wait for request completion.
		done, active := ctx.WaitChannel()
		if !active {
			// Context has been destroyed.
			return nil, syserror.EINVAL
		}
		if err := t.BlockWithDeadline(done, haveDeadline, deadline); err != nil {
			return nil, err
		}
	}
}

// memoryFor returns appropriate memory for the given callback.
func memoryFor(t *kernel.Task, cb *ioCallback) (usermem.IOSequence, error) {
	bytes := int(cb.Bytes)
	if bytes < 0 {
		// Linux also requires that this field fit in ssize_t.
		return usermem.IOSequence{}, syserror.EINVAL
	}

	// Since this I/O will be asynchronous with respect to t's task goroutine,
	// we have no guarantee that t's AddressSpace will be active during the
	// I/O.
	switch cb.OpCode {
	case _IOCB_CMD_PREAD, _IOCB_CMD_PWRITE:
		return t.SingleIOSequence(usermem.Addr(cb.Buf), bytes, usermem.IOOpts{
			AddressSpaceActive: false,
		})

	case _IOCB_CMD_PREADV, _IOCB_CMD_PWRITEV:
		return t.IovecsIOSequence(usermem.Addr(cb.Buf), bytes, usermem.IOOpts{
			AddressSpaceActive: false,
		})

	case _IOCB_CMD_FSYNC, _IOCB_CMD_FDSYNC, _IOCB_CMD_NOOP:
		return usermem.IOSequence{}, nil

	default:
		// Not a supported command.
		return usermem.IOSequence{}, syserror.EINVAL
	}
}

func performCallback(t *kernel.Task, file *fs.File, cbAddr usermem.Addr, cb *ioCallback, ioseq usermem.IOSequence, ctx *mm.AIOContext, eventFile *fs.File) {
	ev := &ioEvent{
		Data: cb.Data,
		Obj:  uint64(cbAddr),
	}

	// Construct a context.Context that will not be interrupted if t is
	// interrupted.
	c := t.AsyncContext()

	var err error
	switch cb.OpCode {
	case _IOCB_CMD_PREAD, _IOCB_CMD_PREADV:
		ev.Result, err = file.Preadv(c, ioseq, cb.Offset)
	case _IOCB_CMD_PWRITE, _IOCB_CMD_PWRITEV:
		ev.Result, err = file.Pwritev(c, ioseq, cb.Offset)
	case _IOCB_CMD_FSYNC:
		err = file.Fsync(c, 0, fs.FileMaxOffset, fs.SyncAll)
	case _IOCB_CMD_FDSYNC:
		err = file.Fsync(c, 0, fs.FileMaxOffset, fs.SyncData)
	}

	// Update the result.
	if err != nil {
		err = handleIOError(t, ev.Result != 0 /* partial */, err, nil /* never interrupted */, "aio", file)
		ev.Result = -int64(t.ExtractErrno(err, 0))
	}

	file.DecRef()

	// Queue the result for delivery.
	ctx.FinishRequest(ev)

	// Notify the event file if one was specified. This needs to happen
	// *after* queueing the result to avoid racing with the thread we may
	// wake up.
	if eventFile != nil {
		eventFile.FileOperations.(*eventfd.EventOperations).Signal(1)
		eventFile.DecRef()
	}
}

// submitCallback processes a single callback.
func submitCallback(t *kernel.Task, id uint64, cb *ioCallback, cbAddr usermem.Addr) error {
	file := t.FDMap().GetFile(kdefs.FD(cb.FD))
	if file == nil {
		// File not found.
		return syserror.EBADF
	}
	defer file.DecRef()

	// Was there an eventFD? Extract it.
	var eventFile *fs.File
	if cb.Flags&_IOCB_FLAG_RESFD != 0 {
		eventFile = t.FDMap().GetFile(kdefs.FD(cb.ResFD))
		if eventFile == nil {
			// Bad FD.
			return syserror.EBADF
		}
		defer eventFile.DecRef()

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
	case _IOCB_CMD_PREAD, _IOCB_CMD_PREADV, _IOCB_CMD_PWRITE, _IOCB_CMD_PWRITEV:
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
	fs.Async(func() { performCallback(t, file, cbAddr, cb, ioseq, ctx, eventFile) })

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
		// Copy in the address.
		cbAddrNative := t.Arch().Native(0)
		if _, err := t.CopyIn(addr, cbAddrNative); err != nil {
			if i > 0 {
				// Some successful.
				return uintptr(i), nil, nil
			}
			// Nothing done.
			return 0, nil, err
		}

		// Copy in this callback.
		var cb ioCallback
		cbAddr := usermem.Addr(t.Arch().Value(cbAddrNative))
		if _, err := t.CopyIn(cbAddr, &cb); err != nil {

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

// IoCancel implements linux syscall io_cancel(2).
//
// It is not presently supported (ENOSYS indicates no support on this
// architecture).
func IoCancel(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, syserror.ENOSYS
}
