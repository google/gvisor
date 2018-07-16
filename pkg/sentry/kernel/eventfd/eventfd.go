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

// Package eventfd provides an implementation of Linux's file-based event
// notification.
package eventfd

import (
	"math"
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/anon"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
	"gvisor.googlesource.com/gvisor/pkg/waiter/fdnotifier"
)

// EventOperations represents an event with the semantics of Linux's file-based event
// notification (eventfd). Eventfds are usually internal to the Sentry but in certain
// situations they may be converted into a host-backed eventfd.
type EventOperations struct {
	fsutil.NoopRelease   `state:"nosave"`
	fsutil.PipeSeek      `state:"nosave"`
	fsutil.NotDirReaddir `state:"nosave"`
	fsutil.NoFsync       `state:"nosave"`
	fsutil.NoopFlush     `state:"nosave"`
	fsutil.NoMMap        `state:"nosave"`
	fsutil.NoIoctl       `state:"nosave"`

	// Mutex that protects accesses to the fields of this event.
	mu sync.Mutex `state:"nosave"`

	// Queue is used to notify interested parties when the event object
	// becomes readable or writable.
	wq waiter.Queue `state:"nosave"`

	// val is the current value of the event counter.
	val uint64

	// semMode specifies whether the event is in "semaphore" mode.
	semMode bool

	// hostfd indicates whether this eventfd is passed through to the host.
	hostfd int
}

// New creates a new event object with the supplied initial value and mode.
func New(ctx context.Context, initVal uint64, semMode bool) *fs.File {
	// name matches fs/eventfd.c:eventfd_file_create.
	dirent := fs.NewDirent(anon.NewInode(ctx), "anon_inode:[eventfd]")
	return fs.NewFile(ctx, dirent, fs.FileFlags{Read: true, Write: true}, &EventOperations{
		val:     initVal,
		semMode: semMode,
		hostfd:  -1,
	})
}

// HostFD returns the host eventfd associated with this event.
func (e *EventOperations) HostFD() (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.hostfd >= 0 {
		return e.hostfd, nil
	}

	flags := linux.EFD_NONBLOCK
	if e.semMode {
		flags |= linux.EFD_SEMAPHORE
	}

	fd, _, err := syscall.Syscall(syscall.SYS_EVENTFD2, uintptr(e.val), uintptr(flags), 0)
	if err != 0 {
		return -1, err
	}

	if err := fdnotifier.AddFD(int32(fd), &e.wq); err != nil {
		syscall.Close(int(fd))
		return -1, err
	}

	e.hostfd = int(fd)
	return e.hostfd, nil
}

// Release implements fs.FileOperations.Release.
func (e *EventOperations) Release() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.hostfd >= 0 {
		fdnotifier.RemoveFD(int32(e.hostfd))
		syscall.Close(e.hostfd)
		e.hostfd = -1
	}
}

// Read implements fs.FileOperations.Read.
func (e *EventOperations) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, _ int64) (int64, error) {
	if dst.NumBytes() < 8 {
		return 0, syscall.EINVAL
	}
	if err := e.read(ctx, dst); err != nil {
		return 0, err
	}
	return 8, nil
}

// Write implements fs.FileOperations.Write.
func (e *EventOperations) Write(ctx context.Context, _ *fs.File, src usermem.IOSequence, _ int64) (int64, error) {
	if src.NumBytes() < 8 {
		return 0, syscall.EINVAL
	}
	if err := e.write(ctx, src); err != nil {
		return 0, err
	}
	return 8, nil
}

// Must be called with e.mu locked.
func (e *EventOperations) hostRead(ctx context.Context, dst usermem.IOSequence) error {
	var buf [8]byte

	if _, err := syscall.Read(e.hostfd, buf[:]); err != nil {
		if err == syscall.EWOULDBLOCK {
			return syserror.ErrWouldBlock
		}
		return err
	}

	_, err := dst.CopyOut(ctx, buf[:])
	return err
}

func (e *EventOperations) read(ctx context.Context, dst usermem.IOSequence) error {
	e.mu.Lock()

	if e.hostfd >= 0 {
		defer e.mu.Unlock()
		return e.hostRead(ctx, dst)
	}

	// We can't complete the read if the value is currently zero.
	if e.val == 0 {
		e.mu.Unlock()
		return syserror.ErrWouldBlock
	}

	// Update the value based on the mode the event is operating in.
	var val uint64
	if e.semMode {
		val = 1
		// Consistent with Linux, this is done even if writing to memory fails.
		e.val--
	} else {
		val = e.val
		e.val = 0
	}

	e.mu.Unlock()

	// Notify writers. We do this even if we were already writable because
	// it is possible that a writer is waiting to write the maximum value
	// to the event.
	e.wq.Notify(waiter.EventOut)

	var buf [8]byte
	usermem.ByteOrder.PutUint64(buf[:], val)
	_, err := dst.CopyOut(ctx, buf[:])
	return err
}

// Must be called with e.mu locked.
func (e *EventOperations) hostWrite(val uint64) error {
	var buf [8]byte
	usermem.ByteOrder.PutUint64(buf[:], val)
	_, err := syscall.Write(e.hostfd, buf[:])
	if err == syscall.EWOULDBLOCK {
		return syserror.ErrWouldBlock
	}
	return err
}

func (e *EventOperations) write(ctx context.Context, src usermem.IOSequence) error {
	var buf [8]byte
	if _, err := src.CopyIn(ctx, buf[:]); err != nil {
		return err
	}
	val := usermem.ByteOrder.Uint64(buf[:])

	return e.Signal(val)
}

// Signal is an internal function to signal the event fd.
func (e *EventOperations) Signal(val uint64) error {
	if val == math.MaxUint64 {
		return syscall.EINVAL
	}

	e.mu.Lock()

	if e.hostfd >= 0 {
		defer e.mu.Unlock()
		return e.hostWrite(val)
	}

	// We only allow writes that won't cause the value to go over the max
	// uint64 minus 1.
	if val > math.MaxUint64-1-e.val {
		e.mu.Unlock()
		return syserror.ErrWouldBlock
	}

	e.val += val
	e.mu.Unlock()

	// Always trigger a notification.
	e.wq.Notify(waiter.EventIn)

	return nil
}

// Readiness returns the ready events for the event fd.
func (e *EventOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	e.mu.Lock()
	if e.hostfd >= 0 {
		defer e.mu.Unlock()
		return fdnotifier.NonBlockingPoll(int32(e.hostfd), mask)
	}

	ready := waiter.EventMask(0)
	if e.val > 0 {
		ready |= waiter.EventIn
	}

	if e.val < math.MaxUint64-1 {
		ready |= waiter.EventOut
	}
	e.mu.Unlock()

	return mask & ready
}

// EventRegister implements waiter.Waitable.EventRegister.
func (e *EventOperations) EventRegister(entry *waiter.Entry, mask waiter.EventMask) {
	e.wq.EventRegister(entry, mask)

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.hostfd >= 0 {
		fdnotifier.UpdateFD(int32(e.hostfd))
	}
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (e *EventOperations) EventUnregister(entry *waiter.Entry) {
	e.wq.EventUnregister(entry)

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.hostfd >= 0 {
		fdnotifier.UpdateFD(int32(e.hostfd))
	}
}
