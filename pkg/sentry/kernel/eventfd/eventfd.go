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

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/anon"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// EventOperations represents an event with the semantics of Linux's file-based event
// notification (eventfd).
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
	waiter.Queue `state:"nosave"`

	// val is the current value of the event counter.
	val uint64

	// semMode specifies whether the event is in "semaphore" mode.
	semMode bool
}

// New creates a new event object with the supplied initial value and mode.
func New(ctx context.Context, initVal uint64, semMode bool) *fs.File {
	// name matches fs/eventfd.c:eventfd_file_create.
	dirent := fs.NewDirent(anon.NewInode(ctx), "anon_inode:[eventfd]")
	return fs.NewFile(ctx, dirent, fs.FileFlags{Read: true, Write: true}, &EventOperations{
		val:     initVal,
		semMode: semMode,
	})
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

func (e *EventOperations) read(ctx context.Context, dst usermem.IOSequence) error {
	e.mu.Lock()

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
	e.Notify(waiter.EventOut)

	var buf [8]byte
	usermem.ByteOrder.PutUint64(buf[:], val)
	_, err := dst.CopyOut(ctx, buf[:])
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

	// We only allow writes that won't cause the value to go over the max
	// uint64 minus 1.
	if val > math.MaxUint64-1-e.val {
		e.mu.Unlock()
		return syserror.ErrWouldBlock
	}

	e.val += val
	e.mu.Unlock()

	// Always trigger a notification.
	e.Notify(waiter.EventIn)

	return nil
}

// Readiness returns the ready events for the event fd.
func (e *EventOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	ready := waiter.EventMask(0)

	e.mu.Lock()
	if e.val > 0 {
		ready |= waiter.EventIn
	}

	if e.val < math.MaxUint64-1 {
		ready |= waiter.EventOut
	}
	e.mu.Unlock()

	return mask & ready
}
