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

// Package eventfd implements event fds.
package eventfd

import (
	"math"
	"sync"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// EventFileDescription implements vfs.FileDescriptionImpl for file-based event
// notification (eventfd). Eventfds are usually internal to the Sentry but in
// certain situations they may be converted into a host-backed eventfd.
//
// +stateify savable
type EventFileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	// queue is used to notify interested parties when the event object
	// becomes readable or writable.
	queue waiter.Queue

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	// val is the current value of the event counter.
	val uint64

	// semMode specifies whether the event is in "semaphore" mode.
	semMode bool

	// hostfd indicates whether this eventfd is passed through to the host.
	hostfd int
}

var _ vfs.FileDescriptionImpl = (*EventFileDescription)(nil)

// New creates a new event fd.
func New(ctx context.Context, vfsObj *vfs.VirtualFilesystem, initVal uint64, semMode bool, flags uint32) (*vfs.FileDescription, error) {
	vd := vfsObj.NewAnonVirtualDentry("[eventfd]")
	defer vd.DecRef(ctx)
	efd := &EventFileDescription{
		val:     initVal,
		semMode: semMode,
		hostfd:  -1,
	}
	if err := efd.vfsfd.Init(efd, flags, vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
	}); err != nil {
		return nil, err
	}
	return &efd.vfsfd, nil
}

// HostFD returns the host eventfd associated with this event.
func (efd *EventFileDescription) HostFD() (int, error) {
	efd.mu.Lock()
	defer efd.mu.Unlock()
	if efd.hostfd >= 0 {
		return efd.hostfd, nil
	}

	flags := linux.EFD_NONBLOCK
	if efd.semMode {
		flags |= linux.EFD_SEMAPHORE
	}

	fd, _, errno := unix.Syscall(unix.SYS_EVENTFD2, uintptr(efd.val), uintptr(flags), 0)
	if errno != 0 {
		return -1, errno
	}

	if err := fdnotifier.AddFD(int32(fd), &efd.queue); err != nil {
		if closeErr := unix.Close(int(fd)); closeErr != nil {
			log.Warningf("close(%d) eventfd failed: %v", fd, closeErr)
		}
		return -1, err
	}

	efd.hostfd = int(fd)
	return efd.hostfd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (efd *EventFileDescription) Release(context.Context) {
	efd.mu.Lock()
	defer efd.mu.Unlock()
	if efd.hostfd >= 0 {
		fdnotifier.RemoveFD(int32(efd.hostfd))
		if closeErr := unix.Close(int(efd.hostfd)); closeErr != nil {
			log.Warningf("close(%d) eventfd failed: %v", efd.hostfd, closeErr)
		}
		efd.hostfd = -1
	}
}

// Read implements vfs.FileDescriptionImpl.Read.
func (efd *EventFileDescription) Read(ctx context.Context, dst usermem.IOSequence, _ vfs.ReadOptions) (int64, error) {
	if dst.NumBytes() < 8 {
		return 0, unix.EINVAL
	}
	if err := efd.read(ctx, dst); err != nil {
		return 0, err
	}
	return 8, nil
}

// Write implements vfs.FileDescriptionImpl.Write.
func (efd *EventFileDescription) Write(ctx context.Context, src usermem.IOSequence, _ vfs.WriteOptions) (int64, error) {
	if src.NumBytes() < 8 {
		return 0, unix.EINVAL
	}
	if err := efd.write(ctx, src); err != nil {
		return 0, err
	}
	return 8, nil
}

// Preconditions: Must be called with efd.mu locked.
func (efd *EventFileDescription) hostReadLocked(ctx context.Context, dst usermem.IOSequence) error {
	var buf [8]byte
	if _, err := unix.Read(efd.hostfd, buf[:]); err != nil {
		if err == unix.EWOULDBLOCK {
			return syserror.ErrWouldBlock
		}
		return err
	}
	_, err := dst.CopyOut(ctx, buf[:])
	return err
}

func (efd *EventFileDescription) read(ctx context.Context, dst usermem.IOSequence) error {
	efd.mu.Lock()
	if efd.hostfd >= 0 {
		defer efd.mu.Unlock()
		return efd.hostReadLocked(ctx, dst)
	}

	// We can't complete the read if the value is currently zero.
	if efd.val == 0 {
		efd.mu.Unlock()
		return syserror.ErrWouldBlock
	}

	// Update the value based on the mode the event is operating in.
	var val uint64
	if efd.semMode {
		val = 1
		// Consistent with Linux, this is done even if writing to memory fails.
		efd.val--
	} else {
		val = efd.val
		efd.val = 0
	}

	efd.mu.Unlock()

	// Notify writers. We do this even if we were already writable because
	// it is possible that a writer is waiting to write the maximum value
	// to the event.
	efd.queue.Notify(waiter.WritableEvents)

	var buf [8]byte
	usermem.ByteOrder.PutUint64(buf[:], val)
	_, err := dst.CopyOut(ctx, buf[:])
	return err
}

// Preconditions: Must be called with efd.mu locked.
func (efd *EventFileDescription) hostWriteLocked(val uint64) error {
	var buf [8]byte
	usermem.ByteOrder.PutUint64(buf[:], val)
	_, err := unix.Write(efd.hostfd, buf[:])
	if err == unix.EWOULDBLOCK {
		return syserror.ErrWouldBlock
	}
	return err
}

func (efd *EventFileDescription) write(ctx context.Context, src usermem.IOSequence) error {
	var buf [8]byte
	if _, err := src.CopyIn(ctx, buf[:]); err != nil {
		return err
	}
	val := usermem.ByteOrder.Uint64(buf[:])

	return efd.Signal(val)
}

// Signal is an internal function to signal the event fd.
func (efd *EventFileDescription) Signal(val uint64) error {
	if val == math.MaxUint64 {
		return unix.EINVAL
	}

	efd.mu.Lock()

	if efd.hostfd >= 0 {
		defer efd.mu.Unlock()
		return efd.hostWriteLocked(val)
	}

	// We only allow writes that won't cause the value to go over the max
	// uint64 minus 1.
	if val > math.MaxUint64-1-efd.val {
		efd.mu.Unlock()
		return syserror.ErrWouldBlock
	}

	efd.val += val
	efd.mu.Unlock()

	// Always trigger a notification.
	efd.queue.Notify(waiter.ReadableEvents)

	return nil
}

// Readiness implements waiter.Waitable.Readiness.
func (efd *EventFileDescription) Readiness(mask waiter.EventMask) waiter.EventMask {
	efd.mu.Lock()
	defer efd.mu.Unlock()

	if efd.hostfd >= 0 {
		return fdnotifier.NonBlockingPoll(int32(efd.hostfd), mask)
	}

	ready := waiter.EventMask(0)
	if efd.val > 0 {
		ready |= waiter.ReadableEvents
	}

	if efd.val < math.MaxUint64-1 {
		ready |= waiter.WritableEvents
	}

	return mask & ready
}

// EventRegister implements waiter.Waitable.EventRegister.
func (efd *EventFileDescription) EventRegister(entry *waiter.Entry, mask waiter.EventMask) {
	efd.queue.EventRegister(entry, mask)

	efd.mu.Lock()
	defer efd.mu.Unlock()
	if efd.hostfd >= 0 {
		fdnotifier.UpdateFD(int32(efd.hostfd))
	}
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (efd *EventFileDescription) EventUnregister(entry *waiter.Entry) {
	efd.queue.EventUnregister(entry)

	efd.mu.Lock()
	defer efd.mu.Unlock()
	if efd.hostfd >= 0 {
		fdnotifier.UpdateFD(int32(efd.hostfd))
	}
}
