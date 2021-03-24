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

package fs

import (
	"io"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/uniqueid"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Inotify represents an inotify instance created by inotify_init(2) or
// inotify_init1(2). Inotify implements the FileOperations interface.
//
// Lock ordering:
//   Inotify.mu -> Inode.Watches.mu -> Watch.mu -> Inotify.evMu
//
// +stateify savable
type Inotify struct {
	// Unique identifier for this inotify instance. We don't just reuse the
	// inotify fd because fds can be duped. These should not be exposed to the
	// user, since we may aggressively reuse an id on S/R.
	id uint64

	waiter.Queue `state:"nosave"`

	// evMu *only* protects the events list. We need a separate lock because
	// while queuing events, a watch needs to lock the event queue, and using mu
	// for that would violate lock ordering since at that point the calling
	// goroutine already holds Watch.target.Watches.mu.
	evMu sync.Mutex `state:"nosave"`

	// A list of pending events for this inotify instance. Protected by evMu.
	events eventList

	// A scratch buffer, use to serialize inotify events. Use allocate this
	// ahead of time and reuse performance. Protected by evMu.
	scratch []byte

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	// The next watch descriptor number to use for this inotify instance. Note
	// that Linux starts numbering watch descriptors from 1.
	nextWatch int32

	// Map from watch descriptors to watch objects.
	watches map[int32]*Watch
}

// NewInotify constructs a new Inotify instance.
func NewInotify(ctx context.Context) *Inotify {
	return &Inotify{
		id:        uniqueid.GlobalFromContext(ctx),
		scratch:   make([]byte, inotifyEventBaseSize),
		nextWatch: 1, // Linux starts numbering watch descriptors from 1.
		watches:   make(map[int32]*Watch),
	}
}

// Release implements FileOperations.Release. Release removes all watches and
// frees all resources for an inotify instance.
func (i *Inotify) Release(ctx context.Context) {
	// We need to hold i.mu to avoid a race with concurrent calls to
	// Inotify.targetDestroyed from Watches. There's no risk of Watches
	// accessing this Inotify after the destructor ends, because we remove all
	// references to it below.
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, w := range i.watches {
		// Remove references to the watch from the watch target. We don't need
		// to worry about the references from the owner instance, since we're in
		// the owner's destructor.
		w.target.Watches.Remove(w.ID())
		// Don't leak any references to the target, held by pins in the watch.
		w.destroy(ctx)
	}
}

// Readiness implements waiter.Waitable.Readiness.
//
// Readiness indicates whether there are pending events for an inotify instance.
func (i *Inotify) Readiness(mask waiter.EventMask) waiter.EventMask {
	ready := waiter.EventMask(0)

	i.evMu.Lock()
	defer i.evMu.Unlock()

	if !i.events.Empty() {
		ready |= waiter.ReadableEvents
	}

	return mask & ready
}

// Seek implements FileOperations.Seek.
func (*Inotify) Seek(context.Context, *File, SeekWhence, int64) (int64, error) {
	return 0, syserror.ESPIPE
}

// Readdir implements FileOperatons.Readdir.
func (*Inotify) Readdir(context.Context, *File, DentrySerializer) (int64, error) {
	return 0, syserror.ENOTDIR
}

// Write implements FileOperations.Write.
func (*Inotify) Write(context.Context, *File, usermem.IOSequence, int64) (int64, error) {
	return 0, syserror.EBADF
}

// Read implements FileOperations.Read.
func (i *Inotify) Read(ctx context.Context, _ *File, dst usermem.IOSequence, _ int64) (int64, error) {
	if dst.NumBytes() < inotifyEventBaseSize {
		return 0, syserror.EINVAL
	}

	i.evMu.Lock()
	defer i.evMu.Unlock()

	if i.events.Empty() {
		// Nothing to read yet, tell caller to block.
		return 0, syserror.ErrWouldBlock
	}

	var writeLen int64
	for it := i.events.Front(); it != nil; {
		event := it
		it = it.Next()

		// Does the buffer have enough remaining space to hold the event we're
		// about to write out?
		if dst.NumBytes() < int64(event.sizeOf()) {
			if writeLen > 0 {
				// Buffer wasn't big enough for all pending events, but we did
				// write some events out.
				return writeLen, nil
			}
			return 0, syserror.EINVAL
		}

		// Linux always dequeues an available event as long as there's enough
		// buffer space to copy it out, even if the copy below fails. Emulate
		// this behaviour.
		i.events.Remove(event)

		// Buffer has enough space, copy event to the read buffer.
		n, err := event.CopyTo(ctx, i.scratch, dst)
		if err != nil {
			return 0, err
		}

		writeLen += n
		dst = dst.DropFirst64(n)
	}
	return writeLen, nil
}

// WriteTo implements FileOperations.WriteTo.
func (*Inotify) WriteTo(context.Context, *File, io.Writer, int64, bool) (int64, error) {
	return 0, syserror.ENOSYS
}

// Fsync implements FileOperations.Fsync.
func (*Inotify) Fsync(context.Context, *File, int64, int64, SyncType) error {
	return syserror.EINVAL
}

// ReadFrom implements FileOperations.ReadFrom.
func (*Inotify) ReadFrom(context.Context, *File, io.Reader, int64) (int64, error) {
	return 0, syserror.ENOSYS
}

// Flush implements FileOperations.Flush.
func (*Inotify) Flush(context.Context, *File) error {
	return nil
}

// ConfigureMMap implements FileOperations.ConfigureMMap.
func (*Inotify) ConfigureMMap(context.Context, *File, *memmap.MMapOpts) error {
	return syserror.ENODEV
}

// UnstableAttr implements FileOperations.UnstableAttr.
func (i *Inotify) UnstableAttr(ctx context.Context, file *File) (UnstableAttr, error) {
	return file.Dirent.Inode.UnstableAttr(ctx)
}

// Ioctl implements fs.FileOperations.Ioctl.
func (i *Inotify) Ioctl(ctx context.Context, _ *File, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	switch args[1].Int() {
	case linux.FIONREAD:
		i.evMu.Lock()
		defer i.evMu.Unlock()
		var n uint32
		for e := i.events.Front(); e != nil; e = e.Next() {
			n += uint32(e.sizeOf())
		}
		var buf [4]byte
		usermem.ByteOrder.PutUint32(buf[:], n)
		_, err := io.CopyOut(ctx, args[2].Pointer(), buf[:], usermem.IOOpts{})
		return 0, err

	default:
		return 0, syserror.ENOTTY
	}
}

func (i *Inotify) queueEvent(ev *Event) {
	i.evMu.Lock()

	// Check if we should coalesce the event we're about to queue with the last
	// one currently in the queue. Events are coalesced if they are identical.
	if last := i.events.Back(); last != nil {
		if ev.equals(last) {
			// "Coalesce" the two events by simply not queuing the new one. We
			// don't need to raise a waiter.EventIn notification because no new
			// data is available for reading.
			i.evMu.Unlock()
			return
		}
	}

	i.events.PushBack(ev)

	// Release mutex before notifying waiters because we don't control what they
	// can do.
	i.evMu.Unlock()

	i.Queue.Notify(waiter.ReadableEvents)
}

// newWatchLocked creates and adds a new watch to target.
func (i *Inotify) newWatchLocked(target *Dirent, mask uint32) *Watch {
	wd := i.nextWatch
	i.nextWatch++

	watch := &Watch{
		owner:  i,
		wd:     wd,
		mask:   mask,
		target: target.Inode,
		pins:   make(map[*Dirent]bool),
	}

	i.watches[wd] = watch

	// Grab an extra reference to target to prevent it from being evicted from
	// memory. This ref is dropped during either watch removal, target
	// destruction, or inotify instance destruction. See callers of Watch.Unpin.
	watch.Pin(target)
	target.Inode.Watches.Add(watch)

	return watch
}

// targetDestroyed is called by w to notify i that w's target is gone. This
// automatically generates a watch removal event.
func (i *Inotify) targetDestroyed(w *Watch) {
	i.mu.Lock()
	_, found := i.watches[w.wd]
	delete(i.watches, w.wd)
	i.mu.Unlock()

	if found {
		i.queueEvent(newEvent(w.wd, "", linux.IN_IGNORED, 0))
	}
}

// AddWatch constructs a new inotify watch and adds it to the target dirent. It
// returns the watch descriptor returned by inotify_add_watch(2).
func (i *Inotify) AddWatch(target *Dirent, mask uint32) int32 {
	// Note: Locking this inotify instance protects the result returned by
	// Lookup() below. With the lock held, we know for sure the lookup result
	// won't become stale because it's impossible for *this* instance to
	// add/remove watches on target.
	i.mu.Lock()
	defer i.mu.Unlock()

	// Does the target already have a watch from this inotify instance?
	if existing := target.Inode.Watches.Lookup(i.id); existing != nil {
		// This may be a watch on a different dirent pointing to the
		// same inode. Obtain an extra reference if necessary.
		existing.Pin(target)

		newmask := mask
		if mergeMask := mask&linux.IN_MASK_ADD != 0; mergeMask {
			// "Add (OR) events to watch mask for this pathname if it already
			// exists (instead of replacing mask)." -- inotify(7)
			newmask |= atomic.LoadUint32(&existing.mask)
		}
		atomic.StoreUint32(&existing.mask, newmask)
		return existing.wd
	}

	// No existing watch, create a new watch.
	watch := i.newWatchLocked(target, mask)
	return watch.wd
}

// RmWatch implements watcher.Watchable.RmWatch.
//
// RmWatch looks up an inotify watch for the given 'wd' and configures the
// target dirent to stop sending events to this inotify instance.
func (i *Inotify) RmWatch(ctx context.Context, wd int32) error {
	i.mu.Lock()

	// Find the watch we were asked to removed.
	watch, ok := i.watches[wd]
	if !ok {
		i.mu.Unlock()
		return syserror.EINVAL
	}

	// Remove the watch from this instance.
	delete(i.watches, wd)

	// Remove the watch from the watch target.
	watch.target.Watches.Remove(watch.ID())

	// The watch is now isolated and we can safely drop the instance lock. We
	// need to do so because watch.destroy() acquires Watch.mu, which cannot be
	// acquired with Inotify.mu held.
	i.mu.Unlock()

	// Generate the event for the removal.
	i.queueEvent(newEvent(watch.wd, "", linux.IN_IGNORED, 0))

	// Remove all pins.
	watch.destroy(ctx)

	return nil
}
