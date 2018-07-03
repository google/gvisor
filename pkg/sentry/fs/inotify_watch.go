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

package fs

import (
	"sync"
	"sync/atomic"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
)

// Watch represent a particular inotify watch created by inotify_add_watch.
//
// While a watch is active, it ensures the target inode is pinned in memory by
// holding an extra ref on each dirent known (by inotify) to point to the
// inode. These are known as pins. For a full discussion, see
// fs/g3doc/inotify.md.
type Watch struct {
	// Inotify instance which owns this watch.
	owner *Inotify

	// Descriptor for this watch. This is unique across an inotify instance.
	wd int32

	// The inode being watched. Note that we don't directly hold a reference on
	// this inode. Instead we hold a reference on the dirent(s) containing the
	// inode, which we record in pins.
	target *Inode

	// unpinned indicates whether we have a hard reference on target. This field
	// may only be modified through atomic ops.
	unpinned uint32

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	// Events being monitored via this watch. Must be accessed atomically,
	// writes are protected by mu.
	mask uint32

	// pins is the set of dirents this watch is currently pinning in memory by
	// holding a reference to them. See Pin()/Unpin().
	pins map[*Dirent]bool
}

// ID returns the id of the inotify instance that owns this watch.
func (w *Watch) ID() uint64 {
	return w.owner.id
}

// NotifyParentAfterUnlink indicates whether the parent of the watched object
// should continue to be be notified of events after the target has been
// unlinked.
func (w *Watch) NotifyParentAfterUnlink() bool {
	return atomic.LoadUint32(&w.mask)&linux.IN_EXCL_UNLINK == 0
}

// isRenameEvent returns true if eventMask describes a rename event.
func isRenameEvent(eventMask uint32) bool {
	return eventMask&(linux.IN_MOVED_FROM|linux.IN_MOVED_TO|linux.IN_MOVE_SELF) != 0
}

// Notify queues a new event on this watch.
func (w *Watch) Notify(name string, events uint32, cookie uint32) {
	unmaskableBits := ^uint32(0) &^ linux.IN_ALL_EVENTS
	effectiveMask := unmaskableBits | atomic.LoadUint32(&w.mask)
	matchedEvents := effectiveMask & events

	if matchedEvents == 0 {
		// We weren't watching for this event.
		return
	}

	w.owner.queueEvent(newEvent(w.wd, name, matchedEvents, cookie))
}

// Pin acquires a new ref on dirent, which pins the dirent in memory while
// the watch is active. Calling Pin for a second time on the same dirent for
// the same watch is a no-op.
func (w *Watch) Pin(d *Dirent) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.pins[d] {
		w.pins[d] = true
		d.IncRef()
	}
}

// Unpin drops any extra refs held on dirent due to a previous Pin
// call. Calling Unpin multiple times for the same dirent, or on a dirent
// without a corresponding Pin call is a no-op.
func (w *Watch) Unpin(d *Dirent) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pins[d] {
		delete(w.pins, d)
		d.DecRef()
	}
}

// TargetDestroyed notifies the owner of the watch that the watch target is
// gone. The owner should release its own references to the watcher upon
// receiving this notification.
func (w *Watch) TargetDestroyed() {
	w.owner.targetDestroyed(w)
}

// destroy prepares the watch for destruction. It unpins all dirents pinned by
// this watch. Destroy does not cause any new events to be generated. The caller
// is responsible for ensuring there are no outstanding references to this
// watch.
func (w *Watch) destroy() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for d := range w.pins {
		d.DecRef()
	}
	w.pins = nil
}
