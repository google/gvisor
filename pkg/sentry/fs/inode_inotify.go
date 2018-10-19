// Copyright 2018 Google LLC
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
	"fmt"
	"sync"
)

// Watches is the collection of inotify watches on an inode.
//
// +stateify savable
type Watches struct {
	// mu protects the fields below.
	mu sync.RWMutex `state:"nosave"`

	// ws is the map of active watches in this collection, keyed by the inotify
	// instance id of the owner.
	ws map[uint64]*Watch

	// unlinked indicates whether the target inode was ever unlinked. This is a
	// hack to figure out if we should queue a IN_DELETE_SELF event when this
	// watches collection is being destroyed, since otherwise we have no way of
	// knowing if the target inode is going down due to a deletion or
	// revalidation.
	unlinked bool
}

func newWatches() *Watches {
	return &Watches{
		ws: make(map[uint64]*Watch),
	}
}

// MarkUnlinked indicates the target for this set of watches to be unlinked.
// This has implications for the IN_EXCL_UNLINK flag.
func (w *Watches) MarkUnlinked() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.unlinked = true
}

// Lookup returns a matching watch with the given id. Returns nil if no such
// watch exists. Note that the result returned by this method only remains valid
// if the inotify instance owning the watch is locked, preventing modification
// of the returned watch and preventing the replacement of the watch by another
// one from the same instance (since there may be at most one watch per
// instance, per target).
func (w *Watches) Lookup(id uint64) *Watch {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ws[id]
}

// Add adds watch into this set of watches. The watch being added must be unique
// - its ID() should not collide with any existing watches.
func (w *Watches) Add(watch *Watch) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Sanity check, the new watch shouldn't collide with an existing
	// watch. Silently replacing an existing watch would result in a ref leak on
	// this inode. We could handle this collision by calling Unpin() on the
	// existing watch, but then we end up leaking watch descriptor ids at the
	// inotify level.
	if _, exists := w.ws[watch.ID()]; exists {
		panic(fmt.Sprintf("Watch collision with ID %+v", watch.ID()))
	}
	w.ws[watch.ID()] = watch
}

// Remove removes a watch with the given id from this set of watches. The caller
// is responsible for generating any watch removal event, as appropriate. The
// provided id must match an existing watch in this collection.
func (w *Watches) Remove(id uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.ws == nil {
		// This watch set is being destroyed. The thread executing the
		// destructor is already in the process of deleting all our watches. We
		// got here with no refs on the inode because we raced with the
		// destructor notifying all the watch owners of the inode's destruction.
		// See the comment in Watches.TargetDestroyed for why this race exists.
		return
	}

	watch, ok := w.ws[id]
	if !ok {
		// While there's technically no problem with silently ignoring a missing
		// watch, this is almost certainly a bug.
		panic(fmt.Sprintf("Attempt to remove a watch, but no watch found with provided id %+v.", id))
	}
	delete(w.ws, watch.ID())
}

// Notify queues a new event with all watches in this set.
func (w *Watches) Notify(name string, events, cookie uint32) {
	// N.B. We don't defer the unlocks because Notify is in the hot path of
	// all IO operations, and the defer costs too much for small IO
	// operations.
	w.mu.RLock()
	for _, watch := range w.ws {
		if name != "" && w.unlinked && !watch.NotifyParentAfterUnlink() {
			// IN_EXCL_UNLINK - By default, when watching events on the children
			// of a directory, events are generated for children even after they
			// have been unlinked from the directory. This can result in large
			// numbers of uninteresting events for some applications (e.g., if
			// watching /tmp, in which many applications create temporary files
			// whose names are immediately unlinked). Specifying IN_EXCL_UNLINK
			// changes the default behavior, so that events are not generated
			// for children after they have been unlinked from the watched
			// directory.  -- inotify(7)
			//
			// We know we're dealing with events for a parent when the name
			// isn't empty.
			continue
		}
		watch.Notify(name, events, cookie)
	}
	w.mu.RUnlock()
}

// Unpin unpins dirent from all watches in this set.
func (w *Watches) Unpin(d *Dirent) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, watch := range w.ws {
		watch.Unpin(d)
	}
}

// targetDestroyed is called by the inode destructor to notify the watch owners
// of the impending destruction of the watch target.
func (w *Watches) targetDestroyed() {
	var ws map[uint64]*Watch

	// We can't hold w.mu while calling watch.TargetDestroyed to preserve lock
	// ordering w.r.t to the owner inotify instances. Instead, atomically move
	// the watches map into a local variable so we can iterate over it safely.
	//
	// Because of this however, it is possible for the watches' owners to reach
	// this inode while the inode has no refs. This is still safe because the
	// owners can only reach the inode until this function finishes calling
	// watch.TargetDestroyed() below and the inode is guaranteed to exist in the
	// meanwhile. But we still have to be very careful not to rely on inode
	// state that may have been already destroyed.
	w.mu.Lock()
	ws = w.ws
	w.ws = nil
	w.mu.Unlock()

	for _, watch := range ws {
		watch.TargetDestroyed()
	}
}
