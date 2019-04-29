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

// Package epoll provides an implementation of Linux's IO event notification
// facility. See epoll(7) for more details.
package epoll

import (
	"fmt"
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/refs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/anon"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// Event describes the event mask that was observed and the user data to be
// returned when one of the events occurs. It has this format to match the linux
// format to avoid extra copying/allocation when writing events to userspace.
type Event struct {
	// Events is the event mask containing the set of events that have been
	// observed on an entry.
	Events uint32

	// Data is an opaque 64-bit value provided by the caller when adding the
	// entry, and returned to the caller when the entry reports an event.
	Data [2]int32
}

// EntryFlags is a bitmask that holds an entry's flags.
type EntryFlags int

// Valid entry flags.
const (
	OneShot EntryFlags = 1 << iota
	EdgeTriggered
)

// FileIdentifier identifies a file. We cannot use just the FD because it could
// potentially be reassigned. We also cannot use just the file pointer because
// it is possible to have multiple entries for the same file object as long as
// they are created with different FDs (i.e., the FDs point to the same file).
//
// +stateify savable
type FileIdentifier struct {
	File *fs.File `state:"wait"`
	Fd   kdefs.FD
}

// pollEntry holds all the state associated with an event poll entry, that is,
// a file being observed by an event poll object.
//
// +stateify savable
type pollEntry struct {
	pollEntryEntry
	file     *refs.WeakRef  `state:"manual"`
	id       FileIdentifier `state:"wait"`
	userData [2]int32
	waiter   waiter.Entry `state:"manual"`
	mask     waiter.EventMask
	flags    EntryFlags

	epoll *EventPoll

	// We cannot save the current list pointer as it points into EventPoll
	// struct, while state framework currently does not support such
	// in-struct pointers. Instead, EventPoll will properly set this field
	// in its loading logic.
	curList *pollEntryList `state:"nosave"`
}

// WeakRefGone implements refs.WeakRefUser.WeakRefGone.
// weakReferenceGone is called when the file in the weak reference is destroyed.
// The poll entry is removed in response to this.
func (p *pollEntry) WeakRefGone() {
	p.epoll.RemoveEntry(p.id)
}

// EventPoll holds all the state associated with an event poll object, that is,
// collection of files to observe and their current state.
//
// +stateify savable
type EventPoll struct {
	fsutil.FilePipeSeek             `state:"zerovalue"`
	fsutil.FileNotDirReaddir        `state:"zerovalue"`
	fsutil.FileNoFsync              `state:"zerovalue"`
	fsutil.FileNoopFlush            `state:"zerovalue"`
	fsutil.FileNoMMap               `state:"zerovalue"`
	fsutil.FileNoIoctl              `state:"zerovalue"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`

	// Wait queue is used to notify interested parties when the event poll
	// object itself becomes readable or writable.
	waiter.Queue `state:"zerovalue"`

	// files is the map of all the files currently being observed, it is
	// protected by mu.
	mu    sync.Mutex `state:"nosave"`
	files map[FileIdentifier]*pollEntry

	// listsMu protects manipulation of the lists below. It needs to be a
	// different lock to avoid circular lock acquisition order involving
	// the wait queue mutexes and mu. The full order is mu, observed file
	// wait queue mutex, then listsMu; this allows listsMu to be acquired
	// when readyCallback is called.
	//
	// An entry is always in one of the following lists:
	//	readyList -- when there's a chance that it's ready to have
	//		events delivered to epoll waiters. Given that being
	//		ready is a transient state, the Readiness() and
	//		readEvents() functions always call the entry's file
	//		Readiness() function to confirm it's ready.
	//	waitingList -- when there's no chance that the entry is ready,
	//		so it's waiting for the readyCallback to be called
	//		on it before it gets moved to the readyList.
	//	disabledList -- when the entry is disabled. This happens when
	//		a one-shot entry gets delivered via readEvents().
	listsMu      sync.Mutex `state:"nosave"`
	readyList    pollEntryList
	waitingList  pollEntryList
	disabledList pollEntryList
}

// cycleMu is used to serialize all the cycle checks. This is only used when
// an event poll file is added as an entry to another event poll. Such checks
// are serialized to avoid lock acquisition order inversion: if a thread is
// adding A to B, and another thread is adding B to A, each would acquire A's
// and B's mutexes in reverse order, and could cause deadlocks. Having this
// lock prevents this by allowing only one check at a time to happen.
//
// We do the cycle check to prevent callers from introducing potentially
// infinite recursions. If a caller were to add A to B and then B to A, for
// event poll A to know if it's readable, it would need to check event poll B,
// which in turn would need event poll A and so on indefinitely.
var cycleMu sync.Mutex

// NewEventPoll allocates and initializes a new event poll object.
func NewEventPoll(ctx context.Context) *fs.File {
	// name matches fs/eventpoll.c:epoll_create1.
	dirent := fs.NewDirent(anon.NewInode(ctx), fmt.Sprintf("anon_inode:[eventpoll]"))
	return fs.NewFile(ctx, dirent, fs.FileFlags{}, &EventPoll{
		files: make(map[FileIdentifier]*pollEntry),
	})
}

// Release implements fs.FileOperations.Release.
func (e *EventPoll) Release() {
	// We need to take the lock now because files may be attempting to
	// remove entries in parallel if they get destroyed.
	e.mu.Lock()
	defer e.mu.Unlock()

	// Go through all entries and clean up.
	for _, entry := range e.files {
		entry.id.File.EventUnregister(&entry.waiter)
		entry.file.Drop()
	}
}

// Read implements fs.FileOperations.Read.
func (*EventPoll) Read(context.Context, *fs.File, usermem.IOSequence, int64) (int64, error) {
	return 0, syscall.ENOSYS
}

// Write implements fs.FileOperations.Write.
func (*EventPoll) Write(context.Context, *fs.File, usermem.IOSequence, int64) (int64, error) {
	return 0, syscall.ENOSYS
}

// eventsAvailable determines if 'e' has events available for delivery.
func (e *EventPoll) eventsAvailable() bool {
	e.listsMu.Lock()

	for it := e.readyList.Front(); it != nil; {
		entry := it
		it = it.Next()

		// If the entry is ready, we know 'e' has at least one entry
		// ready for delivery.
		ready := entry.id.File.Readiness(entry.mask)
		if ready != 0 {
			e.listsMu.Unlock()
			return true
		}

		// Entry is not ready, so move it to waiting list.
		e.readyList.Remove(entry)
		e.waitingList.PushBack(entry)
		entry.curList = &e.waitingList
	}

	e.listsMu.Unlock()

	return false
}

// Readiness determines if the event poll object is currently readable (i.e.,
// if there are pending events for delivery).
func (e *EventPoll) Readiness(mask waiter.EventMask) waiter.EventMask {
	ready := waiter.EventMask(0)

	if (mask&waiter.EventIn) != 0 && e.eventsAvailable() {
		ready |= waiter.EventIn
	}

	return ready
}

// ReadEvents returns up to max available events.
func (e *EventPoll) ReadEvents(max int) []Event {
	var local pollEntryList
	var ret []Event

	e.listsMu.Lock()

	// Go through all entries we believe may be ready.
	for it := e.readyList.Front(); it != nil && len(ret) < max; {
		entry := it
		it = it.Next()

		// Check the entry's readiness. It it's not really ready, we
		// just put it back in the waiting list and move on to the next
		// entry.
		ready := entry.id.File.Readiness(entry.mask) & entry.mask
		if ready == 0 {
			e.readyList.Remove(entry)
			e.waitingList.PushBack(entry)
			entry.curList = &e.waitingList

			continue
		}

		// Add event to the array that will be returned to caller.
		ret = append(ret, Event{
			Events: uint32(ready),
			Data:   entry.userData,
		})

		// The entry is consumed, so we must move it to the disabled
		// list in case it's one-shot, or back to the wait list if it's
		// edge-triggered. If it's neither, we leave it in the ready
		// list so that its readiness can be checked the next time
		// around; however, we must move it to the end of the list so
		// that other events can be delivered as well.
		e.readyList.Remove(entry)
		if entry.flags&OneShot != 0 {
			e.disabledList.PushBack(entry)
			entry.curList = &e.disabledList
		} else if entry.flags&EdgeTriggered != 0 {
			e.waitingList.PushBack(entry)
			entry.curList = &e.waitingList
		} else {
			local.PushBack(entry)
		}
	}

	e.readyList.PushBackList(&local)

	e.listsMu.Unlock()

	return ret
}

// readyCallback is called when one of the files we're polling becomes ready. It
// moves said file to the readyList if it's currently in the waiting list.
type readyCallback struct{}

// Callback implements waiter.EntryCallback.Callback.
func (*readyCallback) Callback(w *waiter.Entry) {
	entry := w.Context.(*pollEntry)
	e := entry.epoll

	e.listsMu.Lock()

	if entry.curList == &e.waitingList {
		e.waitingList.Remove(entry)
		e.readyList.PushBack(entry)
		entry.curList = &e.readyList

		e.Notify(waiter.EventIn)
	}

	e.listsMu.Unlock()
}

// initEntryReadiness initializes the entry's state with regards to its
// readiness by placing it in the appropriate list and registering for
// notifications.
func (e *EventPoll) initEntryReadiness(entry *pollEntry) {
	// A new entry starts off in the waiting list.
	e.listsMu.Lock()
	e.waitingList.PushBack(entry)
	entry.curList = &e.waitingList
	e.listsMu.Unlock()

	// Register for event notifications.
	f := entry.id.File
	f.EventRegister(&entry.waiter, entry.mask)

	// Check if the file happens to already be in a ready state.
	ready := f.Readiness(entry.mask) & entry.mask
	if ready != 0 {
		(*readyCallback).Callback(nil, &entry.waiter)
	}
}

// observes checks if event poll object e is directly or indirectly observing
// event poll object ep. It uses a bounded recursive depth-first search.
func (e *EventPoll) observes(ep *EventPoll, depthLeft int) bool {
	// If we reached the maximum depth, we'll consider that we found it
	// because we don't want to allow chains that are too long.
	if depthLeft <= 0 {
		return true
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Go through each observed file and check if it is or observes ep.
	for id := range e.files {
		f, ok := id.File.FileOperations.(*EventPoll)
		if !ok {
			continue
		}

		if f == ep || f.observes(ep, depthLeft-1) {
			return true
		}
	}

	return false
}

// AddEntry adds a new file to the collection of files observed by e.
func (e *EventPoll) AddEntry(id FileIdentifier, flags EntryFlags, mask waiter.EventMask, data [2]int32) error {
	// Acquire cycle check lock if another event poll is being added.
	ep, ok := id.File.FileOperations.(*EventPoll)
	if ok {
		cycleMu.Lock()
		defer cycleMu.Unlock()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Fail if the file already has an entry.
	if _, ok := e.files[id]; ok {
		return syscall.EEXIST
	}

	// Check if a cycle would be created. We use 4 as the limit because
	// that's the value used by linux and we want to emulate it.
	if ep != nil {
		if e == ep {
			return syscall.EINVAL
		}

		if ep.observes(e, 4) {
			return syscall.ELOOP
		}
	}

	// Create new entry and add it to map.
	//
	// N.B. Even though we are creating a weak reference here, we know it
	//      won't trigger a callback because we hold a reference to the file
	//      throughout the execution of this function.
	entry := &pollEntry{
		id:       id,
		userData: data,
		epoll:    e,
		flags:    flags,
		waiter:   waiter.Entry{Callback: &readyCallback{}},
		mask:     mask,
	}
	entry.waiter.Context = entry
	e.files[id] = entry
	entry.file = refs.NewWeakRef(id.File, entry)

	// Initialize the readiness state of the new entry.
	e.initEntryReadiness(entry)

	return nil
}

// UpdateEntry updates the flags, mask and user data associated with a file that
// is already part of the collection of observed files.
func (e *EventPoll) UpdateEntry(id FileIdentifier, flags EntryFlags, mask waiter.EventMask, data [2]int32) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Fail if the file doesn't have an entry.
	entry, ok := e.files[id]
	if !ok {
		return syscall.ENOENT
	}

	// Unregister the old mask and remove entry from the list it's in, so
	// readyCallback is guaranteed to not be called on this entry anymore.
	entry.id.File.EventUnregister(&entry.waiter)

	// Remove entry from whatever list it's in. This ensure that no other
	// threads have access to this entry as the only way left to find it
	// is via e.files, but we hold e.mu, which prevents that.
	e.listsMu.Lock()
	entry.curList.Remove(entry)
	e.listsMu.Unlock()

	// Initialize new readiness state.
	entry.flags = flags
	entry.mask = mask
	entry.userData = data
	e.initEntryReadiness(entry)

	return nil
}

// RemoveEntry a files from the collection of observed files.
func (e *EventPoll) RemoveEntry(id FileIdentifier) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Fail if the file doesn't have an entry.
	entry, ok := e.files[id]
	if !ok {
		return syscall.ENOENT
	}

	// Unregister from file first so that no concurrent attempts will be
	// made to manipulate the file.
	entry.id.File.EventUnregister(&entry.waiter)

	// Remove from the current list.
	e.listsMu.Lock()
	entry.curList.Remove(entry)
	entry.curList = nil
	e.listsMu.Unlock()

	// Remove file from map, and drop weak reference.
	delete(e.files, id)
	entry.file.Drop()

	return nil
}

// UnregisterEpollWaiters removes the epoll waiter objects from the waiting
// queues. This is different from Release() as the file is not dereferenced.
func (e *EventPoll) UnregisterEpollWaiters() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, entry := range e.files {
		entry.id.File.EventUnregister(&entry.waiter)
	}
}
