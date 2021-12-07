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

package vfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/waiter"
)

// epollCycleMu serializes attempts to register EpollInstances with other
// EpollInstances in order to check for cycles.
var epollCycleMu sync.Mutex

// EpollInstance represents an epoll instance, as described by epoll(7).
//
// +stateify savable
type EpollInstance struct {
	vfsfd FileDescription
	FileDescriptionDefaultImpl
	DentryMetadataFileDescriptionImpl
	NoLockFD

	// q holds waiters on this EpollInstance.
	q waiter.Queue

	// interest is the set of file descriptors that are registered with the
	// EpollInstance for monitoring. interest is protected by interestMu.
	interestMu sync.Mutex `state:"nosave"`
	interest   map[epollInterestKey]*epollInterest

	// mu protects fields in registered epollInterests.
	mu sync.Mutex `state:"nosave"`

	// ready is the set of file descriptors that may be "ready" for I/O. Note
	// that this must be an ordered list, not a map: "If more than maxevents
	// file descriptors are ready when epoll_wait() is called, then successive
	// epoll_wait() calls will round robin through the set of ready file
	// descriptors. This behavior helps avoid starvation scenarios, where a
	// process fails to notice that additional file descriptors are ready
	// because it focuses on a set of file descriptors that are already known
	// to be ready." - epoll_wait(2)
	ready epollInterestList
}

// +stateify savable
type epollInterestKey struct {
	// file is the registered FileDescription. No reference is held on file;
	// instead, when the last reference is dropped, FileDescription.DecRef()
	// removes the FileDescription from all EpollInstances. file is immutable.
	file *FileDescription

	// num is the file descriptor number with which this entry was registered.
	// num is immutable.
	num int32
}

// epollInterest represents an EpollInstance's interest in a file descriptor.
//
// +stateify savable
type epollInterest struct {
	// epoll is the owning EpollInstance. epoll is immutable.
	epoll *EpollInstance `state:"wait"`

	// key is the file to which this epollInterest applies. key is immutable.
	key epollInterestKey

	// waiter is registered with key.file. entry is protected by epoll.mu.
	waiter waiter.Entry

	// mask is the event mask associated with this registration, including
	// flags EPOLLET and EPOLLONESHOT. mask is protected by epoll.mu.
	mask uint32

	// ready is true if epollInterestEntry is linked into epoll.ready. ready
	// and epollInterestEntry are protected by epoll.mu.
	ready bool
	epollInterestEntry

	// userData is the struct epoll_event::data associated with this
	// epollInterest. userData is protected by epoll.mu.
	userData [2]int32
}

// NewEpollInstanceFD returns a FileDescription representing a new epoll
// instance. A reference is taken on the returned FileDescription.
func (vfs *VirtualFilesystem) NewEpollInstanceFD(ctx context.Context) (*FileDescription, error) {
	vd := vfs.NewAnonVirtualDentry("[eventpoll]")
	defer vd.DecRef(ctx)
	ep := &EpollInstance{
		interest: make(map[epollInterestKey]*epollInterest),
	}
	if err := ep.vfsfd.Init(ep, linux.O_RDWR, vd.Mount(), vd.Dentry(), &FileDescriptionOptions{
		DenyPRead:         true,
		DenyPWrite:        true,
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &ep.vfsfd, nil
}

// Release implements FileDescriptionImpl.Release.
func (ep *EpollInstance) Release(ctx context.Context) {
	// Unregister all polled fds.
	ep.interestMu.Lock()
	defer ep.interestMu.Unlock()
	for key, epi := range ep.interest {
		file := key.file
		file.epollMu.Lock()
		delete(file.epolls, epi)
		file.epollMu.Unlock()
		file.EventUnregister(&epi.waiter)
	}
	ep.interest = nil
}

// Readiness implements waiter.Waitable.Readiness.
func (ep *EpollInstance) Readiness(mask waiter.EventMask) waiter.EventMask {
	if mask&waiter.ReadableEvents == 0 {
		return 0
	}
	ep.mu.Lock()
	var next *epollInterest
	for epi := ep.ready.Front(); epi != nil; epi = next {
		next = epi.Next()
		wmask := waiter.EventMaskFromLinux(epi.mask)
		if epi.key.file.Readiness(wmask)&wmask != 0 {
			ep.mu.Unlock()
			return waiter.ReadableEvents
		}
		ep.ready.Remove(epi)
		epi.ready = false
	}
	ep.mu.Unlock()
	return 0
}

// EventRegister implements waiter.Waitable.EventRegister.
func (ep *EpollInstance) EventRegister(e *waiter.Entry) error {
	ep.q.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (ep *EpollInstance) EventUnregister(e *waiter.Entry) {
	ep.q.EventUnregister(e)
}

// Seek implements FileDescriptionImpl.Seek.
func (ep *EpollInstance) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	// Linux: fs/eventpoll.c:eventpoll_fops.llseek == noop_llseek
	return 0, nil
}

// AddInterest implements the semantics of EPOLL_CTL_ADD.
//
// Preconditions: A reference must be held on file.
func (ep *EpollInstance) AddInterest(file *FileDescription, num int32, event linux.EpollEvent) error {
	// Check for cyclic polling if necessary.
	subep, _ := file.impl.(*EpollInstance)
	if subep != nil {
		epollCycleMu.Lock()
		// epollCycleMu must be locked for the rest of AddInterest to ensure
		// that cyclic polling is not introduced after the check.
		defer epollCycleMu.Unlock()
		if subep.mightPoll(ep) {
			return linuxerr.ELOOP
		}
	}

	ep.interestMu.Lock()
	defer ep.interestMu.Unlock()

	// Fail if the key is already registered.
	key := epollInterestKey{
		file: file,
		num:  num,
	}
	if _, ok := ep.interest[key]; ok {
		return linuxerr.EEXIST
	}

	// Register interest in file.
	mask := event.Events | linux.EPOLLERR | linux.EPOLLHUP
	epi := &epollInterest{
		epoll:    ep,
		key:      key,
		mask:     mask,
		userData: event.Data,
	}
	ep.interest[key] = epi
	wmask := waiter.EventMaskFromLinux(mask)
	epi.waiter.Init(epi, wmask)
	if err := file.EventRegister(&epi.waiter); err != nil {
		return err
	}

	// Check if the file is already ready.
	if m := file.Readiness(wmask) & wmask; m != 0 {
		epi.NotifyEvent(m)
	}

	// Add epi to file.epolls so that it is removed when the last
	// FileDescription reference is dropped.
	file.epollMu.Lock()
	if file.epolls == nil {
		file.epolls = make(map[*epollInterest]struct{})
	}
	file.epolls[epi] = struct{}{}
	file.epollMu.Unlock()

	return nil
}

func (ep *EpollInstance) mightPoll(ep2 *EpollInstance) bool {
	return ep.mightPollRecursive(ep2, 4) // Linux: fs/eventpoll.c:EP_MAX_NESTS
}

func (ep *EpollInstance) mightPollRecursive(ep2 *EpollInstance, remainingRecursion int) bool {
	ep.interestMu.Lock()
	defer ep.interestMu.Unlock()
	for key := range ep.interest {
		nextep, ok := key.file.impl.(*EpollInstance)
		if !ok {
			continue
		}
		if nextep == ep2 {
			return true
		}
		if remainingRecursion == 0 {
			return true
		}
		if nextep.mightPollRecursive(ep2, remainingRecursion-1) {
			return true
		}
	}
	return false
}

// ModifyInterest implements the semantics of EPOLL_CTL_MOD.
//
// Preconditions: A reference must be held on file.
func (ep *EpollInstance) ModifyInterest(file *FileDescription, num int32, event linux.EpollEvent) error {
	ep.interestMu.Lock()
	defer ep.interestMu.Unlock()

	// Fail if the key is not already registered.
	epi, ok := ep.interest[epollInterestKey{
		file: file,
		num:  num,
	}]
	if !ok {
		return linuxerr.ENOENT
	}

	// Update epi for the next call to ep.ReadEvents().
	mask := event.Events | linux.EPOLLERR | linux.EPOLLHUP
	ep.mu.Lock()
	epi.mask = mask
	epi.userData = event.Data
	ep.mu.Unlock()

	// Re-register with the new mask.
	file.EventUnregister(&epi.waiter)
	wmask := waiter.EventMaskFromLinux(mask)
	epi.waiter.Init(epi, wmask)
	if err := file.EventRegister(&epi.waiter); err != nil {
		return err
	}

	// Check if the file is already ready with the new mask.
	if m := file.Readiness(wmask) & wmask; m != 0 {
		epi.NotifyEvent(m)
	}

	return nil
}

// DeleteInterest implements the semantics of EPOLL_CTL_DEL.
//
// Preconditions: A reference must be held on file.
func (ep *EpollInstance) DeleteInterest(file *FileDescription, num int32) error {
	ep.interestMu.Lock()
	defer ep.interestMu.Unlock()

	// Fail if the key is not already registered.
	epi, ok := ep.interest[epollInterestKey{
		file: file,
		num:  num,
	}]
	if !ok {
		return linuxerr.ENOENT
	}

	// Unregister from the file so that epi will no longer be readied.
	file.EventUnregister(&epi.waiter)

	// Forget about epi.
	ep.removeLocked(epi)

	file.epollMu.Lock()
	delete(file.epolls, epi)
	file.epollMu.Unlock()

	return nil
}

// NotifyEvent implements waiter.EventListener.NotifyEvent.
func (epi *epollInterest) NotifyEvent(waiter.EventMask) {
	newReady := false
	epi.epoll.mu.Lock()
	if !epi.ready {
		newReady = true
		epi.ready = true
		epi.epoll.ready.PushBack(epi)
	}
	epi.epoll.mu.Unlock()
	if newReady {
		epi.epoll.q.Notify(waiter.ReadableEvents)
	}
}

// Preconditions: ep.interestMu must be locked.
func (ep *EpollInstance) removeLocked(epi *epollInterest) {
	delete(ep.interest, epi.key)
	ep.mu.Lock()
	if epi.ready {
		epi.ready = false
		ep.ready.Remove(epi)
	}
	ep.mu.Unlock()
}

// ReadEvents appends up to maxReady events to events and returns the updated
// slice of events.
func (ep *EpollInstance) ReadEvents(events []linux.EpollEvent, maxEvents int) []linux.EpollEvent {
	i := 0
	// Hot path: avoid defer.
	ep.mu.Lock()
	var next *epollInterest
	var requeue epollInterestList
	for epi := ep.ready.Front(); epi != nil; epi = next {
		next = epi.Next()
		// Regardless of what else happens, epi is initially removed from the
		// ready list.
		ep.ready.Remove(epi)
		wmask := waiter.EventMaskFromLinux(epi.mask)
		ievents := epi.key.file.Readiness(wmask) & wmask
		if ievents == 0 {
			// Leave epi off the ready list.
			epi.ready = false
			continue
		}
		// Determine what we should do with epi.
		switch {
		case epi.mask&linux.EPOLLONESHOT != 0:
			// Clear all events from the mask; they must be re-added by
			// EPOLL_CTL_MOD.
			epi.mask &= linux.EP_PRIVATE_BITS
			fallthrough
		case epi.mask&linux.EPOLLET != 0:
			// Leave epi off the ready list.
			epi.ready = false
		default:
			// Queue epi to be moved to the end of the ready list.
			requeue.PushBack(epi)
		}
		// Report ievents.
		events = append(events, linux.EpollEvent{
			Events: ievents.ToLinux(),
			Data:   epi.userData,
		})
		i++
		if i == maxEvents {
			break
		}
	}
	ep.ready.PushBackList(&requeue)
	ep.mu.Unlock()
	return events
}
