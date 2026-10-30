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

//go:build linux
// +build linux

// Package fdnotifier contains an adapter that translates IO events (e.g., a
// file became readable/writable) from native FDs to the notifications in the
// waiter package. It uses epoll in edge-triggered mode to receive notifications
// for registered FDs.
package fdnotifier

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/waiter"
)

type fdInfo struct {
	// queue is immutable after registration. waiter.Queue.mu protects entry
	// membership and queued event masks.
	queue *waiter.Queue

	// id and mask identify the host epoll registration and the events it
	// monitors. Both are zero when unregistered and protected by the
	// owning notifier's mu.
	id   uint64
	mask waiter.EventMask
}

// notifier holds all the state necessary to issue notifications when IO events
// occur in the observed FDs.
type notifier struct {
	// epFD is the epoll file descriptor used to register for io
	// notifications. The first AddFD sets it before starting waitAndNotify.
	epFD int

	// pauseMu synchronizes notifications with save/restore.
	// It precedes mu in lock order.
	pauseMu sync.Mutex

	mu sync.Mutex

	// fdMap maps file descriptors to their notification queues and waiting
	// status.
	//
	// +checklocks:mu
	fdMap map[int32]*fdInfo

	// queues maps live epoll registrations to their waiters. The host FD may
	// already have been reused when we dispatch a batch from epollWait.
	//
	// +checklocks:mu
	queues map[uint64]*waiter.Queue

	// lastID is the last ID assigned by EPOLL_CTL_ADD.
	//
	// +checklocks:mu
	lastID uint64
}

// waitFD waits on mask for fd.
//
// +checklocks:n.mu
func (n *notifier) waitFD(fd int32, fi *fdInfo, mask waiter.EventMask) error {
	// Even an unchanged EPOLL_CTL_MOD can wake an edge-triggered watcher
	// a second time while the file remains ready.
	if mask == fi.mask {
		return nil
	}
	if mask == 0 {
		unix.EpollCtl(n.epFD, unix.EPOLL_CTL_DEL, int(fd), nil)
		delete(n.queues, fi.id)
		fi.id = 0
		fi.mask = 0
		return nil
	}

	op := unix.EPOLL_CTL_MOD
	id := fi.id
	if id == 0 {
		op = unix.EPOLL_CTL_ADD
		id = n.lastID + 1
		if id == 0 {
			return unix.EOVERFLOW
		}
	}
	// Fd and Pad hold the two words of epoll_event.data.
	e := unix.EpollEvent{
		Events: mask.ToLinux() | unix.EPOLLET,
		Fd:     int32(id),
		Pad:    int32(id >> 32),
	}
	if err := unix.EpollCtl(n.epFD, op, int(fd), &e); err != nil {
		return err
	}
	if op == unix.EPOLL_CTL_ADD {
		n.lastID = id
		fi.id = id
		n.queues[id] = fi.queue
	}
	fi.mask = mask
	return nil
}

// addFD adds an FD to the list of FDs observed by n.
//
// +checklocksexclude:n.mu
// +checklocksexclude:queue.mu
func (n *notifier) addFD(fd int32, queue *waiter.Queue) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.fdMap == nil {
		epfd, err := unix.EpollCreate1(0)
		if err != nil {
			return err
		}
		n.epFD = epfd
		n.fdMap = make(map[int32]*fdInfo)
		n.queues = make(map[uint64]*waiter.Queue)
		go n.waitAndNotify() // S/R-SAFE: pauseMu excludes callbacks during save/restore.
	}

	// Panic if we're already notifying on this FD.
	if _, ok := n.fdMap[fd]; ok {
		panic(fmt.Sprintf("File descriptor %v added twice", fd))
	}

	info := &fdInfo{queue: queue}
	// We might already have something in queue to wait for.
	if err := n.waitFD(fd, info, queue.Events()); err != nil {
		return err
	}
	// Add it to the map.
	n.fdMap[fd] = info
	return nil
}

// updateFD updates the set of events the fd needs to be notified on.
//
// The caller must not hold the registered waiter's queue mutex. checklocks
// cannot name that queue through the FD's entry in fdMap.
//
// +checklocksexclude:n.mu
func (n *notifier) updateFD(fd int32) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if fi, ok := n.fdMap[fd]; ok {
		return n.waitFD(fd, fi, fi.queue.Events())
	}

	return nil
}

// RemoveFD removes an FD from the list of FDs observed by n.
//
// +checklocksexclude:n.mu
func (n *notifier) removeFD(fd int32) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Remove from map, then from epoll object.
	n.waitFD(fd, n.fdMap[fd], 0)
	delete(n.fdMap, fd)
}

// hasFD returns true if the fd is in the list of observed FDs.
//
// +checklocksexclude:n.mu
func (n *notifier) hasFD(fd int32) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	_, ok := n.fdMap[fd]
	return ok
}

// waitAndNotify run is its own goroutine and loops waiting for io event
// notifications from the epoll object. Once notifications arrive, they are
// dispatched to the registered queue.
func (n *notifier) waitAndNotify() error {
	e := make([]unix.EpollEvent, 100)
	for {
		v, err := epollWait(n.epFD, e, -1)
		if err == unix.EINTR {
			continue
		}

		if err != nil {
			return err
		}

		if n.notify(e[:v]) {
			// Let goroutines woken by Notify get a chance to run before we
			// epoll_wait again.
			sync.Goyield()
		}
	}
}

// notify dispatches a batch already returned by epollWait.
func (n *notifier) notify(events []unix.EpollEvent) bool {
	n.pauseMu.Lock()
	defer n.pauseMu.Unlock()
	n.mu.Lock()
	defer n.mu.Unlock()
	notified := false
	for _, event := range events {
		id := uint64(uint32(event.Pad))<<32 | uint64(uint32(event.Fd))
		if queue := n.queues[id]; queue != nil {
			queue.Notify(waiter.EventMaskFromLinux(event.Events))
			notified = true
		}
	}
	return notified
}

// Public FD helpers acquire the shared notifier's mu themselves, but their
// exclusions cannot be exported reliably through this private package global.
// Pause/Resume have the same private-global limitation for their lock effects.
//
// Notifications call waiter callbacks with pauseMu and mu held. Callbacks must
// not reenter the FD helpers or Pause/Resume on the same notifier.
var shared notifier

// AddFD adds an FD to the list of observed FDs.
//
// +checklocksexclude:queue.mu
func AddFD(fd int32, queue *waiter.Queue) error {
	return shared.addFD(fd, queue)
}

// UpdateFD updates the set of events the fd needs to be notified on.
func UpdateFD(fd int32) error {
	return shared.updateFD(fd)
}

// RemoveFD removes an FD from the list of observed FDs.
func RemoveFD(fd int32) {
	shared.removeFD(fd)
}

// HasFD returns true if the FD is in the list of observed FDs.
//
// This should only be used by tests to assert that FDs are correctly registered.
func HasFD(fd int32) bool {
	return shared.hasFD(fd)
}

// Pause suspends notifications until Resume is called.
func Pause() {
	shared.pauseMu.Lock()
}

// Resume ends the effect of a previous call to Pause.
func Resume() {
	shared.pauseMu.Unlock()
}
