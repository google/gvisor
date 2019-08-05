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

// +build linux

// Package fdnotifier contains an adapter that translates IO events (e.g., a
// file became readable/writable) from native FDs to the notifications in the
// waiter package. It uses epoll in edge-triggered mode to receive notifications
// for registered FDs.
package fdnotifier

import (
	"fmt"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/waiter"
)

type fdInfo struct {
	queue   *waiter.Queue
	waiting bool
}

// notifier holds all the state necessary to issue notifications when IO events
// occur in the observed FDs.
type notifier struct {
	// epFD is the epoll file descriptor used to register for io
	// notifications.
	epFD int

	// mu protects fdMap.
	mu sync.Mutex

	// fdMap maps file descriptors to their notification queues and waiting
	// status.
	fdMap map[int32]*fdInfo
}

// newNotifier creates a new notifier object.
func newNotifier() (*notifier, error) {
	epfd, err := syscall.EpollCreate1(0)
	if err != nil {
		return nil, err
	}

	w := &notifier{
		epFD:  epfd,
		fdMap: make(map[int32]*fdInfo),
	}

	go w.waitAndNotify() // S/R-SAFE: no waiter exists during save / load.

	return w, nil
}

// waitFD waits on mask for fd. The fdMap mutex must be hold.
func (n *notifier) waitFD(fd int32, fi *fdInfo, mask waiter.EventMask) error {
	if !fi.waiting && mask == 0 {
		return nil
	}

	e := syscall.EpollEvent{
		Events: mask.ToLinux() | unix.EPOLLET,
		Fd:     fd,
	}

	switch {
	case !fi.waiting && mask != 0:
		if err := syscall.EpollCtl(n.epFD, syscall.EPOLL_CTL_ADD, int(fd), &e); err != nil {
			return err
		}
		fi.waiting = true
	case fi.waiting && mask == 0:
		syscall.EpollCtl(n.epFD, syscall.EPOLL_CTL_DEL, int(fd), nil)
		fi.waiting = false
	case fi.waiting && mask != 0:
		if err := syscall.EpollCtl(n.epFD, syscall.EPOLL_CTL_MOD, int(fd), &e); err != nil {
			return err
		}
	}

	return nil
}

// addFD adds an FD to the list of FDs observed by n.
func (n *notifier) addFD(fd int32, queue *waiter.Queue) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Panic if we're already notifying on this FD.
	if _, ok := n.fdMap[fd]; ok {
		panic(fmt.Sprintf("File descriptor %v added twice", fd))
	}

	// We have nothing to wait for at the moment. Just add it to the map.
	n.fdMap[fd] = &fdInfo{queue: queue}
}

// updateFD updates the set of events the fd needs to be notified on.
func (n *notifier) updateFD(fd int32) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if fi, ok := n.fdMap[fd]; ok {
		return n.waitFD(fd, fi, fi.queue.Events())
	}

	return nil
}

// RemoveFD removes an FD from the list of FDs observed by n.
func (n *notifier) removeFD(fd int32) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Remove from map, then from epoll object.
	n.waitFD(fd, n.fdMap[fd], 0)
	delete(n.fdMap, fd)
}

// hasFD returns true if the fd is in the list of observed FDs.
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
	e := make([]syscall.EpollEvent, 100)
	for {
		v, err := epollWait(n.epFD, e, -1)
		if err == syscall.EINTR {
			continue
		}

		if err != nil {
			return err
		}

		n.mu.Lock()
		for i := 0; i < v; i++ {
			if fi, ok := n.fdMap[e[i].Fd]; ok {
				fi.queue.Notify(waiter.EventMaskFromLinux(e[i].Events))
			}
		}
		n.mu.Unlock()
	}
}

var shared struct {
	notifier *notifier
	once     sync.Once
	initErr  error
}

// AddFD adds an FD to the list of observed FDs.
func AddFD(fd int32, queue *waiter.Queue) error {
	shared.once.Do(func() {
		shared.notifier, shared.initErr = newNotifier()
	})

	if shared.initErr != nil {
		return shared.initErr
	}

	shared.notifier.addFD(fd, queue)
	return nil
}

// UpdateFD updates the set of events the fd needs to be notified on.
func UpdateFD(fd int32) error {
	return shared.notifier.updateFD(fd)
}

// RemoveFD removes an FD from the list of observed FDs.
func RemoveFD(fd int32) {
	shared.notifier.removeFD(fd)
}

// HasFD returns true if the FD is in the list of observed FDs.
//
// This should only be used by tests to assert that FDs are correctly registered.
func HasFD(fd int32) bool {
	return shared.notifier.hasFD(fd)
}
