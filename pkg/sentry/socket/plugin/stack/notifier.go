// Copyright 2023 The gVisor Authors.
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

package stack

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/sentry/socket/plugin"
	"gvisor.dev/gvisor/pkg/sentry/socket/plugin/cgo"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Notifier holds all the state necessary to issue notifications when
// IO events occur on the observed FDs in plugin stack.
type Notifier struct {
	// epFD is the epoll FD used for event registration. It is initialized by
	// waitAndNotify before signaling ioInit and is immutable afterward.
	epFD int32

	mu sync.Mutex

	// eventMap maps file descriptors to their notification queues
	// and waiting status.
	//
	// +checklocks:mu
	eventMap map[uint32]*plugin.EventInfo
}

const (
	MaxEpollEvents = 128
	SleepInMsecond = 100
)

// NewNotifier initialize the event notifier for plugin stack.
// It will allocate a eventMap with fd as key and corresponding eventInfo
// as value and start a goroutine waiting the arrival of events.
func NewNotifier() *Notifier {
	ioInit := make(chan int32)

	n := &Notifier{
		eventMap: make(map[uint32]*plugin.EventInfo),
	}

	go n.waitAndNotify(ioInit)

	epFD := <-ioInit
	if epFD < 0 {
		return nil
	}
	return n
}

// AddFD adds fd and its event notification state to n.eventMap.
//
// +checklocksexclude:n.mu
func (n *Notifier) AddFD(fd uint32, eventInfo *plugin.EventInfo) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Panic if we're already notifying on this FD.
	if _, ok := n.eventMap[fd]; ok {
		panic(fmt.Sprintf("File descriptor %d added twice", fd))
	}

	// We have nothing to wait for at the moment. Just add it to the map.
	n.eventMap[fd] = eventInfo
}

// RemoveFD removes fd's event notification state from n.eventMap.
//
// +checklocksexclude:n.mu
func (n *Notifier) RemoveFD(fd uint32) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.eventMap, fd)
}

// UpdateFD updates fd's event registration in the plugin stack's epoll
// instance.
//
// Callers must not hold the registered queue's mutex. checklocks cannot
// express the queue selected by eventMap[fd] in an entry contract.
//
// +checklocksexclude:n.mu
func (n *Notifier) UpdateFD(fd uint32) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if eventInfo, ok := n.eventMap[fd]; ok {
		n.waitFD(fd, eventInfo)
	}
}

// waitAndNotify loops waiting for io event notifications from the epoll
// object. Once notifications arrive, they are dispatched to the
// registered queue.
func (n *Notifier) waitAndNotify(ioInit chan int32) error {
	// plugin stack leverages TLS variables, so bind this goroutine with
	// one specific OS thread
	runtime.LockOSThread()

	// If current thread is not the main thread, change the thread name.
	if syscall.Getpid() != syscall.Gettid() {
		threadName := []byte("io-thread\x00")
		if err := unix.Prctl(unix.PR_SET_NAME, uintptr(cgo.GetPtr(threadName)), 0, 0, 0); err != nil {
			return err
		}
	}

	n.epFD = int32(cgo.EpollCreate())

	ioInit <- n.epFD

	var events [MaxEpollEvents]syscall.EpollEvent
	for {
		num := cgo.EpollWait(n.epFD, events[:], MaxEpollEvents, SleepInMsecond)
		if num <= 0 {
			continue
		}

		n.mu.Lock()
		for i := 0; i < num; i++ {
			h := uint32(events[i].Fd)
			eventInfo, ok := n.eventMap[h]
			if !ok {
				continue
			}

			ev := waiter.EventMask(events[i].Events)
			atomicbitops.OrUint64(&eventInfo.Ready, uint64(ev&(eventInfo.Mask|waiter.EventErr|waiter.EventHUp)))
			// When an error occurred, invoke all events
			if ev&(waiter.EventErr|waiter.EventHUp) != 0 {
				ev |= waiter.EventIn | waiter.EventOut
			}
			// Callbacks run under n.mu and the queue's read lock. They must
			// not reenter this notifier or call this queue's methods.
			// They may query socket readiness, which acquires neither lock.
			// checklocks cannot propagate these locks through EventListener.
			eventInfo.Wq.Notify(ev)
		}
		n.mu.Unlock()
	}
}

// waitFD updates fd's registration to match its queue's current interest.
//
// Preconditions: eventInfo == n.eventMap[fd].
//
// +checklocks:n.mu
// +checklocksexclude:eventInfo.Wq.mu
func (n *Notifier) waitFD(fd uint32, eventInfo *plugin.EventInfo) {
	mask := eventInfo.Wq.Events()

	eventInfo.Mask = mask
	if !eventInfo.Waiting && mask == 0 {
		return
	}

	switch {
	case !eventInfo.Waiting && mask != 0:
		cgo.EpollCtl(n.epFD, syscall.EPOLL_CTL_ADD, fd, uint32(mask))
		eventInfo.Waiting = true
	case eventInfo.Waiting && mask == 0:
		cgo.EpollCtl(n.epFD, syscall.EPOLL_CTL_DEL, fd, uint32(mask))
		eventInfo.Ready.Store(0)
		eventInfo.Waiting = false
	case eventInfo.Waiting && mask != 0:
		cgo.EpollCtl(n.epFD, syscall.EPOLL_CTL_MOD, fd, uint32(mask))
		atomicbitops.AndUint64(&eventInfo.Ready, uint64(mask))
	}
}
