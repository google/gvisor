// Copyright 2026 The gVisor Authors.
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

package fdnotifier

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestStaleEpollEvent(t *testing.T) {
	for _, name := range []string{"ReusedFD", "RearmedFD"} {
		t.Run(name, func(t *testing.T) {
			// Drive epoll and dispatch separately so we can replace the
			// registration after epoll returns an event.
			epfd, err := unix.EpollCreate1(0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(epfd)
			n := notifier{
				epFD:   epfd,
				fdMap:  make(map[int32]*fdInfo),
				queues: make(map[uint64]*waiter.Queue),
			}
			pipe := func() [2]int {
				t.Helper()
				var fds [2]int
				if err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					unix.Close(fds[0])
					unix.Close(fds[1])
				})
				return fds
			}
			p := pipe()
			fd := int32(p[0])
			readEvent := func(writer int) []unix.EpollEvent {
				t.Helper()
				if _, err := unix.Write(writer, []byte{1}); err != nil {
					t.Fatal(err)
				}
				events := make([]unix.EpollEvent, 1)
				for {
					nr, err := epollWait(n.epFD, events, 0)
					if err == unix.EINTR {
						continue
					}
					if err != nil || nr != 1 || events[0].Events&unix.EPOLLIN == 0 {
						t.Fatalf("epollWait = (%d, %v), events = %+v, want one EPOLLIN", nr, err, events)
					}
					return events
				}
			}

			var oldQueue waiter.Queue
			oldEntry, _ := waiter.NewChannelEntry(waiter.EventIn)
			oldQueue.EventRegister(&oldEntry)
			if err := n.addFD(fd, &oldQueue); err != nil {
				t.Fatal(err)
			}
			stale := readEvent(p[1])
			// Remove the readiness that generated stale before replacing the
			// registration. The next waiter starts with an empty pipe.
			var b [1]byte
			if _, err := unix.Read(p[0], b[:]); err != nil {
				t.Fatal(err)
			}
			oldQueue.EventUnregister(&oldEntry)

			var replacement waiter.Queue
			queue := &oldQueue
			if name == "ReusedFD" {
				n.removeFD(fd)
				newPipe := pipe()
				// Replace the underlying open file description at the same FD.
				if err := unix.Dup3(newPipe[0], int(fd), unix.O_CLOEXEC); err != nil {
					t.Fatal(err)
				}
				p[1] = newPipe[1]
				queue = &replacement
				if err := n.addFD(fd, queue); err != nil {
					t.Fatal(err)
				}
			} else if err := n.updateFD(fd); err != nil {
				t.Fatal(err)
			}
			defer n.removeFD(fd)
			entry, ch := waiter.NewChannelEntry(waiter.EventIn)
			queue.EventRegister(&entry)
			if err := n.updateFD(fd); err != nil {
				t.Fatal(err)
			}
			n.notify(stale)
			select {
			case <-ch:
				t.Error("event from the old epoll registration notified the new waiter")
			default:
			}

			current := readEvent(p[1])
			// MOD keeps the registration that produced current.
			entry.SetQueuedMask(queue, waiter.EventIn|waiter.EventErr)
			if err := n.updateFD(fd); err != nil {
				t.Fatal(err)
			}
			n.notify(current)
			select {
			case <-ch:
			default:
				t.Error("current registration did not notify its waiter")
			}
		})
	}
}
