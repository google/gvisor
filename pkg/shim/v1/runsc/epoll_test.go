// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

package runsc

import (
	"context"
	"testing"
	"time"

	cgroups "github.com/containerd/cgroups/v3/cgroup1"
	"golang.org/x/sys/unix"
)

// fakeCgroup reports a fixed state. The embedded interface is nil; only State
// is called.
type fakeCgroup struct {
	cgroups.Cgroup
	state cgroups.State
}

func (f *fakeCgroup) State() cgroups.State { return f.state }

// newTestEpoller returns an epoller with one live container registered on an
// eventfd, along with its publisher and that fd. The epoll fd is invalid: these
// tests never wait on it.
func newTestEpoller(t *testing.T, state cgroups.State) (*epoller, *errorPublisher, uintptr) {
	t.Helper()
	efd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		t.Skipf("eventfd unavailable: %v", err)
	}
	fd := uintptr(efd)
	pub := &errorPublisher{}
	e := &epoller{
		fd:        -1,
		publisher: pub,
		set: map[uintptr]*item{
			fd: {id: "test", cg: &fakeCgroup{state: state}},
		},
	}
	return e, pub, fd
}

// TestEpollerProcessDoesNotPanicOnPublishError verifies that an OOM publish
// failure is logged rather than fatal, whether or not an event sink is
// configured, matching runscService.forward. A panic would take down every
// container the shim serves.
func TestEpollerProcessDoesNotPanicOnPublishError(t *testing.T) {
	for _, tc := range []struct {
		name         string
		ttrpcAddress string
	}{
		{name: "no-event-sink", ttrpcAddress: ""},
		{name: "containerd", ttrpcAddress: "/run/containerd/containerd.sock.ttrpc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TTRPC_ADDRESS", tc.ttrpcAddress)

			e, pub, fd := newTestEpoller(t, cgroups.Thawed)
			t.Cleanup(func() { unix.Close(int(fd)) })
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("process() panicked on publish error: %v", r)
				}
			}()
			e.process(context.Background(), fd)
			if got := len(pub.ctxs); got != 1 {
				t.Errorf("process() published %d events, want 1", got)
			}
		})
	}
}

// TestEpollerProcessDeletedCgroup verifies that a deleted cgroup is
// unregistered without publishing.
func TestEpollerProcessDeletedCgroup(t *testing.T) {
	// No cleanup: process() closes the fd itself on this path.
	e, pub, fd := newTestEpoller(t, cgroups.Deleted)
	e.process(context.Background(), fd)
	if got := len(pub.ctxs); got != 0 {
		t.Errorf("process() published %d events for a deleted cgroup, want 0", got)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.set[fd]; ok {
		t.Error("deleted cgroup was not removed from the epoller set")
	}
}

// TestEpollerRunStopsOnEpollWaitError verifies that a permanent epoll_wait
// error stops OOM monitoring instead of panicking the shim.
func TestEpollerRunStopsOnEpollWaitError(t *testing.T) {
	// An invalid epoll fd makes epoll_wait fail with EBADF.
	e := &epoller{
		fd:        -1,
		publisher: &errorPublisher{},
		set:       make(map[uintptr]*item),
	}
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		e.run(context.Background())
	}()
	select {
	case r := <-done:
		if r != nil {
			t.Fatalf("run() panicked on epoll_wait error: %v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not return on a permanent epoll_wait error")
	}
}
