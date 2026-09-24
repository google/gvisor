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
// eventfd, along with that fd. The epoll fd is invalid: these tests never wait
// on it.
func newTestEpoller(t *testing.T, state cgroups.State) (*epoller, uintptr) {
	t.Helper()
	efd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		t.Skipf("eventfd unavailable: %v", err)
	}
	fd := uintptr(efd)
	e := &epoller{
		fd:        -1,
		publisher: &errorPublisher{},
		set: map[uintptr]*item{
			fd: {id: "test", cg: &fakeCgroup{state: state}},
		},
	}
	return e, fd
}

// TestEpollerProcessDoesNotPanicOnPublishError verifies that an OOM publish
// failure is logged rather than fatal when no event sink is configured,
// matching runscService.forward. Under CRI-O the first OOM used to kill the
// shim.
func TestEpollerProcessDoesNotPanicOnPublishError(t *testing.T) {
	t.Setenv("TTRPC_ADDRESS", "")

	e, fd := newTestEpoller(t, cgroups.Thawed)
	t.Cleanup(func() { unix.Close(int(fd)) })
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("process() panicked without an event sink: %v", r)
		}
	}()
	e.process(context.Background(), fd)
}

// TestEpollerProcessPanicsOnPublishErrorUnderContainerd verifies that a publish
// failure remains fatal when an event sink is configured.
func TestEpollerProcessPanicsOnPublishErrorUnderContainerd(t *testing.T) {
	t.Setenv("TTRPC_ADDRESS", "/run/containerd/containerd.sock.ttrpc")

	e, fd := newTestEpoller(t, cgroups.Thawed)
	t.Cleanup(func() { unix.Close(int(fd)) })
	defer func() {
		if r := recover(); r == nil {
			t.Error("process() did not panic on publish error under containerd")
		}
	}()
	e.process(context.Background(), fd)
}

// TestEpollerProcessDeletedCgroup verifies that a deleted cgroup is
// unregistered without publishing.
func TestEpollerProcessDeletedCgroup(t *testing.T) {
	t.Setenv("TTRPC_ADDRESS", "/run/containerd/containerd.sock.ttrpc")

	// No cleanup: process() closes the fd itself on this path.
	e, fd := newTestEpoller(t, cgroups.Deleted)
	e.process(context.Background(), fd)
	if _, ok := e.set[fd]; ok {
		t.Error("deleted cgroup was not removed from the epoller set")
	}
}
