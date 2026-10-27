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

package vfs

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Host-backed file descriptions queue the waiter before asking the host to
// monitor the FD. A notification can arrive before that request fails.
type falliblePollFD struct {
	testFD
	waiter.Queue
	err error
}

func (*falliblePollFD) Epollable() bool { return true }

func (fd *falliblePollFD) EventRegister(e *waiter.Entry) error {
	fd.Queue.EventRegister(e)
	if fd.err != nil {
		fd.Notify(waiter.EventIn)
		fd.EventUnregister(e)
	}
	return fd.err
}

func TestEpollFailedRegistration(t *testing.T) {
	ctx := contexttest.Context(t)
	var vfs VirtualFilesystem
	if err := vfs.Init(ctx); err != nil {
		t.Fatal(err)
	}
	defer vfs.Release(ctx)
	epfd, err := vfs.NewEpollInstanceFD(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer epfd.DecRef(ctx)
	ep := epfd.Impl().(*EpollInstance)
	vd := vfs.NewAnonVirtualDentry("fallible poll")
	defer vd.DecRef(ctx)
	fd := &falliblePollFD{err: linuxerr.ENOSPC}
	file := &fd.fileDescription.vfsfd
	if err := file.Init(fd, linux.O_RDONLY, auth.CredentialsFromContext(ctx), vd.Mount(), vd.Dentry(), &FileDescriptionOptions{}); err != nil {
		t.Fatal(err)
	}
	defer file.DecRef(ctx)
	const fdnum = 3
	event := linux.EpollEvent{Events: linux.EPOLLIN}
	if got, want := ep.AddInterest(file, fdnum, event), linuxerr.ENOSPC; got != want {
		t.Fatalf("first ADD: got %v, want %v", got, want)
	}
	if got := ep.ReadEvents(nil, 1); len(got) != 0 {
		t.Errorf("events after failed ADD: got %v, want none", got)
	}
	fd.err = nil
	if err := ep.AddInterest(file, fdnum, event); err != nil {
		t.Errorf("retrying ADD: %v", err)
	}
}
