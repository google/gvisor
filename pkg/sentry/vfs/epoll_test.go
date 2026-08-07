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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/waiter"
)

type pollableFD struct {
	vfsfd FileDescription
	FileDescriptionDefaultImpl
	DentryMetadataFileDescriptionImpl
	NoLockFD

	queue waiter.Queue

	mu    sync.Mutex
	ready waiter.EventMask
}

func newPollableFD(ctx context.Context, vfsObj *VirtualFilesystem) (*pollableFD, error) {
	fd := &pollableFD{}
	vd := vfsObj.NewAnonVirtualDentry("[pollable]")
	defer vd.DecRef(ctx)
	if err := fd.vfsfd.Init(fd, linux.O_RDWR, auth.CredentialsFromContext(ctx), vd.Mount(), vd.Dentry(), &FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
	}); err != nil {
		return nil, err
	}
	return fd, nil
}

func (fd *pollableFD) Release(context.Context) {}

func (fd *pollableFD) EventRegister(e *waiter.Entry) error {
	fd.queue.EventRegister(e)
	return nil
}

func (fd *pollableFD) EventUnregister(e *waiter.Entry) {
	fd.queue.EventUnregister(e)
}

func (fd *pollableFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	return fd.ready & mask
}

func (fd *pollableFD) Epollable() bool { return true }

func (fd *pollableFD) setReady(mask waiter.EventMask) {
	fd.mu.Lock()
	fd.ready = mask
	fd.mu.Unlock()
	fd.queue.Notify(mask)
}

func (fd *pollableFD) clearReady() {
	fd.mu.Lock()
	fd.ready = 0
	fd.mu.Unlock()
}

// TestEpollInterestAfterLoadReRegistersWaiter is a regression test for
// https://github.com/google/gvisor/issues/13920. It verifies that after
// restore, epollInterest.afterLoad re-registers with the waiter.Queue so notifications continue to be delivered.
func TestEpollInterestAfterLoadReRegistersWaiter(t *testing.T) {
	ctx := contexttest.Context(t)
	vfsObj := &VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}

	epFD, err := vfsObj.NewEpollInstanceFD(ctx)
	if err != nil {
		t.Fatalf("NewEpollInstanceFD: %v", err)
	}
	defer epFD.DecRef(ctx)
	ep := epFD.Impl().(*EpollInstance)

	pfd, err := newPollableFD(ctx, vfsObj)
	if err != nil {
		t.Fatalf("newPollableFD: %v", err)
	}
	defer pfd.vfsfd.DecRef(ctx)

	if err := ep.AddInterest(&pfd.vfsfd, 1, linux.EpollEvent{
		Events: linux.EPOLLIN,
		Data:   [2]int32{42, 0},
	}); err != nil {
		t.Fatalf("AddInterest: %v", err)
	}

	ep.interestMu.Lock()
	epi := ep.interest[epollInterestKey{file: &pfd.vfsfd, num: 1}]
	ep.interestMu.Unlock()
	if epi == nil {
		t.Fatalf("epollInterest not found after AddInterest")
	}

	pfd.vfsfd.EventUnregister(&epi.waiter)

	epi.afterLoad(nil)

	pfd.clearReady()
	if events := ep.ReadEvents(nil, 16); len(events) != 0 {
		t.Fatalf("ReadEvents before Notify: got %d events, want 0", len(events))
	}

	pfd.setReady(waiter.ReadableEvents)

	events := ep.ReadEvents(nil, 16)
	if len(events) != 1 {
		t.Fatalf("ReadEvents after Notify: got %d events, want 1", len(events))
	}
	if events[0].Events&linux.EPOLLIN == 0 {
		t.Errorf("ReadEvents returned mask 0x%x, want EPOLLIN set", events[0].Events)
	}
	if events[0].Data[0] != 42 {
		t.Errorf("ReadEvents returned Data[0]=%d, want 42", events[0].Data[0])
	}
}

// TestEpollInterestAfterLoadPreservesReadyState verifies that a readiness
// notification received before restore is still delivered after restore,
// preserving the existing "mark ready after load" behavior.
func TestEpollInterestAfterLoadPreservesReadyState(t *testing.T) {
	ctx := contexttest.Context(t)
	vfsObj := &VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}

	epFD, err := vfsObj.NewEpollInstanceFD(ctx)
	if err != nil {
		t.Fatalf("NewEpollInstanceFD: %v", err)
	}
	defer epFD.DecRef(ctx)
	ep := epFD.Impl().(*EpollInstance)

	pfd, err := newPollableFD(ctx, vfsObj)
	if err != nil {
		t.Fatalf("newPollableFD: %v", err)
	}
	defer pfd.vfsfd.DecRef(ctx)

	if err := ep.AddInterest(&pfd.vfsfd, 1, linux.EpollEvent{Events: linux.EPOLLIN}); err != nil {
		t.Fatalf("AddInterest: %v", err)
	}

	ep.interestMu.Lock()
	epi := ep.interest[epollInterestKey{file: &pfd.vfsfd, num: 1}]
	ep.interestMu.Unlock()

	pfd.mu.Lock()
	pfd.ready = waiter.ReadableEvents
	pfd.mu.Unlock()

	epi.afterLoad(nil)

	events := ep.ReadEvents(nil, 16)
	if len(events) != 1 {
		t.Fatalf("ReadEvents after afterLoad: got %d events, want 1", len(events))
	}
	if events[0].Events&linux.EPOLLIN == 0 {
		t.Errorf("ReadEvents returned mask 0x%x, want EPOLLIN set", events[0].Events)
	}
}

// TestEpollInterestAfterLoadSkipsDeleted verifies that afterLoad ignores
// deleted interests (mask == 0), preserving the behavior introduced by
// commit 5d857245b.
func TestEpollInterestAfterLoadSkipsDeleted(t *testing.T) {
	ctx := contexttest.Context(t)
	vfsObj := &VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}

	epFD, err := vfsObj.NewEpollInstanceFD(ctx)
	if err != nil {
		t.Fatalf("NewEpollInstanceFD: %v", err)
	}
	defer epFD.DecRef(ctx)
	ep := epFD.Impl().(*EpollInstance)

	pfd, err := newPollableFD(ctx, vfsObj)
	if err != nil {
		t.Fatalf("newPollableFD: %v", err)
	}
	defer pfd.vfsfd.DecRef(ctx)

	if err := ep.AddInterest(&pfd.vfsfd, 1, linux.EpollEvent{Events: linux.EPOLLIN}); err != nil {
		t.Fatalf("AddInterest: %v", err)
	}

	ep.interestMu.Lock()
	epi := ep.interest[epollInterestKey{file: &pfd.vfsfd, num: 1}]
	ep.interestMu.Unlock()

	epi.mask = 0

	epi.afterLoad(nil)

	pfd.setReady(waiter.ReadableEvents)

	if events := ep.ReadEvents(nil, 16); len(events) != 0 {
		t.Errorf("ReadEvents for deleted interest: got %d events, want 0", len(events))
	}
}
