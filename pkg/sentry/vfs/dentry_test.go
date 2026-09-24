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
	"errors"
	"fmt"
	"math"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

type dentryTestFilesystemType struct{}

// GetFilesystem implements FilesystemType.GetFilesystem.
func (fstype dentryTestFilesystemType) GetFilesystem(ctx context.Context, vfsObj *VirtualFilesystem, creds *auth.Credentials, source string, opts GetFilesystemOptions) (*Filesystem, *Dentry, error) {
	fs := &dentryTestFilesystem{}
	fs.vfsfs.Init(vfsObj, fstype, fs)
	return &fs.vfsfs, newDentryTestDentry().dentry(), nil
}

// Name implements FilesystemType.Name.
func (dentryTestFilesystemType) Name() string {
	return "dentrytest"
}

// Release implements FilesystemType.Release.
func (dentryTestFilesystemType) Release(ctx context.Context) {}

type dentryTestFilesystem struct {
	FilesystemImpl

	vfsfs Filesystem
}

// Release implements FilesystemImpl.Release.
func (*dentryTestFilesystem) Release(ctx context.Context) {}

// IsDescendant implements FilesystemImpl.IsDescendant.
func (*dentryTestFilesystem) IsDescendant(vfsroot, vd VirtualDentry) bool {
	return true
}

type dentryTestDentry struct {
	vfsd    Dentry
	watches Watches

	refs atomicbitops.Int64
}

func newDentryTestDentry() *dentryTestDentry {
	d := &dentryTestDentry{refs: atomicbitops.FromInt64(1)}
	d.vfsd.Init(d)
	return d
}

func (d *dentryTestDentry) dentry() *Dentry {
	return &d.vfsd
}

func (d *dentryTestDentry) IncRef() {
	d.refs.Add(1)
}

func (d *dentryTestDentry) TryIncRef() bool {
	for {
		r := d.refs.Load()
		if r <= 0 {
			return false
		}
		if d.refs.CompareAndSwap(r, r+1) {
			return true
		}
	}
}

func (d *dentryTestDentry) DecRef(ctx context.Context) {
	d.refs.Add(-1)
}

func (d *dentryTestDentry) InotifyWithParent(ctx context.Context, events, cookie uint32, et EventType) {
}

func (d *dentryTestDentry) Watches() *Watches {
	return &d.watches
}

func (d *dentryTestDentry) OnZeroWatches(context.Context) {}

type dentryTestSystem struct {
	ctx      context.Context
	creds    *auth.Credentials
	vfsObj   *VirtualFilesystem
	mntns    *MountNamespace
	rootVD   VirtualDentry
	childD   *dentryTestDentry
	renameD1 *dentryTestDentry
	renameD2 *dentryTestDentry
}

func newDentryTestSystem(t *testing.T) *dentryTestSystem {
	t.Helper()
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)
	vfsObj := &VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType("dentrytest", dentryTestFilesystemType{}, &RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "dentrytest", &MountOptions{}, nil)
	if err != nil {
		t.Fatalf("failed to create mount namespace: %v", err)
	}
	ctx = WithMountNamespace(ctx, mntns)

	return &dentryTestSystem{
		ctx:      ctx,
		creds:    creds,
		vfsObj:   vfsObj,
		mntns:    mntns,
		rootVD:   mntns.Root(ctx),
		childD:   newDentryTestDentry(),
		renameD1: newDentryTestDentry(),
		renameD2: newDentryTestDentry(),
	}
}

func (s *dentryTestSystem) destroy() {
	s.renameD2.DecRef(s.ctx)
	s.renameD1.DecRef(s.ctx)
	s.childD.DecRef(s.ctx)
	s.rootVD.DecRef(s.ctx)
	s.mntns.DecRef(s.ctx)
}

func (s *dentryTestSystem) newResolvingPath() *ResolvingPath {
	pop := &PathOperation{
		Root:         s.rootVD,
		Start:        s.rootVD,
		Path:         fspath.Parse("dir/.."),
		ResolveFlags: linux.RESOLVE_BENEATH,
	}
	return s.vfsObj.getResolvingPath(s.creds, pop)
}

func (s *dentryTestSystem) walk(rp *ResolvingPath) error {
	return walkDirDotDot(s.ctx, rp, s.rootVD, s.childD)
}

// +checklocksignore
func (s *dentryTestSystem) beginRename(t *testing.T) RenameHandle {
	t.Helper()
	handle, err := s.vfsObj.PrepareRenameDentry(s.mntns, s.renameD1.dentry(), s.renameD2.dentry())
	if err != nil {
		t.Fatalf("PrepareRenameDentry failed: %v", err)
	}
	s.vfsObj.RenameBegin(&handle)
	return handle
}

// +checklocksignore
func (s *dentryTestSystem) endRename(handle *RenameHandle) {
	s.vfsObj.AbortRenameDentry(handle, s.renameD1.dentry(), s.renameD2.dentry())
}

// +checklocksignore
func (s *dentryTestSystem) completeRename(t *testing.T) {
	t.Helper()
	handle := s.beginRename(t)
	s.endRename(&handle)
}

func walkDirDotDot(ctx context.Context, rp *ResolvingPath, rootVD VirtualDentry, childD *dentryTestDentry) error {
	// Advance past "dir" to childD.
	if rp.Done() {
		return errors.New("rp unexpectedly done at start")
	}
	if got, want := rp.Component(), "dir"; got != want {
		return fmt.Errorf("rp.Component(): got %q, want %q", got, want)
	}
	if err := rp.CheckMount(ctx, childD.dentry()); err != nil {
		return fmt.Errorf("CheckMount failed on child: %w", err)
	}
	rp.Advance()

	// Advance past ".." back to rootVD.Dentry().
	if rp.Done() {
		return errors.New("rp unexpectedly done before '..'")
	}
	if got, want := rp.Component(), ".."; got != want {
		return fmt.Errorf("rp.Component(): got %q, want %q", got, want)
	}
	isRoot, err := rp.CheckRoot(ctx, childD.dentry())
	if err != nil {
		return err
	}
	if isRoot {
		return errors.New("CheckRoot returned isRoot=true for child dentry")
	}
	if err := rp.CheckMount(ctx, rootVD.Dentry()); err != nil {
		return fmt.Errorf("CheckMount failed on parent: %w", err)
	}
	rp.Advance()

	if !rp.Done() {
		return errors.New("rp not done after traversing all components")
	}
	if err := rp.finalizeScoped(ctx, rootVD); err != nil {
		return fmt.Errorf("finalizeScoped failed: %w", err)
	}
	return nil
}

func TestRenameState(t *testing.T) {
	ctx := contexttest.Context(t)
	vfsObj := &VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}

	// Beginning a rename operation should increment both the sequence counter and the
	// number of in-progress renames.
	fakeRenameHandle := &RenameHandle{}
	oldSeq, oldInProgress := unpackRenameState(vfsObj.renameState.Load())
	vfsObj.RenameBegin(fakeRenameHandle)
	seq, inProgress := unpackRenameState(vfsObj.renameState.Load())
	if seq != oldSeq+1 {
		t.Fatalf("renameState seq not incremented by rename begin")
	}
	if inProgress != oldInProgress+1 {
		t.Fatalf("renameState inProgress not incremented by rename begin")
	}

	// Ending a rename operation should decrement the number of in-progress renames.
	_, oldInProgress = seq, inProgress
	vfsObj.renameEnd()
	_, inProgress = unpackRenameState(vfsObj.renameState.Load())
	if inProgress != oldInProgress-1 {
		t.Fatalf("renameState inProgress not decremented by rename end")
	}

	// Calling RenameBegin() with seq = MaxUint32 should overflow.
	fakeRenameHandle = &RenameHandle{}
	vfsObj.renameState.Store(packRenameState(math.MaxUint32, 0))
	vfsObj.RenameBegin(fakeRenameHandle)
	seq, _ = unpackRenameState(vfsObj.renameState.Load())
	if seq != 0 {
		t.Fatalf("renameState seq did not overflow")
	}

	// Calling RenameBegin() with MaxUint32 renames in-progress should panic.
	func() {
		fakeRenameHandle = &RenameHandle{}
		vfsObj.renameState.Store(packRenameState(10, math.MaxUint32))
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("RenameBegin() did not panic when in-progress count reached max")
			}
		}()
		vfsObj.RenameBegin(fakeRenameHandle)
	}()

	// Calling renameEnd() with 0 renames in-progress should panic.
	func() {
		vfsObj.renameState.Store(packRenameState(10, 0))
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("renameEnd() did not panic when called with in-progress count = 0")
			}
		}()
		vfsObj.renameEnd()
	}()
}

// The below tests exercise RESOLVE_BENEATH and verify the correctness of
// the rename-race detection logic.

func TestDotDotBeneathRaceWithRename(t *testing.T) {
	t.Run("NoConcurrentRename", func(t *testing.T) {
		s := newDentryTestSystem(t)
		defer s.destroy()

		rp := s.newResolvingPath()
		defer rp.Release(s.ctx)

		if err := s.walk(rp); err != nil {
			t.Fatalf("walk failed: %v", err)
		}
	})

	t.Run("RenameCompletedBeforeSnapshot", func(t *testing.T) {
		s := newDentryTestSystem(t)
		defer s.destroy()

		// Rename completes entirely before getResolvingPath() snapshots renameState.
		s.completeRename(t)

		rp := s.newResolvingPath()
		defer rp.Release(s.ctx)

		if err := s.walk(rp); err != nil {
			t.Fatalf("walk failed: %v", err)
		}
	})

	t.Run("RenameBeginsAndEndsBetweenSnapshotAndCheck", func(t *testing.T) {
		s := newDentryTestSystem(t)
		defer s.destroy()

		rp := s.newResolvingPath()
		defer rp.Release(s.ctx)

		// Rename begins and ends between the snapshot and check in checkRoot().
		s.completeRename(t)

		if err := s.walk(rp); !errors.Is(err, linuxerr.EAGAIN) {
			t.Fatalf("walk: got error %v, want %v", err, linuxerr.EAGAIN)
		}
	})

	t.Run("RenameBeginsAfterSnapshotInProgressAtCheck", func(t *testing.T) {
		s := newDentryTestSystem(t)
		defer s.destroy()

		rp := s.newResolvingPath()
		defer rp.Release(s.ctx)

		// Rename begins after snapshot, still in progress at the check in checkRoot().
		handle := s.beginRename(t)
		defer s.endRename(&handle)

		if err := s.walk(rp); !errors.Is(err, linuxerr.EAGAIN) {
			t.Fatalf("walk: got error %v, want %v", err, linuxerr.EAGAIN)
		}
	})

	t.Run("RenameInProgressAtSnapshotAndCheck", func(t *testing.T) {
		s := newDentryTestSystem(t)
		defer s.destroy()

		// Rename in progress at snapshot, still in progress at check.
		handle := s.beginRename(t)
		defer s.endRename(&handle)

		rp := s.newResolvingPath()
		defer rp.Release(s.ctx)

		if err := s.walk(rp); !errors.Is(err, linuxerr.EAGAIN) {
			t.Fatalf("walk: got error %v, want %v", err, linuxerr.EAGAIN)
		}
	})

	t.Run("RenameInProgressAtSnapshotEndsBeforeCheck", func(t *testing.T) {
		s := newDentryTestSystem(t)
		defer s.destroy()

		// Rename in progress at snapshot, ends before check.
		handle := s.beginRename(t)

		rp := s.newResolvingPath()
		defer rp.Release(s.ctx)

		s.endRename(&handle)

		if err := s.walk(rp); !errors.Is(err, linuxerr.EAGAIN) {
			t.Fatalf("walk: got error %v, want %v", err, linuxerr.EAGAIN)
		}
	})
}
