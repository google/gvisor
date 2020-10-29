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
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/refsvfs2"
)

// FilesystemImplSaveRestoreExtension is an optional extension to
// FilesystemImpl.
type FilesystemImplSaveRestoreExtension interface {
	// PrepareSave prepares this filesystem for serialization.
	PrepareSave(ctx context.Context) error

	// CompleteRestore completes restoration from checkpoint for this
	// filesystem after deserialization.
	CompleteRestore(ctx context.Context, opts CompleteRestoreOptions) error
}

// PrepareSave prepares all filesystems for serialization.
func (vfs *VirtualFilesystem) PrepareSave(ctx context.Context) error {
	failures := 0
	for fs := range vfs.getFilesystems() {
		if ext, ok := fs.impl.(FilesystemImplSaveRestoreExtension); ok {
			if err := ext.PrepareSave(ctx); err != nil {
				ctx.Warningf("%T.PrepareSave failed: %v", fs.impl, err)
				failures++
			}
		}
		fs.DecRef(ctx)
	}
	if failures != 0 {
		return fmt.Errorf("%d filesystems failed to prepare for serialization", failures)
	}
	return nil
}

// CompleteRestore completes restoration from checkpoint for all filesystems
// after deserialization.
func (vfs *VirtualFilesystem) CompleteRestore(ctx context.Context, opts *CompleteRestoreOptions) error {
	failures := 0
	for fs := range vfs.getFilesystems() {
		if ext, ok := fs.impl.(FilesystemImplSaveRestoreExtension); ok {
			if err := ext.CompleteRestore(ctx, *opts); err != nil {
				ctx.Warningf("%T.CompleteRestore failed: %v", fs.impl, err)
				failures++
			}
		}
		fs.DecRef(ctx)
	}
	if failures != 0 {
		return fmt.Errorf("%d filesystems failed to complete restore after deserialization", failures)
	}
	return nil
}

// CompleteRestoreOptions contains options to
// VirtualFilesystem.CompleteRestore() and
// FilesystemImplSaveRestoreExtension.CompleteRestore().
type CompleteRestoreOptions struct {
	// If ValidateFileSizes is true, filesystem implementations backed by
	// remote filesystems should verify that file sizes have not changed
	// between checkpoint and restore.
	ValidateFileSizes bool

	// If ValidateFileModificationTimestamps is true, filesystem
	// implementations backed by remote filesystems should validate that file
	// mtimes have not changed between checkpoint and restore.
	ValidateFileModificationTimestamps bool
}

// saveMounts is called by stateify.
func (vfs *VirtualFilesystem) saveMounts() []*Mount {
	if atomic.LoadPointer(&vfs.mounts.slots) == nil {
		// vfs.Init() was never called.
		return nil
	}
	var mounts []*Mount
	vfs.mounts.Range(func(mount *Mount) bool {
		mounts = append(mounts, mount)
		return true
	})
	return mounts
}

// loadMounts is called by stateify.
func (vfs *VirtualFilesystem) loadMounts(mounts []*Mount) {
	if mounts == nil {
		return
	}
	vfs.mounts.Init()
	for _, mount := range mounts {
		vfs.mounts.Insert(mount)
	}
}

func (mnt *Mount) afterLoad() {
	if atomic.LoadInt64(&mnt.refs) != 0 {
		refsvfs2.Register(mnt)
	}
}

// afterLoad is called by stateify.
func (epi *epollInterest) afterLoad() {
	// Mark all epollInterests as ready after restore so that the next call to
	// EpollInstance.ReadEvents() rechecks their readiness.
	epi.Callback(nil)
}
