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
	goContext "context"
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/waiter"
)

// ErrCorruption indicates a failed restore due to external file system state in
// corruption.
type ErrCorruption struct {
	// Err is the wrapped error.
	Err error
}

// Error returns a sensible description of the restore error.
func (e ErrCorruption) Error() string {
	return "restore failed due to external file system state in corruption: " + e.Err.Error()
}

// PrependErrMsg prepends the passed prefix to the error while preserving
// special vfs errors as the outer most error.
func PrependErrMsg(prefix string, err error) error {
	switch terr := err.(type) {
	case ErrCorruption:
		terr.Err = fmt.Errorf("%s: %w", prefix, terr.Err)
		return terr
	default:
		return fmt.Errorf("%s: %w", prefix, err)
	}
}

// FilesystemImplSaveRestoreExtension is an optional extension to
// FilesystemImpl.
type FilesystemImplSaveRestoreExtension interface {
	// PrepareSave prepares this filesystem for serialization.
	PrepareSave(ctx context.Context) error

	// BeforeResume is called before the kernel is resumed after save. It can be
	// used to clean up any state that should be discarded after save.
	BeforeResume(ctx context.Context)

	// CompleteRestore completes restoration from checkpoint for this
	// filesystem after deserialization.
	CompleteRestore(ctx context.Context, opts CompleteRestoreOptions) error
}

// PrepareSave prepares all filesystems for serialization.
func (vfs *VirtualFilesystem) PrepareSave(ctx context.Context) error {
	for fs := range vfs.getFilesystems() {
		if ext, ok := fs.impl.(FilesystemImplSaveRestoreExtension); ok {
			if err := ext.PrepareSave(ctx); err != nil {
				fs.DecRef(ctx)
				return err
			}
		}
		fs.DecRef(ctx)
	}
	return nil
}

// BeforeResume is called before the kernel is resumed after save and allows
// filesystems to clean up S/R state.
func (vfs *VirtualFilesystem) BeforeResume(ctx context.Context) {
	for fs := range vfs.getFilesystems() {
		if ext, ok := fs.impl.(FilesystemImplSaveRestoreExtension); ok {
			ext.BeforeResume(ctx)
		}
		fs.DecRef(ctx)
	}
}

// CompleteRestore completes restoration from checkpoint for all filesystems
// after deserialization.
func (vfs *VirtualFilesystem) CompleteRestore(ctx context.Context, opts *CompleteRestoreOptions) error {
	for fs := range vfs.getFilesystems() {
		if ext, ok := fs.impl.(FilesystemImplSaveRestoreExtension); ok {
			if err := ext.CompleteRestore(ctx, *opts); err != nil {
				fs.DecRef(ctx)
				return PrependErrMsg(fmt.Sprintf("failed to complete restore for filesystem type %q", fs.fsType.Name()), err)
			}
		}
		fs.DecRef(ctx)
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

// saveKey is called by stateify.
func (mnt *Mount) saveKey() VirtualDentry { return mnt.getKey() }

// saveMountPromises is called by stateify.
func (vfs *VirtualFilesystem) saveMountPromises() map[VirtualDentry]*mountPromise {
	m := make(map[VirtualDentry]*mountPromise)
	vfs.mountPromises.Range(func(key any, val any) bool {
		m[key.(VirtualDentry)] = val.(*mountPromise)
		return true
	})
	return m
}

// loadMounts is called by stateify.
func (vfs *VirtualFilesystem) loadMounts(_ goContext.Context, mounts []*Mount) {
	if mounts == nil {
		return
	}
	vfs.mounts.Init()
	for _, mount := range mounts {
		vfs.mounts.Insert(mount)
	}
}

// loadKey is called by stateify.
func (mnt *Mount) loadKey(_ goContext.Context, vd VirtualDentry) { mnt.setKey(vd) }

// loadMountPromises is called by stateify.
func (vfs *VirtualFilesystem) loadMountPromises(_ goContext.Context, mps map[VirtualDentry]*mountPromise) {
	for vd, mp := range mps {
		vfs.mountPromises.Store(vd, mp)
	}
}

// afterLoad is called by stateify.
func (mnt *Mount) afterLoad(goContext.Context) {
	if mnt.refs.Load() != 0 {
		refs.Register(mnt)
	}
}

// afterLoad is called by stateify.
func (epi *epollInterest) afterLoad(goContext.Context) {
	// Mark all epollInterests as ready after restore so that the next call to
	// EpollInstance.ReadEvents() rechecks their readiness.
	epi.waiter.NotifyEvent(waiter.EventMaskFromLinux(epi.mask))
}

// RestoreID is a unique ID that is used to identify resources between save/restore sessions.
// Example of resources are host files, gofer connection for mount points, etc.
//
// +stateify savable
type RestoreID struct {
	// ContainerName is the name of the container that the resource belongs to.
	ContainerName string
	// Path is the path of the resource.
	Path string
}

func (f RestoreID) String() string {
	return fmt.Sprintf("%s:%s", f.ContainerName, f.Path)
}
