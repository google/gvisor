// Copyright 2018 Google Inc.
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

package tty

import (
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// inodeOperations are the base fs.InodeOperations for master and slave Inodes.
//
// inodeOperations does not implement:
//
// * fs.InodeOperations.Release
// * fs.InodeOperations.GetFile
//
// +stateify savable
type inodeOperations struct {
	fsutil.DeprecatedFileOperations  `state:"nosave"`
	fsutil.InodeNoExtendedAttributes `state:"nosave"`
	fsutil.InodeNotDirectory         `state:"nosave"`
	fsutil.InodeNotRenameable        `state:"nosave"`
	fsutil.InodeNotSocket            `state:"nosave"`
	fsutil.InodeNotSymlink           `state:"nosave"`
	fsutil.NoMappable                `state:"nosave"`
	fsutil.NoopWriteOut              `state:"nosave"`

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	// uattr is the inode's UnstableAttr.
	uattr fs.UnstableAttr
}

// UnstableAttr implements fs.InodeOperations.UnstableAttr.
func (i *inodeOperations) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.uattr, nil
}

// Check implements fs.InodeOperations.Check.
func (i *inodeOperations) Check(ctx context.Context, inode *fs.Inode, p fs.PermMask) bool {
	return fs.ContextCanAccessFile(ctx, inode, p)
}

// SetPermissions implements fs.InodeOperations.SetPermissions
func (i *inodeOperations) SetPermissions(ctx context.Context, inode *fs.Inode, p fs.FilePermissions) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.uattr.Perms = p
	i.uattr.StatusChangeTime = ktime.NowFromContext(ctx)
	return true
}

// SetOwner implements fs.InodeOperations.SetOwner.
func (i *inodeOperations) SetOwner(ctx context.Context, inode *fs.Inode, owner fs.FileOwner) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if owner.UID.Ok() {
		i.uattr.Owner.UID = owner.UID
	}
	if owner.GID.Ok() {
		i.uattr.Owner.GID = owner.GID
	}
	return nil
}

// SetTimestamps implements fs.InodeOperations.SetTimestamps.
func (i *inodeOperations) SetTimestamps(ctx context.Context, inode *fs.Inode, ts fs.TimeSpec) error {
	if ts.ATimeOmit && ts.MTimeOmit {
		return nil
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	now := ktime.NowFromContext(ctx)
	if !ts.ATimeOmit {
		if ts.ATime.IsZero() {
			i.uattr.AccessTime = now
		} else {
			i.uattr.AccessTime = ts.ATime
		}
	}
	if !ts.MTimeOmit {
		if ts.MTime.IsZero() {
			i.uattr.ModificationTime = now
		} else {
			i.uattr.ModificationTime = ts.MTime
		}
	}
	i.uattr.StatusChangeTime = now
	return nil
}

// Truncate implements fs.InodeOperations.Truncate.
func (i *inodeOperations) Truncate(ctx context.Context, inode *fs.Inode, size int64) error {
	return syserror.EINVAL
}

// AddLink implements fs.InodeOperations.AddLink.
func (i *inodeOperations) AddLink() {
}

// DropLink implements fs.InodeOperations.DropLink.
func (i *inodeOperations) DropLink() {
}

// NotifyStatusChange implements fs.InodeOperations.NotifyStatusChange.
func (i *inodeOperations) NotifyStatusChange(ctx context.Context) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.uattr.StatusChangeTime = ktime.NowFromContext(ctx)
}

// IsVirtual implements fs.InodeOperations.IsVirtual.
func (i *inodeOperations) IsVirtual() bool {
	return true
}

// StatFS implements fs.InodeOperations.StatFS.
func (i *inodeOperations) StatFS(ctx context.Context) (fs.Info, error) {
	return fs.Info{
		Type: linux.DEVPTS_SUPER_MAGIC,
	}, nil
}
