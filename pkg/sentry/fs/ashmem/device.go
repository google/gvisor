// Copyright 2018 Google LLC
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

// Package ashmem implements Android ashmem module (Anonymus Shared Memory).
package ashmem

import (
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// Device implements fs.InodeOperations.
//
// +stateify savable
type Device struct {
	fsutil.DeprecatedFileOperations  `state:"nosave"`
	fsutil.InodeNoExtendedAttributes `state:"nosave"`
	fsutil.InodeNotDirectory         `state:"nosave"`
	fsutil.InodeNotRenameable        `state:"nosave"`
	fsutil.InodeNotSocket            `state:"nosave"`
	fsutil.InodeNotSymlink           `state:"nosave"`
	fsutil.NoFsync                   `state:"nosave"`
	fsutil.NoMappable                `state:"nosave"`
	fsutil.NoopWriteOut              `state:"nosave"`
	fsutil.NotDirReaddir             `state:"nosave"`
	fsutil.NoSplice                  `state:"nosave"`

	mu       sync.Mutex `state:"nosave"`
	unstable fs.UnstableAttr
}

// NewDevice creates and intializes a Device structure.
func NewDevice(ctx context.Context, owner fs.FileOwner, fp fs.FilePermissions) *Device {
	return &Device{
		unstable: fs.WithCurrentTime(ctx, fs.UnstableAttr{
			Owner: owner,
			Perms: fp,
			Links: 1,
		}),
	}
}

// Release implements fs.InodeOperations.Release.
func (ad *Device) Release(context.Context) {}

// GetFile implements fs.InodeOperations.GetFile.
func (ad *Device) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, d, flags, &Area{
		ad:        ad,
		tmpfsFile: nil,
		perms:     usermem.AnyAccess,
	}), nil
}

// UnstableAttr implements fs.InodeOperations.UnstableAttr.
func (ad *Device) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	return ad.unstable, nil
}

// Check implements fs.InodeOperations.Check.
func (ad *Device) Check(ctx context.Context, inode *fs.Inode, p fs.PermMask) bool {
	return fs.ContextCanAccessFile(ctx, inode, p)
}

// SetPermissions implements fs.InodeOperations.SetPermissions.
func (ad *Device) SetPermissions(ctx context.Context, inode *fs.Inode, fp fs.FilePermissions) bool {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.unstable.Perms = fp
	ad.unstable.StatusChangeTime = time.NowFromContext(ctx)
	return true
}

// SetOwner implements fs.InodeOperations.SetOwner.
func (ad *Device) SetOwner(ctx context.Context, inode *fs.Inode, owner fs.FileOwner) error {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	if owner.UID.Ok() {
		ad.unstable.Owner.UID = owner.UID
	}
	if owner.GID.Ok() {
		ad.unstable.Owner.GID = owner.GID
	}
	return nil
}

// SetTimestamps implements fs.InodeOperations.SetTimestamps.
func (ad *Device) SetTimestamps(ctx context.Context, inode *fs.Inode, ts fs.TimeSpec) error {
	if ts.ATimeOmit && ts.MTimeOmit {
		return nil
	}

	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.NowFromContext(ctx)
	if !ts.ATimeOmit {
		if ts.ATimeSetSystemTime {
			ad.unstable.AccessTime = now
		} else {
			ad.unstable.AccessTime = ts.ATime
		}
	}
	if !ts.MTimeOmit {
		if ts.MTimeSetSystemTime {
			ad.unstable.ModificationTime = now
		} else {
			ad.unstable.ModificationTime = ts.MTime
		}
	}
	ad.unstable.StatusChangeTime = now
	return nil
}

// Truncate implements fs.InodeOperations.WriteOut.
//
// Ignored by ashmem.
func (ad *Device) Truncate(ctx context.Context, inode *fs.Inode, size int64) error {
	return nil
}

// AddLink implements fs.InodeOperations.AddLink.
//
// Ashmem doesn't support links, no-op.
func (ad *Device) AddLink() {}

// DropLink implements fs.InodeOperations.DropLink.
//
// Ashmem doesn't support links, no-op.
func (ad *Device) DropLink() {}

// NotifyStatusChange implements fs.InodeOperations.NotifyStatusChange.
func (ad *Device) NotifyStatusChange(ctx context.Context) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	now := time.NowFromContext(ctx)
	ad.unstable.ModificationTime = now
	ad.unstable.StatusChangeTime = now
}

// IsVirtual implements fs.InodeOperations.IsVirtual.
//
// Ashmem is virtual.
func (ad *Device) IsVirtual() bool {
	return true
}

// StatFS implements fs.InodeOperations.StatFS.
//
// Ashmem doesn't support querying for filesystem info.
func (ad *Device) StatFS(context.Context) (fs.Info, error) {
	return fs.Info{}, syserror.ENOSYS
}
