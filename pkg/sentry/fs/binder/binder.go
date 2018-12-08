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

// Package binder implements Android Binder IPC module.
package binder

import (
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

const (
	currentProtocolVersion = 8

	// mmapSizeLimit is the upper limit for mapped memory size in Binder.
	mmapSizeLimit = 4 * 1024 * 1024 // 4MB
)

// Device implements fs.InodeOperations.
//
// +stateify savable
type Device struct {
	fsutil.InodeNoExtendedAttributes `state:"nosave"`
	fsutil.InodeNotDirectory         `state:"nosave"`
	fsutil.InodeNotRenameable        `state:"nosave"`
	fsutil.InodeNotSocket            `state:"nosave"`
	fsutil.InodeNotSymlink           `state:"nosave"`
	fsutil.NoMappable                `state:"nosave"`
	fsutil.NoopWriteOut              `state:"nosave"`
	fsutil.DeprecatedFileOperations  `state:"nosave"`

	// mu protects unstable.
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
func (bd *Device) Release(context.Context) {}

// GetFile implements fs.InodeOperations.GetFile.
//
// TODO: Add functionality to GetFile: Additional fields will be
// needed in the Device structure, initialize them here. Also, Device will need
// to keep track of the created Procs in order to implement BINDER_READ_WRITE
// ioctl.
func (bd *Device) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, d, flags, &Proc{
		bd:       bd,
		task:     kernel.TaskFromContext(ctx),
		platform: platform.FromContext(ctx),
	}), nil
}

// UnstableAttr implements fs.InodeOperations.UnstableAttr.
func (bd *Device) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	bd.mu.Lock()
	defer bd.mu.Unlock()
	return bd.unstable, nil
}

// Check implements fs.InodeOperations.Check.
func (bd *Device) Check(ctx context.Context, inode *fs.Inode, p fs.PermMask) bool {
	return fs.ContextCanAccessFile(ctx, inode, p)
}

// SetPermissions implements fs.InodeOperations.SetPermissions.
func (bd *Device) SetPermissions(ctx context.Context, inode *fs.Inode, fp fs.FilePermissions) bool {
	bd.mu.Lock()
	defer bd.mu.Unlock()
	bd.unstable.Perms = fp
	bd.unstable.StatusChangeTime = time.NowFromContext(ctx)
	return true
}

// SetOwner implements fs.InodeOperations.SetOwner.
func (bd *Device) SetOwner(ctx context.Context, inode *fs.Inode, owner fs.FileOwner) error {
	bd.mu.Lock()
	defer bd.mu.Unlock()
	if owner.UID.Ok() {
		bd.unstable.Owner.UID = owner.UID
	}
	if owner.GID.Ok() {
		bd.unstable.Owner.GID = owner.GID
	}
	return nil
}

// SetTimestamps implements fs.InodeOperations.SetTimestamps.
func (bd *Device) SetTimestamps(ctx context.Context, inode *fs.Inode, ts fs.TimeSpec) error {
	if ts.ATimeOmit && ts.MTimeOmit {
		return nil
	}

	bd.mu.Lock()
	defer bd.mu.Unlock()

	now := time.NowFromContext(ctx)
	if !ts.ATimeOmit {
		if ts.ATimeSetSystemTime {
			bd.unstable.AccessTime = now
		} else {
			bd.unstable.AccessTime = ts.ATime
		}
	}
	if !ts.MTimeOmit {
		if ts.MTimeSetSystemTime {
			bd.unstable.ModificationTime = now
		} else {
			bd.unstable.ModificationTime = ts.MTime
		}
	}
	bd.unstable.StatusChangeTime = now
	return nil
}

// Truncate implements fs.InodeOperations.WriteOut.
//
// Ignored for a character device, such as Binder.
func (bd *Device) Truncate(ctx context.Context, inode *fs.Inode, size int64) error {
	return nil
}

// AddLink implements fs.InodeOperations.AddLink.
//
// Binder doesn't support links, no-op.
func (bd *Device) AddLink() {}

// DropLink implements fs.InodeOperations.DropLink.
//
// Binder doesn't support links, no-op.
func (bd *Device) DropLink() {}

// NotifyStatusChange implements fs.InodeOperations.NotifyStatusChange.
func (bd *Device) NotifyStatusChange(ctx context.Context) {
	bd.mu.Lock()
	defer bd.mu.Unlock()
	now := time.NowFromContext(ctx)
	bd.unstable.ModificationTime = now
	bd.unstable.StatusChangeTime = now
}

// IsVirtual implements fs.InodeOperations.IsVirtual.
//
// Binder is virtual.
func (bd *Device) IsVirtual() bool {
	return true
}

// StatFS implements fs.InodeOperations.StatFS.
//
// Binder doesn't support querying for filesystem info.
func (bd *Device) StatFS(context.Context) (fs.Info, error) {
	return fs.Info{}, syserror.ENOSYS
}

// Proc implements fs.FileOperations and fs.IoctlGetter.
//
// +stateify savable
type Proc struct {
	fsutil.NoFsync                  `state:"nosave"`
	fsutil.DeprecatedFileOperations `state:"nosave"`
	fsutil.NotDirReaddir            `state:"nosave"`
	fsutil.NoSplice                 `state:"nosave"`

	bd       *Device
	task     *kernel.Task
	platform platform.Platform

	// mu protects fr.
	mu sync.Mutex `state:"nosave"`

	// mapped is memory allocated from platform.Memory() by AddMapping.
	mapped platform.FileRange
}

// Release implements fs.FileOperations.Release.
func (bp *Proc) Release() {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	if bp.mapped.Length() != 0 {
		bp.platform.Memory().DecRef(bp.mapped)
	}
}

// Seek implements fs.FileOperations.Seek.
//
// Binder doesn't support seek operation (unless in debug mode).
func (bp *Proc) Seek(ctx context.Context, file *fs.File, whence fs.SeekWhence, offset int64) (int64, error) {
	return offset, syserror.EOPNOTSUPP
}

// Read implements fs.FileOperations.Read.
//
// Binder doesn't support read operation (unless in debug mode).
func (bp *Proc) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	return 0, syserror.EOPNOTSUPP
}

// Write implements fs.FileOperations.Write.
//
// Binder doesn't support write operation.
func (bp *Proc) Write(ctx context.Context, file *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
	return 0, syserror.EOPNOTSUPP
}

// Flush implements fs.FileOperations.Flush.
//
// TODO: Implement.
func (bp *Proc) Flush(ctx context.Context, file *fs.File) error {
	return nil
}

// ConfigureMMap implements fs.FileOperations.ConfigureMMap.
func (bp *Proc) ConfigureMMap(ctx context.Context, file *fs.File, opts *memmap.MMapOpts) error {
	// Compare drivers/android/binder.c:binder_mmap().
	if caller := kernel.TaskFromContext(ctx); caller != bp.task {
		return syserror.EINVAL
	}
	if opts.Length > mmapSizeLimit {
		opts.Length = mmapSizeLimit
	}
	opts.MaxPerms.Write = false

	// TODO: Binder sets VM_DONTCOPY, preventing the created vma
	// from being copied across fork(), but we don't support this yet. As
	// a result, MMs containing a Binder mapping cannot be forked (MM.Fork will
	// fail when AddMapping returns EBUSY).

	return fsutil.GenericConfigureMMap(file, bp, opts)
}

// Ioctl implements fs.FileOperations.Ioctl.
//
// TODO: Implement.
func (bp *Proc) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	// Switch on ioctl request.
	switch uint32(args[1].Int()) {
	case linux.BinderVersionIoctl:
		ver := &linux.BinderVersion{
			ProtocolVersion: currentProtocolVersion,
		}
		// Copy result to user-space.
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), ver, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err
	case linux.BinderWriteReadIoctl:
		// TODO: Implement.
		fallthrough
	case linux.BinderSetIdleTimeoutIoctl:
		// TODO: Implement.
		fallthrough
	case linux.BinderSetMaxThreadsIoctl:
		// TODO: Implement.
		fallthrough
	case linux.BinderSetIdlePriorityIoctl:
		// TODO: Implement.
		fallthrough
	case linux.BinderSetContextMgrIoctl:
		// TODO: Implement.
		fallthrough
	case linux.BinderThreadExitIoctl:
		// TODO: Implement.
		return 0, syserror.ENOSYS
	default:
		// Ioctls irrelevant to Binder.
		return 0, syserror.EINVAL
	}
}

// AddMapping implements memmap.Mappable.AddMapping.
func (bp *Proc) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64, _ bool) error {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	if bp.mapped.Length() != 0 {
		// mmap has been called before, which binder_mmap() doesn't like.
		return syserror.EBUSY
	}
	// Binder only allocates and maps a single page up-front
	// (drivers/android/binder.c:binder_mmap() => binder_update_page_range()).
	fr, err := bp.platform.Memory().Allocate(usermem.PageSize, usage.Anonymous)
	if err != nil {
		return err
	}
	bp.mapped = fr
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (*Proc) RemoveMapping(context.Context, memmap.MappingSpace, usermem.AddrRange, uint64, bool) {
	// Nothing to do. Notably, we don't free bp.mapped to allow another mmap.
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (bp *Proc) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR usermem.AddrRange, offset uint64, _ bool) error {
	// Nothing to do. Notably, this is one case where CopyMapping isn't
	// equivalent to AddMapping, as AddMapping would return EBUSY.
	return nil
}

// Translate implements memmap.Mappable.Translate.
func (bp *Proc) Translate(ctx context.Context, required, optional memmap.MappableRange, at usermem.AccessType) ([]memmap.Translation, error) {
	// TODO: In addition to the page initially allocated and mapped
	// in AddMapping (Linux: binder_mmap), Binder allocates and maps pages for
	// each transaction (Linux: binder_ioctl => binder_ioctl_write_read =>
	// binder_thread_write => binder_transaction => binder_alloc_buf =>
	// binder_update_page_range). Since we don't actually implement
	// BinderWriteReadIoctl (Linux: BINDER_WRITE_READ), we only ever have the
	// first page.
	var err error
	if required.End > usermem.PageSize {
		err = &memmap.BusError{syserror.EFAULT}
	}
	if required.Start == 0 {
		return []memmap.Translation{
			{
				Source: memmap.MappableRange{0, usermem.PageSize},
				File:   bp.platform.Memory(),
				Offset: bp.mapped.Start,
			},
		}, err
	}
	return nil, err
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (bp *Proc) InvalidateUnsavable(ctx context.Context) error {
	return nil
}
