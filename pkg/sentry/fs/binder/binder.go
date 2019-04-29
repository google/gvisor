// Copyright 2018 The gVisor Authors.
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
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/pgalloc"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
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
	fsutil.InodeGenericChecker       `state:"nosave"`
	fsutil.InodeNoExtendedAttributes `state:"nosave"`
	fsutil.InodeNoopRelease          `state:"nosave"`
	fsutil.InodeNoopTruncate         `state:"nosave"`
	fsutil.InodeNoopWriteOut         `state:"nosave"`
	fsutil.InodeNotDirectory         `state:"nosave"`
	fsutil.InodeNotMappable          `state:"nosave"`
	fsutil.InodeNotSocket            `state:"nosave"`
	fsutil.InodeNotSymlink           `state:"nosave"`
	fsutil.InodeVirtual              `state:"nosave"`

	fsutil.InodeSimpleAttributes
}

var _ fs.InodeOperations = (*Device)(nil)

// NewDevice creates and intializes a Device structure.
func NewDevice(ctx context.Context, owner fs.FileOwner, fp fs.FilePermissions) *Device {
	return &Device{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, owner, fp, 0),
	}
}

// GetFile implements fs.InodeOperations.GetFile.
//
// TODO(b/30946773): Add functionality to GetFile: Additional fields will be
// needed in the Device structure, initialize them here. Also, Device will need
// to keep track of the created Procs in order to implement BINDER_READ_WRITE
// ioctl.
func (bd *Device) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, d, flags, &Proc{
		bd:   bd,
		task: kernel.TaskFromContext(ctx),
		mfp:  pgalloc.MemoryFileProviderFromContext(ctx),
	}), nil
}

// Proc implements fs.FileOperations and fs.IoctlGetter.
//
// +stateify savable
type Proc struct {
	waiter.AlwaysReady              `state:"nosave"`
	fsutil.FileNoFsync              `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`

	bd   *Device
	task *kernel.Task
	mfp  pgalloc.MemoryFileProvider

	// mu protects fr.
	mu sync.Mutex `state:"nosave"`

	// mapped is memory allocated from mfp.MemoryFile() by AddMapping.
	mapped platform.FileRange
}

// Release implements fs.FileOperations.Release.
func (bp *Proc) Release() {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	if bp.mapped.Length() != 0 {
		bp.mfp.MemoryFile().DecRef(bp.mapped)
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
// TODO(b/30946773): Implement.
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

	// TODO(b/30946773): Binder sets VM_DONTCOPY, preventing the created vma
	// from being copied across fork(), but we don't support this yet. As
	// a result, MMs containing a Binder mapping cannot be forked (MM.Fork will
	// fail when AddMapping returns EBUSY).

	return fsutil.GenericConfigureMMap(file, bp, opts)
}

// Ioctl implements fs.FileOperations.Ioctl.
//
// TODO(b/30946773): Implement.
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
		// TODO(b/30946773): Implement.
		fallthrough
	case linux.BinderSetIdleTimeoutIoctl:
		// TODO(b/30946773): Implement.
		fallthrough
	case linux.BinderSetMaxThreadsIoctl:
		// TODO(b/30946773): Implement.
		fallthrough
	case linux.BinderSetIdlePriorityIoctl:
		// TODO(b/30946773): Implement.
		fallthrough
	case linux.BinderSetContextMgrIoctl:
		// TODO(b/30946773): Implement.
		fallthrough
	case linux.BinderThreadExitIoctl:
		// TODO(b/30946773): Implement.
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
	fr, err := bp.mfp.MemoryFile().Allocate(usermem.PageSize, usage.Anonymous)
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
	// TODO(b/30946773): In addition to the page initially allocated and mapped
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
				File:   bp.mfp.MemoryFile(),
				Offset: bp.mapped.Start,
				Perms:  usermem.AnyAccess,
			},
		}, err
	}
	return nil, err
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (bp *Proc) InvalidateUnsavable(ctx context.Context) error {
	return nil
}
