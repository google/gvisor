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

package ashmem

import (
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/tmpfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

const (
	// namePrefix is the name prefix assumed and forced by the Linux implementation.
	namePrefix = "dev/ashmem"

	// nameLen is the maximum name length.
	nameLen = 256
)

// Area implements fs.FileOperations.
//
// +stateify savable
type Area struct {
	waiter.AlwaysReady       `state:"nosave"`
	fsutil.FileNoFsync       `state:"nosave"`
	fsutil.FileNoopFlush     `state:"nosave"`
	fsutil.FileNotDirReaddir `state:"nosave"`

	ad *Device

	// mu protects fields below.
	mu        sync.Mutex `state:"nosave"`
	tmpfsFile *fs.File
	name      string
	size      uint64
	perms     usermem.AccessType
	pb        *PinBoard
}

// Release implements fs.FileOperations.Release.
func (a *Area) Release() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tmpfsFile != nil {
		a.tmpfsFile.DecRef()
		a.tmpfsFile = nil
	}
}

// Seek implements fs.FileOperations.Seek.
func (a *Area) Seek(ctx context.Context, file *fs.File, whence fs.SeekWhence, offset int64) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.size == 0 {
		return 0, syserror.EINVAL
	}
	if a.tmpfsFile == nil {
		return 0, syserror.EBADF
	}
	return a.tmpfsFile.FileOperations.Seek(ctx, file, whence, offset)
}

// Read implements fs.FileOperations.Read.
func (a *Area) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.size == 0 {
		return 0, nil
	}
	if a.tmpfsFile == nil {
		return 0, syserror.EBADF
	}
	return a.tmpfsFile.FileOperations.Read(ctx, file, dst, offset)
}

// Write implements fs.FileOperations.Write.
func (a *Area) Write(ctx context.Context, file *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
	return 0, syserror.ENOSYS
}

// ConfigureMMap implements fs.FileOperations.ConfigureMMap.
func (a *Area) ConfigureMMap(ctx context.Context, file *fs.File, opts *memmap.MMapOpts) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.size == 0 {
		return syserror.EINVAL
	}

	if !a.perms.SupersetOf(opts.Perms) {
		return syserror.EPERM
	}
	opts.MaxPerms = opts.MaxPerms.Intersect(a.perms)

	if a.tmpfsFile == nil {
		k := kernel.KernelFromContext(ctx)
		if k == nil {
			return syserror.ENOMEM
		}
		tmpfsInodeOps := tmpfs.NewInMemoryFile(ctx, usage.Tmpfs, fs.UnstableAttr{}, k)
		tmpfsInode := fs.NewInode(tmpfsInodeOps, fs.NewPseudoMountSource(), fs.StableAttr{})
		dirent := fs.NewDirent(tmpfsInode, namePrefix+"/"+a.name)
		tmpfsFile, err := tmpfsInode.GetFile(ctx, dirent, fs.FileFlags{Read: true, Write: true})
		// Drop the extra reference on the Dirent.
		dirent.DecRef()

		if err != nil {
			return err
		}

		// Truncate to the size set by ASHMEM_SET_SIZE ioctl.
		err = tmpfsInodeOps.Truncate(ctx, tmpfsInode, int64(a.size))
		if err != nil {
			return err
		}
		a.tmpfsFile = tmpfsFile
		a.pb = NewPinBoard()
	}

	return a.tmpfsFile.ConfigureMMap(ctx, opts)
}

// Ioctl implements fs.FileOperations.Ioctl.
func (a *Area) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	// Switch on ioctl request.
	switch args[1].Uint() {
	case linux.AshmemSetNameIoctl:
		name, err := usermem.CopyStringIn(ctx, io, args[2].Pointer(), nameLen-1, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		if err != nil {
			return 0, err
		}

		a.mu.Lock()
		defer a.mu.Unlock()

		// Cannot set name for already mapped ashmem.
		if a.tmpfsFile != nil {
			return 0, syserror.EINVAL
		}
		a.name = name
		return 0, nil

	case linux.AshmemGetNameIoctl:
		a.mu.Lock()
		var local []byte
		if a.name != "" {
			nameLen := len([]byte(a.name))
			local = make([]byte, nameLen, nameLen+1)
			copy(local, []byte(a.name))
			local = append(local, 0)
		} else {
			nameLen := len([]byte(namePrefix))
			local = make([]byte, nameLen, nameLen+1)
			copy(local, []byte(namePrefix))
			local = append(local, 0)
		}
		a.mu.Unlock()

		if _, err := io.CopyOut(ctx, args[2].Pointer(), local, usermem.IOOpts{
			AddressSpaceActive: true,
		}); err != nil {
			return 0, syserror.EFAULT
		}
		return 0, nil

	case linux.AshmemSetSizeIoctl:
		a.mu.Lock()
		defer a.mu.Unlock()

		// Cannot set size for already mapped ashmem.
		if a.tmpfsFile != nil {
			return 0, syserror.EINVAL
		}
		a.size = uint64(args[2].SizeT())
		return 0, nil

	case linux.AshmemGetSizeIoctl:
		return uintptr(a.size), nil

	case linux.AshmemPinIoctl, linux.AshmemUnpinIoctl, linux.AshmemGetPinStatusIoctl:
		// Locking and unlocking is ok since once tmpfsFile is set, it won't be nil again
		// even after unmapping! Unlocking is needed in order to avoid a deadlock on
		// usermem.CopyObjectIn.

		// Cannot execute pin-related ioctls before mapping.
		a.mu.Lock()
		if a.tmpfsFile == nil {
			a.mu.Unlock()
			return 0, syserror.EINVAL
		}
		a.mu.Unlock()

		var pin linux.AshmemPin
		_, err := usermem.CopyObjectIn(ctx, io, args[2].Pointer(), &pin, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		if err != nil {
			return 0, syserror.EFAULT
		}

		a.mu.Lock()
		defer a.mu.Unlock()
		return a.pinOperation(pin, args[1].Uint())

	case linux.AshmemPurgeAllCachesIoctl:
		return 0, nil

	case linux.AshmemSetProtMaskIoctl:
		prot := uint64(args[2].ModeT())
		perms := usermem.AccessType{
			Read:    prot&linux.PROT_READ != 0,
			Write:   prot&linux.PROT_WRITE != 0,
			Execute: prot&linux.PROT_EXEC != 0,
		}

		a.mu.Lock()
		defer a.mu.Unlock()

		// Can only narrow prot mask.
		if !a.perms.SupersetOf(perms) {
			return 0, syserror.EINVAL
		}

		// TODO: If personality flag
		// READ_IMPLIES_EXEC is set, set PROT_EXEC if PORT_READ is set.

		a.perms = perms
		return 0, nil

	case linux.AshmemGetProtMaskIoctl:
		return uintptr(a.perms.Prot()), nil
	default:
		// Ioctls irrelevant to Ashmem.
		return 0, syserror.EINVAL
	}
}

// pinOperation should only be called while holding a.mu.
func (a *Area) pinOperation(pin linux.AshmemPin, op uint32) (uintptr, error) {
	// Page-align a.size for checks.
	pageAlignedSize, ok := usermem.Addr(a.size).RoundUp()
	if !ok {
		return 0, syserror.EINVAL
	}
	// Len 0 means everything onward.
	if pin.Len == 0 {
		pin.Len = uint32(pageAlignedSize) - pin.Offset
	}
	// Both Offset and Len have to be page-aligned.
	if pin.Offset%uint32(usermem.PageSize) != 0 {
		return 0, syserror.EINVAL
	}
	if pin.Len%uint32(usermem.PageSize) != 0 {
		return 0, syserror.EINVAL
	}
	// Adding Offset and Len must not cause an uint32 overflow.
	if end := pin.Offset + pin.Len; end < pin.Offset {
		return 0, syserror.EINVAL
	}
	// Pin range must not exceed a's size.
	if uint32(pageAlignedSize) < pin.Offset+pin.Len {
		return 0, syserror.EINVAL
	}
	// Handle each operation.
	r := RangeFromAshmemPin(pin)
	switch op {
	case linux.AshmemPinIoctl:
		if a.pb.PinRange(r) {
			return linux.AshmemWasPurged, nil
		}
		return linux.AshmemNotPurged, nil

	case linux.AshmemUnpinIoctl:
		// TODO: Implement purge on unpin.
		a.pb.UnpinRange(r)
		return 0, nil

	case linux.AshmemGetPinStatusIoctl:
		if a.pb.RangePinnedStatus(r) {
			return linux.AshmemIsPinned, nil
		}
		return linux.AshmemIsUnpinned, nil

	default:
		panic("unreachable")
	}

}
