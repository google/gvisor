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

package overlay

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

func (d *dentry) isRegularFile() bool {
	return atomic.LoadUint32(&d.mode)&linux.S_IFMT == linux.S_IFREG
}

func (d *dentry) isSymlink() bool {
	return atomic.LoadUint32(&d.mode)&linux.S_IFMT == linux.S_IFLNK
}

func (d *dentry) readlink(ctx context.Context) (string, error) {
	layerVD := d.topLayer()
	return d.fs.vfsfs.VirtualFilesystem().ReadlinkAt(ctx, d.fs.creds, &vfs.PathOperation{
		Root:  layerVD,
		Start: layerVD,
	})
}

// +stateify savable
type regularFileFD struct {
	fileDescription
	vfs.SpliceInFD

	// If copiedUp is false, cachedFD represents
	// fileDescription.dentry().lowerVDs[0]; otherwise, cachedFD represents
	// fileDescription.dentry().upperVD. cachedFlags is the last known value of
	// cachedFD.StatusFlags(). copiedUp, cachedFD, and cachedFlags are
	// protected by mu.
	mu          sync.Mutex `state:"nosave"`
	copiedUp    bool
	cachedFD    *vfs.FileDescription
	cachedFlags uint32

	// If copiedUp is false, lowerWaiters contains all waiter.Entries
	// registered with cachedFD. lowerWaiters is protected by mu.
	lowerWaiters map[*waiter.Entry]struct{}
}

func (fd *regularFileFD) getCurrentFD(ctx context.Context) (*vfs.FileDescription, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	wrappedFD, err := fd.currentFDLocked(ctx)
	if err != nil {
		return nil, err
	}
	wrappedFD.IncRef()
	return wrappedFD, nil
}

func (fd *regularFileFD) currentFDLocked(ctx context.Context) (*vfs.FileDescription, error) {
	d := fd.dentry()
	statusFlags := fd.vfsfd.StatusFlags()
	if !fd.copiedUp && d.isCopiedUp() {
		// Switch to the copied-up file.
		upperVD := d.topLayer()
		upperFD, err := fd.filesystem().vfsfs.VirtualFilesystem().OpenAt(ctx, d.fs.creds, &vfs.PathOperation{
			Root:  upperVD,
			Start: upperVD,
		}, &vfs.OpenOptions{
			Flags: statusFlags,
		})
		if err != nil {
			return nil, err
		}
		oldOff, oldOffErr := fd.cachedFD.Seek(ctx, 0, linux.SEEK_CUR)
		if oldOffErr == nil {
			if _, err := upperFD.Seek(ctx, oldOff, linux.SEEK_SET); err != nil {
				upperFD.DecRef(ctx)
				return nil, err
			}
		}
		if len(fd.lowerWaiters) != 0 {
			ready := upperFD.Readiness(^waiter.EventMask(0))
			for e := range fd.lowerWaiters {
				fd.cachedFD.EventUnregister(e)
				if err := upperFD.EventRegister(e); err != nil {
					return nil, err
				}
				e.NotifyEvent(ready)
			}
		}
		fd.cachedFD.DecRef(ctx)
		fd.copiedUp = true
		fd.cachedFD = upperFD
		fd.cachedFlags = statusFlags
		fd.lowerWaiters = nil
	} else if fd.cachedFlags != statusFlags {
		if err := fd.cachedFD.SetStatusFlags(ctx, d.fs.creds, statusFlags); err != nil {
			return nil, err
		}
		fd.cachedFlags = statusFlags
	}
	return fd.cachedFD, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *regularFileFD) Release(ctx context.Context) {
	fd.cachedFD.DecRef(ctx)
	fd.cachedFD = nil
}

// OnClose implements vfs.FileDescriptionImpl.OnClose.
func (fd *regularFileFD) OnClose(ctx context.Context) error {
	// Linux doesn't define ovl_file_operations.flush at all (i.e. its
	// equivalent to OnClose is a no-op). We pass through to
	// fd.cachedFD.OnClose() without upgrading if fd.dentry() has been
	// copied-up, since OnClose is mostly used to define post-close writeback,
	// and if fd.cachedFD hasn't been updated then it can't have been used to
	// mutate fd.dentry() anyway.
	fd.mu.Lock()
	if statusFlags := fd.vfsfd.StatusFlags(); fd.cachedFlags != statusFlags {
		if err := fd.cachedFD.SetStatusFlags(ctx, fd.filesystem().creds, statusFlags); err != nil {
			fd.mu.Unlock()
			return err
		}
		fd.cachedFlags = statusFlags
	}
	wrappedFD := fd.cachedFD
	fd.mu.Unlock()
	return wrappedFD.OnClose(ctx)
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *regularFileFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	var stat linux.Statx
	if layerMask := opts.Mask &^ statInternalMask; layerMask != 0 {
		wrappedFD, err := fd.getCurrentFD(ctx)
		if err != nil {
			return linux.Statx{}, err
		}
		stat, err = wrappedFD.Stat(ctx, vfs.StatOptions{
			Mask: layerMask,
			Sync: opts.Sync,
		})
		wrappedFD.DecRef(ctx)
		if err != nil {
			return linux.Statx{}, err
		}
	}
	fd.dentry().statInternalTo(ctx, &opts, &stat)
	return stat, nil
}

// Allocate implements vfs.FileDescriptionImpl.Allocate.
func (fd *regularFileFD) Allocate(ctx context.Context, mode, offset, length uint64) error {
	wrappedFD, err := fd.getCurrentFD(ctx)
	if err != nil {
		return err
	}
	defer wrappedFD.DecRef(ctx)
	return wrappedFD.Allocate(ctx, mode, offset, length)
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *regularFileFD) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	d := fd.dentry()
	mode := linux.FileMode(atomic.LoadUint32(&d.mode))
	if err := vfs.CheckSetStat(ctx, auth.CredentialsFromContext(ctx), &opts, mode, auth.KUID(atomic.LoadUint32(&d.uid)), auth.KGID(atomic.LoadUint32(&d.gid))); err != nil {
		return err
	}
	mnt := fd.vfsfd.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	if err := d.copyUpLocked(ctx); err != nil {
		return err
	}
	// Changes to d's attributes are serialized by d.copyMu.
	d.copyMu.Lock()
	defer d.copyMu.Unlock()
	wrappedFD, err := fd.currentFDLocked(ctx)
	if err != nil {
		return err
	}
	if err := wrappedFD.SetStat(ctx, opts); err != nil {
		return err
	}

	// Changing owners or truncating may clear one or both of the setuid and
	// setgid bits, so we may have to update opts before setting d.mode.
	inotifyMask := opts.Stat.Mask
	if opts.Stat.Mask&(linux.STATX_UID|linux.STATX_GID|linux.STATX_SIZE) != 0 {
		stat, err := wrappedFD.Stat(ctx, vfs.StatOptions{
			Mask: linux.STATX_MODE,
		})
		if err != nil {
			return err
		}
		opts.Stat.Mode = stat.Mode
		opts.Stat.Mask |= linux.STATX_MODE
		// Don't generate inotify IN_ATTRIB for size-only changes (truncations).
		if opts.Stat.Mask&(linux.STATX_UID|linux.STATX_GID) != 0 {
			inotifyMask |= linux.STATX_MODE
		}
	}

	d.updateAfterSetStatLocked(&opts)
	if ev := vfs.InotifyEventFromStatMask(inotifyMask); ev != 0 {
		d.InotifyWithParent(ctx, ev, 0, vfs.InodeEvent)
	}
	return nil
}

// StatFS implements vfs.FileDescriptionImpl.StatFS.
func (fd *regularFileFD) StatFS(ctx context.Context) (linux.Statfs, error) {
	return fd.filesystem().statFS(ctx)
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *regularFileFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	ctx := context.Background()
	wrappedFD, err := fd.getCurrentFD(ctx)
	if err != nil {
		// TODO(b/171089913): Just use fd.cachedFD since Readiness can't return
		// an error. This is obviously wrong, but at least consistent with
		// VFS1.
		log.Warningf("overlay.regularFileFD.Readiness: currentFDLocked failed: %v", err)
		fd.mu.Lock()
		wrappedFD = fd.cachedFD
		wrappedFD.IncRef()
		fd.mu.Unlock()
	}
	defer wrappedFD.DecRef(ctx)
	return wrappedFD.Readiness(mask)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *regularFileFD) EventRegister(e *waiter.Entry) error {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	wrappedFD, err := fd.currentFDLocked(context.Background())
	if err != nil {
		// TODO(b/171089913): Just use fd.cachedFD since EventRegister can't
		// return an error. This is obviously wrong, but at least consistent
		// with VFS1.
		log.Warningf("overlay.regularFileFD.EventRegister: currentFDLocked failed: %v", err)
		wrappedFD = fd.cachedFD
	}
	if err := wrappedFD.EventRegister(e); err != nil {
		return err
	}
	if !fd.copiedUp {
		if fd.lowerWaiters == nil {
			fd.lowerWaiters = make(map[*waiter.Entry]struct{})
		}
		fd.lowerWaiters[e] = struct{}{}
	}
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *regularFileFD) EventUnregister(e *waiter.Entry) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	fd.cachedFD.EventUnregister(e)
	if !fd.copiedUp {
		delete(fd.lowerWaiters, e)
	}
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *regularFileFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	wrappedFD, err := fd.getCurrentFD(ctx)
	if err != nil {
		return 0, err
	}
	defer wrappedFD.DecRef(ctx)
	return wrappedFD.PRead(ctx, dst, offset, opts)
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *regularFileFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	// Hold fd.mu during the read to serialize the file offset.
	fd.mu.Lock()
	defer fd.mu.Unlock()
	wrappedFD, err := fd.currentFDLocked(ctx)
	if err != nil {
		return 0, err
	}
	return wrappedFD.Read(ctx, dst, opts)
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *regularFileFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	wrappedFD, err := fd.getCurrentFD(ctx)
	if err != nil {
		return 0, err
	}
	defer wrappedFD.DecRef(ctx)
	n, err := wrappedFD.PWrite(ctx, src, offset, opts)
	if err != nil {
		return n, err
	}
	return fd.updateSetUserGroupIDs(ctx, wrappedFD, n)
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *regularFileFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	// Hold fd.mu during the write to serialize the file offset.
	fd.mu.Lock()
	defer fd.mu.Unlock()
	wrappedFD, err := fd.currentFDLocked(ctx)
	if err != nil {
		return 0, err
	}
	n, err := wrappedFD.Write(ctx, src, opts)
	if err != nil {
		return n, err
	}
	return fd.updateSetUserGroupIDs(ctx, wrappedFD, n)
}

func (fd *regularFileFD) updateSetUserGroupIDs(ctx context.Context, wrappedFD *vfs.FileDescription, written int64) (int64, error) {
	// Writing can clear the setuid and/or setgid bits. We only have to
	// check this if something was written and one of those bits was set.
	dentry := fd.dentry()
	if written == 0 || atomic.LoadUint32(&dentry.mode)&(linux.S_ISUID|linux.S_ISGID) == 0 {
		return written, nil
	}
	stat, err := wrappedFD.Stat(ctx, vfs.StatOptions{Mask: linux.STATX_MODE})
	if err != nil {
		return written, err
	}
	dentry.copyMu.Lock()
	defer dentry.copyMu.Unlock()
	atomic.StoreUint32(&dentry.mode, uint32(stat.Mode))
	return written, nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *regularFileFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	// Hold fd.mu during the seek to serialize the file offset.
	fd.mu.Lock()
	defer fd.mu.Unlock()
	wrappedFD, err := fd.currentFDLocked(ctx)
	if err != nil {
		return 0, err
	}
	return wrappedFD.Seek(ctx, offset, whence)
}

// Sync implements vfs.FileDescriptionImpl.Sync.
func (fd *regularFileFD) Sync(ctx context.Context) error {
	fd.mu.Lock()
	if !fd.dentry().isCopiedUp() {
		fd.mu.Unlock()
		return nil
	}
	wrappedFD, err := fd.currentFDLocked(ctx)
	if err != nil {
		fd.mu.Unlock()
		return err
	}
	wrappedFD.IncRef()
	defer wrappedFD.DecRef(ctx)
	fd.mu.Unlock()
	return wrappedFD.Sync(ctx)
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *regularFileFD) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	wrappedFD, err := fd.getCurrentFD(ctx)
	if err != nil {
		return 0, err
	}
	defer wrappedFD.DecRef(ctx)
	return wrappedFD.Ioctl(ctx, uio, args)
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *regularFileFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	if err := fd.ensureMappable(ctx, opts); err != nil {
		return err
	}
	return vfs.GenericConfigureMMap(&fd.vfsfd, fd.dentry(), opts)
}

// ensureMappable ensures that fd.dentry().wrappedMappable is not nil.
func (fd *regularFileFD) ensureMappable(ctx context.Context, opts *memmap.MMapOpts) error {
	d := fd.dentry()

	// Fast path if we already have a Mappable for the current top layer.
	if atomic.LoadUint32(&d.isMappable) != 0 {
		return nil
	}

	// Only permit mmap of regular files, since other file types may have
	// unpredictable behavior when mmapped (e.g. /dev/zero).
	if atomic.LoadUint32(&d.mode)&linux.S_IFMT != linux.S_IFREG {
		return linuxerr.ENODEV
	}

	// Get a Mappable for the current top layer.
	fd.mu.Lock()
	defer fd.mu.Unlock()
	d.copyMu.RLock()
	defer d.copyMu.RUnlock()
	if atomic.LoadUint32(&d.isMappable) != 0 {
		return nil
	}
	wrappedFD, err := fd.currentFDLocked(ctx)
	if err != nil {
		return err
	}
	if err := wrappedFD.ConfigureMMap(ctx, opts); err != nil {
		return err
	}
	if opts.MappingIdentity != nil {
		opts.MappingIdentity.DecRef(ctx)
		opts.MappingIdentity = nil
	}
	// Use this Mappable for all mappings of this layer (unless we raced with
	// another call to ensureMappable).
	d.mapsMu.Lock()
	defer d.mapsMu.Unlock()
	d.dataMu.Lock()
	defer d.dataMu.Unlock()
	if d.wrappedMappable == nil {
		d.wrappedMappable = opts.Mappable
		atomic.StoreUint32(&d.isMappable, 1)
	}
	return nil
}

// AddMapping implements memmap.Mappable.AddMapping.
func (d *dentry) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	d.mapsMu.Lock()
	defer d.mapsMu.Unlock()
	if err := d.wrappedMappable.AddMapping(ctx, ms, ar, offset, writable); err != nil {
		return err
	}
	if !d.isCopiedUp() {
		d.lowerMappings.AddMapping(ms, ar, offset, writable)
	}
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (d *dentry) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
	d.mapsMu.Lock()
	defer d.mapsMu.Unlock()
	d.wrappedMappable.RemoveMapping(ctx, ms, ar, offset, writable)
	if !d.isCopiedUp() {
		d.lowerMappings.RemoveMapping(ms, ar, offset, writable)
	}
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (d *dentry) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	d.mapsMu.Lock()
	defer d.mapsMu.Unlock()
	if err := d.wrappedMappable.CopyMapping(ctx, ms, srcAR, dstAR, offset, writable); err != nil {
		return err
	}
	if !d.isCopiedUp() {
		d.lowerMappings.AddMapping(ms, dstAR, offset, writable)
	}
	return nil
}

// Translate implements memmap.Mappable.Translate.
func (d *dentry) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	d.dataMu.RLock()
	defer d.dataMu.RUnlock()
	return d.wrappedMappable.Translate(ctx, required, optional, at)
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (d *dentry) InvalidateUnsavable(ctx context.Context) error {
	d.mapsMu.Lock()
	defer d.mapsMu.Unlock()
	return d.wrappedMappable.InvalidateUnsavable(ctx)
}
