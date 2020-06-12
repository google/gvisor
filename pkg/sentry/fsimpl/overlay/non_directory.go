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
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

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

type nonDirectoryFD struct {
	fileDescription

	// If copiedUp is false, cachedFD represents
	// fileDescription.dentry().lowerVDs[0]; otherwise, cachedFD represents
	// fileDescription.dentry().upperVD. cachedFlags is the last known value of
	// cachedFD.StatusFlags(). copiedUp, cachedFD, and cachedFlags are
	// protected by mu.
	mu          sync.Mutex
	copiedUp    bool
	cachedFD    *vfs.FileDescription
	cachedFlags uint32
}

func (fd *nonDirectoryFD) getCurrentFD(ctx context.Context) (*vfs.FileDescription, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	wrappedFD, err := fd.currentFDLocked(ctx)
	if err != nil {
		return nil, err
	}
	wrappedFD.IncRef()
	return wrappedFD, nil
}

func (fd *nonDirectoryFD) currentFDLocked(ctx context.Context) (*vfs.FileDescription, error) {
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
				upperFD.DecRef()
				return nil, err
			}
		}
		fd.cachedFD.DecRef()
		fd.copiedUp = true
		fd.cachedFD = upperFD
		fd.cachedFlags = statusFlags
	} else if fd.cachedFlags != statusFlags {
		if err := fd.cachedFD.SetStatusFlags(ctx, d.fs.creds, statusFlags); err != nil {
			return nil, err
		}
		fd.cachedFlags = statusFlags
	}
	return fd.cachedFD, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *nonDirectoryFD) Release() {
	fd.cachedFD.DecRef()
	fd.cachedFD = nil
}

// OnClose implements vfs.FileDescriptionImpl.OnClose.
func (fd *nonDirectoryFD) OnClose(ctx context.Context) error {
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
	defer wrappedFD.IncRef()
	fd.mu.Unlock()
	return wrappedFD.OnClose(ctx)
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *nonDirectoryFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
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
		wrappedFD.DecRef()
		if err != nil {
			return linux.Statx{}, err
		}
	}
	fd.dentry().statInternalTo(ctx, &opts, &stat)
	return stat, nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *nonDirectoryFD) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	d := fd.dentry()
	mode := linux.FileMode(atomic.LoadUint32(&d.mode))
	if err := vfs.CheckSetStat(ctx, auth.CredentialsFromContext(ctx), &opts.Stat, mode, auth.KUID(atomic.LoadUint32(&d.uid)), auth.KGID(atomic.LoadUint32(&d.gid))); err != nil {
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
	d.updateAfterSetStatLocked(&opts)
	return nil
}

// StatFS implements vfs.FileDesciptionImpl.StatFS.
func (fd *nonDirectoryFD) StatFS(ctx context.Context) (linux.Statfs, error) {
	return fd.filesystem().statFS(ctx)
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *nonDirectoryFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	wrappedFD, err := fd.getCurrentFD(ctx)
	if err != nil {
		return 0, err
	}
	defer wrappedFD.DecRef()
	return wrappedFD.PRead(ctx, dst, offset, opts)
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *nonDirectoryFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
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
func (fd *nonDirectoryFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	wrappedFD, err := fd.getCurrentFD(ctx)
	if err != nil {
		return 0, err
	}
	defer wrappedFD.DecRef()
	return wrappedFD.PWrite(ctx, src, offset, opts)
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *nonDirectoryFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	// Hold fd.mu during the write to serialize the file offset.
	fd.mu.Lock()
	defer fd.mu.Unlock()
	wrappedFD, err := fd.currentFDLocked(ctx)
	if err != nil {
		return 0, err
	}
	return wrappedFD.Write(ctx, src, opts)
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *nonDirectoryFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
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
func (fd *nonDirectoryFD) Sync(ctx context.Context) error {
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
	defer wrappedFD.DecRef()
	fd.mu.Unlock()
	return wrappedFD.Sync(ctx)
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *nonDirectoryFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	wrappedFD, err := fd.getCurrentFD(ctx)
	if err != nil {
		return err
	}
	defer wrappedFD.DecRef()
	return wrappedFD.ConfigureMMap(ctx, opts)
}
