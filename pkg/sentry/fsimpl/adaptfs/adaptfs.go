// Copyright 2019 The gVisor Authors.
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

// Package adaptfs provides implementations of VFS2 (sentry/vfs) types by
// wrapping VFS1 (sentry/fs) types.
//
// Limitations:
//
// - Dentries are always dropped when their reference count reaches 0 (i.e.
// dentry caching is not supported).
//
// - Hard links are not supported.
//
// - VFS1's "overlayfs" feature is not supported.
package adaptfs

import (
	"fmt"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/syserror"

	vfs1 "gvisor.dev/gvisor/pkg/sentry/fs"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	vfs2 "gvisor.dev/gvisor/pkg/sentry/vfs"
)

type filesystemType struct {
	vfs1fs vfs1.Filesystem
}

// NewFilesystemType returns a vfs2.FilesystemType that wraps the given
// vfs1.Filesystem.
func NewFilesystemType(vfs1fs vfs1.Filesystem) vfs2.FilesystemType {
	return &filesystemType{
		vfs1fs: vfs1fs,
	}
}

// MustRegisterFilesystemType registers a vfs2.FilesystemType with vfsObj that
// wraps the given (globally-registered) vfs1.Filesystem with the given name.
// If no such vfs1.Filesystem exists, or if registration with vfsObj fails,
// MustRegisterFilesystemType panics.
func MustRegisterFilesystemType(vfsObj *vfs2.VirtualFilesystem, name string) {
	vfs1fs, ok := vfs1.FindFilesystem(name)
	if !ok {
		var names []string
		for _, vfs1fs := range vfs1.GetFilesystems() {
			names = append(names, vfs1fs.Name())
		}
		panic(fmt.Sprintf("no registered vfs1.Filesystem named %s; registered vfs1.Filesystems are: %v", name, names))
	}
	vfsObj.MustRegisterFilesystemType(name, NewFilesystemType(vfs1fs))
}

type filesystem struct {
	vfs2fs vfs2.Filesystem

	// mu protects the dentry tree.
	mu sync.Mutex

	// root is the root of the dentry tree. A reference is held on root. root
	// is immutable.
	root *dentry
}

// GetFilesystem implements vfs2.FilesystemType.GetFilesystem.
func (fst *filesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs2.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs2.GetFilesystemOptions) (*vfs2.Filesystem, *vfs2.Dentry, error) {
	rootInode, err := fst.vfs1fs.Mount(ctx, source, vfs1.MountSourceFlags{}, opts.Data, opts.InternalData)
	if err != nil {
		return nil, nil, err
	}
	fs := &filesystem{}
	fs.vfs2fs.Init(vfsObj, fs)
	rootVFS1D := vfs1.NewDirent(ctx, rootInode, "")
	root := fs.newDentry(rootVFS1D)
	root.IncRef() // extra reference held by fs.root
	fs.root = root
	return &fs.vfs2fs, &root.vfs2d, nil
}

// Release implements vfs2.FilesystemImpl.Release.
func (fs *filesystem) Release() {
	fs.root.DecRef()
}

type dentry struct {
	vfs2d vfs2.Dentry
	refs  int64
	vfs1d *vfs1.Dirent
	fs    *filesystem
}

func (fs *filesystem) newDentry(vfs1d *vfs1.Dirent) *dentry {
	d := &dentry{
		refs:  1,
		vfs1d: vfs1d,
		fs:    fs,
	}
	d.vfs2d.Init(d)
	return d
}

// IncRef implements vfs2.DentryImpl.IncRef.
func (d *dentry) IncRef() {
	if atomic.AddInt64(&d.refs, 1) <= 1 {
		panic("adaptfs.dentry.IncRef() called without holding a reference")
	}
}

// TryIncRef implements vfs2.DentryImpl.TryIncRef.
func (d *dentry) TryIncRef() bool {
	for {
		refs := atomic.LoadInt64(&d.refs)
		if refs == 0 {
			return false
		}
		if refs < 0 {
			panic("adaptfs.dentry.TryIncRef() called with negative refcount")
		}
		if atomic.CompareAndSwapInt64(&d.refs, refs, refs+1) {
			return true
		}
	}
}

// DecRef implements vfs2.DentryImpl.DecRef.
func (d *dentry) DecRef() {
	for {
		refs := atomic.LoadInt64(&d.refs)
		if refs == 1 {
			d.fs.mu.Lock()
			d.decRefLocked()
			d.fs.mu.Unlock()
			return
		}
		if refs <= 0 {
			panic("adaptfs.dentry.DecRef() called without holding a reference")
		}
		if atomic.CompareAndSwapInt64(&d.refs, refs, refs-1) {
			return
		}
	}
}

// Preconditions: d.fs.mu must be locked.
func (d *dentry) decRefLocked() {
recurse:
	if refs := atomic.AddInt64(&d.refs, -1); refs == 0 {
		if parentVFS2D := d.vfs2d.Parent(); parentVFS2D != nil {
			if !d.vfs2d.IsDisowned() {
				d.fs.vfs2fs.VirtualFilesystem().ForceDeleteDentry(&d.vfs2d)
			}
			d.vfs1d.DecRef()
			// Tail-recurse to drop d's reference on its parent.
			d = parentVFS2D.Impl().(*dentry)
			goto recurse
		}
		return
	} else if refs < 0 {
		panic("adaptfs.dentry.decRefLocked() called without holding a reference")
	}
}

func (d *dentry) inode() *vfs1.Inode {
	return d.vfs1d.Inode
}

func (d *dentry) iops() vfs1.InodeOperations {
	return d.inode().InodeOperations
}

func (d *dentry) isDirectory() bool {
	return vfs1.IsDir(d.inode().StableAttr)
}

func (d *dentry) isSymlink() bool {
	return vfs1.IsSymlink(d.inode().StableAttr)
}

func (d *dentry) check(ctx context.Context, p vfs1.PermMask) error {
	if !d.iops().Check(ctx, d.inode(), p) {
		return syserror.EACCES
	}
	return nil
}

func (d *dentry) statTo(ctx context.Context, stat *linux.Statx) error {
	uattr, err := d.inode().UnstableAttr(ctx)
	if err != nil {
		return err
	}
	sattr := &d.inode().StableAttr
	*stat = linux.Statx{
		Mask:      linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_NLINK | linux.STATX_UID | linux.STATX_GID | linux.STATX_ATIME | linux.STATX_MTIME | linux.STATX_CTIME | linux.STATX_INO | linux.STATX_SIZE | linux.STATX_BLOCKS,
		Blksize:   uint32(sattr.BlockSize),
		Nlink:     uint32(uattr.Links),
		UID:       uint32(uattr.Owner.UID),
		GID:       uint32(uattr.Owner.GID),
		Mode:      uint16(sattr.Type.LinuxType()) | uint16(uattr.Perms.LinuxMode()),
		Ino:       sattr.InodeID,
		Size:      uint64(uattr.Size),
		Blocks:    (uint64(uattr.Usage) + 511) / 512,
		Atime:     statxTimestampFromKTime(uattr.AccessTime),
		Ctime:     statxTimestampFromKTime(uattr.StatusChangeTime),
		Mtime:     statxTimestampFromKTime(uattr.ModificationTime),
		RdevMajor: uint32(sattr.DeviceFileMajor),
		RdevMinor: sattr.DeviceFileMinor,
		// TODO: device numbers?
	}
	return nil
}

func (d *dentry) setStat(ctx context.Context, creds *auth.Credentials, stat *linux.Statx, mnt *vfs2.Mount) error {
	if stat.Mask&^(linux.STATX_MODE|linux.STATX_UID|linux.STATX_GID|linux.STATX_ATIME|linux.STATX_MTIME|linux.STATX_SIZE) != 0 {
		return syserror.EPERM
	}
	uattr, err := d.inode().UnstableAttr(ctx)
	if err != nil {
		return err
	}
	if err := vfs2.CheckSetStat(creds, stat, uint16(uattr.Perms.LinuxMode()), uattr.Owner.UID, uattr.Owner.GID); err != nil {
		return err
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()

	var retErr error
	if stat.Mask&linux.STATX_MODE != 0 {
		if !d.inode().SetPermissions(ctx, d.vfs1d, vfs1.FilePermsFromMode(linux.FileMode(stat.Mode))) {
			retErr = syserror.EPERM
		}
	}
	if stat.Mask&(linux.STATX_UID|linux.STATX_GID) != 0 {
		o := vfs1.FileOwner{
			UID: auth.NoID,
			GID: auth.NoID,
		}
		if stat.Mask&linux.STATX_UID != 0 {
			o.UID = auth.KUID(stat.UID)
		}
		if stat.Mask&linux.STATX_GID != 0 {
			o.GID = auth.KGID(stat.GID)
		}
		if err := d.inode().SetOwner(ctx, d.vfs1d, o); err != nil && retErr == nil {
			retErr = err
		}
	}
	if stat.Mask&(linux.STATX_ATIME|linux.STATX_MTIME) != 0 {
		if err := d.inode().SetTimestamps(ctx, d.vfs1d, vfs1.TimeSpec{
			ATime:              ktimeFromStatxTimestamp(stat.Atime),
			ATimeOmit:          stat.Mask&linux.STATX_ATIME == 0,
			ATimeSetSystemTime: stat.Atime.Nsec == linux.UTIME_NOW,
			MTime:              ktimeFromStatxTimestamp(stat.Mtime),
			MTimeOmit:          stat.Mask&linux.STATX_MTIME == 0,
			MTimeSetSystemTime: stat.Mtime.Nsec == linux.UTIME_NOW,
		}); err != nil && retErr == nil {
			retErr = err
		}
	}
	if stat.Mask&linux.STATX_SIZE != 0 {
		if err := d.inode().Truncate(ctx, d.vfs1d, int64(stat.Size)); err != nil && retErr == nil {
			retErr = err
		}
	}
	return retErr
}

func (d *dentry) statfs(ctx context.Context) (linux.Statfs, error) {
	info, err := d.inode().StatFS(ctx)
	if err != nil {
		return linux.Statfs{}, err
	}
	return linux.Statfs{
		Type: info.Type,
		// We don't report anything in units of blocks, since vfs1.Info doesn't
		// contain block size so what's the point?
		Files:     info.TotalFiles,
		FilesFree: info.FreeFiles,
	}, nil
}

func vfs1FileFlagsFromOpenFlags(flags uint32) vfs1.FileFlags {
	return vfs1.FileFlags{
		Direct:      flags&linux.O_DIRECT != 0,
		NonBlocking: flags&linux.O_NONBLOCK != 0,
		DSync:       flags&(linux.O_DSYNC|linux.O_SYNC) != 0,
		Sync:        flags&linux.O_SYNC != 0,
		Append:      flags&linux.O_APPEND != 0,
		Read:        vfs2.MayReadFileWithOpenFlags(flags),
		Write:       vfs2.MayWriteFileWithOpenFlags(flags),
		Directory:   flags&linux.O_DIRECTORY != 0,
		Async:       flags&linux.O_ASYNC != 0,
		LargeFile:   true,
		Truncate:    flags&linux.O_TRUNC != 0,
	}
}

func vfs1PermMaskFromVFS2AccessTypes(ats vfs2.AccessTypes) vfs1.PermMask {
	return vfs1.PermMask{
		Read:    ats&vfs2.MayRead != 0,
		Write:   ats&vfs2.MayWrite != 0,
		Execute: ats&vfs2.MayExec != 0,
	}
}

func statxTimestampFromKTime(t ktime.Time) linux.StatxTimestamp {
	return linux.NsecToStatxTimestamp(t.Nanoseconds())
}

func ktimeFromStatxTimestamp(st linux.StatxTimestamp) ktime.Time {
	return ktime.FromUnix(st.Sec, int64(st.Nsec))
}
