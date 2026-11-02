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
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func (d *dentry) isCopiedUp() bool {
	return d.copiedUp.Load() != 0
}

// isMetacopy returns true if d is copied up but its regular file data is still
// on d.lowerVDs[0].
func (d *dentry) isMetacopy() bool {
	return d.metacopy.Load()
}

// isDataCopiedUp returns true if d's data is on the upper layer.
func (d *dentry) isDataCopiedUp() bool {
	return d.isCopiedUp() && !d.isMetacopy()
}

func (d *dentry) isOnLower() bool {
	return len(d.lowerVDs) > 0
}

func (d *dentry) canBeCopiedUp() bool {
	ftype := d.mode.Load() & linux.S_IFMT
	switch ftype {
	case linux.S_IFREG, linux.S_IFDIR, linux.S_IFLNK, linux.S_IFBLK, linux.S_IFCHR:
		// Can be copied-up.
		return true
	default:
		// Can't be copied-up.
		return false
	}
}

// copyUpLocked ensures that d exists on the upper layer, i.e. d.upperVD.Ok().
// If fs.opts.Metacopy is true, a regular file's data stays on the lower layer.
//
// Preconditions: filesystem.renameMu must be locked.
func (d *dentry) copyUpLocked(ctx context.Context) error {
	return d.doCopyUpLocked(ctx, false /* forSyntheticMountpoint */, true /* metacopy */, false /* skipData */, false /* mayUnlockRenameMu */)
}

// copyUpForHardlinkLocked is copyUpLocked for a hard link. Links share the
// upper file, so regular file data is copied.
//
// Preconditions: filesystem.renameMu must be locked.
func (d *dentry) copyUpForHardlinkLocked(ctx context.Context) error {
	if err := d.doCopyUpLocked(ctx, false /* forSyntheticMountpoint */, false /* metacopy */, false /* skipData */, false /* mayUnlockRenameMu */); err != nil {
		return err
	}
	return d.doCopyUpDataLocked(ctx, false /* skipData */, false /* mayUnlockRenameMu */)
}

// copyUpForTruncateLocked is copyUpLocked for an open with O_TRUNC, which
// truncates the upper file right after copy-up, so regular file data is not
// copied. Compare Linux's fs/overlayfs/copy_up.c:ovl_copy_up_flags().
//
// Preconditions: filesystem.renameMu must be locked.
func (d *dentry) copyUpForTruncateLocked(ctx context.Context) error {
	if err := d.doCopyUpLocked(ctx, false /* forSyntheticMountpoint */, false /* metacopy */, true /* skipData */, false /* mayUnlockRenameMu */); err != nil {
		return err
	}
	return d.doCopyUpDataLocked(ctx, true /* skipData */, false /* mayUnlockRenameMu */)
}

// copyUpForWriteLocked is copyUpLocked for a write operation. It may
// temporarily unlock filesystem.renameMu while copying regular file data, but
// returns with filesystem.renameMu locked for reading.
//
// Preconditions: filesystem.renameMu must be locked for reading, and the
// caller must hold a reference on d.
func (d *dentry) copyUpForWriteLocked(ctx context.Context) error {
	if err := d.doCopyUpLocked(ctx, false /* forSyntheticMountpoint */, false /* metacopy */, false /* skipData */, true /* mayUnlockRenameMu */); err != nil {
		return err
	}
	return d.doCopyUpDataLocked(ctx, false /* skipData */, true /* mayUnlockRenameMu */)
}

// copyUpForSetStatLocked is copyUpForWriteLocked for a setattr with opts,
// which needs regular file data on the upper layer only to truncate.
//
// Preconditions: filesystem.renameMu must be locked for reading, and the
// caller must hold a reference on d.
func (d *dentry) copyUpForSetStatLocked(ctx context.Context, opts *vfs.SetStatOptions) error {
	if opts.Stat.Mask&linux.STATX_SIZE != 0 {
		return d.copyUpForWriteLocked(ctx)
	}
	return d.doCopyUpLocked(ctx, false /* forSyntheticMountpoint */, true /* metacopy */, false /* skipData */, true /* mayUnlockRenameMu */)
}

// doCopyUpLocked creates d on the upper layer if it is not there already. A
// regular file's data is copied with it unless skipData is true, or metacopy
// and fs.opts.Metacopy are true, in which case the data stays on the lower
// layer. forSyntheticMountpoint is passed to the upper layer when creating
// directories. If mayUnlockRenameMu is true, filesystem.renameMu may be
// temporarily unlocked while copying data.
//
// Preconditions: filesystem.renameMu must be locked. If mayUnlockRenameMu is
// true, filesystem.renameMu must be locked for reading, and the caller must
// hold a reference on d.
func (d *dentry) doCopyUpLocked(ctx context.Context, forSyntheticMountpoint, metacopy, skipData, mayUnlockRenameMu bool) error {
	// Fast path.
	if d.isCopiedUp() {
		return nil
	}

	// Attach our credentials to the context, as some VFS operations use
	// credentials from context rather an take an explicit creds parameter.
	ctx = auth.ContextWithCredentials(ctx, d.fs.creds)

	if !d.canBeCopiedUp() {
		return linuxerr.EPERM
	}

	// Ensure that our parent directory is copied-up.
	parent := d.parent.Load()
	if parent == nil {
		// d is a filesystem root with no upper layer.
		return linuxerr.EROFS
	}
	if err := parent.doCopyUpLocked(ctx, forSyntheticMountpoint, false /* metacopy */, false /* skipData */, false /* mayUnlockRenameMu */); err != nil {
		return err
	}

	d.copyMu.Lock()
	// Can free renameMu when copying data, but must reclaim it to exit cleanly.
	renameMuUnlocked := false
	defer func() {
		d.copyMu.Unlock()
		if renameMuUnlocked {
			d.fs.renameMu.RLock()
		}
	}()
	if d.upperVD.Ok() {
		// Raced with another call to d.copyUpLocked().
		return nil
	}
	if d.vfsd.IsDead() {
		// Raced with deletion of d.
		return linuxerr.ENOENT
	}

	// Obtain settable timestamps from the lower layer.
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	oldpop := vfs.PathOperation{
		Root:  d.lowerVDs[0],
		Start: d.lowerVDs[0],
	}
	const timestampsMask = linux.STATX_ATIME | linux.STATX_MTIME
	oldStat, err := vfsObj.StatAt(ctx, d.fs.creds, &oldpop, &vfs.StatOptions{
		Mask: timestampsMask | linux.STATX_SIZE,
	})
	if err != nil {
		return err
	}

	// Perform copy-up.
	ftype := d.mode.Load() & linux.S_IFMT
	isRegularFile := ftype == linux.S_IFREG
	lowerSizeKnown := oldStat.Mask&linux.STATX_SIZE != 0
	bigEnough := oldStat.Size >= d.fs.opts.MetacopyMinSize
	metacopy = metacopy && d.fs.opts.Metacopy && isRegularFile && lowerSizeKnown && bigEnough
	newpop := vfs.PathOperation{
		Root:  parent.upperVD,
		Start: parent.upperVD,
		Path:  fspath.Parse(d.name),
	}
	// Used during copy-up of memory-mapped regular files.
	var mmapOpts *memmap.MMapOpts
	cleanupUndoCopyUp := func() {
		var err error
		if ftype == linux.S_IFDIR {
			err = vfsObj.RmdirAt(ctx, d.fs.creds, &newpop)
		} else {
			err = vfsObj.UnlinkAt(ctx, d.fs.creds, &newpop)
		}
		if err != nil {
			panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to delete upper layer file after copy-up error: %v", err))
		}
		if d.upperVD.Ok() {
			d.upperVD.DecRef(ctx)
			d.upperVD = vfs.VirtualDentry{}
		}
	}
	switch ftype {
	case linux.S_IFREG:
		oldFD, err := vfsObj.OpenAt(ctx, d.fs.creds, &oldpop, &vfs.OpenOptions{
			Flags: linux.O_RDONLY,
		})
		if err != nil {
			return err
		}
		defer oldFD.DecRef(ctx)
		newFD, err := vfsObj.OpenAt(ctx, d.fs.creds, &newpop, &vfs.OpenOptions{
			Flags: linux.O_WRONLY | linux.O_CREAT | linux.O_EXCL,
			// d.mode can be read because d.copyMu is locked.
			Mode: linux.FileMode(d.mode.RacyLoad() &^ linux.S_IFMT),
		})
		if err != nil {
			return err
		}
		defer newFD.DecRef(ctx)
		var sizeMask uint32
		if metacopy {
			// Mark the file before sizing it, so that the upper layer never
			// holds a sized file whose data reads as zeros.
			if err := d.setMetacopyXattrsLocked(ctx, newFD); err != nil {
				cleanupUndoCopyUp()
				return err
			}
			sizeMask = linux.STATX_SIZE
		} else if !skipData {
			// While copying data, free renameMu.
			if mayUnlockRenameMu {
				d.fs.renameMu.RUnlock()
				renameMuUnlocked = true
			}
			if _, err := vfs.CopyRegularFileData(ctx, newFD, oldFD); err != nil {
				cleanupUndoCopyUp()
				return err
			}
		}
		if d.wrappedMappable != nil && !metacopy {
			// We may have memory mappings of the file on the lower layer.
			// Switch to mapping the file on the upper layer instead.
			mmapOpts = &memmap.MMapOpts{
				Perms:    hostarch.ReadWrite,
				MaxPerms: hostarch.ReadWrite,
			}
			if err := newFD.ConfigureMMap(ctx, mmapOpts); err != nil {
				cleanupUndoCopyUp()
				return err
			}
			if mmapOpts.MappingIdentity != nil {
				mmapOpts.MappingIdentity.DecRef(ctx)
			}
			// Don't actually switch Mappables until the end of copy-up; see
			// below for why.
		}
		if err := newFD.SetStat(ctx, vfs.SetStatOptions{
			Stat: linux.Statx{
				Mask: linux.STATX_UID | linux.STATX_GID | oldStat.Mask&timestampsMask | linux.STATX_MODE | sizeMask,
				// d.{uid,gid,mode} can be read because d.copyMu is locked.
				UID:   d.uid.RacyLoad(),
				GID:   d.gid.RacyLoad(),
				Atime: oldStat.Atime,
				Mtime: oldStat.Mtime,
				// Mode is specified again because the vfs.CopyRegularFileData() clears the setid bits.
				Mode: uint16(d.mode.RacyLoad() &^ linux.S_IFMT),
				Size: oldStat.Size,
			},
		}); err != nil {
			cleanupUndoCopyUp()
			return err
		}
		acl := d.accessACL.Load()
		newACL, newMode, err := newFD.SetPosixACL(ctx, vfs.AccessACL, acl, false /* clearSGID */)
		if err == nil {
			d.accessACL.Store(newACL)
			d.mode.Store(uint32(newMode))
		} else if acl == nil && linuxerr.Equals(linuxerr.EOPNOTSUPP, err) {
			// Tolerate EOPNOTSUPP for nil ACLs since if the upper filesystem
			// doesn't support ACLs, all files have an implicit nil ACL
		} else {
			cleanupUndoCopyUp()
			return err
		}
		d.upperVD = newFD.VirtualDentry()
		d.upperVD.IncRef()

	case linux.S_IFDIR:
		if err := vfsObj.MkdirAt(ctx, d.fs.creds, &newpop, &vfs.MkdirOptions{
			// d.mode can be read because d.copyMu is locked.
			Mode:                   linux.FileMode(d.mode.RacyLoad() &^ linux.S_IFMT),
			ForSyntheticMountpoint: forSyntheticMountpoint,
		}); err != nil {
			return err
		}
		if err := vfsObj.SetStatAt(ctx, d.fs.creds, &newpop, &vfs.SetStatOptions{
			Stat: linux.Statx{
				Mask: linux.STATX_UID | linux.STATX_GID | oldStat.Mask&timestampsMask | linux.STATX_MODE,
				// d.{uid,gid,mode} can be read because d.copyMu is locked.
				UID:   d.uid.RacyLoad(),
				GID:   d.gid.RacyLoad(),
				Atime: oldStat.Atime,
				Mtime: oldStat.Mtime,
				// Mode is specified again because vfs.MkdirAt() strips off the setgid bit.
				Mode: uint16(d.mode.RacyLoad() &^ linux.S_IFMT),
			},
		}); err != nil {
			cleanupUndoCopyUp()
			return err
		}
		acl := d.accessACL.Load()
		newACL, newMode, err := vfsObj.SetPosixACLAt(ctx, d.fs.creds, &newpop, vfs.AccessACL, acl, false /* clearSGID */)
		if err == nil {
			d.accessACL.Store(newACL)
			d.mode.Store(uint32(newMode))
		} else if acl == nil && linuxerr.Equals(linuxerr.EOPNOTSUPP, err) {
			// Tolerate EOPNOTSUPP for nil ACLs since if the upper filesystem
			// doesn't support ACLs, all files have an implicit nil ACL
		} else {
			cleanupUndoCopyUp()
			return err
		}
		defaultACL := d.defaultACL.Load()
		newDefaultACL, _, err := vfsObj.SetPosixACLAt(ctx, d.fs.creds, &newpop, vfs.DefaultACL, defaultACL, false /* clearSGID */)
		if err == nil {
			d.defaultACL.Store(newDefaultACL)
		} else if defaultACL == nil && linuxerr.Equals(linuxerr.EOPNOTSUPP, err) {
			// Tolerate EOPNOTSUPP for nil ACLs since if the upper filesystem
			// doesn't support ACLs, all files have an implicit nil ACL
		} else {
			cleanupUndoCopyUp()
			return err
		}
		upperVD, err := vfsObj.GetDentryAt(ctx, d.fs.creds, &newpop, &vfs.GetDentryOptions{})
		if err != nil {
			cleanupUndoCopyUp()
			return err
		}
		d.upperVD = upperVD

	case linux.S_IFLNK:
		target, err := vfsObj.ReadlinkAt(ctx, d.fs.creds, &oldpop)
		if err != nil {
			return err
		}
		if err := vfsObj.SymlinkAt(ctx, d.fs.creds, &newpop, target); err != nil {
			return err
		}
		if err := vfsObj.SetStatAt(ctx, d.fs.creds, &newpop, &vfs.SetStatOptions{
			Stat: linux.Statx{
				Mask: linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID | oldStat.Mask&timestampsMask,
				// d.{uid,gid,mode} can be read because d.copyMu is locked.
				Mode:  uint16(d.mode.RacyLoad()),
				UID:   d.uid.RacyLoad(),
				GID:   d.gid.RacyLoad(),
				Atime: oldStat.Atime,
				Mtime: oldStat.Mtime,
			},
		}); err != nil {
			cleanupUndoCopyUp()
			return err
		}
		// Skip POSIX ACLs since symlinks cannot have them.
		upperVD, err := vfsObj.GetDentryAt(ctx, d.fs.creds, &newpop, &vfs.GetDentryOptions{})
		if err != nil {
			cleanupUndoCopyUp()
			return err
		}
		d.upperVD = upperVD

	case linux.S_IFBLK, linux.S_IFCHR:
		if err := vfsObj.MknodAt(ctx, d.fs.creds, &newpop, &vfs.MknodOptions{
			// d.mode can be read because d.copyMu is locked.
			Mode:     linux.FileMode(d.mode.RacyLoad()),
			DevMajor: oldStat.RdevMajor,
			DevMinor: oldStat.RdevMinor,
		}); err != nil {
			return err
		}
		if err := vfsObj.SetStatAt(ctx, d.fs.creds, &newpop, &vfs.SetStatOptions{
			Stat: linux.Statx{
				Mask: linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID | oldStat.Mask&timestampsMask,
				// d.uid and d.gid can be read because d.copyMu is locked.
				Mode:  uint16(d.mode.RacyLoad()),
				UID:   d.uid.RacyLoad(),
				GID:   d.gid.RacyLoad(),
				Atime: oldStat.Atime,
				Mtime: oldStat.Mtime,
			},
		}); err != nil {
			cleanupUndoCopyUp()
			return err
		}
		acl := d.accessACL.Load()
		newACL, newMode, err := vfsObj.SetPosixACLAt(ctx, d.fs.creds, &newpop, vfs.AccessACL, acl, false /* clearSGID */)
		if err == nil {
			d.accessACL.Store(newACL)
			d.mode.Store(uint32(newMode))
		} else if acl == nil && linuxerr.Equals(linuxerr.EOPNOTSUPP, err) {
			// Tolerate EOPNOTSUPP for nil ACLs since if the upper filesystem
			// doesn't support ACLs, all files have an implicit nil ACL
		} else {
			cleanupUndoCopyUp()
			return err
		}
		upperVD, err := vfsObj.GetDentryAt(ctx, d.fs.creds, &newpop, &vfs.GetDentryOptions{})
		if err != nil {
			cleanupUndoCopyUp()
			return err
		}
		d.upperVD = upperVD

	default:
		// Should have rejected this at the beginning of this function?
		panic(fmt.Sprintf("unexpected file type %o", ftype))
	}

	if err := d.copyXattrsLocked(ctx); err != nil {
		cleanupUndoCopyUp()
		return err
	}

	// Update the dentry's device and inode numbers (except for directories,
	// for which these remain overlay-assigned).
	if ftype != linux.S_IFDIR {
		upperStat, err := vfsObj.StatAt(ctx, d.fs.creds, &vfs.PathOperation{
			Root:  d.upperVD,
			Start: d.upperVD,
		}, &vfs.StatOptions{
			Mask: linux.STATX_INO,
		})
		if err != nil {
			cleanupUndoCopyUp()
			return err
		}
		if upperStat.Mask&linux.STATX_INO == 0 {
			cleanupUndoCopyUp()
			return linuxerr.EREMOTE
		}
		d.devMajor.Store(upperStat.DevMajor)
		d.devMinor.Store(upperStat.DevMinor)
		d.ino.Store(upperStat.Ino)

		if !metacopy {
			d.markLowerEvictable()
		}
	}

	if mmapOpts != nil && mmapOpts.Mappable != nil {
		d.mapsMu.Lock()
		defer d.mapsMu.Unlock()
		// Without data, the upper file is already empty, so the open's
		// truncation won't invalidate private copies of lower pages.
		if err := d.switchToUpperMappableLocked(ctx, mmapOpts.Mappable, skipData); err != nil {
			return err
		}
	}

	d.metacopy.Store(metacopy)
	d.copiedUp.Store(1)
	return nil
}

// markLowerEvictable frees lower dentry cache when a lower file's data is
// copied up. Does not apply to metacopy!
func (d *dentry) markLowerEvictable() {
	for _, lowerDentry := range d.lowerVDs {
		lowerDentry.Dentry().MarkEvictable()
	}
}

// setMetacopyXattrsLocked marks the upper file of fd as a metacopy file whose
// data is d.lowerVDs[0]. As in Linux overlayfs, the redirect xattr is the
// absolute path of the data file in its layer.
//
// Preconditions: d.copyMu must be locked for writing.
func (d *dentry) setMetacopyXattrsLocked(ctx context.Context, fd *vfs.FileDescription) error {
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	redirect, err := vfsObj.PathnameReachable(ctx, d.fs.opts.LowerRoots[0], d.lowerVDs[0])
	if err != nil {
		return err
	}
	if err := fd.SetXattr(ctx, &vfs.SetXattrOptions{Name: d.fs.xattrMetacopy}); err != nil {
		return err
	}
	return fd.SetXattr(ctx, &vfs.SetXattrOptions{Name: d.fs.xattrRedirect, Value: redirect})
}

// doCopyUpDataLocked copies the data of d, if it is a metacopy file, to the
// upper layer, or drops it if skipData is true. If mayUnlockRenameMu is true,
// filesystem.renameMu may be temporarily unlocked while copying data. Compare
// Linux's fs/overlayfs/copy_up.c:ovl_copy_up_meta_inode_data().
//
// Preconditions: filesystem.renameMu must be locked. If mayUnlockRenameMu is
// true, filesystem.renameMu must be locked for reading, and the caller must
// hold a reference on d.
func (d *dentry) doCopyUpDataLocked(ctx context.Context, skipData, mayUnlockRenameMu bool) error {
	if !d.isMetacopy() {
		return nil
	}
	ctx = auth.ContextWithCredentials(ctx, d.fs.creds)
	d.copyMu.Lock()
	renameMuUnlocked := false
	defer func() {
		d.copyMu.Unlock()
		if renameMuUnlocked {
			d.fs.renameMu.RLock()
		}
	}()
	if !d.isMetacopy() {
		// Raced with another call to d.doCopyUpDataLocked().
		return nil
	}

	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	upperPop := vfs.PathOperation{
		Root:  d.upperVD,
		Start: d.upperVD,
	}
	upperFD, err := vfsObj.OpenAt(ctx, d.fs.creds, &upperPop, &vfs.OpenOptions{
		Flags: linux.O_WRONLY,
	})
	if err != nil {
		return err
	}
	defer upperFD.DecRef(ctx)
	if skipData {
		if err := upperFD.SetStat(ctx, vfs.SetStatOptions{
			Stat: linux.Statx{Mask: linux.STATX_SIZE},
		}); err != nil {
			return err
		}
	} else {
		lowerFD, err := vfsObj.OpenAt(ctx, d.fs.creds, &vfs.PathOperation{
			Root:  d.lowerVDs[0],
			Start: d.lowerVDs[0],
		}, &vfs.OpenOptions{
			Flags: linux.O_RDONLY,
		})
		if err != nil {
			return err
		}
		defer lowerFD.DecRef(ctx)
		const restoredMask = linux.STATX_ATIME | linux.STATX_MTIME | linux.STATX_MODE
		stat, err := upperFD.Stat(ctx, vfs.StatOptions{Mask: restoredMask})
		if err != nil {
			return err
		}
		// Writing the data also removes file capabilities.
		caps, err := vfsObj.GetXattrAt(ctx, d.fs.creds, &upperPop, &vfs.GetXattrOptions{Name: linux.XATTR_SECURITY_CAPABILITY})
		hasCaps := err == nil
		noCaps := linuxerr.Equals(linuxerr.ENODATA, err) || linuxerr.Equals(linuxerr.EOPNOTSUPP, err)
		if !hasCaps && !noCaps {
			return err
		}
		// The upper file's data reads as d's data only once the metacopy xattr
		// is removed, so a failed copy leaves d intact once its metadata is
		// restored.
		if mayUnlockRenameMu {
			d.fs.renameMu.RUnlock()
			renameMuUnlocked = true
		}
		_, copyErr := vfs.CopyRegularFileData(ctx, upperFD, lowerFD)
		if err := upperFD.SetStat(ctx, vfs.SetStatOptions{
			Stat: linux.Statx{
				Mask:  stat.Mask & restoredMask,
				Atime: stat.Atime,
				Mtime: stat.Mtime,
				// Mode is specified again because the vfs.CopyRegularFileData() clears the setid bits.
				Mode: stat.Mode &^ linux.S_IFMT,
			},
		}); err != nil {
			return err
		}
		if hasCaps {
			if err := vfsObj.SetXattrAt(ctx, d.fs.creds, &upperPop, &vfs.SetXattrOptions{Name: linux.XATTR_SECURITY_CAPABILITY, Value: caps}); err != nil {
				return err
			}
		}
		if copyErr != nil {
			return copyErr
		}
	}
	for _, name := range []string{d.fs.xattrMetacopy, d.fs.xattrRedirect} {
		if err := vfsObj.RemoveXattrAt(ctx, d.fs.creds, &upperPop, name); err != nil && !linuxerr.Equals(linuxerr.ENODATA, err) {
			return err
		}
	}

	if d.wrappedMappable != nil {
		mmapOpts := memmap.MMapOpts{
			Perms:    hostarch.ReadWrite,
			MaxPerms: hostarch.ReadWrite,
		}
		if err := upperFD.ConfigureMMap(ctx, &mmapOpts); err != nil {
			return err
		}
		if mmapOpts.MappingIdentity != nil {
			mmapOpts.MappingIdentity.DecRef(ctx)
		}
		d.mapsMu.Lock()
		defer d.mapsMu.Unlock()
		if err := d.switchToUpperMappableLocked(ctx, mmapOpts.Mappable, skipData); err != nil {
			return err
		}
	}
	d.metacopy.Store(false)
	d.markLowerEvictable()
	return nil
}

// switchToUpperMappableLocked moves the memory mappings of d's lower layer
// file to upperMappable.
//
// Preconditions:
//   - d.copyMu must be locked for writing.
//   - d.mapsMu must be locked.
func (d *dentry) switchToUpperMappableLocked(ctx context.Context, upperMappable memmap.Mappable, invalidatePrivate bool) error {
	// Propagate mappings of d to the new Mappable. Remember which mappings
	// we added so we can remove them on failure.
	allAdded := make(map[memmap.MappableRange]memmap.MappingsOfRange)
	for seg := d.lowerMappings.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		added := make(memmap.MappingsOfRange)
		for m := range seg.Value() {
			if err := upperMappable.AddMapping(ctx, m.MappingSpace, m.AddrRange, seg.Start(), m.Writable); err != nil {
				for m := range added {
					upperMappable.RemoveMapping(ctx, m.MappingSpace, m.AddrRange, seg.Start(), m.Writable)
				}
				for mr, mappings := range allAdded {
					for m := range mappings {
						upperMappable.RemoveMapping(ctx, m.MappingSpace, m.AddrRange, mr.Start, m.Writable)
					}
				}
				return err
			}
			added[m] = struct{}{}
		}
		allAdded[seg.Range()] = added
	}

	// Switch to the new Mappable. We do this at the end of copy-up
	// because:
	//
	//	- We need to switch Mappables (by changing d.wrappedMappable) before
	//		invalidating Translations from the old Mappable (to pick up
	//		Translations from the new one).
	//
	//	- We need to lock d.dataMu while changing d.wrappedMappable, but
	//		must invalidate Translations with d.dataMu unlocked (due to lock
	//		ordering).
	//
	//	- Consequently, once we unlock d.dataMu, other threads may
	//		immediately observe the new (copied-up) Mappable, which we want to
	//		delay until copy-up is guaranteed to succeed.
	d.dataMu.Lock()
	lowerMappable := d.wrappedMappable
	d.wrappedMappable = upperMappable
	d.dataMu.Unlock()
	d.lowerMappings.InvalidateAll(memmap.InvalidateOpts{InvalidatePrivate: invalidatePrivate})

	// Remove mappings from the old Mappable.
	for seg := d.lowerMappings.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		for m := range seg.Value() {
			lowerMappable.RemoveMapping(ctx, m.MappingSpace, m.AddrRange, seg.Start(), m.Writable)
		}
	}
	d.lowerMappings.RemoveAll()
	return nil
}

// mustCopyXattr returns true if a copy-up failure on the given xattr must
// abort the copy-up. Loosely analogous to Linux's
// fs/overlayfs/util.c:ovl_must_copy_xattr(). Here are the differences:
//   - Linux includes "system.posix_acl_access" and "system.posix_acl_default".
//     In gVisor, we handle these separately.
//   - Linux includes all "security.*" xattrs. gVisor only supports
//     "security.capability" and so only that is included here.
func mustCopyXattr(name string) bool {
	return name == linux.XATTR_SECURITY_CAPABILITY
}

// copyXattrsLocked copies a subset of lower's extended attributes to upper.
// Attributes that configure an overlay in the lower are not copied up.
//
// Preconditions: d.copyMu must be locked for writing.
func (d *dentry) copyXattrsLocked(ctx context.Context) error {
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	lowerPop := &vfs.PathOperation{Root: d.lowerVDs[0], Start: d.lowerVDs[0]}
	upperPop := &vfs.PathOperation{Root: d.upperVD, Start: d.upperVD}

	lowerXattrs, err := vfsObj.ListXattrAt(ctx, d.fs.creds, lowerPop, 0)
	if err != nil {
		if linuxerr.Equals(linuxerr.EOPNOTSUPP, err) {
			// There are no guarantees as to the contents of lowerXattrs.
			return nil
		}
		ctx.Infof("failed to copy up xattrs because ListXattrAt failed: %v", err)
		return err
	}

	for _, name := range lowerXattrs {
		// Do not copy up overlay attributes.
		if d.fs.isOverlayXattr(name) {
			continue
		}

		// Skip POSIX ACLs, which are handled separately.
		if name == linux.XATTR_NAME_POSIX_ACL_ACCESS || name == linux.XATTR_NAME_POSIX_ACL_DEFAULT {
			continue
		}

		value, err := vfsObj.GetXattrAt(ctx, d.fs.creds, lowerPop, &vfs.GetXattrOptions{Name: name, Size: 0})
		if err != nil {
			ctx.Infof("failed to copy up %q xattr because GetXattrAt failed: %v", name, err)
			return err
		}

		if err := vfsObj.SetXattrAt(ctx, d.fs.creds, upperPop, &vfs.SetXattrOptions{Name: name, Value: value}); err != nil {
			ctx.Infof("failed to copy up %q xattr because SetXattrAt failed: %v", name, err)
			if linuxerr.Equals(linuxerr.EOPNOTSUPP, err) && !mustCopyXattr(name) {
				continue
			}
			return err
		}
	}
	return nil
}

// copyUpDescendantsLocked ensures that all descendants of d are copied up.
//
// Preconditions:
//   - filesystem.renameMu must be locked.
//   - d.dirMu must be locked.
//   - d.isDir().
func (d *dentry) copyUpDescendantsLocked(ctx context.Context, ds **[]*dentry) error {
	dirents, err := d.getDirentsLocked(ctx)
	if err != nil {
		return err
	}
	for _, dirent := range dirents {
		if dirent.Name == "." || dirent.Name == ".." {
			continue
		}
		child, _, err := d.fs.getChildLocked(ctx, d, dirent.Name, ds)
		if err != nil {
			return err
		}
		if err := child.copyUpLocked(ctx); err != nil {
			return err
		}
		if child.isDir() {
			child.dirMu.Lock()
			err := child.copyUpDescendantsLocked(ctx, ds)
			child.dirMu.Unlock()
			if err != nil {
				return err
			}
		}
	}
	return nil
}
