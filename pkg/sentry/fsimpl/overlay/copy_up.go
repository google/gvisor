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
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

func (d *dentry) isCopiedUp() bool {
	return atomic.LoadUint32(&d.copiedUp) != 0
}

// copyUpLocked ensures that d exists on the upper layer, i.e. d.upperVD.Ok().
//
// Preconditions: filesystem.renameMu must be locked.
func (d *dentry) copyUpLocked(ctx context.Context) error {
	// Fast path.
	if d.isCopiedUp() {
		return nil
	}

	// Attach our credentials to the context, as some VFS operations use
	// credentials from context rather an take an explicit creds parameter.
	ctx = auth.ContextWithCredentials(ctx, d.fs.creds)

	ftype := atomic.LoadUint32(&d.mode) & linux.S_IFMT
	switch ftype {
	case linux.S_IFREG, linux.S_IFDIR, linux.S_IFLNK, linux.S_IFBLK, linux.S_IFCHR:
		// Can be copied-up.
	default:
		// Can't be copied-up.
		return syserror.EPERM
	}

	// Ensure that our parent directory is copied-up.
	if d.parent == nil {
		// d is a filesystem root with no upper layer.
		return syserror.EROFS
	}
	if err := d.parent.copyUpLocked(ctx); err != nil {
		return err
	}

	d.copyMu.Lock()
	defer d.copyMu.Unlock()
	if d.upperVD.Ok() {
		// Raced with another call to d.copyUpLocked().
		return nil
	}
	if d.vfsd.IsDead() {
		// Raced with deletion of d.
		return syserror.ENOENT
	}

	// Obtain settable timestamps from the lower layer.
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	oldpop := vfs.PathOperation{
		Root:  d.lowerVDs[0],
		Start: d.lowerVDs[0],
	}
	const timestampsMask = linux.STATX_ATIME | linux.STATX_MTIME
	oldStat, err := vfsObj.StatAt(ctx, d.fs.creds, &oldpop, &vfs.StatOptions{
		Mask: timestampsMask,
	})
	if err != nil {
		return err
	}

	// Perform copy-up.
	newpop := vfs.PathOperation{
		Root:  d.parent.upperVD,
		Start: d.parent.upperVD,
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
			Mode:  linux.FileMode(d.mode &^ linux.S_IFMT),
		})
		if err != nil {
			return err
		}
		defer newFD.DecRef(ctx)
		if _, err := vfs.CopyRegularFileData(ctx, newFD, oldFD); err != nil {
			cleanupUndoCopyUp()
			return err
		}
		d.mapsMu.Lock()
		defer d.mapsMu.Unlock()
		if d.wrappedMappable != nil {
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
				Mask:  linux.STATX_UID | linux.STATX_GID | oldStat.Mask&timestampsMask,
				UID:   d.uid,
				GID:   d.gid,
				Atime: oldStat.Atime,
				Mtime: oldStat.Mtime,
			},
		}); err != nil {
			cleanupUndoCopyUp()
			return err
		}
		d.upperVD = newFD.VirtualDentry()
		d.upperVD.IncRef()

	case linux.S_IFDIR:
		if err := vfsObj.MkdirAt(ctx, d.fs.creds, &newpop, &vfs.MkdirOptions{
			Mode: linux.FileMode(d.mode &^ linux.S_IFMT),
		}); err != nil {
			return err
		}
		if err := vfsObj.SetStatAt(ctx, d.fs.creds, &newpop, &vfs.SetStatOptions{
			Stat: linux.Statx{
				Mask:  linux.STATX_UID | linux.STATX_GID | oldStat.Mask&timestampsMask,
				UID:   d.uid,
				GID:   d.gid,
				Atime: oldStat.Atime,
				Mtime: oldStat.Mtime,
			},
		}); err != nil {
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
				Mask:  linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID | oldStat.Mask&timestampsMask,
				Mode:  uint16(d.mode),
				UID:   d.uid,
				GID:   d.gid,
				Atime: oldStat.Atime,
				Mtime: oldStat.Mtime,
			},
		}); err != nil {
			cleanupUndoCopyUp()
			return err
		}
		upperVD, err := vfsObj.GetDentryAt(ctx, d.fs.creds, &newpop, &vfs.GetDentryOptions{})
		if err != nil {
			cleanupUndoCopyUp()
			return err
		}
		d.upperVD = upperVD

	case linux.S_IFBLK, linux.S_IFCHR:
		if err := vfsObj.MknodAt(ctx, d.fs.creds, &newpop, &vfs.MknodOptions{
			Mode:     linux.FileMode(d.mode),
			DevMajor: oldStat.RdevMajor,
			DevMinor: oldStat.RdevMinor,
		}); err != nil {
			return err
		}
		if err := vfsObj.SetStatAt(ctx, d.fs.creds, &newpop, &vfs.SetStatOptions{
			Stat: linux.Statx{
				Mask:  linux.STATX_UID | linux.STATX_GID | oldStat.Mask&timestampsMask,
				UID:   d.uid,
				GID:   d.gid,
				Atime: oldStat.Atime,
				Mtime: oldStat.Mtime,
			},
		}); err != nil {
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
			return syserror.EREMOTE
		}
		atomic.StoreUint32(&d.devMajor, upperStat.DevMajor)
		atomic.StoreUint32(&d.devMinor, upperStat.DevMinor)
		atomic.StoreUint64(&d.ino, upperStat.Ino)
	}

	if mmapOpts != nil && mmapOpts.Mappable != nil {
		// Note that if mmapOpts != nil, then d.mapsMu is locked for writing
		// (from the S_IFREG path above).

		// Propagate mappings of d to the new Mappable. Remember which mappings
		// we added so we can remove them on failure.
		upperMappable := mmapOpts.Mappable
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
		// - We need to switch Mappables (by changing d.wrappedMappable) before
		// invalidating Translations from the old Mappable (to pick up
		// Translations from the new one).
		//
		// - We need to lock d.dataMu while changing d.wrappedMappable, but
		// must invalidate Translations with d.dataMu unlocked (due to lock
		// ordering).
		//
		// - Consequently, once we unlock d.dataMu, other threads may
		// immediately observe the new (copied-up) Mappable, which we want to
		// delay until copy-up is guaranteed to succeed.
		d.dataMu.Lock()
		lowerMappable := d.wrappedMappable
		d.wrappedMappable = upperMappable
		d.dataMu.Unlock()
		d.lowerMappings.InvalidateAll(memmap.InvalidateOpts{})

		// Remove mappings from the old Mappable.
		for seg := d.lowerMappings.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
			for m := range seg.Value() {
				lowerMappable.RemoveMapping(ctx, m.MappingSpace, m.AddrRange, seg.Start(), m.Writable)
			}
		}
		d.lowerMappings.RemoveAll()
	}

	atomic.StoreUint32(&d.copiedUp, 1)
	return nil
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
		if err == syserror.EOPNOTSUPP {
			// There are no guarantees as to the contents of lowerXattrs.
			return nil
		}
		ctx.Infof("failed to copy up xattrs because ListXattrAt failed: %v", err)
		return err
	}

	for _, name := range lowerXattrs {
		// Do not copy up overlay attributes.
		if isOverlayXattr(name) {
			continue
		}

		value, err := vfsObj.GetXattrAt(ctx, d.fs.creds, lowerPop, &vfs.GetXattrOptions{Name: name, Size: 0})
		if err != nil {
			ctx.Infof("failed to copy up xattrs because GetXattrAt failed: %v", err)
			return err
		}

		if err := vfsObj.SetXattrAt(ctx, d.fs.creds, upperPop, &vfs.SetXattrOptions{Name: name, Value: value}); err != nil {
			ctx.Infof("failed to copy up xattrs because SetXattrAt failed: %v", err)
			return err
		}
	}
	return nil
}

// copyUpDescendantsLocked ensures that all descendants of d are copied up.
//
// Preconditions:
// * filesystem.renameMu must be locked.
// * d.dirMu must be locked.
// * d.isDir().
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
