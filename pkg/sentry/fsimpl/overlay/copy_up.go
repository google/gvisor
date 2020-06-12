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
	"io"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
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

	// Perform copy-up.
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	newpop := vfs.PathOperation{
		Root:  d.parent.upperVD,
		Start: d.parent.upperVD,
		Path:  fspath.Parse(d.name),
	}
	cleanupUndoCopyUp := func() {
		var err error
		if ftype == linux.S_IFDIR {
			err = vfsObj.RmdirAt(ctx, d.fs.creds, &newpop)
		} else {
			err = vfsObj.UnlinkAt(ctx, d.fs.creds, &newpop)
		}
		if err != nil {
			ctx.Warningf("Unrecoverable overlayfs inconsistency: failed to delete upper layer file after copy-up error: %v", err)
		}
	}
	switch ftype {
	case linux.S_IFREG:
		oldFD, err := vfsObj.OpenAt(ctx, d.fs.creds, &vfs.PathOperation{
			Root:  d.lowerVDs[0],
			Start: d.lowerVDs[0],
		}, &vfs.OpenOptions{
			Flags: linux.O_RDONLY,
		})
		if err != nil {
			return err
		}
		defer oldFD.DecRef()
		newFD, err := vfsObj.OpenAt(ctx, d.fs.creds, &newpop, &vfs.OpenOptions{
			Flags: linux.O_WRONLY | linux.O_CREAT | linux.O_EXCL,
			Mode:  linux.FileMode(d.mode &^ linux.S_IFMT),
		})
		if err != nil {
			return err
		}
		defer newFD.DecRef()
		bufIOSeq := usermem.BytesIOSequence(make([]byte, 32*1024)) // arbitrary buffer size
		for {
			readN, readErr := oldFD.Read(ctx, bufIOSeq, vfs.ReadOptions{})
			if readErr != nil && readErr != io.EOF {
				cleanupUndoCopyUp()
				return readErr
			}
			total := int64(0)
			for total < readN {
				writeN, writeErr := newFD.Write(ctx, bufIOSeq.DropFirst64(total), vfs.WriteOptions{})
				total += writeN
				if writeErr != nil {
					cleanupUndoCopyUp()
					return writeErr
				}
			}
			if readErr == io.EOF {
				break
			}
		}
		if err := newFD.SetStat(ctx, vfs.SetStatOptions{
			Stat: linux.Statx{
				Mask: linux.STATX_UID | linux.STATX_GID,
				UID:  d.uid,
				GID:  d.gid,
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
				Mask: linux.STATX_UID | linux.STATX_GID,
				UID:  d.uid,
				GID:  d.gid,
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
		target, err := vfsObj.ReadlinkAt(ctx, d.fs.creds, &vfs.PathOperation{
			Root:  d.lowerVDs[0],
			Start: d.lowerVDs[0],
		})
		if err != nil {
			return err
		}
		if err := vfsObj.SymlinkAt(ctx, d.fs.creds, &newpop, target); err != nil {
			return err
		}
		if err := vfsObj.SetStatAt(ctx, d.fs.creds, &newpop, &vfs.SetStatOptions{
			Stat: linux.Statx{
				Mask: linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID,
				Mode: uint16(d.mode),
				UID:  d.uid,
				GID:  d.gid,
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
		lowerStat, err := vfsObj.StatAt(ctx, d.fs.creds, &vfs.PathOperation{
			Root:  d.lowerVDs[0],
			Start: d.lowerVDs[0],
		}, &vfs.StatOptions{})
		if err != nil {
			return err
		}
		if err := vfsObj.MknodAt(ctx, d.fs.creds, &newpop, &vfs.MknodOptions{
			Mode:     linux.FileMode(d.mode),
			DevMajor: lowerStat.RdevMajor,
			DevMinor: lowerStat.RdevMinor,
		}); err != nil {
			return err
		}
		if err := vfsObj.SetStatAt(ctx, d.fs.creds, &newpop, &vfs.SetStatOptions{
			Stat: linux.Statx{
				Mask: linux.STATX_UID | linux.STATX_GID,
				UID:  d.uid,
				GID:  d.gid,
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

	// TODO(gvisor.dev/issue/1199): copy up xattrs

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
			d.upperVD.DecRef()
			d.upperVD = vfs.VirtualDentry{}
			cleanupUndoCopyUp()
			return err
		}
		if upperStat.Mask&linux.STATX_INO == 0 {
			d.upperVD.DecRef()
			d.upperVD = vfs.VirtualDentry{}
			cleanupUndoCopyUp()
			return syserror.EREMOTE
		}
		atomic.StoreUint32(&d.devMajor, upperStat.DevMajor)
		atomic.StoreUint32(&d.devMinor, upperStat.DevMinor)
		atomic.StoreUint64(&d.ino, upperStat.Ino)
	}

	atomic.StoreUint32(&d.copiedUp, 1)
	return nil
}
