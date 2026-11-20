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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func (d *dentry) isDir() bool {
	return d.mode.Load()&linux.S_IFMT == linux.S_IFDIR
}

func isDirOrUnknown(direntType uint8) bool {
	return direntType == linux.DT_DIR || direntType == linux.DT_UNKNOWN
}

// hasLowerDirChildLocked reports whether d has a child dentry for a directory
// that a lower layer supplies.
//
// Preconditions: d.dirMu must be locked.
func (d *dentry) hasLowerDirChildLocked() bool {
	for _, child := range d.children {
		if child.isDir() && len(child.lowerVDs) != 0 {
			return true
		}
	}
	return false
}

func (d *dentry) isSGIDSet() bool {
	return d.mode.Load()&linux.ModeSetGID != 0
}

// Preconditions:
//   - d.dirMu must be locked.
//   - d.isDir().
func (d *dentry) collectWhiteoutsForRmdirLocked(ctx context.Context) (map[string]bool, error) {
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	var readdirErr error
	whiteouts := make(map[string]bool)
	var maybeWhiteouts []string
	d.iterLayers(func(layerVD vfs.VirtualDentry, isUpper bool) bool {
		layerFD, err := vfsObj.OpenAt(ctx, d.fs.creds, &vfs.PathOperation{
			Root:  layerVD,
			Start: layerVD,
		}, &vfs.OpenOptions{
			Flags: linux.O_RDONLY | linux.O_DIRECTORY,
		})
		if err != nil {
			readdirErr = err
			return false
		}
		defer layerFD.DecRef(ctx)

		// Reuse slice allocated for maybeWhiteouts from a previous layer to
		// reduce allocations.
		maybeWhiteouts = maybeWhiteouts[:0]
		err = layerFD.IterDirents(ctx, vfs.IterDirentsCallbackFunc(func(dirent vfs.Dirent) error {
			if dirent.Name == "." || dirent.Name == ".." {
				return nil
			}
			if _, ok := whiteouts[dirent.Name]; ok {
				// This file has been whited-out in a previous layer.
				return nil
			}
			if dirent.Type == linux.DT_CHR {
				// We have to determine if this is a whiteout, which doesn't
				// count against the directory's emptiness. However, we can't
				// do so while holding locks held by layerFD.IterDirents().
				maybeWhiteouts = append(maybeWhiteouts, dirent.Name)
				return nil
			}
			// Non-whiteout file in the directory prevents rmdir.
			return linuxerr.ENOTEMPTY
		}))
		if err != nil {
			readdirErr = err
			return false
		}

		for _, maybeWhiteoutName := range maybeWhiteouts {
			stat, err := vfsObj.StatAt(ctx, d.fs.creds, &vfs.PathOperation{
				Root:  layerVD,
				Start: layerVD,
				Path:  fspath.Parse(maybeWhiteoutName),
			}, &vfs.StatOptions{})
			if linuxerr.Equals(linuxerr.ENOENT, err) {
				continue
			}
			if err != nil {
				readdirErr = err
				return false
			}
			if linux.MakeDeviceID(uint16(stat.RdevMajor), stat.RdevMinor) != linux.WHITEOUT_DEV {
				// This file is a real character device, not a whiteout.
				readdirErr = linuxerr.ENOTEMPTY
				return false
			}
			whiteouts[maybeWhiteoutName] = isUpper
		}
		// Continue iteration since we haven't found any non-whiteout files in
		// this directory yet.
		return true
	})
	return whiteouts, readdirErr
}

// +stateify savable
type directoryFD struct {
	fileDescription
	vfs.DirectoryFileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl

	mu      directoryFDMutex `state:"nosave"`
	off     int64
	dirents []vfs.Dirent
}

func (fd *directoryFD) lockIndex() directoryFDlockNameIndex {
	return directoryFDlockNameIndex(fd.filesystem().depthIndex())
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *directoryFD) Release(ctx context.Context) {
}

// IterDirents implements vfs.FileDescriptionImpl.IterDirents.
func (fd *directoryFD) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback) error {
	d := fd.dentry()
	fdIdx := fd.lockIndex()
	fd.mu.NestedLock(fdIdx)
	defer fd.mu.NestedUnlock(fdIdx)

	if fd.dirents == nil {
		ds, err := d.getDirents(ctx)
		if err != nil {
			return err
		}
		fd.dirents = ds
	}

	for fd.off < int64(len(fd.dirents)) {
		if err := cb.Handle(fd.dirents[fd.off]); err != nil {
			return err
		}
		fd.off++
	}
	return nil
}

// Preconditions: d.isDir().
func (d *dentry) getDirents(ctx context.Context) ([]vfs.Dirent, error) {
	var ds *[]*dentry
	renameIdx := d.fs.renameLockIndex()
	d.fs.renameMu.NestedRLock(renameIdx)
	defer d.fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	dirIdx := d.dirLockIndex(dirLockD1)
	d.dirMu.NestedLock(dirIdx)
	defer d.dirMu.NestedUnlock(dirIdx)
	return d.getDirentsLocked(ctx, &ds)
}

// Preconditions:
//   - filesystem.renameMu must be locked.
//   - d.dirMu must be locked.
//   - d.isDir().
func (d *dentry) getDirentsLocked(ctx context.Context, ds **[]*dentry) ([]vfs.Dirent, error) {
	if err := d.fs.ensureDirInoCache(ctx); err != nil {
		return nil, err
	}
	epoch := d.direntsEpoch.Load()
	if d.dirents != nil && epoch == d.direntsEpochCached {
		return d.dirents, nil
	}

	parent := genericParentOrSelf(d)
	dirents := []vfs.Dirent{
		{
			Name:    ".",
			Type:    linux.DT_DIR,
			Ino:     d.ino.Load(),
			NextOff: 1,
		},
		{
			Name:    "..",
			Type:    uint8(parent.mode.Load() >> 12),
			Ino:     parent.ino.Load(),
			NextOff: 2,
		},
	}

	// Merge dirents from all layers comprising this directory.
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	var readdirErr error
	prevDirents := make(map[string]struct{})
	var maybeWhiteouts []vfs.Dirent
	// mergedNames contains the names that a higher layer supplies and that a
	// lower layer also supplies as a directory or as a file of unknown type.
	var mergedNames map[string]struct{}
	d.iterLayers(func(layerVD vfs.VirtualDentry, isUpper bool) bool {
		stat, err := vfsObj.StatAt(ctx, d.fs.creds, &vfs.PathOperation{
			Root:  layerVD,
			Start: layerVD,
		}, &vfs.StatOptions{Mask: linux.STATX_INO})
		if err != nil {
			readdirErr = err
			return false
		}
		dev := layerDevNumber{stat.DevMajor, stat.DevMinor}
		layerFD, err := vfsObj.OpenAt(ctx, d.fs.creds, &vfs.PathOperation{
			Root:  layerVD,
			Start: layerVD,
		}, &vfs.OpenOptions{
			Flags: linux.O_RDONLY | linux.O_DIRECTORY,
		})
		if err != nil {
			readdirErr = err
			return false
		}
		defer layerFD.DecRef(ctx)

		// Reuse slice allocated for maybeWhiteouts from a previous layer to
		// reduce allocations.
		maybeWhiteouts = maybeWhiteouts[:0]
		firstDirent := len(dirents)
		err = layerFD.IterDirents(ctx, vfs.IterDirentsCallbackFunc(func(dirent vfs.Dirent) error {
			if dirent.Name == "." || dirent.Name == ".." {
				return nil
			}
			if _, ok := prevDirents[dirent.Name]; ok {
				// This file is hidden by, or merged with, another file with
				// the same name in a previous layer.
				if isDirOrUnknown(dirent.Type) {
					if mergedNames == nil {
						mergedNames = make(map[string]struct{})
					}
					mergedNames[dirent.Name] = struct{}{}
				}
				return nil
			}
			prevDirents[dirent.Name] = struct{}{}
			if dirent.Type == linux.DT_CHR {
				// We can't determine if this file is a whiteout while holding
				// locks held by layerFD.IterDirents().
				maybeWhiteouts = append(maybeWhiteouts, dirent)
				return nil
			}
			dirent.NextOff = int64(len(dirents) + 1)
			dirents = append(dirents, dirent)
			return nil
		}))
		if err != nil {
			readdirErr = err
			return false
		}

		// Convert a layer's entries under one lock, after IterDirents releases
		// its filesystem locks. No layer operations run under dirInoCacheMu.
		d.fs.dirInoCacheMu.Lock()
		for i := firstDirent; i < len(dirents); i++ {
			dirents[i].Ino = d.fs.identityForLocked(layerDevNoAndIno{dev, dirents[i].Ino}).ino
		}
		d.fs.dirInoCacheMu.Unlock()

		for _, dirent := range maybeWhiteouts {
			stat, err := vfsObj.StatAt(ctx, d.fs.creds, &vfs.PathOperation{
				Root:  layerVD,
				Start: layerVD,
				Path:  fspath.Parse(dirent.Name),
			}, &vfs.StatOptions{})
			if linuxerr.Equals(linuxerr.ENOENT, err) {
				delete(prevDirents, dirent.Name)
				continue
			}
			if err != nil {
				readdirErr = err
				return false
			}
			if stat.RdevMajor == 0 && stat.RdevMinor == 0 {
				// This file is a whiteout; don't emit a dirent for it.
				continue
			}
			dirent.Ino = d.fs.identityFor(layerDevNoAndIno{
				layerDevNumber{stat.DevMajor, stat.DevMinor}, stat.Ino,
			}).ino
			dirent.NextOff = int64(len(dirents) + 1)
			dirents = append(dirents, dirent)
		}
		return true
	})
	if readdirErr != nil {
		return nil, readdirErr
	}

	// A child directory that more than one layer supplies uses its
	// bottommost origin. This origin can differ from the layer that
	// supplied the name. A name that only one layer supplies uses the inode
	// of that layer, so it needs no child lookup. If a child dentry exists,
	// the listing uses the inode of that dentry. For example, a directory
	// that a rename moves to a name that only the upper layer supplies keeps
	// its lower layer inode while its dentry exists.
	childInoDiffers := false
	if len(mergedNames) != 0 || d.hasLowerDirChildLocked() {
		for i := 2; i < len(dirents); i++ {
			if !isDirOrUnknown(dirents[i].Type) {
				continue
			}
			name := dirents[i].Name
			if _, ok := mergedNames[name]; ok {
				if child, _, err := d.fs.getChildLocked(ctx, d, name, ds); err == nil {
					dirents[i].Ino = child.ino.Load()
				}
				continue
			}
			child, ok := d.children[name]
			if !ok {
				continue
			}
			if ino := child.ino.Load(); ino != dirents[i].Ino {
				dirents[i].Ino = ino
				childInoDiffers = true
			}
		}
	}

	// Leave the cache empty if this listing uses the inode of a child dentry
	// that can be destroyed without invalidating d.dirents, or if a child's
	// inode changed while this listing was built. This listing is still
	// returned to the caller.
	if childInoDiffers || d.direntsEpoch.Load() != epoch {
		d.dirents = nil
		return dirents, nil
	}
	d.dirents = dirents
	d.direntsEpochCached = epoch
	return dirents, nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *directoryFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fdIdx := fd.lockIndex()
	fd.mu.NestedLock(fdIdx)
	defer fd.mu.NestedUnlock(fdIdx)

	switch whence {
	case linux.SEEK_SET:
		if offset < 0 {
			return 0, linuxerr.EINVAL
		}
		if offset == 0 {
			// Ensure that the next call to fd.IterDirents() calls
			// fd.dentry().getDirents().
			fd.dirents = nil
		}
		fd.off = offset
		return fd.off, nil
	case linux.SEEK_CUR:
		offset += fd.off
		if offset < 0 {
			return 0, linuxerr.EINVAL
		}
		// Don't clear fd.dirents in this case, even if offset == 0.
		fd.off = offset
		return fd.off, nil
	default:
		return 0, linuxerr.EINVAL
	}
}

// Sync implements vfs.FileDescriptionImpl.Sync. Forwards sync to the upper
// layer, if there is one. The lower layer doesn't need to sync because it
// never changes.
func (fd *directoryFD) Sync(ctx context.Context, opts vfs.SyncOptions) error {
	d := fd.dentry()
	if !d.isCopiedUp() {
		return nil
	}
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	pop := vfs.PathOperation{
		Root:  d.upperVD,
		Start: d.upperVD,
	}
	upperFD, err := vfsObj.OpenAt(ctx, d.fs.creds, &pop, &vfs.OpenOptions{Flags: linux.O_RDONLY | linux.O_DIRECTORY})
	if err != nil {
		return err
	}
	if opts.DataOnly {
		err = upperFD.SyncData(ctx)
	} else {
		err = upperFD.Sync(ctx)
	}
	upperFD.DecRef(ctx)
	return err
}
