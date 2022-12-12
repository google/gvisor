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

// Preconditions:
//   - d.dirMu must be locked.
//   - d.isDir().
func (d *dentry) collectWhiteoutsForRmdirLocked(ctx context.Context) (map[string]bool, error) {
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	var readdirErr error
	whiteouts := make(map[string]bool)
	var maybeWhiteouts []string
	d.iterLayers(func(ld layerDentry, isUpper bool) bool {
		layerFD, err := vfsObj.OpenAt(ctx, d.fs.creds, &vfs.PathOperation{
			Root:  ld.vd,
			Start: ld.vd,
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
				Root:  ld.vd,
				Start: ld.vd,
				Path:  fspath.Parse(maybeWhiteoutName),
			}, &vfs.StatOptions{})
			if err != nil {
				readdirErr = err
				return false
			}
			if stat.RdevMajor != 0 || stat.RdevMinor != 0 {
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

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *directoryFD) Release(ctx context.Context) {
}

// IterDirents implements vfs.FileDescriptionImpl.IterDirents.
func (fd *directoryFD) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback) error {
	d := fd.dentry()
	fd.mu.Lock()
	defer fd.mu.Unlock()

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
	d.fs.renameMu.RLock()
	defer d.fs.renameMu.RUnlock()
	d.dirMu.Lock()
	defer d.dirMu.Unlock()
	return d.getDirentsLocked(ctx)
}

type direntInfo struct {
	dirent  vfs.Dirent
	merging bool
}

// Preconditions:
//   - filesystem.renameMu must be locked.
//   - d.dirMu must be locked.
//   - d.isDir().
func (d *dentry) getDirentsLocked(ctx context.Context) ([]vfs.Dirent, error) {
	if d.dirents != nil {
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
	prevDirents := make(map[string]direntInfo)
	var maybeWhiteouts []vfs.Dirent
	d.iterLayers(func(ld layerDentry, isUpper bool) bool {
		layerFD, err := vfsObj.OpenAt(ctx, d.fs.creds, &vfs.PathOperation{
			Root:  ld.vd,
			Start: ld.vd,
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
			if dirent.Type == linux.DT_DIR {
				// Re-calculate directory inode number using the lowest layer's
				// device IDs.
				dirent.Ino = d.fs.newDirIno(ld.realDevMajor, ld.realDevMinor, dirent.Ino)
			}
			if di, ok := prevDirents[dirent.Name]; ok {
				if di.dirent.Type != linux.DT_DIR || !di.merging {
					// This file is hidden by another file with the same name in a previous
					// layer.
					return nil
				}
				// We are still merging this directory from lower layers.
				if dirent.Type == linux.DT_DIR {
					di.dirent.Ino = dirent.Ino
				} else {
					// Can only merge with directories. Any further directories with the
					// same name from lower layers can not merge.
					di.merging = false
				}
				prevDirents[dirent.Name] = di
				return nil
			}
			prevDirents[dirent.Name] = direntInfo{dirent, true}
			if dirent.Type == linux.DT_CHR {
				// We can't determine if this file is a whiteout while holding
				// locks held by layerFD.IterDirents().
				maybeWhiteouts = append(maybeWhiteouts, dirent)
				return nil
			}
			return nil
		}))
		if err != nil {
			readdirErr = err
			return false
		}

		for _, dirent := range maybeWhiteouts {
			stat, err := vfsObj.StatAt(ctx, d.fs.creds, &vfs.PathOperation{
				Root:  ld.vd,
				Start: ld.vd,
				Path:  fspath.Parse(dirent.Name),
			}, &vfs.StatOptions{})
			if err != nil {
				readdirErr = err
				return false
			}
			if stat.RdevMajor == 0 && stat.RdevMinor == 0 {
				// This file is a whiteout; don't emit a dirent for it.
				continue
			}
			dirent.NextOff = int64(len(dirents) + 1)
			dirents = append(dirents, dirent)
		}
		return true
	})
	if readdirErr != nil {
		return nil, readdirErr
	}

	for _, di := range prevDirents {
		if di.dirent.Type == linux.DT_CHR {
			// This dirent is part of maybeWhiteouts. Handled above.
			continue
		}
		di.dirent.NextOff = int64(len(dirents) + 1)
		dirents = append(dirents, di.dirent)
	}

	// Cache dirents for future directoryFDs.
	d.dirents = dirents
	return dirents, nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *directoryFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

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
func (fd *directoryFD) Sync(ctx context.Context) error {
	d := fd.dentry()
	if !d.isCopiedUp() {
		return nil
	}
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	pop := vfs.PathOperation{
		Root:  d.upper.vd,
		Start: d.upper.vd,
	}
	upperFD, err := vfsObj.OpenAt(ctx, d.fs.creds, &pop, &vfs.OpenOptions{Flags: linux.O_RDONLY | linux.O_DIRECTORY})
	if err != nil {
		return err
	}
	err = upperFD.Sync(ctx)
	upperFD.DecRef(ctx)
	return err
}
