// Copyright 2023 The gVisor Authors.
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

package erofs

import (
	goContext "context"
	"fmt"
	"os"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/erofs"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

var _ vfs.FilesystemImplSaveRestoreExtension = (*filesystem)(nil)

// PrepareSave implements vfs.FilesystemImplSaveRestoreExtension.PrepareSave.
func (fs *filesystem) PrepareSave(ctx context.Context, _ vfs.PrepareSaveOptions) error {
	return nil
}

// BeforeResume implements vfs.FilesystemImplSaveRestoreExtension.BeforeResume.
func (fs *filesystem) BeforeResume(ctx context.Context) {}

// afterLoad is called by stateify.
func (fs *filesystem) afterLoad(ctx goContext.Context) {
	fs.memoryFile = pgalloc.MemoryFileFromContext(ctx)
	fdmap := vfs.RestoreFilesystemFDMapFromContext(ctx)
	fd, ok := fdmap[fs.iopts.UniqueID]
	if !ok {
		panic(fmt.Sprintf("no image FD available for filesystem with unique ID %q, map: %#v", fs.iopts.UniqueID, fdmap))
	}
	newImage, err := erofs.OpenImage(os.NewFile(uintptr(fd), "EROFS image file"))
	if err != nil {
		panic(fmt.Sprintf("erofs.OpenImage failed: %v", err))
	}
	// The saved inodes describe the image that was checkpointed. If this is
	// another one, CompleteRestore replaces them.
	fs.superBlockChanged = newImage.SuperBlock() != fs.image.SuperBlock()
	// We need to update the image in place, as there are other pointers
	// pointing to this image as well.
	*fs.image = *newImage
}

// CompleteRestore implements
// vfs.FilesystemImplSaveRestoreExtension.CompleteRestore.
func (fs *filesystem) CompleteRestore(ctx context.Context, opts vfs.CompleteRestoreOptions) error {
	// Cached dentries are unused, so drop them rather than check them against
	// fs.image. Every dentry that remains is in use.
	fs.evictAllCachedDentries(ctx)
	if !fs.superBlockChanged && fs.inodesUnchanged() {
		return nil
	}
	ctx.Infof("EROFS image of mount %q was rebuilt since the checkpoint, resolving its inodes by path", fs.iopts.UniqueID)

	// Inodes are indexed by nid, which is their position in the image.
	for i := range fs.inodeBuckets {
		fs.inodeBuckets[i].init()
	}
	restored := make(map[*inode]struct{})
	for todo := []*dentry{fs.root}; len(todo) > 0; {
		d := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if err := d.restoreInode(restored); err != nil {
			return vfs.ErrCorruption{Err: fmt.Errorf("erofs.dentry(%q in mount %q).restoreInode: %w", genericDebugPathname(fs, d), fs.iopts.UniqueID, err)}
		}
		d.dirMu.RLock()
		for _, child := range d.childMap {
			todo = append(todo, child)
		}
		d.dirMu.RUnlock()
	}

	// A file may now have the inode number that another had. Applications
	// such as the dynamic linker tell files apart by device and inode number,
	// so change the former, and keep the old one allocated.
	devMinor, err := fs.vfsfs.VirtualFilesystem().GetAnonBlockDevMinor()
	if err != nil {
		return err
	}
	fs.devMinor = devMinor
	return nil
}

// inodesUnchanged returns true if fs.image has an inode equal to each of
// fs's inodes at the nid of that inode.
func (fs *filesystem) inodesUnchanged() bool {
	for b := range fs.inodeBuckets {
		ib := &fs.inodeBuckets[b]
		ib.mu.RLock()
		for nid, i := range ib.inodeMap {
			if ino, err := fs.image.Inode(nid); err != nil || ino != i.Inode {
				ib.mu.RUnlock()
				return false
			}
		}
		ib.mu.RUnlock()
	}
	return true
}

// restoreInode makes d.inode represent the inode that d's path names in
// fs.image. restored is the set of inodes that already do.
//
// Preconditions: d.parent, if any, has been restored.
func (d *dentry) restoreInode(restored map[*inode]struct{}) error {
	i := d.inode
	nid := i.fs.image.RootNid()
	if parent := d.parent.Load(); parent != nil {
		var err error
		if nid, err = parent.inode.Lookup(d.name); err != nil {
			return err
		}
	}
	ib := i.fs.inodeBucket(nid)
	ib.mu.Lock()
	defer ib.mu.Unlock()
	if _, ok := restored[i]; ok || ib.inodeMap[nid] != nil {
		// Hard links share an inode, whose locks, watches and mappings can be
		// neither split nor merged, so the same dentries must share it.
		if ib.inodeMap[nid] != i {
			return fmt.Errorf("hard links changed")
		}
		return nil
	}
	ino, err := i.fs.image.Inode(nid)
	if err != nil {
		return err
	}
	// File descriptions and the dentry tree depend on the file type, and an
	// overlay keeps the mode and owner that it cached.
	if ino.Mode() != i.Mode() || ino.UID() != i.UID() || ino.GID() != i.GID() {
		return fmt.Errorf("mode or owner changed from %#o %d:%d to %#o %d:%d", i.Mode(), i.UID(), i.GID(), ino.Mode(), ino.UID(), ino.GID())
	}
	// The application may hold contents of a regular file that another file
	// at its path would not match.
	if i.IsRegular() && (ino.Size() != i.Size() || ino.Mtime() != i.Mtime() || ino.MtimeNsec() != i.MtimeNsec()) {
		return fmt.Errorf("size or mtime changed from %d and %d.%09d to %d and %d.%09d", i.Size(), i.Mtime(), i.MtimeNsec(), ino.Size(), ino.Mtime(), ino.MtimeNsec())
	}
	i.Inode = ino
	restored[i] = struct{}{}
	ib.inodeMap[nid] = i
	return nil
}

// saveParent is called by stateify.
func (d *dentry) saveParent() *dentry {
	return d.parent.Load()
}

// loadParent is called by stateify.
func (d *dentry) loadParent(_ goContext.Context, parent *dentry) {
	d.parent.Store(parent)
}

// afterLoad is called by stateify.
func (d *dentry) afterLoad(goContext.Context) {
	if d.refs.Load() != -1 {
		refs.Register(d)
	}
}
