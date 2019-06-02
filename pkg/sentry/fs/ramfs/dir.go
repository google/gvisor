// Copyright 2018 The gVisor Authors.
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

package ramfs

import (
	"fmt"
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// CreateOps represents operations to create different file types.
type CreateOps struct {
	// NewDir creates a new directory.
	NewDir func(ctx context.Context, dir *fs.Inode, perms fs.FilePermissions) (*fs.Inode, error)

	// NewFile creates a new file.
	NewFile func(ctx context.Context, dir *fs.Inode, perms fs.FilePermissions) (*fs.Inode, error)

	// NewSymlink creates a new symlink with permissions 0777.
	NewSymlink func(ctx context.Context, dir *fs.Inode, target string) (*fs.Inode, error)

	// NewBoundEndpoint creates a new socket.
	NewBoundEndpoint func(ctx context.Context, dir *fs.Inode, ep transport.BoundEndpoint, perms fs.FilePermissions) (*fs.Inode, error)

	// NewFifo creates a new fifo.
	NewFifo func(ctx context.Context, dir *fs.Inode, perm fs.FilePermissions) (*fs.Inode, error)
}

// Dir represents a single directory in the filesystem.
//
// +stateify savable
type Dir struct {
	fsutil.InodeGenericChecker `state:"nosave"`
	fsutil.InodeIsDirAllocate  `state:"nosave"`
	fsutil.InodeIsDirTruncate  `state:"nosave"`
	fsutil.InodeNoopRelease    `state:"nosave"`
	fsutil.InodeNoopWriteOut   `state:"nosave"`
	fsutil.InodeNotMappable    `state:"nosave"`
	fsutil.InodeNotSocket      `state:"nosave"`
	fsutil.InodeNotSymlink     `state:"nosave"`
	fsutil.InodeVirtual        `state:"nosave"`

	fsutil.InodeSimpleAttributes
	fsutil.InodeSimpleExtendedAttributes

	// CreateOps may be provided.
	//
	// These may only be modified during initialization (while the application
	// is not running). No sychronization is performed when accessing these
	// operations during syscalls.
	*CreateOps `state:"nosave"`

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	// children are inodes that are in this directory.  A reference is held
	// on each inode while it is in the map.
	children map[string]*fs.Inode

	// dentryMap is a sortedDentryMap containing entries for all children.
	// Its entries are kept up-to-date with d.children.
	dentryMap *fs.SortedDentryMap
}

var _ fs.InodeOperations = (*Dir)(nil)

// NewDir returns a new Dir with the given contents and attributes.
func NewDir(ctx context.Context, contents map[string]*fs.Inode, owner fs.FileOwner, perms fs.FilePermissions) *Dir {
	d := &Dir{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, owner, perms, linux.RAMFS_MAGIC),
	}

	if contents == nil {
		contents = make(map[string]*fs.Inode)
	}
	d.children = contents

	// Build the entries map ourselves, rather than calling addChildLocked,
	// because it will be faster.
	entries := make(map[string]fs.DentAttr, len(contents))
	for name, inode := range contents {
		entries[name] = fs.DentAttr{
			Type:    inode.StableAttr.Type,
			InodeID: inode.StableAttr.InodeID,
		}
	}
	d.dentryMap = fs.NewSortedDentryMap(entries)

	// Directories have an extra link, corresponding to '.'.
	d.AddLink()

	return d
}

// addChildLocked add the child inode, inheriting its reference.
func (d *Dir) addChildLocked(ctx context.Context, name string, inode *fs.Inode) {
	d.children[name] = inode
	d.dentryMap.Add(name, fs.DentAttr{
		Type:    inode.StableAttr.Type,
		InodeID: inode.StableAttr.InodeID,
	})

	// If the child is a directory, increment this dir's link count,
	// corresponding to '..' from the subdirectory.
	if fs.IsDir(inode.StableAttr) {
		d.AddLink()
		// ctime updated below.
	}

	// Given we're now adding this inode to the directory we must also
	// increase its link count. Similarly we decrement it in removeChildLocked.
	//
	// Changing link count updates ctime.
	inode.AddLink()
	inode.InodeOperations.NotifyStatusChange(ctx)

	// We've change the directory. This always updates our mtime and ctime.
	d.NotifyModificationAndStatusChange(ctx)
}

// AddChild adds a child to this dir.
func (d *Dir) AddChild(ctx context.Context, name string, inode *fs.Inode) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.addChildLocked(ctx, name, inode)
}

// FindChild returns (child, true) if the directory contains name.
func (d *Dir) FindChild(name string) (*fs.Inode, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	child, ok := d.children[name]
	return child, ok
}

// Children returns the names and DentAttrs of all children. It can be used to
// implement Readdir for types that embed ramfs.Dir.
func (d *Dir) Children() ([]string, map[string]fs.DentAttr) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Return a copy to prevent callers from modifying our children.
	names, entries := d.dentryMap.GetAll()
	namesCopy := make([]string, len(names))
	copy(namesCopy, names)

	entriesCopy := make(map[string]fs.DentAttr)
	for k, v := range entries {
		entriesCopy[k] = v
	}

	return namesCopy, entriesCopy
}

// removeChildLocked attempts to remove an entry from this directory.
func (d *Dir) removeChildLocked(ctx context.Context, name string) (*fs.Inode, error) {
	inode, ok := d.children[name]
	if !ok {
		return nil, syserror.EACCES
	}

	delete(d.children, name)
	d.dentryMap.Remove(name)
	d.NotifyModification(ctx)

	// If the child was a subdirectory, then we must decrement this dir's
	// link count which was the child's ".." directory entry.
	if fs.IsDir(inode.StableAttr) {
		d.DropLink()
		// ctime changed below.
	}

	// Given we're now removing this inode to the directory we must also
	// decrease its link count. Similarly it is increased in addChildLocked.
	//
	// Changing link count updates ctime.
	inode.DropLink()
	inode.InodeOperations.NotifyStatusChange(ctx)

	// We've change the directory. This always updates our mtime and ctime.
	d.NotifyModificationAndStatusChange(ctx)

	return inode, nil
}

// Remove removes the named non-directory.
func (d *Dir) Remove(ctx context.Context, _ *fs.Inode, name string) error {
	if len(name) > linux.NAME_MAX {
		return syserror.ENAMETOOLONG
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	inode, err := d.removeChildLocked(ctx, name)
	if err != nil {
		return err
	}

	// Remove our reference on the inode.
	inode.DecRef()
	return nil
}

// RemoveDirectory removes the named directory.
func (d *Dir) RemoveDirectory(ctx context.Context, _ *fs.Inode, name string) error {
	if len(name) > linux.NAME_MAX {
		return syserror.ENAMETOOLONG
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Get the child and make sure it is not empty.
	childInode, err := d.walkLocked(ctx, name)
	if err != nil {
		return err
	}
	if ok, err := hasChildren(ctx, childInode); err != nil {
		return err
	} else if ok {
		return syserror.ENOTEMPTY
	}

	// Child was empty. Proceed with removal.
	inode, err := d.removeChildLocked(ctx, name)
	if err != nil {
		return err
	}

	// Remove our reference on the inode.
	inode.DecRef()

	return nil
}

// Lookup loads an inode at p into a Dirent.
func (d *Dir) Lookup(ctx context.Context, _ *fs.Inode, p string) (*fs.Dirent, error) {
	if len(p) > linux.NAME_MAX {
		return nil, syserror.ENAMETOOLONG
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	inode, err := d.walkLocked(ctx, p)
	if err != nil {
		return nil, err
	}

	// Take a reference on the inode before returning it.  This reference
	// is owned by the dirent we are about to create.
	inode.IncRef()
	return fs.NewDirent(inode, p), nil
}

// walkLocked must be called with d.mu held.
func (d *Dir) walkLocked(ctx context.Context, p string) (*fs.Inode, error) {
	// Lookup a child node.
	if inode, ok := d.children[p]; ok {
		return inode, nil
	}

	// fs.InodeOperations.Lookup returns syserror.ENOENT if p
	// does not exist.
	return nil, syserror.ENOENT
}

// createInodeOperationsCommon creates a new child node at this dir by calling
// makeInodeOperations. It is the common logic for creating a new child.
func (d *Dir) createInodeOperationsCommon(ctx context.Context, name string, makeInodeOperations func() (*fs.Inode, error)) (*fs.Inode, error) {
	if len(name) > linux.NAME_MAX {
		return nil, syserror.ENAMETOOLONG
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	inode, err := makeInodeOperations()
	if err != nil {
		return nil, err
	}

	d.addChildLocked(ctx, name, inode)

	return inode, nil
}

// Create creates a new Inode with the given name and returns its File.
func (d *Dir) Create(ctx context.Context, dir *fs.Inode, name string, flags fs.FileFlags, perms fs.FilePermissions) (*fs.File, error) {
	if d.CreateOps == nil || d.CreateOps.NewFile == nil {
		return nil, syserror.EACCES
	}

	inode, err := d.createInodeOperationsCommon(ctx, name, func() (*fs.Inode, error) {
		return d.NewFile(ctx, dir, perms)
	})
	if err != nil {
		return nil, err
	}

	// Take an extra ref on inode, which will be owned by the dirent.
	inode.IncRef()

	// Create the Dirent and corresponding file.
	created := fs.NewDirent(inode, name)
	defer created.DecRef()
	return created.Inode.GetFile(ctx, created, flags)
}

// CreateLink returns a new link.
func (d *Dir) CreateLink(ctx context.Context, dir *fs.Inode, oldname, newname string) error {
	if d.CreateOps == nil || d.CreateOps.NewSymlink == nil {
		return syserror.EACCES
	}
	_, err := d.createInodeOperationsCommon(ctx, newname, func() (*fs.Inode, error) {
		return d.NewSymlink(ctx, dir, oldname)
	})
	return err
}

// CreateHardLink creates a new hard link.
func (d *Dir) CreateHardLink(ctx context.Context, dir *fs.Inode, target *fs.Inode, name string) error {
	if len(name) > linux.NAME_MAX {
		return syserror.ENAMETOOLONG
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Take an extra reference on the inode and add it to our children.
	target.IncRef()

	// The link count will be incremented in addChildLocked.
	d.addChildLocked(ctx, name, target)

	return nil
}

// CreateDirectory returns a new subdirectory.
func (d *Dir) CreateDirectory(ctx context.Context, dir *fs.Inode, name string, perms fs.FilePermissions) error {
	if d.CreateOps == nil || d.CreateOps.NewDir == nil {
		return syserror.EACCES
	}
	_, err := d.createInodeOperationsCommon(ctx, name, func() (*fs.Inode, error) {
		return d.NewDir(ctx, dir, perms)
	})
	return err
}

// Bind implements fs.InodeOperations.Bind.
func (d *Dir) Bind(ctx context.Context, dir *fs.Inode, name string, ep transport.BoundEndpoint, perms fs.FilePermissions) (*fs.Dirent, error) {
	if d.CreateOps == nil || d.CreateOps.NewBoundEndpoint == nil {
		return nil, syserror.EACCES
	}
	inode, err := d.createInodeOperationsCommon(ctx, name, func() (*fs.Inode, error) {
		return d.NewBoundEndpoint(ctx, dir, ep, perms)
	})
	if err == syscall.EEXIST {
		return nil, syscall.EADDRINUSE
	}
	if err != nil {
		return nil, err
	}
	// Take another ref on inode which will be donated to the new dirent.
	inode.IncRef()
	return fs.NewDirent(inode, name), nil
}

// CreateFifo implements fs.InodeOperations.CreateFifo.
func (d *Dir) CreateFifo(ctx context.Context, dir *fs.Inode, name string, perms fs.FilePermissions) error {
	if d.CreateOps == nil || d.CreateOps.NewFifo == nil {
		return syserror.EACCES
	}
	_, err := d.createInodeOperationsCommon(ctx, name, func() (*fs.Inode, error) {
		return d.NewFifo(ctx, dir, perms)
	})
	return err
}

// GetFile implements fs.InodeOperations.GetFile.
func (d *Dir) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	flags.Pread = true
	return fs.NewFile(ctx, dirent, flags, &dirFileOperations{dir: d}), nil
}

// Rename implements fs.InodeOperations.Rename.
func (*Dir) Rename(ctx context.Context, inode *fs.Inode, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string, replacement bool) error {
	return Rename(ctx, oldParent.InodeOperations, oldName, newParent.InodeOperations, newName, replacement)
}

// dirFileOperations implements fs.FileOperations for a ramfs directory.
//
// +stateify savable
type dirFileOperations struct {
	fsutil.DirFileOperations        `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`

	// dirCursor contains the name of the last directory entry that was
	// serialized.
	dirCursor string

	// dir is the ramfs dir that this file corresponds to.
	dir *Dir
}

var _ fs.FileOperations = (*dirFileOperations)(nil)

// Seek implements fs.FileOperations.Seek.
func (dfo *dirFileOperations) Seek(ctx context.Context, file *fs.File, whence fs.SeekWhence, offset int64) (int64, error) {
	return fsutil.SeekWithDirCursor(ctx, file, whence, offset, &dfo.dirCursor)
}

// IterateDir implements DirIterator.IterateDir.
func (dfo *dirFileOperations) IterateDir(ctx context.Context, dirCtx *fs.DirCtx, offset int) (int, error) {
	dfo.dir.mu.Lock()
	defer dfo.dir.mu.Unlock()

	n, err := fs.GenericReaddir(dirCtx, dfo.dir.dentryMap)
	return offset + n, err
}

// Readdir implements FileOperations.Readdir.
func (dfo *dirFileOperations) Readdir(ctx context.Context, file *fs.File, serializer fs.DentrySerializer) (int64, error) {
	root := fs.RootFromContext(ctx)
	if root != nil {
		defer root.DecRef()
	}
	dirCtx := &fs.DirCtx{
		Serializer: serializer,
		DirCursor:  &dfo.dirCursor,
	}
	dfo.dir.InodeSimpleAttributes.NotifyAccess(ctx)
	return fs.DirentReaddir(ctx, file.Dirent, dfo, root, dirCtx, file.Offset())
}

// hasChildren is a helper method that determines whether an arbitrary inode
// (not necessarily ramfs) has any children.
func hasChildren(ctx context.Context, inode *fs.Inode) (bool, error) {
	// Take an extra ref on inode which will be given to the dirent and
	// dropped when that dirent is destroyed.
	inode.IncRef()
	d := fs.NewTransientDirent(inode)
	defer d.DecRef()

	file, err := inode.GetFile(ctx, d, fs.FileFlags{Read: true})
	if err != nil {
		return false, err
	}
	defer file.DecRef()

	ser := &fs.CollectEntriesSerializer{}
	if err := file.Readdir(ctx, ser); err != nil {
		return false, err
	}
	// We will always write "." and "..", so ignore those two.
	if ser.Written() > 2 {
		return true, nil
	}
	return false, nil
}

// Rename renames from a *ramfs.Dir to another *ramfs.Dir.
func Rename(ctx context.Context, oldParent fs.InodeOperations, oldName string, newParent fs.InodeOperations, newName string, replacement bool) error {
	op, ok := oldParent.(*Dir)
	if !ok {
		return syserror.EXDEV
	}
	np, ok := newParent.(*Dir)
	if !ok {
		return syserror.EXDEV
	}
	if len(newName) > linux.NAME_MAX {
		return syserror.ENAMETOOLONG
	}

	np.mu.Lock()
	defer np.mu.Unlock()

	// Is this is an overwriting rename?
	if replacement {
		replaced, ok := np.children[newName]
		if !ok {
			panic(fmt.Sprintf("Dirent claims rename is replacement, but %q is missing from %+v", newName, np))
		}

		// Non-empty directories cannot be replaced.
		if fs.IsDir(replaced.StableAttr) {
			if ok, err := hasChildren(ctx, replaced); err != nil {
				return err
			} else if ok {
				return syserror.ENOTEMPTY
			}
		}

		// Remove the replaced child and drop our reference on it.
		inode, err := np.removeChildLocked(ctx, newName)
		if err != nil {
			return err
		}
		inode.DecRef()
	}

	// Be careful, we may have already grabbed this mutex above.
	if op != np {
		op.mu.Lock()
		defer op.mu.Unlock()
	}

	// Do the swap.
	n := op.children[oldName]
	op.removeChildLocked(ctx, oldName)
	np.addChildLocked(ctx, newName, n)

	return nil
}
