// Copyright 2018 Google Inc.
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
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
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
	Entry

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
	// Its entries ar kept up-to-date with d.children.
	dentryMap *fs.SortedDentryMap
}

// InitDir initializes a directory.
func (d *Dir) InitDir(ctx context.Context, contents map[string]*fs.Inode, owner fs.FileOwner, perms fs.FilePermissions) {
	d.InitEntry(ctx, owner, perms)
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
}

// addChildLocked add the child inode, inheriting its reference.
func (d *Dir) addChildLocked(name string, inode *fs.Inode) {
	d.children[name] = inode
	d.dentryMap.Add(name, fs.DentAttr{
		Type:    inode.StableAttr.Type,
		InodeID: inode.StableAttr.InodeID,
	})

	// If the child is a directory, increment this dir's link count,
	// corresponding to '..' from the subdirectory.
	if fs.IsDir(inode.StableAttr) {
		d.AddLink()
	}

	// Given we're now adding this inode to the directory we must also
	// increase its link count. Similarly we decremented it in removeChildLocked.
	inode.AddLink()
}

// AddChild adds a child to this dir.
func (d *Dir) AddChild(ctx context.Context, name string, inode *fs.Inode) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.addChildLocked(name, inode)
}

// FindChild returns (child, true) if the directory contains name.
func (d *Dir) FindChild(name string) (*fs.Inode, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	child, ok := d.children[name]
	return child, ok
}

// removeChildLocked attempts to remove an entry from this directory.
// This Entry's mutex must be held. It returns the removed Inode.
func (d *Dir) removeChildLocked(ctx context.Context, name string) (*fs.Inode, error) {
	inode, ok := d.children[name]
	if !ok {
		return nil, ErrNotFound
	}

	delete(d.children, name)
	d.dentryMap.Remove(name)
	d.Entry.NotifyModification(ctx)

	// If the child was a subdirectory, then we must decrement this dir's
	// link count which was the child's ".." directory entry.
	if fs.IsDir(inode.StableAttr) {
		d.DropLink()
	}

	// Update ctime.
	inode.NotifyStatusChange(ctx)

	// Given we're now removing this inode to the directory we must also
	// decrease its link count. Similarly it is increased in addChildLocked.
	inode.DropLink()

	return inode, nil
}

// RemoveEntry attempts to remove an entry from this directory.
func (d *Dir) RemoveEntry(ctx context.Context, name string) error {
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

// Remove removes the named non-directory.
func (d *Dir) Remove(ctx context.Context, dir *fs.Inode, name string) error {
	return d.RemoveEntry(ctx, name)
}

// RemoveDirectory removes the named directory.
func (d *Dir) RemoveDirectory(ctx context.Context, dir *fs.Inode, name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	n, err := d.walkLocked(ctx, name)
	if err != nil {
		return err
	}
	dirCtx := &fs.DirCtx{}
	if _, err := n.HandleOps().DeprecatedReaddir(ctx, dirCtx, 0); err != nil {
		return err
	}
	if len(dirCtx.DentAttrs()) > 0 {
		return ErrNotEmpty
	}
	inode, err := d.removeChildLocked(ctx, name)
	if err != nil {
		return err
	}

	// Remove our reference on the inode.
	inode.DecRef()

	return err
}

// Lookup loads an inode at p into a Dirent.
func (d *Dir) Lookup(ctx context.Context, dir *fs.Inode, p string) (*fs.Dirent, error) {
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

// walkLocked must be called with this Entry's mutex held.
func (d *Dir) walkLocked(ctx context.Context, p string) (*fs.Inode, error) {
	d.Entry.NotifyAccess(ctx)

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
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.children[name]; ok {
		return nil, syscall.EEXIST
	}

	inode, err := makeInodeOperations()
	if err != nil {
		return nil, err
	}

	d.addChildLocked(name, inode)
	d.Entry.NotifyModification(ctx)

	return inode, nil
}

// Create creates a new Inode with the given name and returns its File.
func (d *Dir) Create(ctx context.Context, dir *fs.Inode, name string, flags fs.FileFlags, perms fs.FilePermissions) (*fs.File, error) {
	if d.CreateOps == nil || d.CreateOps.NewFile == nil {
		return nil, ErrDenied
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
		return ErrDenied
	}
	_, err := d.createInodeOperationsCommon(ctx, newname, func() (*fs.Inode, error) {
		return d.NewSymlink(ctx, dir, oldname)
	})
	return err
}

// CreateHardLink creates a new hard link.
func (d *Dir) CreateHardLink(ctx context.Context, dir *fs.Inode, target *fs.Inode, name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Take an extra reference on the inode and add it to our children.
	target.IncRef()

	// The link count will be incremented in addChildLocked.
	d.addChildLocked(name, target)
	d.Entry.NotifyModification(ctx)

	// Update ctime.
	target.NotifyStatusChange(ctx)

	return nil
}

// CreateDirectory returns a new subdirectory.
func (d *Dir) CreateDirectory(ctx context.Context, dir *fs.Inode, name string, perms fs.FilePermissions) error {
	if d.CreateOps == nil || d.CreateOps.NewDir == nil {
		return ErrDenied
	}
	_, err := d.createInodeOperationsCommon(ctx, name, func() (*fs.Inode, error) {
		return d.NewDir(ctx, dir, perms)
	})
	// TODO: Support updating status times, as those should be
	// updated by links.
	return err
}

// Bind implements fs.InodeOperations.Bind.
func (d *Dir) Bind(ctx context.Context, dir *fs.Inode, name string, ep transport.BoundEndpoint, perms fs.FilePermissions) (*fs.Dirent, error) {
	if d.CreateOps == nil || d.CreateOps.NewBoundEndpoint == nil {
		return nil, ErrDenied
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
		return ErrDenied
	}
	_, err := d.createInodeOperationsCommon(ctx, name, func() (*fs.Inode, error) {
		return d.NewFifo(ctx, dir, perms)
	})
	return err
}

func (d *Dir) readdirLocked(ctx context.Context, dirCtx *fs.DirCtx, offset int) (int, error) {
	// Serialize the entries in dentryMap.
	n, err := fs.GenericReaddir(dirCtx, d.dentryMap)

	// Touch the access time.
	d.Entry.NotifyAccess(ctx)

	return offset + n, err
}

// DeprecatedReaddir emits the entries contained in this directory.
func (d *Dir) DeprecatedReaddir(ctx context.Context, dirCtx *fs.DirCtx, offset int) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.readdirLocked(ctx, dirCtx, offset)
}

// DeprecatedPreadv always returns ErrIsDirectory
func (*Dir) DeprecatedPreadv(context.Context, usermem.IOSequence, int64) (int64, error) {
	return 0, ErrIsDirectory
}

// DeprecatedPwritev always returns ErrIsDirectory
func (*Dir) DeprecatedPwritev(context.Context, usermem.IOSequence, int64) (int64, error) {
	return 0, ErrIsDirectory
}
