// Copyright 2018 Google LLC
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

package gofer

import (
	"fmt"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/p9"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/device"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// maxFilenameLen is the maximum length of a filename. This is dictated by 9P's
// encoding of strings, which uses 2 bytes for the length prefix.
const maxFilenameLen = (1 << 16) - 1

// Lookup loads an Inode at name into a Dirent based on the session's cache
// policy.
func (i *inodeOperations) Lookup(ctx context.Context, dir *fs.Inode, name string) (*fs.Dirent, error) {
	if len(name) > maxFilenameLen {
		return nil, syserror.ENAMETOOLONG
	}

	cp := i.session().cachePolicy
	if cp.cacheReaddir() {
		// Check to see if we have readdirCache that indicates the
		// child does not exist.  Avoid holding readdirMu longer than
		// we need to.
		i.readdirMu.Lock()
		if i.readdirCache != nil && !i.readdirCache.Contains(name) {
			// No such child.
			i.readdirMu.Unlock()
			if cp.cacheNegativeDirents() {
				return fs.NewNegativeDirent(name), nil
			}
			return nil, syserror.ENOENT
		}
		i.readdirMu.Unlock()
	}

	// Get a p9.File for name.
	qids, newFile, mask, p9attr, err := i.fileState.file.walkGetAttr(ctx, []string{name})
	if err != nil {
		if err == syscall.ENOENT {
			if cp.cacheNegativeDirents() {
				// Return a negative Dirent. It will stay cached until something
				// is created over it.
				return fs.NewNegativeDirent(name), nil
			}
			return nil, syserror.ENOENT
		}
		return nil, err
	}

	// Construct the Inode operations.
	sattr, node := newInodeOperations(ctx, i.fileState.s, newFile, qids[0], mask, p9attr, false)

	// Construct a positive Dirent.
	return fs.NewDirent(fs.NewInode(node, dir.MountSource, sattr), name), nil
}

// Creates a new Inode at name and returns its File based on the session's cache policy.
//
// Ownership is currently ignored.
func (i *inodeOperations) Create(ctx context.Context, dir *fs.Inode, name string, flags fs.FileFlags, perm fs.FilePermissions) (*fs.File, error) {
	if len(name) > maxFilenameLen {
		return nil, syserror.ENAMETOOLONG
	}

	// Create replaces the directory fid with the newly created/opened
	// file, so clone this directory so it doesn't change out from under
	// this node.
	_, newFile, err := i.fileState.file.walk(ctx, nil)
	if err != nil {
		return nil, err
	}

	// Map the FileFlags to p9 OpenFlags.
	var openFlags p9.OpenFlags
	switch {
	case flags.Read && flags.Write:
		openFlags = p9.ReadWrite
	case flags.Read:
		openFlags = p9.ReadOnly
	case flags.Write:
		openFlags = p9.WriteOnly
	default:
		panic(fmt.Sprintf("Create called with unknown or unset open flags: %v", flags))
	}

	owner := fs.FileOwnerFromContext(ctx)
	hostFile, err := newFile.create(ctx, name, openFlags, p9.FileMode(perm.LinuxMode()), p9.UID(owner.UID), p9.GID(owner.GID))
	if err != nil {
		// Could not create the file.
		return nil, err
	}

	i.touchModificationTime(ctx, dir)

	// Get an unopened p9.File for the file we created so that it can be cloned
	// and re-opened multiple times after creation, while also getting its
	// attributes. Both are required for inodeOperations.
	qids, unopened, mask, p9attr, err := i.fileState.file.walkGetAttr(ctx, []string{name})
	if err != nil {
		newFile.close(ctx)
		return nil, err
	}
	if len(qids) != 1 {
		log.Warningf("WalkGetAttr(%s) succeeded, but returned %d QIDs (%v), wanted 1", name, len(qids), qids)
		newFile.close(ctx)
		return nil, syserror.EIO
	}
	qid := qids[0]

	// Construct the InodeOperations.
	sattr, iops := newInodeOperations(ctx, i.fileState.s, unopened, qid, mask, p9attr, false)

	// Construct the positive Dirent.
	d := fs.NewDirent(fs.NewInode(iops, dir.MountSource, sattr), name)
	defer d.DecRef()

	// Construct the new file, caching the handles if allowed.
	h := &handles{
		File: newFile,
		Host: hostFile,
	}
	if iops.fileState.canShareHandles() {
		iops.fileState.handlesMu.Lock()
		iops.fileState.setSharedHandlesLocked(flags, h)
		iops.fileState.handlesMu.Unlock()
	}
	return NewFile(ctx, d, name, flags, iops, h), nil
}

// CreateLink uses Create to create a symlink between oldname and newname.
func (i *inodeOperations) CreateLink(ctx context.Context, dir *fs.Inode, oldname string, newname string) error {
	if len(newname) > maxFilenameLen {
		return syserror.ENAMETOOLONG
	}

	owner := fs.FileOwnerFromContext(ctx)
	if _, err := i.fileState.file.symlink(ctx, oldname, newname, p9.UID(owner.UID), p9.GID(owner.GID)); err != nil {
		return err
	}
	i.touchModificationTime(ctx, dir)
	return nil
}

// CreateHardLink implements InodeOperations.CreateHardLink.
func (i *inodeOperations) CreateHardLink(ctx context.Context, inode *fs.Inode, target *fs.Inode, newName string) error {
	if len(newName) > maxFilenameLen {
		return syserror.ENAMETOOLONG
	}

	targetOpts, ok := target.InodeOperations.(*inodeOperations)
	if !ok {
		return syscall.EXDEV
	}

	if err := i.fileState.file.link(ctx, &targetOpts.fileState.file, newName); err != nil {
		return err
	}
	if i.session().cachePolicy.cacheUAttrs(inode) {
		// Increase link count.
		targetOpts.cachingInodeOps.IncLinks(ctx)
	}
	i.touchModificationTime(ctx, inode)
	return nil
}

// CreateDirectory uses Create to create a directory named s under inodeOperations.
func (i *inodeOperations) CreateDirectory(ctx context.Context, dir *fs.Inode, s string, perm fs.FilePermissions) error {
	if len(s) > maxFilenameLen {
		return syserror.ENAMETOOLONG
	}

	owner := fs.FileOwnerFromContext(ctx)
	if _, err := i.fileState.file.mkdir(ctx, s, p9.FileMode(perm.LinuxMode()), p9.UID(owner.UID), p9.GID(owner.GID)); err != nil {
		return err
	}
	if i.session().cachePolicy.cacheUAttrs(dir) {
		// Increase link count.
		i.cachingInodeOps.IncLinks(ctx)
	}
	if i.session().cachePolicy.cacheReaddir() {
		// Invalidate readdir cache.
		i.markDirectoryDirty()
	}
	return nil
}

// Bind implements InodeOperations.Bind.
func (i *inodeOperations) Bind(ctx context.Context, dir *fs.Inode, name string, ep transport.BoundEndpoint, perm fs.FilePermissions) (*fs.Dirent, error) {
	if len(name) > maxFilenameLen {
		return nil, syserror.ENAMETOOLONG
	}

	if i.session().endpoints == nil {
		return nil, syscall.EOPNOTSUPP
	}

	// Create replaces the directory fid with the newly created/opened
	// file, so clone this directory so it doesn't change out from under
	// this node.
	_, newFile, err := i.fileState.file.walk(ctx, nil)
	if err != nil {
		return nil, err
	}

	// Stabilize the endpoint map while creation is in progress.
	unlock := i.session().endpoints.lock()
	defer unlock()

	// Create a regular file in the gofer and then mark it as a socket by
	// adding this inode key in the 'endpoints' map.
	owner := fs.FileOwnerFromContext(ctx)
	hostFile, err := newFile.create(ctx, name, p9.ReadWrite, p9.FileMode(perm.LinuxMode()), p9.UID(owner.UID), p9.GID(owner.GID))
	if err != nil {
		return nil, err
	}
	// We're not going to use this file.
	hostFile.Close()

	i.touchModificationTime(ctx, dir)

	// Get the attributes of the file to create inode key.
	qid, mask, attr, err := getattr(ctx, newFile)
	if err != nil {
		newFile.close(ctx)
		return nil, err
	}

	key := device.MultiDeviceKey{
		Device:          attr.RDev,
		SecondaryDevice: i.session().connID,
		Inode:           qid.Path,
	}

	// Create child dirent.

	// Get an unopened p9.File for the file we created so that it can be
	// cloned and re-opened multiple times after creation.
	_, unopened, err := i.fileState.file.walk(ctx, []string{name})
	if err != nil {
		newFile.close(ctx)
		return nil, err
	}

	// Construct the InodeOperations.
	sattr, iops := newInodeOperations(ctx, i.fileState.s, unopened, qid, mask, attr, true)

	// Construct the positive Dirent.
	childDir := fs.NewDirent(fs.NewInode(iops, dir.MountSource, sattr), name)
	i.session().endpoints.add(key, childDir, ep)
	return childDir, nil
}

// CreateFifo implements fs.InodeOperations.CreateFifo. Gofer nodes do not support the
// creation of fifos and always returns EOPNOTSUPP.
func (*inodeOperations) CreateFifo(context.Context, *fs.Inode, string, fs.FilePermissions) error {
	return syscall.EOPNOTSUPP
}

// Remove implements InodeOperations.Remove.
func (i *inodeOperations) Remove(ctx context.Context, dir *fs.Inode, name string) error {
	if len(name) > maxFilenameLen {
		return syserror.ENAMETOOLONG
	}

	var key device.MultiDeviceKey
	removeSocket := false
	if i.session().endpoints != nil {
		// Find out if file being deleted is a socket that needs to be
		// removed from endpoint map.
		if d, err := i.Lookup(ctx, dir, name); err == nil {
			defer d.DecRef()
			if fs.IsSocket(d.Inode.StableAttr) {
				child := d.Inode.InodeOperations.(*inodeOperations)
				key = child.fileState.key
				removeSocket = true

				// Stabilize the endpoint map while deletion is in progress.
				unlock := i.session().endpoints.lock()
				defer unlock()
			}
		}
	}

	if err := i.fileState.file.unlinkAt(ctx, name, 0); err != nil {
		return err
	}
	if removeSocket {
		i.session().endpoints.remove(key)
	}
	i.touchModificationTime(ctx, dir)

	return nil
}

// Remove implements InodeOperations.RemoveDirectory.
func (i *inodeOperations) RemoveDirectory(ctx context.Context, dir *fs.Inode, name string) error {
	if len(name) > maxFilenameLen {
		return syserror.ENAMETOOLONG
	}

	// 0x200 = AT_REMOVEDIR.
	if err := i.fileState.file.unlinkAt(ctx, name, 0x200); err != nil {
		return err
	}
	if i.session().cachePolicy.cacheUAttrs(dir) {
		// Decrease link count and updates atime.
		i.cachingInodeOps.DecLinks(ctx)
	}
	if i.session().cachePolicy.cacheReaddir() {
		// Invalidate readdir cache.
		i.markDirectoryDirty()
	}
	return nil
}

// Rename renames this node.
func (i *inodeOperations) Rename(ctx context.Context, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string, replacement bool) error {
	if len(newName) > maxFilenameLen {
		return syserror.ENAMETOOLONG
	}

	// Unwrap the new parent to a *inodeOperations.
	newParentInodeOperations, ok := newParent.InodeOperations.(*inodeOperations)
	if !ok {
		return syscall.EXDEV
	}

	// Unwrap the old parent to a *inodeOperations.
	oldParentInodeOperations, ok := oldParent.InodeOperations.(*inodeOperations)
	if !ok {
		return syscall.EXDEV
	}

	// Do the rename.
	if err := i.fileState.file.rename(ctx, newParentInodeOperations.fileState.file, newName); err != nil {
		return err
	}

	// Is the renamed entity a directory? Fix link counts.
	if fs.IsDir(i.fileState.sattr) {
		// Update cached state.
		if i.session().cachePolicy.cacheUAttrs(oldParent) {
			oldParentInodeOperations.cachingInodeOps.DecLinks(ctx)
		}
		if i.session().cachePolicy.cacheUAttrs(newParent) {
			// Only IncLinks if there is a new addition to
			// newParent. If this is replacement, then the total
			// count remains the same.
			if !replacement {
				newParentInodeOperations.cachingInodeOps.IncLinks(ctx)
			}
		}
	}
	if i.session().cachePolicy.cacheReaddir() {
		// Mark old directory dirty.
		oldParentInodeOperations.markDirectoryDirty()
		if oldParent != newParent {
			// Mark new directory dirty.
			newParentInodeOperations.markDirectoryDirty()
		}
	}
	return nil
}

func (i *inodeOperations) touchModificationTime(ctx context.Context, inode *fs.Inode) {
	if i.session().cachePolicy.cacheUAttrs(inode) {
		i.cachingInodeOps.TouchModificationTime(ctx)
	}
	if i.session().cachePolicy.cacheReaddir() {
		// Invalidate readdir cache.
		i.markDirectoryDirty()
	}
}

// markDirectoryDirty marks any cached data dirty for this directory. This is necessary in order
// to ensure that this node does not retain stale state throughout its lifetime across multiple
// open directory handles.
//
// Currently this means invalidating any readdir caches.
func (i *inodeOperations) markDirectoryDirty() {
	i.readdirMu.Lock()
	defer i.readdirMu.Unlock()
	i.readdirCache = nil
}
