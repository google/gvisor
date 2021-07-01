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

package gofer

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/sentry/device"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/syserror"
)

// maxFilenameLen is the maximum length of a filename. This is dictated by 9P's
// encoding of strings, which uses 2 bytes for the length prefix.
const maxFilenameLen = (1 << 16) - 1

func changeType(mode p9.FileMode, newType p9.FileMode) p9.FileMode {
	if newType&^p9.FileModeMask != 0 {
		panic(fmt.Sprintf("newType contained more bits than just file mode: %x", newType))
	}
	clear := mode &^ p9.FileModeMask
	return clear | newType
}

// Lookup loads an Inode at name into a Dirent based on the session's cache
// policy.
func (i *inodeOperations) Lookup(ctx context.Context, dir *fs.Inode, name string) (*fs.Dirent, error) {
	if len(name) > maxFilenameLen {
		return nil, linuxerr.ENAMETOOLONG
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
		if linuxerr.Equals(linuxerr.ENOENT, err) {
			if cp.cacheNegativeDirents() {
				// Return a negative Dirent. It will stay cached until something
				// is created over it.
				return fs.NewNegativeDirent(name), nil
			}
			return nil, syserror.ENOENT
		}
		return nil, err
	}

	if i.session().overrides != nil {
		// Check if file belongs to a internal named pipe. Note that it doesn't need
		// to check for sockets because it's done in newInodeOperations below.
		deviceKey := device.MultiDeviceKey{
			Device:          p9attr.RDev,
			SecondaryDevice: i.session().connID,
			Inode:           qids[0].Path,
		}
		unlock := i.session().overrides.lock()
		if pipeInode := i.session().overrides.getPipe(deviceKey); pipeInode != nil {
			unlock()
			pipeInode.IncRef()
			return fs.NewDirent(ctx, pipeInode, name), nil
		}
		unlock()
	}

	// Construct the Inode operations.
	sattr, node := newInodeOperations(ctx, i.fileState.s, newFile, qids[0], mask, p9attr)

	// Construct a positive Dirent.
	return fs.NewDirent(ctx, fs.NewInode(ctx, node, dir.MountSource, sattr), name), nil
}

// Creates a new Inode at name and returns its File based on the session's cache policy.
//
// Ownership is currently ignored.
func (i *inodeOperations) Create(ctx context.Context, dir *fs.Inode, name string, flags fs.FileFlags, perm fs.FilePermissions) (*fs.File, error) {
	if len(name) > maxFilenameLen {
		return nil, linuxerr.ENAMETOOLONG
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

	// If the parent directory has setgid enabled, change the new file's owner.
	owner := fs.FileOwnerFromContext(ctx)
	parentUattr, err := dir.UnstableAttr(ctx)
	if err != nil {
		return nil, err
	}
	if parentUattr.Perms.SetGID {
		owner.GID = parentUattr.Owner.GID
	}

	hostFile, err := newFile.create(ctx, name, openFlags, p9.FileMode(perm.LinuxMode()), p9.UID(owner.UID), p9.GID(owner.GID))
	if err != nil {
		// Could not create the file.
		newFile.close(ctx)
		return nil, err
	}

	i.touchModificationAndStatusChangeTime(ctx, dir)

	// Get an unopened p9.File for the file we created so that it can be cloned
	// and re-opened multiple times after creation, while also getting its
	// attributes. Both are required for inodeOperations.
	qids, unopened, mask, p9attr, err := i.fileState.file.walkGetAttr(ctx, []string{name})
	if err != nil {
		newFile.close(ctx)
		if hostFile != nil {
			hostFile.Close()
		}
		return nil, err
	}
	if len(qids) != 1 {
		log.Warningf("WalkGetAttr(%s) succeeded, but returned %d QIDs (%v), wanted 1", name, len(qids), qids)
		newFile.close(ctx)
		if hostFile != nil {
			hostFile.Close()
		}
		unopened.close(ctx)
		return nil, syserror.EIO
	}
	qid := qids[0]

	// Construct the InodeOperations.
	sattr, iops := newInodeOperations(ctx, i.fileState.s, unopened, qid, mask, p9attr)

	// Construct the positive Dirent.
	d := fs.NewDirent(ctx, fs.NewInode(ctx, iops, dir.MountSource, sattr), name)
	defer d.DecRef(ctx)

	// Construct the new file, caching the handles if allowed.
	h := handles{
		File: newFile,
		Host: hostFile,
	}
	h.EnableLeakCheck("gofer.handles")
	if iops.fileState.canShareHandles() {
		iops.fileState.handlesMu.Lock()
		iops.fileState.setSharedHandlesLocked(flags, &h)
		iops.fileState.handlesMu.Unlock()
	}
	return NewFile(ctx, d, name, flags, iops, &h), nil
}

// CreateLink uses Create to create a symlink between oldname and newname.
func (i *inodeOperations) CreateLink(ctx context.Context, dir *fs.Inode, oldname string, newname string) error {
	if len(newname) > maxFilenameLen {
		return linuxerr.ENAMETOOLONG
	}

	owner := fs.FileOwnerFromContext(ctx)
	if _, err := i.fileState.file.symlink(ctx, oldname, newname, p9.UID(owner.UID), p9.GID(owner.GID)); err != nil {
		return err
	}
	i.touchModificationAndStatusChangeTime(ctx, dir)
	return nil
}

// CreateHardLink implements InodeOperations.CreateHardLink.
func (i *inodeOperations) CreateHardLink(ctx context.Context, inode *fs.Inode, target *fs.Inode, newName string) error {
	if len(newName) > maxFilenameLen {
		return linuxerr.ENAMETOOLONG
	}

	targetOpts, ok := target.InodeOperations.(*inodeOperations)
	if !ok {
		return linuxerr.EXDEV
	}

	if err := i.fileState.file.link(ctx, &targetOpts.fileState.file, newName); err != nil {
		return err
	}
	if i.session().cachePolicy.cacheUAttrs(inode) {
		// Increase link count.
		targetOpts.cachingInodeOps.IncLinks(ctx)
	}
	i.touchModificationAndStatusChangeTime(ctx, inode)
	return nil
}

// CreateDirectory uses Create to create a directory named s under inodeOperations.
func (i *inodeOperations) CreateDirectory(ctx context.Context, dir *fs.Inode, s string, perm fs.FilePermissions) error {
	if len(s) > maxFilenameLen {
		return linuxerr.ENAMETOOLONG
	}

	// If the parent directory has setgid enabled, change the new directory's
	// owner and enable setgid.
	owner := fs.FileOwnerFromContext(ctx)
	parentUattr, err := dir.UnstableAttr(ctx)
	if err != nil {
		return err
	}
	if parentUattr.Perms.SetGID {
		owner.GID = parentUattr.Owner.GID
		perm.SetGID = true
	}

	if _, err := i.fileState.file.mkdir(ctx, s, p9.FileMode(perm.LinuxMode()), p9.UID(owner.UID), p9.GID(owner.GID)); err != nil {
		return err
	}
	if i.session().cachePolicy.cacheUAttrs(dir) {
		// Increase link count.
		//
		// N.B. This will update the modification time.
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
		return nil, linuxerr.ENAMETOOLONG
	}

	if i.session().overrides == nil {
		return nil, syserror.EOPNOTSUPP
	}

	// Stabilize the override map while creation is in progress.
	unlock := i.session().overrides.lock()
	defer unlock()

	sattr, iops, err := i.createEndpointFile(ctx, dir, name, perm, p9.ModeSocket)
	if err != nil {
		return nil, err
	}

	// Construct the positive Dirent.
	childDir := fs.NewDirent(ctx, fs.NewInode(ctx, iops, dir.MountSource, sattr), name)
	i.session().overrides.addBoundEndpoint(iops.fileState.key, childDir, ep)
	return childDir, nil
}

// CreateFifo implements fs.InodeOperations.CreateFifo.
func (i *inodeOperations) CreateFifo(ctx context.Context, dir *fs.Inode, name string, perm fs.FilePermissions) error {
	if len(name) > maxFilenameLen {
		return linuxerr.ENAMETOOLONG
	}

	owner := fs.FileOwnerFromContext(ctx)
	mode := p9.FileMode(perm.LinuxMode()) | p9.ModeNamedPipe

	// N.B. FIFOs use major/minor numbers 0.
	if _, err := i.fileState.file.mknod(ctx, name, mode, 0, 0, p9.UID(owner.UID), p9.GID(owner.GID)); err != nil {
		if i.session().overrides == nil || !linuxerr.Equals(linuxerr.EPERM, err) {
			return err
		}
		// If gofer doesn't support mknod, check if we can create an internal fifo.
		return i.createInternalFifo(ctx, dir, name, owner, perm)
	}

	i.touchModificationAndStatusChangeTime(ctx, dir)
	return nil
}

func (i *inodeOperations) createInternalFifo(ctx context.Context, dir *fs.Inode, name string, owner fs.FileOwner, perm fs.FilePermissions) error {
	if i.session().overrides == nil {
		return linuxerr.EPERM
	}

	// Stabilize the override map while creation is in progress.
	unlock := i.session().overrides.lock()
	defer unlock()

	sattr, fileOps, err := i.createEndpointFile(ctx, dir, name, perm, p9.ModeNamedPipe)
	if err != nil {
		return err
	}

	// First create a pipe.
	p := pipe.NewPipe(true /* isNamed */, pipe.DefaultPipeSize)

	// Wrap the fileOps with our Fifo.
	iops := &fifo{
		InodeOperations: pipe.NewInodeOperations(ctx, perm, p),
		fileIops:        fileOps,
	}
	inode := fs.NewInode(ctx, iops, dir.MountSource, sattr)

	// Construct the positive Dirent.
	childDir := fs.NewDirent(ctx, fs.NewInode(ctx, iops, dir.MountSource, sattr), name)
	i.session().overrides.addPipe(fileOps.fileState.key, childDir, inode)
	return nil
}

// Caller must hold Session.endpoint lock.
func (i *inodeOperations) createEndpointFile(ctx context.Context, dir *fs.Inode, name string, perm fs.FilePermissions, fileType p9.FileMode) (fs.StableAttr, *inodeOperations, error) {
	_, dirClone, err := i.fileState.file.walk(ctx, nil)
	if err != nil {
		return fs.StableAttr{}, nil, err
	}
	// We're not going to use dirClone after return.
	defer dirClone.close(ctx)

	// Create a regular file in the gofer and then mark it as a socket by
	// adding this inode key in the 'overrides' map.
	owner := fs.FileOwnerFromContext(ctx)
	hostFile, err := dirClone.create(ctx, name, p9.ReadWrite, p9.FileMode(perm.LinuxMode()), p9.UID(owner.UID), p9.GID(owner.GID))
	if err != nil {
		return fs.StableAttr{}, nil, err
	}
	// We're not going to use this file.
	hostFile.Close()

	i.touchModificationAndStatusChangeTime(ctx, dir)

	// Get the attributes of the file to create inode key.
	qid, mask, attr, err := getattr(ctx, dirClone)
	if err != nil {
		return fs.StableAttr{}, nil, err
	}

	// Get an unopened p9.File for the file we created so that it can be
	// cloned and re-opened multiple times after creation.
	_, unopened, err := i.fileState.file.walk(ctx, []string{name})
	if err != nil {
		return fs.StableAttr{}, nil, err
	}

	// Construct new inode with file type overridden.
	attr.Mode = changeType(attr.Mode, fileType)
	sattr, iops := newInodeOperations(ctx, i.fileState.s, unopened, qid, mask, attr)
	return sattr, iops, nil
}

// Remove implements InodeOperations.Remove.
func (i *inodeOperations) Remove(ctx context.Context, dir *fs.Inode, name string) error {
	if len(name) > maxFilenameLen {
		return linuxerr.ENAMETOOLONG
	}

	var key *device.MultiDeviceKey
	if i.session().overrides != nil {
		// Find out if file being deleted is a socket or pipe that needs to be
		// removed from endpoint map.
		if d, err := i.Lookup(ctx, dir, name); err == nil {
			defer d.DecRef(ctx)

			if fs.IsSocket(d.Inode.StableAttr) || fs.IsPipe(d.Inode.StableAttr) {
				switch iops := d.Inode.InodeOperations.(type) {
				case *inodeOperations:
					key = &iops.fileState.key
				case *fifo:
					key = &iops.fileIops.fileState.key
				}

				// Stabilize the override map while deletion is in progress.
				unlock := i.session().overrides.lock()
				defer unlock()
			}
		}
	}

	if err := i.fileState.file.unlinkAt(ctx, name, 0); err != nil {
		return err
	}
	if key != nil {
		i.session().overrides.remove(ctx, *key)
	}
	i.touchModificationAndStatusChangeTime(ctx, dir)

	return nil
}

// Remove implements InodeOperations.RemoveDirectory.
func (i *inodeOperations) RemoveDirectory(ctx context.Context, dir *fs.Inode, name string) error {
	if len(name) > maxFilenameLen {
		return linuxerr.ENAMETOOLONG
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
func (i *inodeOperations) Rename(ctx context.Context, inode *fs.Inode, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string, replacement bool) error {
	if len(newName) > maxFilenameLen {
		return linuxerr.ENAMETOOLONG
	}

	// Don't allow renames across different mounts.
	if newParent.MountSource != oldParent.MountSource {
		return linuxerr.EXDEV
	}

	// Unwrap the new parent to a *inodeOperations.
	newParentInodeOperations := newParent.InodeOperations.(*inodeOperations)

	// Unwrap the old parent to a *inodeOperations.
	oldParentInodeOperations := oldParent.InodeOperations.(*inodeOperations)

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

	// Rename always updates ctime.
	if i.session().cachePolicy.cacheUAttrs(inode) {
		i.cachingInodeOps.TouchStatusChangeTime(ctx)
	}
	return nil
}

func (i *inodeOperations) touchModificationAndStatusChangeTime(ctx context.Context, inode *fs.Inode) {
	if i.session().cachePolicy.cacheUAttrs(inode) {
		i.cachingInodeOps.TouchModificationAndStatusChangeTime(ctx)
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
