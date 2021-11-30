// Copyright 2019 The gVisor Authors.
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

package tmpfs

import (
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/fsmetric"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Sync implements vfs.FilesystemImpl.Sync.
func (fs *filesystem) Sync(ctx context.Context) error {
	// All filesystem state is in-memory.
	return nil
}

// stepLocked resolves rp.Component() to an existing file, starting from the
// given directory.
//
// stepLocked is loosely analogous to fs/namei.c:walk_component().
//
// Preconditions:
// * filesystem.mu must be locked.
// * !rp.Done().
func stepLocked(ctx context.Context, rp *vfs.ResolvingPath, d *dentry) (*dentry, error) {
	dir, ok := d.inode.impl.(*directory)
	if !ok {
		return nil, linuxerr.ENOTDIR
	}
	if err := d.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, err
	}
afterSymlink:
	name := rp.Component()
	if name == "." {
		rp.Advance()
		return d, nil
	}
	if name == ".." {
		if isRoot, err := rp.CheckRoot(ctx, &d.vfsd); err != nil {
			return nil, err
		} else if isRoot || d.parent == nil {
			rp.Advance()
			return d, nil
		}
		if err := rp.CheckMount(ctx, &d.parent.vfsd); err != nil {
			return nil, err
		}
		rp.Advance()
		return d.parent, nil
	}
	if len(name) > d.inode.fs.maxFilenameLen {
		return nil, linuxerr.ENAMETOOLONG
	}
	child, ok := dir.childMap[name]
	if !ok {
		return nil, linuxerr.ENOENT
	}
	if err := rp.CheckMount(ctx, &child.vfsd); err != nil {
		return nil, err
	}
	if symlink, ok := child.inode.impl.(*symlink); ok && rp.ShouldFollowSymlink() {
		// Symlink traversal updates access time.
		child.inode.touchAtime(rp.Mount())
		if err := rp.HandleSymlink(symlink.target); err != nil {
			return nil, err
		}
		goto afterSymlink // don't check the current directory again
	}
	rp.Advance()
	return child, nil
}

// walkParentDirLocked resolves all but the last path component of rp to an
// existing directory, starting from the given directory (which is usually
// rp.Start().Impl().(*dentry)). It does not check that the returned directory
// is searchable by the provider of rp.
//
// walkParentDirLocked is loosely analogous to Linux's
// fs/namei.c:path_parentat().
//
// Preconditions:
// * filesystem.mu must be locked.
// * !rp.Done().
func walkParentDirLocked(ctx context.Context, rp *vfs.ResolvingPath, d *dentry) (*directory, error) {
	for !rp.Final() {
		next, err := stepLocked(ctx, rp, d)
		if err != nil {
			return nil, err
		}
		d = next
	}
	dir, ok := d.inode.impl.(*directory)
	if !ok {
		return nil, linuxerr.ENOTDIR
	}
	return dir, nil
}

// resolveLocked resolves rp to an existing file.
//
// resolveLocked is loosely analogous to Linux's fs/namei.c:path_lookupat().
//
// Preconditions: filesystem.mu must be locked.
func resolveLocked(ctx context.Context, rp *vfs.ResolvingPath) (*dentry, error) {
	d := rp.Start().Impl().(*dentry)
	for !rp.Done() {
		next, err := stepLocked(ctx, rp, d)
		if err != nil {
			return nil, err
		}
		d = next
	}
	if rp.MustBeDir() && !d.inode.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	return d, nil
}

// doCreateAt checks that creating a file at rp is permitted, then invokes
// create to do so.
//
// doCreateAt is loosely analogous to a conjunction of Linux's
// fs/namei.c:filename_create() and done_path_create().
//
// Preconditions:
// * !rp.Done().
// * For the final path component in rp, !rp.ShouldFollowSymlink().
func (fs *filesystem) doCreateAt(ctx context.Context, rp *vfs.ResolvingPath, dir bool, create func(parentDir *directory, name string) error) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parentDir, err := walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}

	// Order of checks is important. First check if parent directory can be
	// executed, then check for existence, and lastly check if mount is writable.
	if err := parentDir.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return linuxerr.EEXIST
	}
	if len(name) > fs.maxFilenameLen {
		return linuxerr.ENAMETOOLONG
	}
	if _, ok := parentDir.childMap[name]; ok {
		return linuxerr.EEXIST
	}
	if !dir && rp.MustBeDir() {
		return linuxerr.ENOENT
	}
	// tmpfs never calls VFS.InvalidateDentry(), so parentDir.dentry can only
	// be dead if it was deleted.
	if parentDir.dentry.vfsd.IsDead() {
		return linuxerr.ENOENT
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()

	if err := parentDir.inode.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
		return err
	}
	if err := create(parentDir, name); err != nil {
		return err
	}

	ev := linux.IN_CREATE
	if dir {
		ev |= linux.IN_ISDIR
	}
	parentDir.inode.watches.Notify(ctx, name, uint32(ev), 0, vfs.InodeEvent, false /* unlinked */)
	parentDir.inode.touchCMtime()
	return nil
}

// AccessAt implements vfs.Filesystem.Impl.AccessAt.
func (fs *filesystem) AccessAt(ctx context.Context, rp *vfs.ResolvingPath, creds *auth.Credentials, ats vfs.AccessTypes) error {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	d, err := resolveLocked(ctx, rp)
	if err != nil {
		return err
	}
	return d.inode.checkPermissions(creds, ats)
}

// GetDentryAt implements vfs.FilesystemImpl.GetDentryAt.
func (fs *filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	d, err := resolveLocked(ctx, rp)
	if err != nil {
		return nil, err
	}
	if opts.CheckSearchable {
		if !d.inode.isDir() {
			return nil, linuxerr.ENOTDIR
		}
		if err := d.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
			return nil, err
		}
	}
	d.IncRef()
	return &d.vfsd, nil
}

// GetParentDentryAt implements vfs.FilesystemImpl.GetParentDentryAt.
func (fs *filesystem) GetParentDentryAt(ctx context.Context, rp *vfs.ResolvingPath) (*vfs.Dentry, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	dir, err := walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return nil, err
	}
	dir.dentry.IncRef()
	return &dir.dentry.vfsd, nil
}

// LinkAt implements vfs.FilesystemImpl.LinkAt.
func (fs *filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	return fs.doCreateAt(ctx, rp, false /* dir */, func(parentDir *directory, name string) error {
		if rp.Mount() != vd.Mount() {
			return linuxerr.EXDEV
		}
		d := vd.Dentry().Impl().(*dentry)
		i := d.inode
		if i.isDir() {
			return linuxerr.EPERM
		}
		if err := vfs.MayLink(auth.CredentialsFromContext(ctx), linux.FileMode(atomic.LoadUint32(&i.mode)), auth.KUID(atomic.LoadUint32(&i.uid)), auth.KGID(atomic.LoadUint32(&i.gid))); err != nil {
			return err
		}
		if i.nlink == 0 {
			return linuxerr.ENOENT
		}
		if i.nlink == maxLinks {
			return linuxerr.EMLINK
		}
		i.incLinksLocked()
		i.watches.Notify(ctx, "", linux.IN_ATTRIB, 0, vfs.InodeEvent, false /* unlinked */)
		parentDir.insertChildLocked(fs.newDentry(i), name)
		return nil
	})
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	return fs.doCreateAt(ctx, rp, true /* dir */, func(parentDir *directory, name string) error {
		creds := rp.Credentials()
		if parentDir.inode.nlink == maxLinks {
			return linuxerr.EMLINK
		}
		parentDir.inode.incLinksLocked() // from child's ".."
		childDir := fs.newDirectory(creds.EffectiveKUID, creds.EffectiveKGID, opts.Mode, parentDir)
		parentDir.insertChildLocked(&childDir.dentry, name)
		return nil
	})
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	return fs.doCreateAt(ctx, rp, false /* dir */, func(parentDir *directory, name string) error {
		creds := rp.Credentials()
		var childInode *inode
		switch opts.Mode.FileType() {
		case linux.S_IFREG:
			childInode = fs.newRegularFile(creds.EffectiveKUID, creds.EffectiveKGID, opts.Mode, parentDir)
		case linux.S_IFIFO:
			childInode = fs.newNamedPipe(creds.EffectiveKUID, creds.EffectiveKGID, opts.Mode, parentDir)
		case linux.S_IFBLK:
			childInode = fs.newDeviceFile(creds.EffectiveKUID, creds.EffectiveKGID, opts.Mode, vfs.BlockDevice, opts.DevMajor, opts.DevMinor, parentDir)
		case linux.S_IFCHR:
			childInode = fs.newDeviceFile(creds.EffectiveKUID, creds.EffectiveKGID, opts.Mode, vfs.CharDevice, opts.DevMajor, opts.DevMinor, parentDir)
		case linux.S_IFSOCK:
			childInode = fs.newSocketFile(creds.EffectiveKUID, creds.EffectiveKGID, opts.Mode, opts.Endpoint, parentDir)
		default:
			return linuxerr.EINVAL
		}
		child := fs.newDentry(childInode)
		parentDir.insertChildLocked(child, name)
		return nil
	})
}

// OpenAt implements vfs.FilesystemImpl.OpenAt.
func (fs *filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	if opts.Flags&linux.O_TMPFILE != 0 {
		// Not yet supported.
		return nil, linuxerr.EOPNOTSUPP
	}

	// Handle O_CREAT and !O_CREAT separately, since in the latter case we
	// don't need fs.mu for writing.
	if opts.Flags&linux.O_CREAT == 0 {
		fs.mu.RLock()
		d, err := resolveLocked(ctx, rp)
		if err != nil {
			fs.mu.RUnlock()
			return nil, err
		}
		d.IncRef()
		defer d.DecRef(ctx)
		fs.mu.RUnlock()
		return d.open(ctx, rp, &opts, false /* afterCreate */)
	}

	mustCreate := opts.Flags&linux.O_EXCL != 0
	start := rp.Start().Impl().(*dentry)
	fs.mu.Lock()
	unlocked := false
	unlock := func() {
		if !unlocked {
			fs.mu.Unlock()
			unlocked = true
		}
	}
	defer unlock()
	if rp.Done() {
		// Reject attempts to open mount root directory with O_CREAT.
		if rp.MustBeDir() {
			return nil, linuxerr.EISDIR
		}
		if mustCreate {
			return nil, linuxerr.EEXIST
		}
		start.IncRef()
		defer start.DecRef(ctx)
		unlock()
		return start.open(ctx, rp, &opts, false /* afterCreate */)
	}
afterTrailingSymlink:
	parentDir, err := walkParentDirLocked(ctx, rp, start)
	if err != nil {
		return nil, err
	}
	// Check for search permission in the parent directory.
	if err := parentDir.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, err
	}
	// Reject attempts to open directories with O_CREAT.
	if rp.MustBeDir() {
		return nil, linuxerr.EISDIR
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return nil, linuxerr.EISDIR
	}
	if len(name) > fs.maxFilenameLen {
		return nil, linuxerr.ENAMETOOLONG
	}
	// Determine whether or not we need to create a file.
	child, ok := parentDir.childMap[name]
	if !ok {
		// Already checked for searchability above; now check for writability.
		if err := parentDir.inode.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
			return nil, err
		}
		if err := rp.Mount().CheckBeginWrite(); err != nil {
			return nil, err
		}
		defer rp.Mount().EndWrite()
		// Create and open the child.
		creds := rp.Credentials()
		child := fs.newDentry(fs.newRegularFile(creds.EffectiveKUID, creds.EffectiveKGID, opts.Mode, parentDir))
		parentDir.insertChildLocked(child, name)
		child.IncRef()
		defer child.DecRef(ctx)
		unlock()
		fd, err := child.open(ctx, rp, &opts, true)
		if err != nil {
			return nil, err
		}
		parentDir.inode.watches.Notify(ctx, name, linux.IN_CREATE, 0, vfs.PathEvent, false /* unlinked */)
		parentDir.inode.touchCMtime()
		return fd, nil
	}
	if mustCreate {
		return nil, linuxerr.EEXIST
	}
	// Is the file mounted over?
	if err := rp.CheckMount(ctx, &child.vfsd); err != nil {
		return nil, err
	}
	// Do we need to resolve a trailing symlink?
	if symlink, ok := child.inode.impl.(*symlink); ok && rp.ShouldFollowSymlink() {
		// Symlink traversal updates access time.
		child.inode.touchAtime(rp.Mount())
		if err := rp.HandleSymlink(symlink.target); err != nil {
			return nil, err
		}
		start = &parentDir.dentry
		goto afterTrailingSymlink
	}
	if rp.MustBeDir() && !child.inode.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	child.IncRef()
	defer child.DecRef(ctx)
	unlock()
	return child.open(ctx, rp, &opts, false)
}

// Preconditions: The caller must hold no locks (since opening pipes may block
// indefinitely).
func (d *dentry) open(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions, afterCreate bool) (*vfs.FileDescription, error) {
	ats := vfs.AccessTypesForOpenFlags(opts)
	if !afterCreate {
		if err := d.inode.checkPermissions(rp.Credentials(), ats); err != nil {
			return nil, err
		}
	}
	switch impl := d.inode.impl.(type) {
	case *regularFile:
		var fd regularFileFD
		fd.LockFD.Init(&d.inode.locks)
		if err := fd.vfsfd.Init(&fd, opts.Flags, rp.Mount(), &d.vfsd, &vfs.FileDescriptionOptions{AllowDirectIO: true}); err != nil {
			return nil, err
		}
		if !afterCreate && opts.Flags&linux.O_TRUNC != 0 {
			if _, err := impl.truncate(0); err != nil {
				return nil, err
			}
		}
		if fd.vfsfd.IsWritable() {
			fsmetric.TmpfsOpensW.Increment()
		} else if fd.vfsfd.IsReadable() {
			fsmetric.TmpfsOpensRO.Increment()
		}
		return &fd.vfsfd, nil
	case *directory:
		// Can't open directories writably.
		if ats&vfs.MayWrite != 0 {
			return nil, linuxerr.EISDIR
		}
		var fd directoryFD
		fd.LockFD.Init(&d.inode.locks)
		if err := fd.vfsfd.Init(&fd, opts.Flags, rp.Mount(), &d.vfsd, &vfs.FileDescriptionOptions{AllowDirectIO: true}); err != nil {
			return nil, err
		}
		return &fd.vfsfd, nil
	case *symlink:
		// Can't open symlinks without O_PATH, which is handled at the VFS layer.
		return nil, linuxerr.ELOOP
	case *namedPipe:
		return impl.pipe.Open(ctx, rp.Mount(), &d.vfsd, opts.Flags, &d.inode.locks)
	case *deviceFile:
		return rp.VirtualFilesystem().OpenDeviceSpecialFile(ctx, rp.Mount(), &d.vfsd, impl.kind, impl.major, impl.minor, opts)
	case *socketFile:
		return nil, linuxerr.ENXIO
	default:
		panic(fmt.Sprintf("unknown inode type: %T", d.inode.impl))
	}
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	d, err := resolveLocked(ctx, rp)
	if err != nil {
		return "", err
	}
	symlink, ok := d.inode.impl.(*symlink)
	if !ok {
		return "", linuxerr.EINVAL
	}
	symlink.inode.touchAtime(rp.Mount())
	return symlink.target, nil
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, oldParentVD vfs.VirtualDentry, oldName string, opts vfs.RenameOptions) error {
	// Resolve newParentDir first to verify that it's on this Mount.
	fs.mu.Lock()
	defer fs.mu.Unlock()
	newParentDir, err := walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}

	if opts.Flags&^linux.RENAME_NOREPLACE != 0 {
		// TODO(b/145974740): Support other renameat2 flags.
		return linuxerr.EINVAL
	}

	newName := rp.Component()
	if newName == "." || newName == ".." {
		if opts.Flags&linux.RENAME_NOREPLACE != 0 {
			return linuxerr.EEXIST
		}
		return linuxerr.EBUSY
	}
	mnt := rp.Mount()
	if mnt != oldParentVD.Mount() {
		return linuxerr.EXDEV
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()

	oldParentDir := oldParentVD.Dentry().Impl().(*dentry).inode.impl.(*directory)
	if err := oldParentDir.inode.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	renamed, ok := oldParentDir.childMap[oldName]
	if !ok {
		return linuxerr.ENOENT
	}
	if err := oldParentDir.mayDelete(rp.Credentials(), renamed); err != nil {
		return err
	}
	// Note that we don't need to call rp.CheckMount(), since if renamed is a
	// mount point then we want to rename the mount point, not anything in the
	// mounted filesystem.
	if renamed.inode.isDir() {
		if renamed == &newParentDir.dentry || genericIsAncestorDentry(renamed, &newParentDir.dentry) {
			return linuxerr.EINVAL
		}
		if oldParentDir != newParentDir {
			// Writability is needed to change renamed's "..".
			if err := renamed.inode.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
				return err
			}
		}
	} else {
		if opts.MustBeDir || rp.MustBeDir() {
			return linuxerr.ENOTDIR
		}
	}

	if err := newParentDir.inode.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	replaced, ok := newParentDir.childMap[newName]
	if ok {
		if opts.Flags&linux.RENAME_NOREPLACE != 0 {
			return linuxerr.EEXIST
		}
		replacedDir, ok := replaced.inode.impl.(*directory)
		if ok {
			if !renamed.inode.isDir() {
				return linuxerr.EISDIR
			}
			if len(replacedDir.childMap) != 0 {
				return linuxerr.ENOTEMPTY
			}
		} else {
			if rp.MustBeDir() {
				return linuxerr.ENOTDIR
			}
			if renamed.inode.isDir() {
				return linuxerr.ENOTDIR
			}
		}
	} else {
		if renamed.inode.isDir() && newParentDir.inode.nlink == maxLinks {
			return linuxerr.EMLINK
		}
	}
	// tmpfs never calls VFS.InvalidateDentry(), so newParentDir.dentry can
	// only be dead if it was deleted.
	if newParentDir.dentry.vfsd.IsDead() {
		return linuxerr.ENOENT
	}

	// Linux places this check before some of those above; we do it here for
	// simplicity, under the assumption that applications are not intentionally
	// doing noop renames expecting them to succeed where non-noop renames
	// would fail.
	if renamed == replaced {
		return nil
	}
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	var replacedVFSD *vfs.Dentry
	if replaced != nil {
		replacedVFSD = &replaced.vfsd
	}
	if err := vfsObj.PrepareRenameDentry(mntns, &renamed.vfsd, replacedVFSD); err != nil {
		return err
	}
	if replaced != nil {
		newParentDir.removeChildLocked(replaced)
		if replaced.inode.isDir() {
			// Remove links for replaced/. and replaced/..
			replaced.inode.decLinksLocked(ctx)
			newParentDir.inode.decLinksLocked(ctx)
		}
		replaced.inode.decLinksLocked(ctx)
	}
	oldParentDir.removeChildLocked(renamed)
	newParentDir.insertChildLocked(renamed, newName)
	vfsObj.CommitRenameReplaceDentry(ctx, &renamed.vfsd, replacedVFSD)
	oldParentDir.inode.touchCMtime()
	if oldParentDir != newParentDir {
		if renamed.inode.isDir() {
			oldParentDir.inode.decLinksLocked(ctx)
			newParentDir.inode.incLinksLocked()
		}
		newParentDir.inode.touchCMtime()
	}
	renamed.inode.touchCtime()

	vfs.InotifyRename(ctx, &renamed.inode.watches, &oldParentDir.inode.watches, &newParentDir.inode.watches, oldName, newName, renamed.inode.isDir())
	return nil
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parentDir, err := walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	if err := parentDir.inode.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." {
		return linuxerr.EINVAL
	}
	if name == ".." {
		return linuxerr.ENOTEMPTY
	}
	child, ok := parentDir.childMap[name]
	if !ok {
		return linuxerr.ENOENT
	}
	if err := parentDir.mayDelete(rp.Credentials(), child); err != nil {
		return err
	}
	childDir, ok := child.inode.impl.(*directory)
	if !ok {
		return linuxerr.ENOTDIR
	}
	if len(childDir.childMap) != 0 {
		return linuxerr.ENOTEMPTY
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	if err := vfsObj.PrepareDeleteDentry(mntns, &child.vfsd); err != nil {
		return err
	}
	parentDir.removeChildLocked(child)
	parentDir.inode.watches.Notify(ctx, name, linux.IN_DELETE|linux.IN_ISDIR, 0, vfs.InodeEvent, true /* unlinked */)
	// Remove links for child, child/., and child/..
	child.inode.decLinksLocked(ctx)
	child.inode.decLinksLocked(ctx)
	parentDir.inode.decLinksLocked(ctx)
	vfsObj.CommitDeleteDentry(ctx, &child.vfsd)
	parentDir.inode.touchCMtime()
	return nil
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	fs.mu.RLock()
	d, err := resolveLocked(ctx, rp)
	if err != nil {
		fs.mu.RUnlock()
		return err
	}
	err = d.inode.setStat(ctx, rp.Credentials(), &opts)
	fs.mu.RUnlock()
	if err != nil {
		return err
	}

	if ev := vfs.InotifyEventFromStatMask(opts.Stat.Mask); ev != 0 {
		d.InotifyWithParent(ctx, ev, 0, vfs.InodeEvent)
	}
	return nil
}

// StatAt implements vfs.FilesystemImpl.StatAt.
func (fs *filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	d, err := resolveLocked(ctx, rp)
	if err != nil {
		return linux.Statx{}, err
	}
	var stat linux.Statx
	d.inode.statTo(&stat)
	return stat, nil
}

// StatFSAt implements vfs.FilesystemImpl.StatFSAt.
func (fs *filesystem) StatFSAt(ctx context.Context, rp *vfs.ResolvingPath) (linux.Statfs, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	if _, err := resolveLocked(ctx, rp); err != nil {
		return linux.Statfs{}, err
	}
	return globalStatfs, nil
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt.
func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	return fs.doCreateAt(ctx, rp, false /* dir */, func(parentDir *directory, name string) error {
		creds := rp.Credentials()
		child := fs.newDentry(fs.newSymlink(creds.EffectiveKUID, creds.EffectiveKGID, 0777, target, parentDir))
		parentDir.insertChildLocked(child, name)
		return nil
	})
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parentDir, err := walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	if err := parentDir.inode.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return linuxerr.EISDIR
	}
	child, ok := parentDir.childMap[name]
	if !ok {
		return linuxerr.ENOENT
	}
	if err := parentDir.mayDelete(rp.Credentials(), child); err != nil {
		return err
	}
	if child.inode.isDir() {
		return linuxerr.EISDIR
	}
	if rp.MustBeDir() {
		return linuxerr.ENOTDIR
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	if err := vfsObj.PrepareDeleteDentry(mntns, &child.vfsd); err != nil {
		return err
	}

	// Generate inotify events. Note that this must take place before the link
	// count of the child is decremented, or else the watches may be dropped
	// before these events are added.
	vfs.InotifyRemoveChild(ctx, &child.inode.watches, &parentDir.inode.watches, name)

	parentDir.removeChildLocked(child)
	child.inode.decLinksLocked(ctx)
	vfsObj.CommitDeleteDentry(ctx, &child.vfsd)
	parentDir.inode.touchCMtime()
	return nil
}

// BoundEndpointAt implements vfs.FilesystemImpl.BoundEndpointAt.
func (fs *filesystem) BoundEndpointAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.BoundEndpointOptions) (transport.BoundEndpoint, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	d, err := resolveLocked(ctx, rp)
	if err != nil {
		return nil, err
	}
	if err := d.inode.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
		return nil, err
	}
	switch impl := d.inode.impl.(type) {
	case *socketFile:
		if impl.ep == nil {
			return nil, linuxerr.ECONNREFUSED
		}
		return impl.ep, nil
	default:
		return nil, linuxerr.ECONNREFUSED
	}
}

// ListXattrAt implements vfs.FilesystemImpl.ListXattrAt.
func (fs *filesystem) ListXattrAt(ctx context.Context, rp *vfs.ResolvingPath, size uint64) ([]string, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	d, err := resolveLocked(ctx, rp)
	if err != nil {
		return nil, err
	}
	return d.inode.listXattr(rp.Credentials(), size)
}

// GetXattrAt implements vfs.FilesystemImpl.GetXattrAt.
func (fs *filesystem) GetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetXattrOptions) (string, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	d, err := resolveLocked(ctx, rp)
	if err != nil {
		return "", err
	}
	return d.inode.getXattr(rp.Credentials(), &opts)
}

// SetXattrAt implements vfs.FilesystemImpl.SetXattrAt.
func (fs *filesystem) SetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetXattrOptions) error {
	fs.mu.RLock()
	d, err := resolveLocked(ctx, rp)
	if err != nil {
		fs.mu.RUnlock()
		return err
	}
	err = d.inode.setXattr(rp.Credentials(), &opts)
	fs.mu.RUnlock()
	if err != nil {
		return err
	}

	d.InotifyWithParent(ctx, linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}

// RemoveXattrAt implements vfs.FilesystemImpl.RemoveXattrAt.
func (fs *filesystem) RemoveXattrAt(ctx context.Context, rp *vfs.ResolvingPath, name string) error {
	fs.mu.RLock()
	d, err := resolveLocked(ctx, rp)
	if err != nil {
		fs.mu.RUnlock()
		return err
	}
	err = d.inode.removeXattr(rp.Credentials(), name)
	fs.mu.RUnlock()
	if err != nil {
		return err
	}

	d.InotifyWithParent(ctx, linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}

// PrependPath implements vfs.FilesystemImpl.PrependPath.
func (fs *filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	mnt := vd.Mount()
	d := vd.Dentry().Impl().(*dentry)
	for {
		if mnt == vfsroot.Mount() && &d.vfsd == vfsroot.Dentry() {
			return vfs.PrependPathAtVFSRootError{}
		}
		if &d.vfsd == mnt.Root() {
			return nil
		}
		if d.parent == nil {
			if d.name != "" {
				// This file must have been created by
				// newUnlinkedRegularFileDescription(). In Linux,
				// mm/shmem.c:__shmem_file_setup() =>
				// fs/file_table.c:alloc_file_pseudo() sets the created
				// dentry's dentry_operations to anon_ops, for which d_dname ==
				// simple_dname. fs/d_path.c:simple_dname() defines the
				// dentry's pathname to be its name, prefixed with "/" and
				// suffixed with " (deleted)".
				b.PrependComponent("/" + d.name)
				b.AppendString(" (deleted)")
				return vfs.PrependPathSyntheticError{}
			}
			return vfs.PrependPathAtNonMountRootError{}
		}
		b.PrependComponent(d.name)
		d = d.parent
	}
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	return fs.mopts
}
