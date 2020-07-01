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
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
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
// Preconditions: filesystem.mu must be locked. !rp.Done().
func stepLocked(rp *vfs.ResolvingPath, d *dentry) (*dentry, error) {
	dir, ok := d.inode.impl.(*directory)
	if !ok {
		return nil, syserror.ENOTDIR
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
		if isRoot, err := rp.CheckRoot(&d.vfsd); err != nil {
			return nil, err
		} else if isRoot || d.parent == nil {
			rp.Advance()
			return d, nil
		}
		if err := rp.CheckMount(&d.parent.vfsd); err != nil {
			return nil, err
		}
		rp.Advance()
		return d.parent, nil
	}
	if len(name) > linux.NAME_MAX {
		return nil, syserror.ENAMETOOLONG
	}
	child, ok := dir.childMap[name]
	if !ok {
		return nil, syserror.ENOENT
	}
	if err := rp.CheckMount(&child.vfsd); err != nil {
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
// Preconditions: filesystem.mu must be locked. !rp.Done().
func walkParentDirLocked(rp *vfs.ResolvingPath, d *dentry) (*directory, error) {
	for !rp.Final() {
		next, err := stepLocked(rp, d)
		if err != nil {
			return nil, err
		}
		d = next
	}
	dir, ok := d.inode.impl.(*directory)
	if !ok {
		return nil, syserror.ENOTDIR
	}
	return dir, nil
}

// resolveLocked resolves rp to an existing file.
//
// resolveLocked is loosely analogous to Linux's fs/namei.c:path_lookupat().
//
// Preconditions: filesystem.mu must be locked.
func resolveLocked(rp *vfs.ResolvingPath) (*dentry, error) {
	d := rp.Start().Impl().(*dentry)
	for !rp.Done() {
		next, err := stepLocked(rp, d)
		if err != nil {
			return nil, err
		}
		d = next
	}
	if rp.MustBeDir() && !d.inode.isDir() {
		return nil, syserror.ENOTDIR
	}
	return d, nil
}

// doCreateAt checks that creating a file at rp is permitted, then invokes
// create to do so.
//
// doCreateAt is loosely analogous to a conjunction of Linux's
// fs/namei.c:filename_create() and done_path_create().
//
// Preconditions: !rp.Done(). For the final path component in rp,
// !rp.ShouldFollowSymlink().
func (fs *filesystem) doCreateAt(rp *vfs.ResolvingPath, dir bool, create func(parentDir *directory, name string) error) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parentDir, err := walkParentDirLocked(rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	if err := parentDir.inode.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return syserror.EEXIST
	}
	if len(name) > linux.NAME_MAX {
		return syserror.ENAMETOOLONG
	}
	if _, ok := parentDir.childMap[name]; ok {
		return syserror.EEXIST
	}
	if !dir && rp.MustBeDir() {
		return syserror.ENOENT
	}
	// tmpfs never calls VFS.InvalidateDentry(), so parentDir.dentry can only
	// be dead if it was deleted.
	if parentDir.dentry.vfsd.IsDead() {
		return syserror.ENOENT
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	if err := create(parentDir, name); err != nil {
		return err
	}

	ev := linux.IN_CREATE
	if dir {
		ev |= linux.IN_ISDIR
	}
	parentDir.inode.watches.Notify(name, uint32(ev), 0, vfs.InodeEvent, false /* unlinked */)
	parentDir.inode.touchCMtime()
	return nil
}

// AccessAt implements vfs.Filesystem.Impl.AccessAt.
func (fs *filesystem) AccessAt(ctx context.Context, rp *vfs.ResolvingPath, creds *auth.Credentials, ats vfs.AccessTypes) error {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	d, err := resolveLocked(rp)
	if err != nil {
		return err
	}
	return d.inode.checkPermissions(creds, ats)
}

// GetDentryAt implements vfs.FilesystemImpl.GetDentryAt.
func (fs *filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	d, err := resolveLocked(rp)
	if err != nil {
		return nil, err
	}
	if opts.CheckSearchable {
		if !d.inode.isDir() {
			return nil, syserror.ENOTDIR
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
	dir, err := walkParentDirLocked(rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return nil, err
	}
	dir.dentry.IncRef()
	return &dir.dentry.vfsd, nil
}

// LinkAt implements vfs.FilesystemImpl.LinkAt.
func (fs *filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	return fs.doCreateAt(rp, false /* dir */, func(parentDir *directory, name string) error {
		if rp.Mount() != vd.Mount() {
			return syserror.EXDEV
		}
		d := vd.Dentry().Impl().(*dentry)
		i := d.inode
		if i.isDir() {
			return syserror.EPERM
		}
		if err := vfs.MayLink(auth.CredentialsFromContext(ctx), linux.FileMode(atomic.LoadUint32(&i.mode)), auth.KUID(atomic.LoadUint32(&i.uid)), auth.KGID(atomic.LoadUint32(&i.gid))); err != nil {
			return err
		}
		if i.nlink == 0 {
			return syserror.ENOENT
		}
		if i.nlink == maxLinks {
			return syserror.EMLINK
		}
		i.incLinksLocked()
		i.watches.Notify("", linux.IN_ATTRIB, 0, vfs.InodeEvent, false /* unlinked */)
		parentDir.insertChildLocked(fs.newDentry(i), name)
		return nil
	})
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	return fs.doCreateAt(rp, true /* dir */, func(parentDir *directory, name string) error {
		creds := rp.Credentials()
		if parentDir.inode.nlink == maxLinks {
			return syserror.EMLINK
		}
		parentDir.inode.incLinksLocked() // from child's ".."
		childDir := fs.newDirectory(creds.EffectiveKUID, creds.EffectiveKGID, opts.Mode)
		parentDir.insertChildLocked(&childDir.dentry, name)
		return nil
	})
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	return fs.doCreateAt(rp, false /* dir */, func(parentDir *directory, name string) error {
		creds := rp.Credentials()
		var childInode *inode
		switch opts.Mode.FileType() {
		case 0, linux.S_IFREG:
			childInode = fs.newRegularFile(creds.EffectiveKUID, creds.EffectiveKGID, opts.Mode)
		case linux.S_IFIFO:
			childInode = fs.newNamedPipe(creds.EffectiveKUID, creds.EffectiveKGID, opts.Mode)
		case linux.S_IFBLK:
			childInode = fs.newDeviceFile(creds.EffectiveKUID, creds.EffectiveKGID, opts.Mode, vfs.BlockDevice, opts.DevMajor, opts.DevMinor)
		case linux.S_IFCHR:
			childInode = fs.newDeviceFile(creds.EffectiveKUID, creds.EffectiveKGID, opts.Mode, vfs.CharDevice, opts.DevMajor, opts.DevMinor)
		case linux.S_IFSOCK:
			childInode = fs.newSocketFile(creds.EffectiveKUID, creds.EffectiveKGID, opts.Mode, opts.Endpoint)
		default:
			return syserror.EINVAL
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
		return nil, syserror.EOPNOTSUPP
	}

	// Handle O_CREAT and !O_CREAT separately, since in the latter case we
	// don't need fs.mu for writing.
	if opts.Flags&linux.O_CREAT == 0 {
		fs.mu.RLock()
		defer fs.mu.RUnlock()
		d, err := resolveLocked(rp)
		if err != nil {
			return nil, err
		}
		return d.open(ctx, rp, &opts, false /* afterCreate */)
	}

	mustCreate := opts.Flags&linux.O_EXCL != 0
	start := rp.Start().Impl().(*dentry)
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if rp.Done() {
		// Reject attempts to open directories with O_CREAT.
		if rp.MustBeDir() {
			return nil, syserror.EISDIR
		}
		if mustCreate {
			return nil, syserror.EEXIST
		}
		return start.open(ctx, rp, &opts, false /* afterCreate */)
	}
afterTrailingSymlink:
	parentDir, err := walkParentDirLocked(rp, start)
	if err != nil {
		return nil, err
	}
	// Check for search permission in the parent directory.
	if err := parentDir.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, err
	}
	// Reject attempts to open directories with O_CREAT.
	if rp.MustBeDir() {
		return nil, syserror.EISDIR
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return nil, syserror.EISDIR
	}
	if len(name) > linux.NAME_MAX {
		return nil, syserror.ENAMETOOLONG
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
		child := fs.newDentry(fs.newRegularFile(creds.EffectiveKUID, creds.EffectiveKGID, opts.Mode))
		parentDir.insertChildLocked(child, name)
		fd, err := child.open(ctx, rp, &opts, true)
		if err != nil {
			return nil, err
		}
		parentDir.inode.watches.Notify(name, linux.IN_CREATE, 0, vfs.PathEvent, false /* unlinked */)
		parentDir.inode.touchCMtime()
		return fd, nil
	}
	if mustCreate {
		return nil, syserror.EEXIST
	}
	// Is the file mounted over?
	if err := rp.CheckMount(&child.vfsd); err != nil {
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
	// Open existing file.
	if mustCreate {
		return nil, syserror.EEXIST
	}
	return child.open(ctx, rp, &opts, false)
}

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
		if opts.Flags&linux.O_TRUNC != 0 {
			if _, err := impl.truncate(0); err != nil {
				return nil, err
			}
		}
		return &fd.vfsfd, nil
	case *directory:
		// Can't open directories writably.
		if ats&vfs.MayWrite != 0 {
			return nil, syserror.EISDIR
		}
		var fd directoryFD
		fd.LockFD.Init(&d.inode.locks)
		if err := fd.vfsfd.Init(&fd, opts.Flags, rp.Mount(), &d.vfsd, &vfs.FileDescriptionOptions{AllowDirectIO: true}); err != nil {
			return nil, err
		}
		return &fd.vfsfd, nil
	case *symlink:
		// TODO(gvisor.dev/issue/2782): Can't open symlinks without O_PATH.
		return nil, syserror.ELOOP
	case *namedPipe:
		return impl.pipe.Open(ctx, rp.Mount(), &d.vfsd, opts.Flags, &d.inode.locks)
	case *deviceFile:
		return rp.VirtualFilesystem().OpenDeviceSpecialFile(ctx, rp.Mount(), &d.vfsd, impl.kind, impl.major, impl.minor, opts)
	case *socketFile:
		return nil, syserror.ENXIO
	default:
		panic(fmt.Sprintf("unknown inode type: %T", d.inode.impl))
	}
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	d, err := resolveLocked(rp)
	if err != nil {
		return "", err
	}
	symlink, ok := d.inode.impl.(*symlink)
	if !ok {
		return "", syserror.EINVAL
	}
	symlink.inode.touchAtime(rp.Mount())
	return symlink.target, nil
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, oldParentVD vfs.VirtualDentry, oldName string, opts vfs.RenameOptions) error {
	if opts.Flags != 0 {
		// TODO(b/145974740): Support renameat2 flags.
		return syserror.EINVAL
	}

	// Resolve newParent first to verify that it's on this Mount.
	fs.mu.Lock()
	defer fs.mu.Unlock()
	newParentDir, err := walkParentDirLocked(rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	newName := rp.Component()
	if newName == "." || newName == ".." {
		return syserror.EBUSY
	}
	mnt := rp.Mount()
	if mnt != oldParentVD.Mount() {
		return syserror.EXDEV
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
		return syserror.ENOENT
	}
	// Note that we don't need to call rp.CheckMount(), since if renamed is a
	// mount point then we want to rename the mount point, not anything in the
	// mounted filesystem.
	if renamed.inode.isDir() {
		if renamed == &newParentDir.dentry || genericIsAncestorDentry(renamed, &newParentDir.dentry) {
			return syserror.EINVAL
		}
		if oldParentDir != newParentDir {
			// Writability is needed to change renamed's "..".
			if err := renamed.inode.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
				return err
			}
		}
	} else {
		if opts.MustBeDir || rp.MustBeDir() {
			return syserror.ENOTDIR
		}
	}

	if err := newParentDir.inode.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	replaced, ok := newParentDir.childMap[newName]
	if ok {
		replacedDir, ok := replaced.inode.impl.(*directory)
		if ok {
			if !renamed.inode.isDir() {
				return syserror.EISDIR
			}
			if len(replacedDir.childMap) != 0 {
				return syserror.ENOTEMPTY
			}
		} else {
			if rp.MustBeDir() {
				return syserror.ENOTDIR
			}
			if renamed.inode.isDir() {
				return syserror.ENOTDIR
			}
		}
	} else {
		if renamed.inode.isDir() && newParentDir.inode.nlink == maxLinks {
			return syserror.EMLINK
		}
	}
	// tmpfs never calls VFS.InvalidateDentry(), so newParentDir.dentry can
	// only be dead if it was deleted.
	if newParentDir.dentry.vfsd.IsDead() {
		return syserror.ENOENT
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
	defer mntns.DecRef()
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
			newParentDir.inode.decLinksLocked() // from replaced's ".."
		}
		replaced.inode.decLinksLocked()
	}
	oldParentDir.removeChildLocked(renamed)
	newParentDir.insertChildLocked(renamed, newName)
	vfsObj.CommitRenameReplaceDentry(&renamed.vfsd, replacedVFSD)
	oldParentDir.inode.touchCMtime()
	if oldParentDir != newParentDir {
		if renamed.inode.isDir() {
			oldParentDir.inode.decLinksLocked()
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
	parentDir, err := walkParentDirLocked(rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	if err := parentDir.inode.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." {
		return syserror.EINVAL
	}
	if name == ".." {
		return syserror.ENOTEMPTY
	}
	child, ok := parentDir.childMap[name]
	if !ok {
		return syserror.ENOENT
	}
	childDir, ok := child.inode.impl.(*directory)
	if !ok {
		return syserror.ENOTDIR
	}
	if len(childDir.childMap) != 0 {
		return syserror.ENOTEMPTY
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef()
	if err := vfsObj.PrepareDeleteDentry(mntns, &child.vfsd); err != nil {
		return err
	}
	parentDir.removeChildLocked(child)
	parentDir.inode.watches.Notify(name, linux.IN_DELETE|linux.IN_ISDIR, 0, vfs.InodeEvent, true /* unlinked */)
	// Remove links for child, child/., and child/..
	child.inode.decLinksLocked()
	child.inode.decLinksLocked()
	parentDir.inode.decLinksLocked()
	vfsObj.CommitDeleteDentry(&child.vfsd)
	parentDir.inode.touchCMtime()
	return nil
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	fs.mu.RLock()
	d, err := resolveLocked(rp)
	if err != nil {
		fs.mu.RUnlock()
		return err
	}
	if err := d.inode.setStat(ctx, rp.Credentials(), &opts.Stat); err != nil {
		fs.mu.RUnlock()
		return err
	}
	fs.mu.RUnlock()

	if ev := vfs.InotifyEventFromStatMask(opts.Stat.Mask); ev != 0 {
		d.InotifyWithParent(ev, 0, vfs.InodeEvent)
	}
	return nil
}

// StatAt implements vfs.FilesystemImpl.StatAt.
func (fs *filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	d, err := resolveLocked(rp)
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
	if _, err := resolveLocked(rp); err != nil {
		return linux.Statfs{}, err
	}
	statfs := linux.Statfs{
		Type:         linux.TMPFS_MAGIC,
		BlockSize:    usermem.PageSize,
		FragmentSize: usermem.PageSize,
		NameLength:   linux.NAME_MAX,
		// TODO(b/29637826): Allow configuring a tmpfs size and enforce it.
		Blocks:     0,
		BlocksFree: 0,
	}
	return statfs, nil
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt.
func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	return fs.doCreateAt(rp, false /* dir */, func(parentDir *directory, name string) error {
		creds := rp.Credentials()
		child := fs.newDentry(fs.newSymlink(creds.EffectiveKUID, creds.EffectiveKGID, 0777, target))
		parentDir.insertChildLocked(child, name)
		return nil
	})
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parentDir, err := walkParentDirLocked(rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	if err := parentDir.inode.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return syserror.EISDIR
	}
	child, ok := parentDir.childMap[name]
	if !ok {
		return syserror.ENOENT
	}
	if child.inode.isDir() {
		return syserror.EISDIR
	}
	if rp.MustBeDir() {
		return syserror.ENOTDIR
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef()
	if err := vfsObj.PrepareDeleteDentry(mntns, &child.vfsd); err != nil {
		return err
	}

	// Generate inotify events. Note that this must take place before the link
	// count of the child is decremented, or else the watches may be dropped
	// before these events are added.
	vfs.InotifyRemoveChild(&child.inode.watches, &parentDir.inode.watches, name)

	parentDir.removeChildLocked(child)
	child.inode.decLinksLocked()
	vfsObj.CommitDeleteDentry(&child.vfsd)
	parentDir.inode.touchCMtime()
	return nil
}

// BoundEndpointAt implements FilesystemImpl.BoundEndpointAt.
func (fs *filesystem) BoundEndpointAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.BoundEndpointOptions) (transport.BoundEndpoint, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	d, err := resolveLocked(rp)
	if err != nil {
		return nil, err
	}
	if err := d.inode.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
		return nil, err
	}
	switch impl := d.inode.impl.(type) {
	case *socketFile:
		return impl.ep, nil
	default:
		return nil, syserror.ECONNREFUSED
	}
}

// ListxattrAt implements vfs.FilesystemImpl.ListxattrAt.
func (fs *filesystem) ListxattrAt(ctx context.Context, rp *vfs.ResolvingPath, size uint64) ([]string, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	d, err := resolveLocked(rp)
	if err != nil {
		return nil, err
	}
	return d.inode.listxattr(size)
}

// GetxattrAt implements vfs.FilesystemImpl.GetxattrAt.
func (fs *filesystem) GetxattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetxattrOptions) (string, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	d, err := resolveLocked(rp)
	if err != nil {
		return "", err
	}
	return d.inode.getxattr(rp.Credentials(), &opts)
}

// SetxattrAt implements vfs.FilesystemImpl.SetxattrAt.
func (fs *filesystem) SetxattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetxattrOptions) error {
	fs.mu.RLock()
	d, err := resolveLocked(rp)
	if err != nil {
		fs.mu.RUnlock()
		return err
	}
	if err := d.inode.setxattr(rp.Credentials(), &opts); err != nil {
		fs.mu.RUnlock()
		return err
	}
	fs.mu.RUnlock()

	d.InotifyWithParent(linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}

// RemovexattrAt implements vfs.FilesystemImpl.RemovexattrAt.
func (fs *filesystem) RemovexattrAt(ctx context.Context, rp *vfs.ResolvingPath, name string) error {
	fs.mu.RLock()
	d, err := resolveLocked(rp)
	if err != nil {
		fs.mu.RUnlock()
		return err
	}
	if err := d.inode.removexattr(rp.Credentials(), name); err != nil {
		fs.mu.RUnlock()
		return err
	}
	fs.mu.RUnlock()

	d.InotifyWithParent(linux.IN_ATTRIB, 0, vfs.InodeEvent)
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
				// This must be an anonymous memfd file.
				b.PrependComponent("/" + d.name)
				return vfs.PrependPathSyntheticError{}
			}
			return vfs.PrependPathAtNonMountRootError{}
		}
		b.PrependComponent(d.name)
		d = d.parent
	}
}
