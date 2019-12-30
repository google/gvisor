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

package memfs

import (
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
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
	if !d.inode.isDir() {
		return nil, syserror.ENOTDIR
	}
	if err := d.inode.checkPermissions(rp.Credentials(), vfs.MayExec, true); err != nil {
		return nil, err
	}
afterSymlink:
	nextVFSD, err := rp.ResolveComponent(&d.vfsd)
	if err != nil {
		return nil, err
	}
	if nextVFSD == nil {
		// Since the Dentry tree is the sole source of truth for memfs, if it's
		// not in the Dentry tree, it doesn't exist.
		return nil, syserror.ENOENT
	}
	next := nextVFSD.Impl().(*dentry)
	if symlink, ok := next.inode.impl.(*symlink); ok && rp.ShouldFollowSymlink() {
		// TODO: symlink traversals update access time
		if err := rp.HandleSymlink(symlink.target); err != nil {
			return nil, err
		}
		goto afterSymlink // don't check the current directory again
	}
	rp.Advance()
	return next, nil
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
func walkParentDirLocked(rp *vfs.ResolvingPath, d *dentry) (*dentry, error) {
	for !rp.Final() {
		next, err := stepLocked(rp, d)
		if err != nil {
			return nil, err
		}
		d = next
	}
	if !d.inode.isDir() {
		return nil, syserror.ENOTDIR
	}
	return d, nil
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
func (fs *filesystem) doCreateAt(rp *vfs.ResolvingPath, dir bool, create func(parent *dentry, name string) error) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parent, err := walkParentDirLocked(rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	if err := parent.inode.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec, true /* isDir */); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return syserror.EEXIST
	}
	// Call parent.vfsd.Child() instead of stepLocked() or rp.ResolveChild(),
	// because if the child exists we want to return EEXIST immediately instead
	// of attempting symlink/mount traversal.
	if parent.vfsd.Child(name) != nil {
		return syserror.EEXIST
	}
	if !dir && rp.MustBeDir() {
		return syserror.ENOENT
	}
	// In memfs, the only way to cause a dentry to be disowned is by removing
	// it from the filesystem, so this check is equivalent to checking if
	// parent has been removed.
	if parent.vfsd.IsDisowned() {
		return syserror.ENOENT
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	return create(parent, name)
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
		if err := d.inode.checkPermissions(rp.Credentials(), vfs.MayExec, true /* isDir */); err != nil {
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
	d, err := walkParentDirLocked(rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return nil, err
	}
	d.IncRef()
	return &d.vfsd, nil
}

// LinkAt implements vfs.FilesystemImpl.LinkAt.
func (fs *filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	return fs.doCreateAt(rp, false /* dir */, func(parent *dentry, name string) error {
		if rp.Mount() != vd.Mount() {
			return syserror.EXDEV
		}
		d := vd.Dentry().Impl().(*dentry)
		if d.inode.isDir() {
			return syserror.EPERM
		}
		if d.inode.nlink == 0 {
			return syserror.ENOENT
		}
		if d.inode.nlink == maxLinks {
			return syserror.EMLINK
		}
		d.inode.incLinksLocked()
		child := fs.newDentry(d.inode)
		parent.vfsd.InsertChild(&child.vfsd, name)
		parent.inode.impl.(*directory).childList.PushBack(child)
		return nil
	})
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	return fs.doCreateAt(rp, true /* dir */, func(parent *dentry, name string) error {
		if parent.inode.nlink == maxLinks {
			return syserror.EMLINK
		}
		parent.inode.incLinksLocked() // from child's ".."
		child := fs.newDentry(fs.newDirectory(rp.Credentials(), opts.Mode))
		parent.vfsd.InsertChild(&child.vfsd, name)
		parent.inode.impl.(*directory).childList.PushBack(child)
		return nil
	})
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	return fs.doCreateAt(rp, false /* dir */, func(parent *dentry, name string) error {
		switch opts.Mode.FileType() {
		case 0, linux.S_IFREG:
			child := fs.newDentry(fs.newRegularFile(rp.Credentials(), opts.Mode))
			parent.vfsd.InsertChild(&child.vfsd, name)
			parent.inode.impl.(*directory).childList.PushBack(child)
			return nil
		case linux.S_IFIFO:
			child := fs.newDentry(fs.newNamedPipe(rp.Credentials(), opts.Mode))
			parent.vfsd.InsertChild(&child.vfsd, name)
			parent.inode.impl.(*directory).childList.PushBack(child)
			return nil
		case linux.S_IFBLK, linux.S_IFCHR, linux.S_IFSOCK:
			// Not yet supported.
			return syserror.EPERM
		default:
			return syserror.EINVAL
		}
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
		return d.open(ctx, rp, opts.Flags, false /* afterCreate */)
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
		return start.open(ctx, rp, opts.Flags, false /* afterCreate */)
	}
afterTrailingSymlink:
	parent, err := walkParentDirLocked(rp, start)
	if err != nil {
		return nil, err
	}
	// Check for search permission in the parent directory.
	if err := parent.inode.checkPermissions(rp.Credentials(), vfs.MayExec, true); err != nil {
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
	// Determine whether or not we need to create a file.
	child, err := stepLocked(rp, parent)
	if err == syserror.ENOENT {
		// Already checked for searchability above; now check for writability.
		if err := parent.inode.checkPermissions(rp.Credentials(), vfs.MayWrite, true); err != nil {
			return nil, err
		}
		if err := rp.Mount().CheckBeginWrite(); err != nil {
			return nil, err
		}
		defer rp.Mount().EndWrite()
		// Create and open the child.
		child := fs.newDentry(fs.newRegularFile(rp.Credentials(), opts.Mode))
		parent.vfsd.InsertChild(&child.vfsd, name)
		parent.inode.impl.(*directory).childList.PushBack(child)
		return child.open(ctx, rp, opts.Flags, true)
	}
	if err != nil {
		return nil, err
	}
	// Do we need to resolve a trailing symlink?
	if !rp.Done() {
		start = parent
		goto afterTrailingSymlink
	}
	// Open existing file.
	if mustCreate {
		return nil, syserror.EEXIST
	}
	return child.open(ctx, rp, opts.Flags, false)
}

func (d *dentry) open(ctx context.Context, rp *vfs.ResolvingPath, flags uint32, afterCreate bool) (*vfs.FileDescription, error) {
	ats := vfs.AccessTypesForOpenFlags(flags)
	if !afterCreate {
		if err := d.inode.checkPermissions(rp.Credentials(), ats, d.inode.isDir()); err != nil {
			return nil, err
		}
	}
	mnt := rp.Mount()
	switch impl := d.inode.impl.(type) {
	case *regularFile:
		var fd regularFileFD
		fd.readable = vfs.MayReadFileWithOpenFlags(flags)
		fd.writable = vfs.MayWriteFileWithOpenFlags(flags)
		if fd.writable {
			if err := mnt.CheckBeginWrite(); err != nil {
				return nil, err
			}
			// mnt.EndWrite() is called by regularFileFD.Release().
		}
		fd.vfsfd.Init(&fd, flags, mnt, &d.vfsd, &vfs.FileDescriptionOptions{})
		if flags&linux.O_TRUNC != 0 {
			impl.mu.Lock()
			impl.data = impl.data[:0]
			atomic.StoreInt64(&impl.dataLen, 0)
			impl.mu.Unlock()
		}
		return &fd.vfsfd, nil
	case *directory:
		// Can't open directories writably.
		if ats&vfs.MayWrite != 0 {
			return nil, syserror.EISDIR
		}
		var fd directoryFD
		fd.vfsfd.Init(&fd, flags, mnt, &d.vfsd, &vfs.FileDescriptionOptions{})
		return &fd.vfsfd, nil
	case *symlink:
		// Can't open symlinks without O_PATH (which is unimplemented).
		return nil, syserror.ELOOP
	case *namedPipe:
		return newNamedPipeFD(ctx, impl, rp, &d.vfsd, flags)
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
	newParent, err := walkParentDirLocked(rp, rp.Start().Impl().(*dentry))
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

	oldParent := oldParentVD.Dentry().Impl().(*dentry)
	if err := oldParent.inode.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec, true /* isDir */); err != nil {
		return err
	}
	// Call vfs.Dentry.Child() instead of stepLocked() or rp.ResolveChild(),
	// because if the existing child is a symlink or mount point then we want
	// to rename over it rather than follow it.
	renamedVFSD := oldParent.vfsd.Child(oldName)
	if renamedVFSD == nil {
		return syserror.ENOENT
	}
	renamed := renamedVFSD.Impl().(*dentry)
	if renamed.inode.isDir() {
		if renamed == newParent || renamedVFSD.IsAncestorOf(&newParent.vfsd) {
			return syserror.EINVAL
		}
		if oldParent != newParent {
			// Writability is needed to change renamed's "..".
			if err := renamed.inode.checkPermissions(rp.Credentials(), vfs.MayWrite, true /* isDir */); err != nil {
				return err
			}
		}
	} else {
		if opts.MustBeDir || rp.MustBeDir() {
			return syserror.ENOTDIR
		}
	}

	if err := newParent.inode.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec, true /* isDir */); err != nil {
		return err
	}
	replacedVFSD := newParent.vfsd.Child(newName)
	var replaced *dentry
	if replacedVFSD != nil {
		replaced = replacedVFSD.Impl().(*dentry)
		if replaced.inode.isDir() {
			if !renamed.inode.isDir() {
				return syserror.EISDIR
			}
			if replaced.vfsd.HasChildren() {
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
		if renamed.inode.isDir() && newParent.inode.nlink == maxLinks {
			return syserror.EMLINK
		}
	}
	if newParent.vfsd.IsDisowned() {
		return syserror.ENOENT
	}

	// Linux places this check before some of those above; we do it here for
	// simplicity, under the assumption that applications are not intentionally
	// doing noop renames expecting them to succeed where non-noop renames
	// would fail.
	if renamedVFSD == replacedVFSD {
		return nil
	}
	vfsObj := rp.VirtualFilesystem()
	oldParentDir := oldParent.inode.impl.(*directory)
	newParentDir := newParent.inode.impl.(*directory)
	if err := vfsObj.PrepareRenameDentry(vfs.MountNamespaceFromContext(ctx), renamedVFSD, replacedVFSD); err != nil {
		return err
	}
	if replaced != nil {
		newParentDir.childList.Remove(replaced)
		if replaced.inode.isDir() {
			newParent.inode.decLinksLocked() // from replaced's ".."
		}
		replaced.inode.decLinksLocked()
	}
	oldParentDir.childList.Remove(renamed)
	newParentDir.childList.PushBack(renamed)
	if renamed.inode.isDir() {
		oldParent.inode.decLinksLocked()
		newParent.inode.incLinksLocked()
	}
	// TODO: update timestamps and parent directory sizes
	vfsObj.CommitRenameReplaceDentry(renamedVFSD, &newParent.vfsd, newName, replacedVFSD)
	return nil
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parent, err := walkParentDirLocked(rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	if err := parent.inode.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec, true /* isDir */); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." {
		return syserror.EINVAL
	}
	if name == ".." {
		return syserror.ENOTEMPTY
	}
	childVFSD := parent.vfsd.Child(name)
	if childVFSD == nil {
		return syserror.ENOENT
	}
	child := childVFSD.Impl().(*dentry)
	if !child.inode.isDir() {
		return syserror.ENOTDIR
	}
	if childVFSD.HasChildren() {
		return syserror.ENOTEMPTY
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	vfsObj := rp.VirtualFilesystem()
	if err := vfsObj.PrepareDeleteDentry(vfs.MountNamespaceFromContext(ctx), childVFSD); err != nil {
		return err
	}
	parent.inode.impl.(*directory).childList.Remove(child)
	parent.inode.decLinksLocked() // from child's ".."
	child.inode.decLinksLocked()
	vfsObj.CommitDeleteDentry(childVFSD)
	return nil
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	_, err := resolveLocked(rp)
	if err != nil {
		return err
	}
	if opts.Stat.Mask == 0 {
		return nil
	}
	// TODO: implement inode.setStat
	return syserror.EPERM
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
	_, err := resolveLocked(rp)
	if err != nil {
		return linux.Statfs{}, err
	}
	// TODO: actually implement statfs
	return linux.Statfs{}, syserror.ENOSYS
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt.
func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	return fs.doCreateAt(rp, false /* dir */, func(parent *dentry, name string) error {
		child := fs.newDentry(fs.newSymlink(rp.Credentials(), target))
		parent.vfsd.InsertChild(&child.vfsd, name)
		parent.inode.impl.(*directory).childList.PushBack(child)
		return nil
	})
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parent, err := walkParentDirLocked(rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	if err := parent.inode.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec, true /* isDir */); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return syserror.EISDIR
	}
	childVFSD := parent.vfsd.Child(name)
	if childVFSD == nil {
		return syserror.ENOENT
	}
	child := childVFSD.Impl().(*dentry)
	if child.inode.isDir() {
		return syserror.EISDIR
	}
	if !rp.MustBeDir() {
		return syserror.ENOTDIR
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	vfsObj := rp.VirtualFilesystem()
	if err := vfsObj.PrepareDeleteDentry(vfs.MountNamespaceFromContext(ctx), childVFSD); err != nil {
		return err
	}
	parent.inode.impl.(*directory).childList.Remove(child)
	child.inode.decLinksLocked()
	vfsObj.CommitDeleteDentry(childVFSD)
	return nil
}

// ListxattrAt implements vfs.FilesystemImpl.ListxattrAt.
func (fs *filesystem) ListxattrAt(ctx context.Context, rp *vfs.ResolvingPath) ([]string, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	_, err := resolveLocked(rp)
	if err != nil {
		return nil, err
	}
	// TODO(b/127675828): support extended attributes
	return nil, syserror.ENOTSUP
}

// GetxattrAt implements vfs.FilesystemImpl.GetxattrAt.
func (fs *filesystem) GetxattrAt(ctx context.Context, rp *vfs.ResolvingPath, name string) (string, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	_, err := resolveLocked(rp)
	if err != nil {
		return "", err
	}
	// TODO(b/127675828): support extended attributes
	return "", syserror.ENOTSUP
}

// SetxattrAt implements vfs.FilesystemImpl.SetxattrAt.
func (fs *filesystem) SetxattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetxattrOptions) error {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	_, err := resolveLocked(rp)
	if err != nil {
		return err
	}
	// TODO(b/127675828): support extended attributes
	return syserror.ENOTSUP
}

// RemovexattrAt implements vfs.FilesystemImpl.RemovexattrAt.
func (fs *filesystem) RemovexattrAt(ctx context.Context, rp *vfs.ResolvingPath, name string) error {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	_, err := resolveLocked(rp)
	if err != nil {
		return err
	}
	// TODO(b/127675828): support extended attributes
	return syserror.ENOTSUP
}

// PrependPath implements vfs.FilesystemImpl.PrependPath.
func (fs *filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return vfs.GenericPrependPath(vfsroot, vd, b)
}
