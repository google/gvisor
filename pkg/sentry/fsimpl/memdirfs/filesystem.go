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

// This file implements vfs.FilesystemImpl for memdirfs.

package memdirfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// stepLocked resolves rp.Component() in parent directory vfsd.
//
// stepLocked is loosely analogous to fs/namei.c:walk_component().
//
// Preconditions: filesystem.mu must be locked. !rp.Done(). inode ==
// vfsd.Impl().(*dentry).inode.
func stepLocked(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, inode *Inode) (*vfs.Dentry, *Inode, error) {
	if !inode.isDir() {
		return nil, nil, syserror.ENOTDIR
	}
	if err := inode.checkPermissions(rp.Credentials(), vfs.MayExec, true); err != nil {
		return nil, nil, err
	}
afterSymlink:
	nextVFSD, err := rp.ResolveComponent(vfsd)
	if nextVFSD == nil && err == nil {
		// Try using Inode.DynamicLookup() to resolve the child.
		nextVFSD, err = inode.impl.DynamicLookup(rp)
	}
	if err != nil {
		return nil, nil, err
	}
	if nextVFSD == nil {
		// If it's not in the Dentry tree and the implementation didn't provide
		// a match on a dynamic lookup, it doesn't exist.
		return nil, nil, syserror.ENOENT
	}

	nextInode := nextVFSD.Impl().(*Dentry).inode
	if symlink, ok := nextInode.impl.(*symlink); ok && rp.ShouldFollowSymlink() {
		// TODO: symlink traversals update access time
		if err := rp.HandleSymlink(symlink.target); err != nil {
			return nil, nil, err
		}
		goto afterSymlink // don't check the current directory again
	}
	rp.Advance()
	return nextVFSD, nextInode, nil
}

// walkExistingLocked resolves rp to an existing file.
//
// walkExistingLocked is loosely analogous to Linux's
// fs/namei.c:path_lookupat().
//
// Preconditions: filesystem.mu must be locked.
func walkExistingLocked(rp *vfs.ResolvingPath) (*vfs.Dentry, *Inode, error) {
	vfsd := rp.Start()
	inode := vfsd.Impl().(*Dentry).inode
	for !rp.Done() {
		var err error
		vfsd, inode, err = stepLocked(rp, vfsd, inode)
		if err != nil {
			return nil, nil, err
		}
	}
	if rp.MustBeDir() && !inode.isDir() {
		return nil, nil, syserror.ENOTDIR
	}
	return vfsd, inode, nil
}

// walkParentDirLocked resolves all but the last path component of rp to an
// existing directory. It does not check that the returned directory is
// searchable by the provider of rp.
//
// walkParentDirLocked is loosely analogous to Linux's
// fs/namei.c:path_parentat().
//
// Preconditions: filesystem.mu must be locked. !rp.Done().
func walkParentDirLocked(rp *vfs.ResolvingPath) (*vfs.Dentry, *Inode, error) {
	vfsd := rp.Start()
	inode := vfsd.Impl().(*Dentry).inode
	for !rp.Final() {
		var err error
		vfsd, inode, err = stepLocked(rp, vfsd, inode)
		if err != nil {
			return nil, nil, err
		}
	}
	if !inode.isDir() {
		return nil, nil, syserror.ENOTDIR
	}
	return vfsd, inode, nil
}

// checkCreateLocked checks that a file named rp.Component() may be created in
// directory parentVFSD, then returns rp.Component().
//
// Preconditions: filesystem.mu must be locked. parentInode ==
// parentVFSD.Impl().(*dentry).inode. parentInode.isDir() == true.
func checkCreateLocked(rp *vfs.ResolvingPath, parentVFSD *vfs.Dentry, parentInode *Inode) (string, error) {
	if err := parentInode.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec, true); err != nil {
		return "", err
	}
	pc := rp.Component()
	if pc == "." || pc == ".." {
		return "", syserror.EEXIST
	}
	childVFSD, err := rp.ResolveChild(parentVFSD, pc)
	if err != nil {
		return "", err
	}
	if childVFSD != nil {
		return "", syserror.EEXIST
	}
	if parentVFSD.IsDisowned() {
		return "", syserror.ENOENT
	}
	return pc, nil
}

// checkDeleteLocked checks that the file represented by vfsd may be deleted.
func checkDeleteLocked(vfsd *vfs.Dentry) error {
	parentVFSD := vfsd.Parent()
	if parentVFSD == nil {
		return syserror.EBUSY
	}
	if parentVFSD.IsDisowned() {
		return syserror.ENOENT
	}
	return nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *Filesystem) Release() {
}

// Sync implements vfs.FilesystemImpl.Sync.
func (fs *Filesystem) Sync(ctx context.Context) error {
	// All filesystem state is in-memory.
	return nil
}

// GetDentryAt implements vfs.FilesystemImpl.GetDentryAt.
func (fs *Filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	vfsd, inode, err := walkExistingLocked(rp)
	if err != nil {
		return nil, err
	}

	if opts.CheckSearchable {
		if !inode.isDir() {
			return nil, syserror.ENOTDIR
		}
		if err := inode.checkPermissions(rp.Credentials(), vfs.MayExec, true); err != nil {
			return nil, err
		}
	}
	inode.IncRef() // vfsd.IncRef(&fs.vfsfs)
	return vfsd, nil
}

// LinkAt implements vfs.FilesystemImpl.LinkAt.
func (fs *Filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	if rp.Done() {
		return syserror.EEXIST
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parentVFSD, parentInode, err := walkParentDirLocked(rp)
	if err != nil {
		return err
	}
	pc, err := checkCreateLocked(rp, parentVFSD, parentInode)
	if err != nil {
		return err
	}
	if rp.Mount() != vd.Mount() {
		return syserror.EXDEV
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()

	d := vd.Dentry().Impl().(*Dentry)
	if d.inode.isDir() {
		return syserror.EPERM
	}
	d.inode.IncLinksLocked()
	child := &Dentry{
		inode: d.inode,
	}
	child.vfsd.Init(child)
	parentVFSD.InsertChild(&child.vfsd, pc)
	parentInode.impl.(*Directory).childList.PushBack(child)
	return nil
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *Filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	if rp.Done() {
		return syserror.EEXIST
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parentVFSD, parentInode, err := walkParentDirLocked(rp)
	if err != nil {
		return err
	}
	pc, err := checkCreateLocked(rp, parentVFSD, parentInode)
	if err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	child := fs.NewDirectoryInode(rp.Credentials(), opts.Mode).NewDentry()
	parentVFSD.InsertChild(&child.vfsd, pc)
	parentInode.impl.(*Directory).childList.PushBack(child)
	parentInode.IncLinksLocked() // from child's ".."
	return nil
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *Filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	if rp.Done() {
		return syserror.EEXIST
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parentVFSD, parentInode, err := walkParentDirLocked(rp)
	if err != nil {
		return err
	}
	_, err = checkCreateLocked(rp, parentVFSD, parentInode)
	if err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	// TODO: actually implement mknod
	return syserror.EPERM
}

// OpenAt implements vfs.FilesystemImpl.OpenAt.
func (fs *Filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	// Filter out flags that are not supported by memdirfs. O_DIRECTORY and
	// O_NOFOLLOW have no effect here (they're handled by VFS by setting
	// appropriate bits in rp), but are returned by
	// FileDescriptionImpl.StatusFlags().
	opts.Flags &= linux.O_ACCMODE | linux.O_CREAT | linux.O_EXCL | linux.O_TRUNC | linux.O_DIRECTORY | linux.O_NOFOLLOW
	ats := vfs.AccessTypesForOpenFlags(opts.Flags)

	if opts.Flags&linux.O_CREAT == 0 {
		fs.mu.RLock()
		defer fs.mu.RUnlock()
		vfsd, inode, err := walkExistingLocked(rp)
		if err != nil {
			return nil, err
		}
		if err := inode.checkPermissions(rp.Credentials(), ats, inode.isDir()); err != nil {
			return nil, err
		}
		return inode.impl.Open(rp, vfsd, opts.Flags)
	}

	mustCreate := opts.Flags&linux.O_EXCL != 0
	vfsd := rp.Start()
	inode := vfsd.Impl().(*Dentry).inode
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if rp.Done() {
		if rp.MustBeDir() {
			return nil, syserror.EISDIR
		}
		if mustCreate {
			return nil, syserror.EEXIST
		}
		if err := inode.checkPermissions(rp.Credentials(), ats, inode.isDir()); err != nil {
			return nil, err
		}
		return inode.impl.Open(rp, vfsd, opts.Flags)
	}
afterTrailingSymlink:
	// Walk to the parent directory of the last path component.
	for !rp.Final() {
		var err error
		vfsd, inode, err = stepLocked(rp, vfsd, inode)
		if err != nil {
			return nil, err
		}
	}
	if !inode.isDir() {
		return nil, syserror.ENOTDIR
	}
	// Check for search permission in the parent directory.
	if err := inode.checkPermissions(rp.Credentials(), vfs.MayExec, true); err != nil {
		return nil, err
	}
	// Reject attempts to open directories with O_CREAT.
	if rp.MustBeDir() {
		return nil, syserror.EISDIR
	}
	pc := rp.Component()
	if pc == "." || pc == ".." {
		return nil, syserror.EISDIR
	}
	// Determine whether or not we need to create a file.
	childVFSD, err := rp.ResolveChild(vfsd, pc)
	if err != nil {
		return nil, err
	}
	if childVFSD == nil {
		// Already checked for searchability above; now check for writability.
		if err := inode.checkPermissions(rp.Credentials(), vfs.MayWrite, true); err != nil {
			return nil, err
		}
		if err := rp.Mount().CheckBeginWrite(); err != nil {
			return nil, err
		}
		defer rp.Mount().EndWrite()
		// Create and open the child.
		child := fs.NewInode(InodeOpts{Creds: rp.Credentials(), Mode: opts.Mode, Impl: fs.NewEmptyFileInodeImpl()}).NewDentry()
		vfsd.InsertChild(&child.vfsd, pc)
		inode.impl.(*Directory).childList.PushBack(child)
		return child.inode.impl.Open(rp, &child.vfsd, opts.Flags)
	}
	// Open existing file or follow symlink.
	if mustCreate {
		return nil, syserror.EEXIST
	}
	childInode := childVFSD.Impl().(*Dentry).inode
	if symlink, ok := childInode.impl.(*symlink); ok && rp.ShouldFollowSymlink() {
		// TODO: symlink traversals update access time
		if err := rp.HandleSymlink(symlink.target); err != nil {
			return nil, err
		}
		// rp.Final() may no longer be true since we now need to resolve the
		// symlink target.
		goto afterTrailingSymlink
	}
	if err := childInode.checkPermissions(rp.Credentials(), ats, childInode.isDir()); err != nil {
		return nil, err
	}
	return childInode.impl.Open(rp, childVFSD, opts.Flags)
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *Filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	fs.mu.RLock()
	_, inode, err := walkExistingLocked(rp)
	fs.mu.RUnlock()
	if err != nil {
		return "", err
	}
	symlink, ok := inode.impl.(*symlink)
	if !ok {
		return "", syserror.EINVAL
	}
	return symlink.target, nil
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *Filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry, opts vfs.RenameOptions) error {
	if rp.Done() {
		return syserror.ENOENT
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parentVFSD, parentInode, err := walkParentDirLocked(rp)
	if err != nil {
		return err
	}
	_, err = checkCreateLocked(rp, parentVFSD, parentInode)
	if err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	// TODO: actually implement RenameAt
	return syserror.EPERM
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *Filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	vfsd, inode, err := walkExistingLocked(rp)
	if err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	if err := checkDeleteLocked(vfsd); err != nil {
		return err
	}
	if !inode.isDir() {
		return syserror.ENOTDIR
	}
	if vfsd.HasChildren() {
		return syserror.ENOTEMPTY
	}
	if err := rp.VirtualFilesystem().DeleteDentry(vfs.MountNamespaceFromContext(ctx), vfsd); err != nil {
		return err
	}
	// Remove from parent directory's childList.
	vfsd.Parent().Impl().(*Dentry).inode.impl.(*Directory).childList.Remove(vfsd.Impl().(*Dentry))
	inode.DecRef()
	return nil
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *Filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	fs.mu.RLock()
	_, _, err := walkExistingLocked(rp)
	fs.mu.RUnlock()
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
func (fs *Filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	fs.mu.RLock()
	_, inode, err := walkExistingLocked(rp)
	fs.mu.RUnlock()
	if err != nil {
		return linux.Statx{}, err
	}
	var stat linux.Statx
	inode.statTo(fs, &stat)
	return stat, nil
}

// StatFSAt implements vfs.FilesystemImpl.StatFSAt.
func (fs *Filesystem) StatFSAt(ctx context.Context, rp *vfs.ResolvingPath) (linux.Statfs, error) {
	fs.mu.RLock()
	_, _, err := walkExistingLocked(rp)
	fs.mu.RUnlock()
	if err != nil {
		return linux.Statfs{}, err
	}
	// TODO: actually implement statfs
	return linux.Statfs{}, syserror.ENOSYS
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt.
func (fs *Filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	if rp.Done() {
		return syserror.EEXIST
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parentVFSD, parentInode, err := walkParentDirLocked(rp)
	if err != nil {
		return err
	}
	pc, err := checkCreateLocked(rp, parentVFSD, parentInode)
	if err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	child := fs.NewSymlinkInode(rp.Credentials(), target).NewDentry()
	parentVFSD.InsertChild(&child.vfsd, pc)
	parentInode.impl.(*Directory).childList.PushBack(child)
	return nil
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *Filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	vfsd, inode, err := walkExistingLocked(rp)
	if err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	if err := checkDeleteLocked(vfsd); err != nil {
		return err
	}
	if inode.isDir() {
		return syserror.EISDIR
	}
	if err := rp.VirtualFilesystem().DeleteDentry(vfs.MountNamespaceFromContext(ctx), vfsd); err != nil {
		return err
	}
	// Remove from parent directory's childList.
	vfsd.Parent().Impl().(*Dentry).inode.impl.(*Directory).childList.Remove(vfsd.Impl().(*Dentry))
	inode.DecLinksLocked()
	return nil
}
