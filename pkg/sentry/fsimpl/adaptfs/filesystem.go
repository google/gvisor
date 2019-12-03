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

package adaptfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/syserror"

	vfs1 "gvisor.dev/gvisor/pkg/sentry/fs"
	vfs2 "gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Sync implements vfs2.FilesystemImpl.Sync.
func (fs *filesystem) Sync(ctx context.Context) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.root.syncRecursiveLocked(ctx)
}

// Preconditions: d.fs.mu must be locked.
func (d *dentry) syncRecursiveLocked(ctx context.Context) error {
	retErr := d.inode().WriteOut(ctx)
	for _, childVFS2D := range d.vfs2d.Children() {
		if err := childVFS2D.Impl().(*dentry).syncRecursiveLocked(ctx); err != nil && retErr == nil {
			retErr = err
		}
	}
	return retErr
}

// stepExistingLocked resolves rp.Component() to an existing file in the
// directory d. A reference is taken on the returned dentry.
//
// Preconditions: fs.mu must be locked. !rp.Done().
func (fs *filesystem) stepExistingLocked(ctx context.Context, rp *vfs2.ResolvingPath, d *dentry, mayFollowSymlinks bool) (*dentry, error) {
	if !d.isDirectory() {
		return nil, syserror.ENOTDIR
	}
	if err := d.check(ctx, vfs1.PermMask{Execute: true}); err != nil {
		return nil, err
	}
afterSymlink:
	name := rp.Component()
	if name == "." {
		d.IncRef()
		return d, nil
	}
	if name == ".." {
		parentVFS2D, err := rp.ResolveParent(&d.vfs2d)
		if err != nil {
			return nil, err
		}
		parent := parentVFS2D.Impl().(*dentry)
		parent.IncRef()
		return parent, nil
	}
	childVFS2D, err := rp.ResolveChild(&d.vfs2d, name)
	if err != nil {
		return nil, err
	}
	var child *dentry
	if childVFS2D != nil {
		child = childVFS2D.Impl().(*dentry)
		if child.inode().MountSource.Revalidate(ctx, name, d.inode(), child.inode()) {
			// Remove the stale dentry from the tree.
			rp.VirtualFilesystem().ForceDeleteDentry(childVFS2D)
			childVFS2D = nil
			child = nil
		}
	}
	if childVFS2D == nil {
		childVFS1D, err := d.inode().Lookup(ctx, name)
		if err != nil {
			return nil, err
		}
		if childVFS1D.Inode == nil {
			// adaptfs does not cache negative lookups.
			return nil, syserror.ENOENT
		}
		child = fs.newDentry(childVFS1D)
		childVFS2D = &child.vfs2d
		d.IncRef() // reference held by child on its parent d
		d.vfs2d.InsertChild(childVFS2D, name)
	} else {
		child = childVFS2D.Impl().(*dentry)
	}
	if child.isSymlink() && rp.ShouldFollowSymlink() && mayFollowSymlinks {
		target, err := child.inode().Readlink(ctx)
		if err != nil {
			return nil, err
		}
		if err := rp.HandleSymlink(target); err != nil {
			return nil, err
		}
		goto afterSymlink // don't check the current directory again
	}
	child.IncRef()
	rp.Advance()
	return child, nil
}

// walkExistingLocked resolves rp to an existing file. A reference is taken on
// the returned dentry.
//
// Preconditions: fs.mu must be locked.
func (fs *filesystem) walkExistingLocked(ctx context.Context, rp *vfs2.ResolvingPath) (*dentry, error) {
	d := rp.Start().Impl().(*dentry)
	haveRef := false
	for !rp.Done() {
		next, err := fs.stepExistingLocked(ctx, rp, d, true /* mayFollowSymlinks */)
		if haveRef {
			d.decRefLocked()
		}
		if err != nil {
			return nil, err
		}
		d = next
		haveRef = true
	}
	if rp.MustBeDir() && !d.isDirectory() {
		if haveRef {
			d.decRefLocked()
		}
		return nil, syserror.ENOTDIR
	}
	if !haveRef {
		d.IncRef()
	}
	return d, nil
}

// walkParentDirLocked resolves all but the last path component of rp to an
// existing directory, starting from the given directory (which is usually
// rp.Start().Impl().(*dentry)). It does not check that the returned directory
// is searchable by the provider of rp. A reference is taken on the returned
// dentry.
//
// Preconditions: fs.mu must be locked. !rp.Done().
func (fs *filesystem) walkParentDirLocked(ctx context.Context, rp *vfs2.ResolvingPath, d *dentry) (*dentry, error) {
	haveRef := false
	for !rp.Final() {
		next, err := fs.stepExistingLocked(ctx, rp, d, true /* mayFollowSymlinks */)
		if haveRef {
			d.decRefLocked()
		}
		if err != nil {
			return nil, err
		}
		d = next
		haveRef = true
	}
	if !d.isDirectory() {
		if haveRef {
			d.decRefLocked()
		}
		return nil, syserror.ENOTDIR
	}
	if !haveRef {
		d.IncRef()
	}
	return d, nil
}

// GetDentryAt implements vfs2.FilesystemImpl.GetDentryAt.
func (fs *filesystem) GetDentryAt(ctx context.Context, rp *vfs2.ResolvingPath, opts vfs2.GetDentryOptions) (*vfs2.Dentry, error) {
	fs.mu.Lock()
	d, err := fs.walkExistingLocked(ctx, rp)
	fs.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if opts.CheckSearchable {
		if !d.isDirectory() {
			d.DecRef()
			return nil, syserror.ENOTDIR
		}
		if err := d.check(ctx, vfs1.PermMask{Execute: true}); err != nil {
			d.DecRef()
			return nil, err
		}
	}
	return &d.vfs2d, nil
}

// LinkAt implements vfs2.FilesystemImpl.LinkAt.
func (fs *filesystem) LinkAt(ctx context.Context, rp *vfs2.ResolvingPath, vd vfs2.VirtualDentry) error {
	// FIXME
	return syserror.EPERM
}

// MkdirAt implements vfs2.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs2.ResolvingPath, opts vfs2.MkdirOptions) error {
	// FIXME
	return syserror.EPERM
}

// MknodAt implements vfs2.FilesystemImpl.MknodAt.
func (fs *filesystem) MknodAt(ctx context.Context, rp *vfs2.ResolvingPath, opts vfs2.MknodOptions) error {
	// FIXME
	return syserror.EPERM
}

// OpenAt implements vfs2.FilesystemImpl.OpenAt.
func (fs *filesystem) OpenAt(ctx context.Context, rp *vfs2.ResolvingPath, opts vfs2.OpenOptions) (*vfs2.FileDescription, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if opts.Flags&linux.O_CREAT == 0 {
		d, err := fs.walkExistingLocked(ctx, rp)
		if err != nil {
			return nil, err
		}
		fd, err := d.open(ctx, rp, opts.Flags)
		d.decRefLocked()
		return fd, err
	}

	mustCreate := opts.Flags&linux.O_EXCL != 0
	start := rp.Start().Impl().(*dentry)
	if rp.Done() {
		// Reject attempts to open directories with O_CREAT.
		if rp.MustBeDir() {
			return nil, syserror.EISDIR
		}
		if mustCreate {
			return nil, syserror.EEXIST
		}
		return start.open(ctx, rp, opts.Flags)
	}

	haveStartRef := false
afterTrailingSymlink:
	// Walk to the parent directory of the last path component.
	parent, err := fs.walkParentDirLocked(ctx, rp, start)
	if haveStartRef {
		start.decRefLocked()
		haveStartRef = false
	}
	if err != nil {
		return nil, err
	}
	// Reject attempts to open directories with O_CREAT.
	if rp.MustBeDir() {
		parent.decRefLocked()
		return nil, syserror.EISDIR
	}
	name := rp.Component()
	if name == "." || name == ".." {
		parent.decRefLocked()
		return nil, syserror.EISDIR
	}

	child, err := fs.stepExistingLocked(ctx, rp, parent, false /* mayFollowSymlinks */)
	if err == syserror.ENOENT {
		fd, err := parent.createAndOpenLocked(ctx, rp, name, &opts)
		parent.decRefLocked()
		return fd, err
	}
	if err != nil {
		parent.decRefLocked()
		return nil, err
	}
	if mustCreate {
		child.decRefLocked()
		parent.decRefLocked()
		return nil, syserror.EEXIST
	}
	if child.isSymlink() && rp.ShouldFollowSymlink() {
		target, err := child.inode().Readlink(ctx)
		child.decRefLocked()
		if err != nil {
			parent.decRefLocked()
			return nil, err
		}
		if err := rp.HandleSymlink(target); err != nil {
			parent.decRefLocked()
			return nil, err
		}
		// rp.Final() may no longer be true since we now need to resolve the
		// symlink target.
		start = parent
		haveStartRef = true
		goto afterTrailingSymlink
	}
	fd, err := child.open(ctx, rp, opts.Flags)
	child.decRefLocked()
	parent.decRefLocked()
	return fd, err
}

func (d *dentry) open(ctx context.Context, rp *vfs2.ResolvingPath, flags uint32) (*vfs2.FileDescription, error) {
	ats := vfs2.AccessTypesForOpenFlags(flags)
	if err := d.check(ctx, vfs1PermMaskFromVFS2AccessTypes(ats)); err != nil {
		return nil, err
	}
	mnt := rp.Mount()
	if ats&vfs2.MayWrite != 0 {
		if err := mnt.CheckBeginWrite(); err != nil {
			return nil, err
		}
	}
	vfs1fd, err := d.inode().GetFile(ctx, d.vfs1d, vfs1FileFlagsFromOpenFlags(flags))
	if err != nil {
		if ats&vfs2.MayWrite != 0 {
			mnt.EndWrite()
		}
		return nil, err
	}
	if ats&vfs2.MayWrite != 0 && !vfs1fd.Flags().Write {
		mnt.EndWrite()
	}
	fd := d.fs.newFileDescription(vfs1fd, flags, mnt, d)
	return &fd.vfs2fd, nil
}

// Preconditions: fs.mu must be locked.
func (d *dentry) createAndOpenLocked(ctx context.Context, rp *vfs2.ResolvingPath, name string, opts *vfs2.OpenOptions) (*vfs2.FileDescription, error) {
	if err := d.check(ctx, vfs1.PermMask{
		Write:   true,
		Execute: true,
	}); err != nil {
		return nil, err
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return nil, err
	}
	childVFS1FD, err := d.inode().Create(ctx, d.vfs1d, name, vfs1FileFlagsFromOpenFlags(opts.Flags), vfs1.FilePermsFromMode(linux.FileMode(opts.Mode)))
	if err != nil {
		mnt.EndWrite()
		return nil, err
	}
	if !childVFS1FD.Flags().Write {
		mnt.EndWrite()
	}
	child := d.fs.newDentry(childVFS1FD.Dirent)
	d.IncRef() // reference held by child on its parent d
	d.vfs2d.InsertChild(&child.vfs2d, name)
	fd := d.fs.newFileDescription(childVFS1FD, opts.Flags, mnt, child)
	return &fd.vfs2fd, nil
}

// ReadlinkAt implements vfs2.FilesystemImpl.ReadlinkAt.
func (fs *filesystem) ReadlinkAt(ctx context.Context, rp *vfs2.ResolvingPath) (string, error) {
	// FIXME
	return "", syserror.EPERM
}

// RenameAt implements vfs2.FilesystemImpl.RenameAt.
func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs2.ResolvingPath, vd vfs2.VirtualDentry, opts vfs2.RenameOptions) error {
	// FIXME
	return syserror.EPERM
}

// RmdirAt implements vfs2.FilesystemImpl.RmdirAt.
func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs2.ResolvingPath) error {
	// FIXME
	return syserror.EPERM
}

// SetStatAt implements vfs2.FilesystemImpl.SetStatAt.
func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs2.ResolvingPath, opts vfs2.SetStatOptions) error {
	// FIXME
	return syserror.EPERM
}

// StatAt implements vfs2.FilesystemImpl.StatAt.
func (fs *filesystem) StatAt(ctx context.Context, rp *vfs2.ResolvingPath, opts vfs2.StatOptions) (linux.Statx, error) {
	fs.mu.Lock()
	d, err := fs.walkExistingLocked(ctx, rp)
	if err != nil {
		fs.mu.Unlock()
		return linux.Statx{}, err
	}
	var stat linux.Statx
	err = d.statTo(ctx, &stat)
	d.decRefLocked()
	fs.mu.Unlock()
	return stat, err
}

// StatFSAt implements vfs2.FilesystemImpl.StatFSAt.
func (fs *filesystem) StatFSAt(ctx context.Context, rp *vfs2.ResolvingPath) (linux.Statfs, error) {
	// FIXME
	return linux.Statfs{}, syserror.EPERM
}

// SymlinkAt implements vfs2.FilesystemImpl.SymlinkAt.
func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs2.ResolvingPath, target string) error {
	// FIXME
	return syserror.EPERM
}

// UnlinkAt implements vfs2.FilesystemImpl.UnlinkAt.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs2.ResolvingPath) error {
	// FIXME
	return syserror.EPERM
}

// ListxattrAt implements vfs2.FilesystemImpl.ListxattrAt.
func (fs *filesystem) ListxattrAt(ctx context.Context, rp *vfs2.ResolvingPath) ([]string, error) {
	// FIXME
	return nil, syserror.EPERM
}

// GetxattrAt implements vfs2.FilesystemImpl.GetxattrAt.
func (fs *filesystem) GetxattrAt(ctx context.Context, rp *vfs2.ResolvingPath, name string) (string, error) {
	// FIXME
	return "", syserror.EPERM
}

// SetxattrAt implements vfs2.FilesystemImpl.SetxattrAt.
func (fs *filesystem) SetxattrAt(ctx context.Context, rp *vfs2.ResolvingPath, opts vfs2.SetxattrOptions) error {
	// FIXME
	return syserror.EPERM
}

// RemovexattrAt implements vfs2.FilesystemImpl.RemovexattrAt.
func (fs *filesystem) RemovexattrAt(ctx context.Context, rp *vfs2.ResolvingPath, name string) error {
	// FIXME
	return syserror.EPERM
}

// PrependPath implements vfs2.FilesystemImpl.PrependPath.
func (fs *filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs2.VirtualDentry, b *fspath.Builder) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return vfs2.GenericPrependPath(vfsroot, vd, b)
}
