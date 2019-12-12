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

// This file implements vfs.FilesystemImpl for kernfs.

package kernfs

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// stepExistingLocked resolves rp.Component() in parent directory vfsd.
//
// stepExistingLocked is loosely analogous to fs/namei.c:walk_component().
//
// Preconditions: Filesystem.mu must be locked for at least reading. !rp.Done().
//
// Postcondition: Caller must call fs.processDeferredDecRefs*.
func (fs *Filesystem) stepExistingLocked(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry) (*vfs.Dentry, error) {
	d := vfsd.Impl().(*Dentry)
	if !d.isDir() {
		return nil, syserror.ENOTDIR
	}
	// Directory searchable?
	if err := d.inode.CheckPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, err
	}
afterSymlink:
	d.dirMu.Lock()
	nextVFSD, err := rp.ResolveComponent(vfsd)
	d.dirMu.Unlock()
	if err != nil {
		return nil, err
	}
	if nextVFSD != nil {
		// Cached dentry exists, revalidate.
		next := nextVFSD.Impl().(*Dentry)
		if !next.inode.Valid(ctx) {
			d.dirMu.Lock()
			rp.VirtualFilesystem().ForceDeleteDentry(nextVFSD)
			d.dirMu.Unlock()
			fs.deferDecRef(nextVFSD) // Reference from Lookup.
			nextVFSD = nil
		}
	}
	if nextVFSD == nil {
		// Dentry isn't cached; it either doesn't exist or failed
		// revalidation. Attempt to resolve it via Lookup.
		name := rp.Component()
		var err error
		nextVFSD, err = d.inode.Lookup(ctx, name)
		// Reference on nextVFSD dropped by a corresponding Valid.
		if err != nil {
			return nil, err
		}
		d.InsertChild(name, nextVFSD)
	}
	next := nextVFSD.Impl().(*Dentry)

	// Resolve any symlink at current path component.
	if rp.ShouldFollowSymlink() && d.isSymlink() {
		target, err := next.inode.Readlink(ctx)
		switch err {
		case nil:
			if err := rp.HandleSymlink(target); err != nil {
				return nil, err
			}
			goto afterSymlink
		case ErrResolveViaGetlink:
			targetVD, err := next.inode.Getlink(ctx)
			if err != nil {
				return nil, err
			}
			if err := rp.HandleJump(targetVD); err != nil {
				return nil, err
			}
			goto afterSymlink
		default:
			return nil, err
		}
	}
	rp.Advance()
	return nextVFSD, nil
}

// walkExistingLocked resolves rp to an existing file.
//
// walkExistingLocked is loosely analogous to Linux's
// fs/namei.c:path_lookupat().
//
// Preconditions: Filesystem.mu must be locked for at least reading.
//
// Postconditions: Caller must call fs.processDeferredDecRefs*.
func (fs *Filesystem) walkExistingLocked(ctx context.Context, rp *vfs.ResolvingPath) (*vfs.Dentry, Inode, error) {
	vfsd := rp.Start()
	for !rp.Done() {
		var err error
		vfsd, err = fs.stepExistingLocked(ctx, rp, vfsd)
		if err != nil {
			return nil, nil, err
		}
	}
	d := vfsd.Impl().(*Dentry)
	if rp.MustBeDir() && !d.isDir() {
		return nil, nil, syserror.ENOTDIR
	}
	return vfsd, d.inode, nil
}

// walkParentDirLocked resolves all but the last path component of rp to an
// existing directory. It does not check that the returned directory is
// searchable by the provider of rp.
//
// walkParentDirLocked is loosely analogous to Linux's
// fs/namei.c:path_parentat().
//
// Preconditions: Filesystem.mu must be locked for at least reading. !rp.Done().
//
// Postconditions: Caller must call fs.processDeferredDecRefs*.
func (fs *Filesystem) walkParentDirLocked(ctx context.Context, rp *vfs.ResolvingPath) (*vfs.Dentry, Inode, error) {
	vfsd := rp.Start()
	for !rp.Final() {
		var err error
		vfsd, err = fs.stepExistingLocked(ctx, rp, vfsd)
		if err != nil {
			return nil, nil, err
		}
	}
	d := vfsd.Impl().(*Dentry)
	if !d.isDir() {
		return nil, nil, syserror.ENOTDIR
	}
	return vfsd, d.inode, nil
}

// checkCreateLocked checks that a file named rp.Component() may be created in
// directory parentVFSD, then returns rp.Component().
//
// Preconditions: Filesystem.mu must be locked for at least reading. parentInode
// == parentVFSD.Impl().(*Dentry).Inode. isDir(parentInode) == true.
func checkCreateLocked(rp *vfs.ResolvingPath, parentVFSD *vfs.Dentry, parentInode Inode) (string, error) {
	if err := parentInode.CheckPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
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
//
// Preconditions: Filesystem.mu must be locked for at least reading.
func checkDeleteLocked(rp *vfs.ResolvingPath, vfsd *vfs.Dentry) error {
	parentVFSD := vfsd.Parent()
	if parentVFSD == nil {
		return syserror.EBUSY
	}
	if parentVFSD.IsDisowned() {
		return syserror.ENOENT
	}
	if err := parentVFSD.Impl().(*Dentry).inode.CheckPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	return nil
}

// checkRenameLocked checks that a rename operation may be performed on the
// target dentry across the given set of parent directories. The target dentry
// may be nil.
//
// Precondition: isDir(dstInode) == true.
func checkRenameLocked(creds *auth.Credentials, src, dstDir *vfs.Dentry, dstInode Inode) error {
	srcDir := src.Parent()
	if srcDir == nil {
		return syserror.EBUSY
	}
	if srcDir.IsDisowned() {
		return syserror.ENOENT
	}
	if dstDir.IsDisowned() {
		return syserror.ENOENT
	}
	// Check for creation permissions on dst dir.
	if err := dstInode.CheckPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return err
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
	defer fs.processDeferredDecRefs()
	defer fs.mu.RUnlock()
	vfsd, inode, err := fs.walkExistingLocked(ctx, rp)
	if err != nil {
		return nil, err
	}

	if opts.CheckSearchable {
		d := vfsd.Impl().(*Dentry)
		if !d.isDir() {
			return nil, syserror.ENOTDIR
		}
		if err := inode.CheckPermissions(rp.Credentials(), vfs.MayExec); err != nil {
			return nil, err
		}
	}
	vfsd.IncRef() // Ownership transferred to caller.
	return vfsd, nil
}

// LinkAt implements vfs.FilesystemImpl.LinkAt.
func (fs *Filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	if rp.Done() {
		return syserror.EEXIST
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parentVFSD, parentInode, err := fs.walkParentDirLocked(ctx, rp)
	fs.processDeferredDecRefsLocked()
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
	if d.isDir() {
		return syserror.EPERM
	}

	child, err := parentInode.NewLink(ctx, pc, d.inode)
	if err != nil {
		return err
	}
	parentVFSD.Impl().(*Dentry).InsertChild(pc, child)
	return nil
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *Filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	if rp.Done() {
		return syserror.EEXIST
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parentVFSD, parentInode, err := fs.walkParentDirLocked(ctx, rp)
	fs.processDeferredDecRefsLocked()
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
	child, err := parentInode.NewDir(ctx, pc, opts)
	if err != nil {
		return err
	}
	parentVFSD.Impl().(*Dentry).InsertChild(pc, child)
	return nil
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *Filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	if rp.Done() {
		return syserror.EEXIST
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parentVFSD, parentInode, err := fs.walkParentDirLocked(ctx, rp)
	fs.processDeferredDecRefsLocked()
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
	new, err := parentInode.NewNode(ctx, pc, opts)
	if err != nil {
		return err
	}
	parentVFSD.Impl().(*Dentry).InsertChild(pc, new)
	return nil
}

// OpenAt implements vfs.FilesystemImpl.OpenAt.
func (fs *Filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	// Filter out flags that are not supported by kernfs. O_DIRECTORY and
	// O_NOFOLLOW have no effect here (they're handled by VFS by setting
	// appropriate bits in rp), but are returned by
	// FileDescriptionImpl.StatusFlags().
	opts.Flags &= linux.O_ACCMODE | linux.O_CREAT | linux.O_EXCL | linux.O_TRUNC | linux.O_DIRECTORY | linux.O_NOFOLLOW
	ats := vfs.AccessTypesForOpenFlags(opts.Flags)

	// Do not create new file.
	if opts.Flags&linux.O_CREAT == 0 {
		fs.mu.RLock()
		defer fs.processDeferredDecRefs()
		defer fs.mu.RUnlock()
		vfsd, inode, err := fs.walkExistingLocked(ctx, rp)
		if err != nil {
			return nil, err
		}
		if err := inode.CheckPermissions(rp.Credentials(), ats); err != nil {
			return nil, err
		}
		return inode.Open(rp, vfsd, opts.Flags)
	}

	// May create new file.
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
		if err := inode.CheckPermissions(rp.Credentials(), ats); err != nil {
			return nil, err
		}
		return inode.Open(rp, vfsd, opts.Flags)
	}
afterTrailingSymlink:
	parentVFSD, parentInode, err := fs.walkParentDirLocked(ctx, rp)
	fs.processDeferredDecRefsLocked()
	if err != nil {
		return nil, err
	}
	// Check for search permission in the parent directory.
	if err := parentInode.CheckPermissions(rp.Credentials(), vfs.MayExec); err != nil {
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
	childVFSD, err := rp.ResolveChild(parentVFSD, pc)
	if err != nil {
		return nil, err
	}
	if childVFSD == nil {
		// Already checked for searchability above; now check for writability.
		if err := parentInode.CheckPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
			return nil, err
		}
		if err := rp.Mount().CheckBeginWrite(); err != nil {
			return nil, err
		}
		defer rp.Mount().EndWrite()
		// Create and open the child.
		child, err := parentInode.NewFile(ctx, pc, opts)
		if err != nil {
			return nil, err
		}
		parentVFSD.Impl().(*Dentry).InsertChild(pc, child)
		return child.Impl().(*Dentry).inode.Open(rp, child, opts.Flags)
	}
	// Open existing file or follow symlink.
	if mustCreate {
		return nil, syserror.EEXIST
	}
	childDentry := childVFSD.Impl().(*Dentry)
	childInode := childDentry.inode
	if rp.ShouldFollowSymlink() {
		if childDentry.isSymlink() {
			target, err := childInode.Readlink(ctx)
			if err != nil {
				return nil, err
			}
			if err := rp.HandleSymlink(target); err != nil {
				return nil, err
			}
			// rp.Final() may no longer be true since we now need to resolve the
			// symlink target.
			goto afterTrailingSymlink
		}
	}
	if err := childInode.CheckPermissions(rp.Credentials(), ats); err != nil {
		return nil, err
	}
	return childInode.Open(rp, childVFSD, opts.Flags)
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *Filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	fs.mu.RLock()
	d, inode, err := fs.walkExistingLocked(ctx, rp)
	fs.mu.RUnlock()
	fs.processDeferredDecRefs()
	if err != nil {
		return "", err
	}
	if !d.Impl().(*Dentry).isSymlink() {
		return "", syserror.EINVAL
	}
	target, err := inode.Readlink(ctx)
	if err == ErrResolveViaGetlink {
		// We won't be traversing to the target, so no need to handle this.
		err = nil
	}
	return target, err
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *Filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry, opts vfs.RenameOptions) error {
	noReplace := opts.Flags&linux.RENAME_NOREPLACE != 0
	exchange := opts.Flags&linux.RENAME_EXCHANGE != 0
	whiteout := opts.Flags&linux.RENAME_WHITEOUT != 0
	if exchange && (noReplace || whiteout) {
		// Can't specify RENAME_NOREPLACE or RENAME_WHITEOUT with RENAME_EXCHANGE.
		return syserror.EINVAL
	}
	if exchange || whiteout {
		// Exchange and Whiteout flags are not supported on kernfs.
		return syserror.EINVAL
	}

	fs.mu.Lock()
	defer fs.mu.Lock()

	mnt := rp.Mount()
	if mnt != vd.Mount() {
		return syserror.EXDEV
	}

	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()

	dstDirVFSD, dstDirInode, err := fs.walkParentDirLocked(ctx, rp)
	fs.processDeferredDecRefsLocked()
	if err != nil {
		return err
	}

	srcVFSD := vd.Dentry()
	srcDirVFSD := srcVFSD.Parent()

	// Can we remove the src dentry?
	if err := checkDeleteLocked(rp, srcVFSD); err != nil {
		return err
	}

	// Can we create the dst dentry?
	var dstVFSD *vfs.Dentry
	pc, err := checkCreateLocked(rp, dstDirVFSD, dstDirInode)
	switch err {
	case nil:
		// Ok, continue with rename as replacement.
	case syserror.EEXIST:
		if noReplace {
			// Won't overwrite existing node since RENAME_NOREPLACE was requested.
			return syserror.EEXIST
		}
		dstVFSD, err = rp.ResolveChild(dstDirVFSD, pc)
		if err != nil {
			panic(fmt.Sprintf("Child %q for parent Dentry %+v disappeared inside atomic section?", pc, dstDirVFSD))
		}
	default:
		return err
	}

	mntns := vfs.MountNamespaceFromContext(ctx)
	virtfs := rp.VirtualFilesystem()

	srcDirDentry := srcDirVFSD.Impl().(*Dentry)
	dstDirDentry := dstDirVFSD.Impl().(*Dentry)

	// We can't deadlock here due to lock ordering because we're protected from
	// concurrent renames by fs.mu held for writing.
	srcDirDentry.dirMu.Lock()
	defer srcDirDentry.dirMu.Unlock()
	dstDirDentry.dirMu.Lock()
	defer dstDirDentry.dirMu.Unlock()

	if err := virtfs.PrepareRenameDentry(mntns, srcVFSD, dstVFSD); err != nil {
		return err
	}
	srcDirInode := srcDirDentry.inode
	replaced, err := srcDirInode.Rename(ctx, srcVFSD.Name(), pc, srcVFSD, dstDirVFSD)
	if err != nil {
		virtfs.AbortRenameDentry(srcVFSD, dstVFSD)
		return err
	}
	virtfs.CommitRenameReplaceDentry(srcVFSD, dstDirVFSD, pc, replaced)
	return nil
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *Filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	vfsd, inode, err := fs.walkExistingLocked(ctx, rp)
	fs.processDeferredDecRefsLocked()
	if err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	if err := checkDeleteLocked(rp, vfsd); err != nil {
		return err
	}
	if !vfsd.Impl().(*Dentry).isDir() {
		return syserror.ENOTDIR
	}
	if inode.HasChildren() {
		return syserror.ENOTEMPTY
	}
	virtfs := rp.VirtualFilesystem()
	parentDentry := vfsd.Parent().Impl().(*Dentry)
	parentDentry.dirMu.Lock()
	defer parentDentry.dirMu.Unlock()
	if err := virtfs.PrepareDeleteDentry(vfs.MountNamespaceFromContext(ctx), vfsd); err != nil {
		return err
	}
	if err := parentDentry.inode.RmDir(ctx, rp.Component(), vfsd); err != nil {
		virtfs.AbortDeleteDentry(vfsd)
		return err
	}
	virtfs.CommitDeleteDentry(vfsd)
	return nil
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *Filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	fs.mu.RLock()
	_, inode, err := fs.walkExistingLocked(ctx, rp)
	fs.mu.RUnlock()
	fs.processDeferredDecRefs()
	if err != nil {
		return err
	}
	if opts.Stat.Mask == 0 {
		return nil
	}
	return inode.SetStat(fs.VFSFilesystem(), opts)
}

// StatAt implements vfs.FilesystemImpl.StatAt.
func (fs *Filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	fs.mu.RLock()
	_, inode, err := fs.walkExistingLocked(ctx, rp)
	fs.mu.RUnlock()
	fs.processDeferredDecRefs()
	if err != nil {
		return linux.Statx{}, err
	}
	return inode.Stat(fs.VFSFilesystem()), nil
}

// StatFSAt implements vfs.FilesystemImpl.StatFSAt.
func (fs *Filesystem) StatFSAt(ctx context.Context, rp *vfs.ResolvingPath) (linux.Statfs, error) {
	fs.mu.RLock()
	_, _, err := fs.walkExistingLocked(ctx, rp)
	fs.mu.RUnlock()
	fs.processDeferredDecRefs()
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
	parentVFSD, parentInode, err := fs.walkParentDirLocked(ctx, rp)
	fs.processDeferredDecRefsLocked()
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
	child, err := parentInode.NewSymlink(ctx, pc, target)
	if err != nil {
		return err
	}
	parentVFSD.Impl().(*Dentry).InsertChild(pc, child)
	return nil
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *Filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	vfsd, _, err := fs.walkExistingLocked(ctx, rp)
	fs.processDeferredDecRefsLocked()
	if err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	if err := checkDeleteLocked(rp, vfsd); err != nil {
		return err
	}
	if vfsd.Impl().(*Dentry).isDir() {
		return syserror.EISDIR
	}
	virtfs := rp.VirtualFilesystem()
	parentDentry := vfsd.Parent().Impl().(*Dentry)
	parentDentry.dirMu.Lock()
	defer parentDentry.dirMu.Unlock()
	if err := virtfs.PrepareDeleteDentry(vfs.MountNamespaceFromContext(ctx), vfsd); err != nil {
		return err
	}
	if err := parentDentry.inode.Unlink(ctx, rp.Component(), vfsd); err != nil {
		virtfs.AbortDeleteDentry(vfsd)
		return err
	}
	virtfs.CommitDeleteDentry(vfsd)
	return nil
}

// PrependPath implements vfs.FilesystemImpl.PrependPath.
func (fs *Filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return vfs.GenericPrependPath(vfsroot, vd, b)
}
