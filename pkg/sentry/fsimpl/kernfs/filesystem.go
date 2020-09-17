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

package kernfs

// This file implements vfs.FilesystemImpl for kernfs.

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// stepExistingLocked resolves rp.Component() in parent directory vfsd.
//
// stepExistingLocked is loosely analogous to fs/namei.c:walk_component().
//
// Preconditions:
// * Filesystem.mu must be locked for at least reading.
// * !rp.Done().
//
// Postcondition: Caller must call fs.processDeferredDecRefs*.
func (fs *Filesystem) stepExistingLocked(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, mayFollowSymlinks bool) (*vfs.Dentry, error) {
	d := vfsd.Impl().(*Dentry)
	if !d.isDir() {
		return nil, syserror.ENOTDIR
	}
	// Directory searchable?
	if err := d.inode.CheckPermissions(ctx, rp.Credentials(), vfs.MayExec); err != nil {
		return nil, err
	}
afterSymlink:
	name := rp.Component()
	// Revalidation must be skipped if name is "." or ".."; d or its parent
	// respectively can't be expected to transition from invalidated back to
	// valid, so detecting invalidation and retrying would loop forever. This
	// is consistent with Linux: fs/namei.c:walk_component() => lookup_fast()
	// calls d_revalidate(), but walk_component() => handle_dots() does not.
	if name == "." {
		rp.Advance()
		return vfsd, nil
	}
	if name == ".." {
		if isRoot, err := rp.CheckRoot(ctx, vfsd); err != nil {
			return nil, err
		} else if isRoot || d.parent == nil {
			rp.Advance()
			return vfsd, nil
		}
		if err := rp.CheckMount(ctx, &d.parent.vfsd); err != nil {
			return nil, err
		}
		rp.Advance()
		return &d.parent.vfsd, nil
	}
	if len(name) > linux.NAME_MAX {
		return nil, syserror.ENAMETOOLONG
	}
	d.dirMu.Lock()
	next, err := fs.revalidateChildLocked(ctx, rp.VirtualFilesystem(), d, name, d.children[name])
	d.dirMu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := rp.CheckMount(ctx, &next.vfsd); err != nil {
		return nil, err
	}
	// Resolve any symlink at current path component.
	if mayFollowSymlinks && rp.ShouldFollowSymlink() && next.isSymlink() {
		targetVD, targetPathname, err := next.inode.Getlink(ctx, rp.Mount())
		if err != nil {
			return nil, err
		}
		if targetVD.Ok() {
			err := rp.HandleJump(targetVD)
			targetVD.DecRef(ctx)
			if err != nil {
				return nil, err
			}
		} else {
			if err := rp.HandleSymlink(targetPathname); err != nil {
				return nil, err
			}
		}
		goto afterSymlink
	}
	rp.Advance()
	return &next.vfsd, nil
}

// revalidateChildLocked must be called after a call to parent.vfsd.Child(name)
// or vfs.ResolvingPath.ResolveChild(name) returns childVFSD (which may be
// nil) to verify that the returned child (or lack thereof) is correct.
//
// Preconditions:
// * Filesystem.mu must be locked for at least reading.
// * parent.dirMu must be locked.
// * parent.isDir().
// * name is not "." or "..".
//
// Postconditions: Caller must call fs.processDeferredDecRefs*.
func (fs *Filesystem) revalidateChildLocked(ctx context.Context, vfsObj *vfs.VirtualFilesystem, parent *Dentry, name string, child *Dentry) (*Dentry, error) {
	if child != nil {
		// Cached dentry exists, revalidate.
		if !child.inode.Valid(ctx) {
			delete(parent.children, name)
			vfsObj.InvalidateDentry(ctx, &child.vfsd)
			fs.deferDecRef(&child.vfsd) // Reference from Lookup.
			child = nil
		}
	}
	if child == nil {
		// Dentry isn't cached; it either doesn't exist or failed
		// revalidation. Attempt to resolve it via Lookup.
		//
		// FIXME(gvisor.dev/issue/1193): Inode.Lookup() should return
		// *(kernfs.)Dentry, not *vfs.Dentry, since (kernfs.)Filesystem assumes
		// that all dentries in the filesystem are (kernfs.)Dentry and performs
		// vfs.DentryImpl casts accordingly.
		childVFSD, err := parent.inode.Lookup(ctx, name)
		if err != nil {
			return nil, err
		}
		// Reference on childVFSD dropped by a corresponding Valid.
		child = childVFSD.Impl().(*Dentry)
		parent.InsertChildLocked(name, child)
	}
	return child, nil
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
		vfsd, err = fs.stepExistingLocked(ctx, rp, vfsd, true /* mayFollowSymlinks */)
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
// Preconditions:
// * Filesystem.mu must be locked for at least reading.
// * !rp.Done().
//
// Postconditions: Caller must call fs.processDeferredDecRefs*.
func (fs *Filesystem) walkParentDirLocked(ctx context.Context, rp *vfs.ResolvingPath) (*vfs.Dentry, Inode, error) {
	vfsd := rp.Start()
	for !rp.Final() {
		var err error
		vfsd, err = fs.stepExistingLocked(ctx, rp, vfsd, true /* mayFollowSymlinks */)
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
// Preconditions:
// * Filesystem.mu must be locked for at least reading.
// * parentInode == parentVFSD.Impl().(*Dentry).Inode.
// * isDir(parentInode) == true.
func checkCreateLocked(ctx context.Context, rp *vfs.ResolvingPath, parentVFSD *vfs.Dentry, parentInode Inode) (string, error) {
	if err := parentInode.CheckPermissions(ctx, rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return "", err
	}
	pc := rp.Component()
	if pc == "." || pc == ".." {
		return "", syserror.EEXIST
	}
	if len(pc) > linux.NAME_MAX {
		return "", syserror.ENAMETOOLONG
	}
	// FIXME(gvisor.dev/issue/1193): Data race due to not holding dirMu.
	if _, ok := parentVFSD.Impl().(*Dentry).children[pc]; ok {
		return "", syserror.EEXIST
	}
	if parentVFSD.IsDead() {
		return "", syserror.ENOENT
	}
	return pc, nil
}

// checkDeleteLocked checks that the file represented by vfsd may be deleted.
//
// Preconditions: Filesystem.mu must be locked for at least reading.
func checkDeleteLocked(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry) error {
	parent := vfsd.Impl().(*Dentry).parent
	if parent == nil {
		return syserror.EBUSY
	}
	if parent.vfsd.IsDead() {
		return syserror.ENOENT
	}
	if err := parent.inode.CheckPermissions(ctx, rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	return nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *Filesystem) Release(context.Context) {
}

// Sync implements vfs.FilesystemImpl.Sync.
func (fs *Filesystem) Sync(ctx context.Context) error {
	// All filesystem state is in-memory.
	return nil
}

// AccessAt implements vfs.Filesystem.Impl.AccessAt.
func (fs *Filesystem) AccessAt(ctx context.Context, rp *vfs.ResolvingPath, creds *auth.Credentials, ats vfs.AccessTypes) error {
	fs.mu.RLock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.RUnlock()

	_, inode, err := fs.walkExistingLocked(ctx, rp)
	if err != nil {
		return err
	}
	return inode.CheckPermissions(ctx, creds, ats)
}

// GetDentryAt implements vfs.FilesystemImpl.GetDentryAt.
func (fs *Filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	fs.mu.RLock()
	defer fs.processDeferredDecRefs(ctx)
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
		if err := inode.CheckPermissions(ctx, rp.Credentials(), vfs.MayExec); err != nil {
			return nil, err
		}
	}
	vfsd.IncRef() // Ownership transferred to caller.
	return vfsd, nil
}

// GetParentDentryAt implements vfs.FilesystemImpl.GetParentDentryAt.
func (fs *Filesystem) GetParentDentryAt(ctx context.Context, rp *vfs.ResolvingPath) (*vfs.Dentry, error) {
	fs.mu.RLock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.RUnlock()
	vfsd, _, err := fs.walkParentDirLocked(ctx, rp)
	if err != nil {
		return nil, err
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
	fs.processDeferredDecRefsLocked(ctx)
	if err != nil {
		return err
	}
	pc, err := checkCreateLocked(ctx, rp, parentVFSD, parentInode)
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

	childVFSD, err := parentInode.NewLink(ctx, pc, d.inode)
	if err != nil {
		return err
	}
	parentVFSD.Impl().(*Dentry).InsertChild(pc, childVFSD.Impl().(*Dentry))
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
	fs.processDeferredDecRefsLocked(ctx)
	if err != nil {
		return err
	}
	pc, err := checkCreateLocked(ctx, rp, parentVFSD, parentInode)
	if err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	childVFSD, err := parentInode.NewDir(ctx, pc, opts)
	if err != nil {
		if !opts.ForSyntheticMountpoint || err == syserror.EEXIST {
			return err
		}
		childVFSD = newSyntheticDirectory(rp.Credentials(), opts.Mode)
	}
	parentVFSD.Impl().(*Dentry).InsertChild(pc, childVFSD.Impl().(*Dentry))
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
	fs.processDeferredDecRefsLocked(ctx)
	if err != nil {
		return err
	}
	pc, err := checkCreateLocked(ctx, rp, parentVFSD, parentInode)
	if err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	newVFSD, err := parentInode.NewNode(ctx, pc, opts)
	if err != nil {
		return err
	}
	parentVFSD.Impl().(*Dentry).InsertChild(pc, newVFSD.Impl().(*Dentry))
	return nil
}

// OpenAt implements vfs.FilesystemImpl.OpenAt.
func (fs *Filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	// Filter out flags that are not supported by kernfs. O_DIRECTORY and
	// O_NOFOLLOW have no effect here (they're handled by VFS by setting
	// appropriate bits in rp), but are returned by
	// FileDescriptionImpl.StatusFlags().
	opts.Flags &= linux.O_ACCMODE | linux.O_CREAT | linux.O_EXCL | linux.O_TRUNC | linux.O_DIRECTORY | linux.O_NOFOLLOW | linux.O_NONBLOCK
	ats := vfs.AccessTypesForOpenFlags(&opts)

	// Do not create new file.
	if opts.Flags&linux.O_CREAT == 0 {
		fs.mu.RLock()
		vfsd, inode, err := fs.walkExistingLocked(ctx, rp)
		if err != nil {
			fs.mu.RUnlock()
			fs.processDeferredDecRefs(ctx)
			return nil, err
		}
		if err := inode.CheckPermissions(ctx, rp.Credentials(), ats); err != nil {
			fs.mu.RUnlock()
			fs.processDeferredDecRefs(ctx)
			return nil, err
		}
		inode.IncRef()
		defer inode.DecRef(ctx)
		fs.mu.RUnlock()
		fs.processDeferredDecRefs(ctx)
		return inode.Open(ctx, rp, vfsd, opts)
	}

	// May create new file.
	mustCreate := opts.Flags&linux.O_EXCL != 0
	vfsd := rp.Start()
	inode := vfsd.Impl().(*Dentry).inode
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
		if rp.MustBeDir() {
			return nil, syserror.EISDIR
		}
		if mustCreate {
			return nil, syserror.EEXIST
		}
		if err := inode.CheckPermissions(ctx, rp.Credentials(), ats); err != nil {
			return nil, err
		}
		inode.IncRef()
		defer inode.DecRef(ctx)
		unlock()
		return inode.Open(ctx, rp, vfsd, opts)
	}
afterTrailingSymlink:
	parentVFSD, parentInode, err := fs.walkParentDirLocked(ctx, rp)
	fs.processDeferredDecRefsLocked(ctx)
	if err != nil {
		return nil, err
	}
	// Check for search permission in the parent directory.
	if err := parentInode.CheckPermissions(ctx, rp.Credentials(), vfs.MayExec); err != nil {
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
	if len(pc) > linux.NAME_MAX {
		return nil, syserror.ENAMETOOLONG
	}
	// Determine whether or not we need to create a file.
	childVFSD, err := fs.stepExistingLocked(ctx, rp, parentVFSD, false /* mayFollowSymlinks */)
	if err == syserror.ENOENT {
		// Already checked for searchability above; now check for writability.
		if err := parentInode.CheckPermissions(ctx, rp.Credentials(), vfs.MayWrite); err != nil {
			return nil, err
		}
		if err := rp.Mount().CheckBeginWrite(); err != nil {
			return nil, err
		}
		defer rp.Mount().EndWrite()
		// Create and open the child.
		childVFSD, err = parentInode.NewFile(ctx, pc, opts)
		if err != nil {
			return nil, err
		}
		child := childVFSD.Impl().(*Dentry)
		parentVFSD.Impl().(*Dentry).InsertChild(pc, child)
		child.inode.IncRef()
		defer child.inode.DecRef(ctx)
		unlock()
		return child.inode.Open(ctx, rp, childVFSD, opts)
	}
	if err != nil {
		return nil, err
	}
	// Open existing file or follow symlink.
	if mustCreate {
		return nil, syserror.EEXIST
	}
	child := childVFSD.Impl().(*Dentry)
	if rp.ShouldFollowSymlink() && child.isSymlink() {
		targetVD, targetPathname, err := child.inode.Getlink(ctx, rp.Mount())
		if err != nil {
			return nil, err
		}
		if targetVD.Ok() {
			err := rp.HandleJump(targetVD)
			targetVD.DecRef(ctx)
			if err != nil {
				return nil, err
			}
		} else {
			if err := rp.HandleSymlink(targetPathname); err != nil {
				return nil, err
			}
		}
		// rp.Final() may no longer be true since we now need to resolve the
		// symlink target.
		goto afterTrailingSymlink
	}
	if err := child.inode.CheckPermissions(ctx, rp.Credentials(), ats); err != nil {
		return nil, err
	}
	child.inode.IncRef()
	defer child.inode.DecRef(ctx)
	unlock()
	return child.inode.Open(ctx, rp, &child.vfsd, opts)
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *Filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	fs.mu.RLock()
	d, inode, err := fs.walkExistingLocked(ctx, rp)
	fs.mu.RUnlock()
	fs.processDeferredDecRefs(ctx)
	if err != nil {
		return "", err
	}
	if !d.Impl().(*Dentry).isSymlink() {
		return "", syserror.EINVAL
	}
	return inode.Readlink(ctx, rp.Mount())
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *Filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, oldParentVD vfs.VirtualDentry, oldName string, opts vfs.RenameOptions) error {
	// Only RENAME_NOREPLACE is supported.
	if opts.Flags&^linux.RENAME_NOREPLACE != 0 {
		return syserror.EINVAL
	}
	noReplace := opts.Flags&linux.RENAME_NOREPLACE != 0

	fs.mu.Lock()
	defer fs.processDeferredDecRefsLocked(ctx)
	defer fs.mu.Unlock()

	// Resolve the destination directory first to verify that it's on this
	// Mount.
	dstDirVFSD, dstDirInode, err := fs.walkParentDirLocked(ctx, rp)
	if err != nil {
		return err
	}
	dstDir := dstDirVFSD.Impl().(*Dentry)
	mnt := rp.Mount()
	if mnt != oldParentVD.Mount() {
		return syserror.EXDEV
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()

	srcDirVFSD := oldParentVD.Dentry()
	srcDir := srcDirVFSD.Impl().(*Dentry)
	srcDir.dirMu.Lock()
	src, err := fs.revalidateChildLocked(ctx, rp.VirtualFilesystem(), srcDir, oldName, srcDir.children[oldName])
	srcDir.dirMu.Unlock()
	if err != nil {
		return err
	}
	srcVFSD := &src.vfsd

	// Can we remove the src dentry?
	if err := checkDeleteLocked(ctx, rp, srcVFSD); err != nil {
		return err
	}

	// Can we create the dst dentry?
	var dst *Dentry
	pc, err := checkCreateLocked(ctx, rp, dstDirVFSD, dstDirInode)
	switch err {
	case nil:
		// Ok, continue with rename as replacement.
	case syserror.EEXIST:
		if noReplace {
			// Won't overwrite existing node since RENAME_NOREPLACE was requested.
			return syserror.EEXIST
		}
		dst = dstDir.children[pc]
		if dst == nil {
			panic(fmt.Sprintf("Child %q for parent Dentry %+v disappeared inside atomic section?", pc, dstDirVFSD))
		}
	default:
		return err
	}
	var dstVFSD *vfs.Dentry
	if dst != nil {
		dstVFSD = &dst.vfsd
	}

	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	virtfs := rp.VirtualFilesystem()

	// We can't deadlock here due to lock ordering because we're protected from
	// concurrent renames by fs.mu held for writing.
	srcDir.dirMu.Lock()
	defer srcDir.dirMu.Unlock()
	if srcDir != dstDir {
		dstDir.dirMu.Lock()
		defer dstDir.dirMu.Unlock()
	}

	if err := virtfs.PrepareRenameDentry(mntns, srcVFSD, dstVFSD); err != nil {
		return err
	}
	replaced, err := srcDir.inode.Rename(ctx, src.name, pc, srcVFSD, dstDirVFSD)
	if err != nil {
		virtfs.AbortRenameDentry(srcVFSD, dstVFSD)
		return err
	}
	delete(srcDir.children, src.name)
	if srcDir != dstDir {
		fs.deferDecRef(srcDirVFSD)
		dstDir.IncRef()
	}
	src.parent = dstDir
	src.name = pc
	if dstDir.children == nil {
		dstDir.children = make(map[string]*Dentry)
	}
	dstDir.children[pc] = src
	virtfs.CommitRenameReplaceDentry(ctx, srcVFSD, replaced)
	return nil
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *Filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Store the name before walkExistingLocked as rp will be advanced past the
	// name in the following call.
	name := rp.Component()
	vfsd, inode, err := fs.walkExistingLocked(ctx, rp)
	fs.processDeferredDecRefsLocked(ctx)
	if err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	if err := checkDeleteLocked(ctx, rp, vfsd); err != nil {
		return err
	}
	d := vfsd.Impl().(*Dentry)
	if !d.isDir() {
		return syserror.ENOTDIR
	}
	if inode.HasChildren() {
		return syserror.ENOTEMPTY
	}
	virtfs := rp.VirtualFilesystem()
	parentDentry := d.parent
	parentDentry.dirMu.Lock()
	defer parentDentry.dirMu.Unlock()

	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	if err := virtfs.PrepareDeleteDentry(mntns, vfsd); err != nil {
		return err
	}

	if err := parentDentry.inode.RmDir(ctx, name, vfsd); err != nil {
		virtfs.AbortDeleteDentry(vfsd)
		return err
	}
	virtfs.CommitDeleteDentry(ctx, vfsd)
	return nil
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *Filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	fs.mu.RLock()
	_, inode, err := fs.walkExistingLocked(ctx, rp)
	fs.mu.RUnlock()
	fs.processDeferredDecRefs(ctx)
	if err != nil {
		return err
	}
	if opts.Stat.Mask == 0 {
		return nil
	}
	return inode.SetStat(ctx, fs.VFSFilesystem(), rp.Credentials(), opts)
}

// StatAt implements vfs.FilesystemImpl.StatAt.
func (fs *Filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	fs.mu.RLock()
	_, inode, err := fs.walkExistingLocked(ctx, rp)
	fs.mu.RUnlock()
	fs.processDeferredDecRefs(ctx)
	if err != nil {
		return linux.Statx{}, err
	}
	return inode.Stat(ctx, fs.VFSFilesystem(), opts)
}

// StatFSAt implements vfs.FilesystemImpl.StatFSAt.
func (fs *Filesystem) StatFSAt(ctx context.Context, rp *vfs.ResolvingPath) (linux.Statfs, error) {
	fs.mu.RLock()
	_, inode, err := fs.walkExistingLocked(ctx, rp)
	fs.mu.RUnlock()
	fs.processDeferredDecRefs(ctx)
	if err != nil {
		return linux.Statfs{}, err
	}
	return inode.StatFS(ctx, fs.VFSFilesystem())
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt.
func (fs *Filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	if rp.Done() {
		return syserror.EEXIST
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parentVFSD, parentInode, err := fs.walkParentDirLocked(ctx, rp)
	fs.processDeferredDecRefsLocked(ctx)
	if err != nil {
		return err
	}
	pc, err := checkCreateLocked(ctx, rp, parentVFSD, parentInode)
	if err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	childVFSD, err := parentInode.NewSymlink(ctx, pc, target)
	if err != nil {
		return err
	}
	parentVFSD.Impl().(*Dentry).InsertChild(pc, childVFSD.Impl().(*Dentry))
	return nil
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *Filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Store the name before walkExistingLocked as rp will be advanced past the
	// name in the following call.
	name := rp.Component()
	vfsd, _, err := fs.walkExistingLocked(ctx, rp)
	fs.processDeferredDecRefsLocked(ctx)
	if err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	if err := checkDeleteLocked(ctx, rp, vfsd); err != nil {
		return err
	}
	d := vfsd.Impl().(*Dentry)
	if d.isDir() {
		return syserror.EISDIR
	}
	virtfs := rp.VirtualFilesystem()
	parentDentry := d.parent
	parentDentry.dirMu.Lock()
	defer parentDentry.dirMu.Unlock()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	if err := virtfs.PrepareDeleteDentry(mntns, vfsd); err != nil {
		return err
	}
	if err := parentDentry.inode.Unlink(ctx, name, vfsd); err != nil {
		virtfs.AbortDeleteDentry(vfsd)
		return err
	}
	virtfs.CommitDeleteDentry(ctx, vfsd)
	return nil
}

// BoundEndpointAt implements FilesystemImpl.BoundEndpointAt.
func (fs *Filesystem) BoundEndpointAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.BoundEndpointOptions) (transport.BoundEndpoint, error) {
	fs.mu.RLock()
	_, inode, err := fs.walkExistingLocked(ctx, rp)
	fs.mu.RUnlock()
	fs.processDeferredDecRefs(ctx)
	if err != nil {
		return nil, err
	}
	if err := inode.CheckPermissions(ctx, rp.Credentials(), vfs.MayWrite); err != nil {
		return nil, err
	}
	return nil, syserror.ECONNREFUSED
}

// ListXattrAt implements vfs.FilesystemImpl.ListXattrAt.
func (fs *Filesystem) ListXattrAt(ctx context.Context, rp *vfs.ResolvingPath, size uint64) ([]string, error) {
	fs.mu.RLock()
	_, _, err := fs.walkExistingLocked(ctx, rp)
	fs.mu.RUnlock()
	fs.processDeferredDecRefs(ctx)
	if err != nil {
		return nil, err
	}
	// kernfs currently does not support extended attributes.
	return nil, syserror.ENOTSUP
}

// GetXattrAt implements vfs.FilesystemImpl.GetXattrAt.
func (fs *Filesystem) GetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetXattrOptions) (string, error) {
	fs.mu.RLock()
	_, _, err := fs.walkExistingLocked(ctx, rp)
	fs.mu.RUnlock()
	fs.processDeferredDecRefs(ctx)
	if err != nil {
		return "", err
	}
	// kernfs currently does not support extended attributes.
	return "", syserror.ENOTSUP
}

// SetXattrAt implements vfs.FilesystemImpl.SetXattrAt.
func (fs *Filesystem) SetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetXattrOptions) error {
	fs.mu.RLock()
	_, _, err := fs.walkExistingLocked(ctx, rp)
	fs.mu.RUnlock()
	fs.processDeferredDecRefs(ctx)
	if err != nil {
		return err
	}
	// kernfs currently does not support extended attributes.
	return syserror.ENOTSUP
}

// RemoveXattrAt implements vfs.FilesystemImpl.RemoveXattrAt.
func (fs *Filesystem) RemoveXattrAt(ctx context.Context, rp *vfs.ResolvingPath, name string) error {
	fs.mu.RLock()
	_, _, err := fs.walkExistingLocked(ctx, rp)
	fs.mu.RUnlock()
	fs.processDeferredDecRefs(ctx)
	if err != nil {
		return err
	}
	// kernfs currently does not support extended attributes.
	return syserror.ENOTSUP
}

// PrependPath implements vfs.FilesystemImpl.PrependPath.
func (fs *Filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return genericPrependPath(vfsroot, vd.Mount(), vd.Dentry().Impl().(*Dentry), b)
}
