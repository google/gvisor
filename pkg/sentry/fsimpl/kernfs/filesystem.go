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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
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
func (fs *Filesystem) stepExistingLocked(ctx context.Context, rp *vfs.ResolvingPath, d *Dentry, mayFollowSymlinks bool) (*Dentry, error) {
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
		return d, nil
	}
	if name == ".." {
		if isRoot, err := rp.CheckRoot(ctx, d.VFSDentry()); err != nil {
			return nil, err
		} else if isRoot || d.parent == nil {
			rp.Advance()
			return d, nil
		}
		if err := rp.CheckMount(ctx, d.parent.VFSDentry()); err != nil {
			return nil, err
		}
		rp.Advance()
		return d.parent, nil
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
	if err := rp.CheckMount(ctx, next.VFSDentry()); err != nil {
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
			fs.deferDecRefVD(ctx, targetVD)
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
	return next, nil
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
			if child.inode.Keep() {
				// Drop the ref owned by kernfs.
				fs.deferDecRef(child)
			}
			vfsObj.InvalidateDentry(ctx, child.VFSDentry())
			child = nil
		}
	}
	if child == nil {
		// Dentry isn't cached; it either doesn't exist or failed revalidation.
		// Attempt to resolve it via Lookup.
		childInode, err := parent.inode.Lookup(ctx, name)
		if err != nil {
			return nil, err
		}
		var newChild Dentry
		newChild.Init(fs, childInode) // childInode's ref is transferred to newChild.
		parent.insertChildLocked(name, &newChild)
		child = &newChild

		// Drop the ref on newChild. This will cause the dentry to get pruned
		// from the dentry tree by the end of current filesystem operation
		// (before returning to the VFS layer) if another ref is not picked on
		// this dentry.
		if !childInode.Keep() {
			fs.deferDecRef(&newChild)
		}
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
func (fs *Filesystem) walkExistingLocked(ctx context.Context, rp *vfs.ResolvingPath) (*Dentry, error) {
	d := rp.Start().Impl().(*Dentry)
	for !rp.Done() {
		var err error
		d, err = fs.stepExistingLocked(ctx, rp, d, true /* mayFollowSymlinks */)
		if err != nil {
			return nil, err
		}
	}
	if rp.MustBeDir() && !d.isDir() {
		return nil, syserror.ENOTDIR
	}
	return d, nil
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
func (fs *Filesystem) walkParentDirLocked(ctx context.Context, rp *vfs.ResolvingPath) (*Dentry, error) {
	d := rp.Start().Impl().(*Dentry)
	for !rp.Final() {
		var err error
		d, err = fs.stepExistingLocked(ctx, rp, d, true /* mayFollowSymlinks */)
		if err != nil {
			return nil, err
		}
	}
	if !d.isDir() {
		return nil, syserror.ENOTDIR
	}
	return d, nil
}

// checkCreateLocked checks that a file named rp.Component() may be created in
// directory parent, then returns rp.Component().
//
// Preconditions:
// * Filesystem.mu must be locked for at least reading.
// * isDir(parentInode) == true.
func checkCreateLocked(ctx context.Context, creds *auth.Credentials, name string, parent *Dentry) error {
	// Order of checks is important. First check if parent directory can be
	// executed, then check for existence, and lastly check if mount is writable.
	if err := parent.inode.CheckPermissions(ctx, creds, vfs.MayExec); err != nil {
		return err
	}
	if name == "." || name == ".." {
		return syserror.EEXIST
	}
	if len(name) > linux.NAME_MAX {
		return syserror.ENAMETOOLONG
	}
	if _, ok := parent.children[name]; ok {
		return syserror.EEXIST
	}
	if parent.VFSDentry().IsDead() {
		return syserror.ENOENT
	}
	if err := parent.inode.CheckPermissions(ctx, creds, vfs.MayWrite); err != nil {
		return err
	}
	return nil
}

// checkDeleteLocked checks that the file represented by vfsd may be deleted.
//
// Preconditions: Filesystem.mu must be locked for at least reading.
func checkDeleteLocked(ctx context.Context, rp *vfs.ResolvingPath, d *Dentry) error {
	parent := d.parent
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
func (fs *Filesystem) Release(ctx context.Context) {
	root := fs.root
	if root == nil {
		return
	}
	fs.mu.Lock()
	root.releaseKeptDentriesLocked(ctx)
	for fs.cachedDentriesLen != 0 {
		fs.evictCachedDentryLocked(ctx)
	}
	fs.mu.Unlock()
	// Drop ref acquired in Dentry.InitRoot().
	root.DecRef(ctx)
}

// releaseKeptDentriesLocked recursively drops all dentry references created by
// Lookup when Dentry.inode.Keep() is true.
//
// Precondition: Filesystem.mu is held.
func (d *Dentry) releaseKeptDentriesLocked(ctx context.Context) {
	if d.inode.Keep() && d != d.fs.root {
		d.decRefLocked(ctx)
	}

	if d.isDir() {
		var children []*Dentry
		d.dirMu.Lock()
		for _, child := range d.children {
			children = append(children, child)
		}
		d.dirMu.Unlock()
		for _, child := range children {
			child.releaseKeptDentriesLocked(ctx)
		}
	}
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

	d, err := fs.walkExistingLocked(ctx, rp)
	if err != nil {
		return err
	}
	return d.inode.CheckPermissions(ctx, creds, ats)
}

// GetDentryAt implements vfs.FilesystemImpl.GetDentryAt.
func (fs *Filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	fs.mu.RLock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.RUnlock()
	d, err := fs.walkExistingLocked(ctx, rp)
	if err != nil {
		return nil, err
	}

	if opts.CheckSearchable {
		if !d.isDir() {
			return nil, syserror.ENOTDIR
		}
		if err := d.inode.CheckPermissions(ctx, rp.Credentials(), vfs.MayExec); err != nil {
			return nil, err
		}
	}
	vfsd := d.VFSDentry()
	vfsd.IncRef() // Ownership transferred to caller.
	return vfsd, nil
}

// GetParentDentryAt implements vfs.FilesystemImpl.GetParentDentryAt.
func (fs *Filesystem) GetParentDentryAt(ctx context.Context, rp *vfs.ResolvingPath) (*vfs.Dentry, error) {
	fs.mu.RLock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.RUnlock()
	d, err := fs.walkParentDirLocked(ctx, rp)
	if err != nil {
		return nil, err
	}
	d.IncRef() // Ownership transferred to caller.
	return d.VFSDentry(), nil
}

// LinkAt implements vfs.FilesystemImpl.LinkAt.
func (fs *Filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	if rp.Done() {
		return syserror.EEXIST
	}
	fs.mu.Lock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.Unlock()
	parent, err := fs.walkParentDirLocked(ctx, rp)
	if err != nil {
		return err
	}

	parent.dirMu.Lock()
	defer parent.dirMu.Unlock()
	pc := rp.Component()
	if err := checkCreateLocked(ctx, rp.Credentials(), pc, parent); err != nil {
		return err
	}
	if rp.MustBeDir() {
		return syserror.ENOENT
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

	childI, err := parent.inode.NewLink(ctx, pc, d.inode)
	if err != nil {
		return err
	}
	var child Dentry
	child.Init(fs, childI)
	parent.insertChildLocked(pc, &child)
	return nil
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *Filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	if rp.Done() {
		return syserror.EEXIST
	}
	fs.mu.Lock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.Unlock()
	parent, err := fs.walkParentDirLocked(ctx, rp)
	if err != nil {
		return err
	}

	parent.dirMu.Lock()
	defer parent.dirMu.Unlock()
	pc := rp.Component()
	if err := checkCreateLocked(ctx, rp.Credentials(), pc, parent); err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	childI, err := parent.inode.NewDir(ctx, pc, opts)
	if err != nil {
		if !opts.ForSyntheticMountpoint || linuxerr.Equals(linuxerr.EEXIST, err) {
			return err
		}
		childI = newSyntheticDirectory(ctx, rp.Credentials(), opts.Mode)
	}
	var child Dentry
	child.Init(fs, childI)
	parent.insertChildLocked(pc, &child)
	return nil
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *Filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	if rp.Done() {
		return syserror.EEXIST
	}
	fs.mu.Lock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.Unlock()
	parent, err := fs.walkParentDirLocked(ctx, rp)
	if err != nil {
		return err
	}

	parent.dirMu.Lock()
	defer parent.dirMu.Unlock()
	pc := rp.Component()
	if err := checkCreateLocked(ctx, rp.Credentials(), pc, parent); err != nil {
		return err
	}
	if rp.MustBeDir() {
		return syserror.ENOENT
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	newI, err := parent.inode.NewNode(ctx, pc, opts)
	if err != nil {
		return err
	}
	var newD Dentry
	newD.Init(fs, newI)
	parent.insertChildLocked(pc, &newD)
	return nil
}

// OpenAt implements vfs.FilesystemImpl.OpenAt.
func (fs *Filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	// Filter out flags that are not supported by kernfs. O_DIRECTORY and
	// O_NOFOLLOW have no effect here (they're handled by VFS by setting
	// appropriate bits in rp), but are returned by
	// FileDescriptionImpl.StatusFlags().
	opts.Flags &= linux.O_ACCMODE | linux.O_CREAT | linux.O_EXCL | linux.O_TRUNC |
		linux.O_DIRECTORY | linux.O_NOFOLLOW | linux.O_NONBLOCK | linux.O_NOCTTY
	ats := vfs.AccessTypesForOpenFlags(&opts)

	// Do not create new file.
	if opts.Flags&linux.O_CREAT == 0 {
		fs.mu.RLock()
		defer fs.processDeferredDecRefs(ctx)
		d, err := fs.walkExistingLocked(ctx, rp)
		if err != nil {
			fs.mu.RUnlock()
			return nil, err
		}
		if err := d.inode.CheckPermissions(ctx, rp.Credentials(), ats); err != nil {
			fs.mu.RUnlock()
			return nil, err
		}
		// Open may block so we need to unlock fs.mu. IncRef d to prevent
		// its destruction while fs.mu is unlocked.
		d.IncRef()
		fs.mu.RUnlock()
		fd, err := d.inode.Open(ctx, rp, d, opts)
		d.DecRef(ctx)
		return fd, err
	}

	// May create new file.
	mustCreate := opts.Flags&linux.O_EXCL != 0
	d := rp.Start().Impl().(*Dentry)
	fs.mu.Lock()
	unlocked := false
	unlock := func() {
		if !unlocked {
			fs.mu.Unlock()
			unlocked = true
		}
	}
	// Process all to-be-decref'd dentries at the end at once.
	// Since we defer unlock() AFTER this, fs.mu is guaranteed to be unlocked
	// when this is executed.
	defer fs.processDeferredDecRefs(ctx)
	defer unlock()
	if rp.Done() {
		if rp.MustBeDir() {
			return nil, syserror.EISDIR
		}
		if mustCreate {
			return nil, syserror.EEXIST
		}
		if err := d.inode.CheckPermissions(ctx, rp.Credentials(), ats); err != nil {
			return nil, err
		}
		// Open may block so we need to unlock fs.mu. IncRef d to prevent
		// its destruction while fs.mu is unlocked.
		d.IncRef()
		unlock()
		fd, err := d.inode.Open(ctx, rp, d, opts)
		d.DecRef(ctx)
		return fd, err
	}
afterTrailingSymlink:
	parent, err := fs.walkParentDirLocked(ctx, rp)
	if err != nil {
		return nil, err
	}
	// Check for search permission in the parent directory.
	if err := parent.inode.CheckPermissions(ctx, rp.Credentials(), vfs.MayExec); err != nil {
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
	child, err := fs.stepExistingLocked(ctx, rp, parent, false /* mayFollowSymlinks */)
	if linuxerr.Equals(linuxerr.ENOENT, err) {
		// Already checked for searchability above; now check for writability.
		if err := parent.inode.CheckPermissions(ctx, rp.Credentials(), vfs.MayWrite); err != nil {
			return nil, err
		}
		if err := rp.Mount().CheckBeginWrite(); err != nil {
			return nil, err
		}
		defer rp.Mount().EndWrite()
		// Create and open the child.
		childI, err := parent.inode.NewFile(ctx, pc, opts)
		if err != nil {
			return nil, err
		}
		var child Dentry
		child.Init(fs, childI)
		parent.insertChild(pc, &child)
		// Open may block so we need to unlock fs.mu. IncRef child to prevent
		// its destruction while fs.mu is unlocked.
		child.IncRef()
		unlock()
		fd, err := child.inode.Open(ctx, rp, &child, opts)
		child.DecRef(ctx)
		return fd, err
	}
	if err != nil {
		return nil, err
	}
	// Open existing file or follow symlink.
	if mustCreate {
		return nil, syserror.EEXIST
	}
	if rp.ShouldFollowSymlink() && child.isSymlink() {
		targetVD, targetPathname, err := child.inode.Getlink(ctx, rp.Mount())
		if err != nil {
			return nil, err
		}
		if targetVD.Ok() {
			err := rp.HandleJump(targetVD)
			fs.deferDecRefVD(ctx, targetVD)
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
	// Open may block so we need to unlock fs.mu. IncRef child to prevent
	// its destruction while fs.mu is unlocked.
	child.IncRef()
	unlock()
	fd, err := child.inode.Open(ctx, rp, child, opts)
	child.DecRef(ctx)
	return fd, err
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *Filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	defer fs.processDeferredDecRefs(ctx)

	fs.mu.RLock()
	d, err := fs.walkExistingLocked(ctx, rp)
	if err != nil {
		fs.mu.RUnlock()
		return "", err
	}
	if !d.isSymlink() {
		fs.mu.RUnlock()
		return "", linuxerr.EINVAL
	}

	// Inode.Readlink() cannot be called holding fs locks.
	d.IncRef()
	defer d.DecRef(ctx)
	fs.mu.RUnlock()

	return d.inode.Readlink(ctx, rp.Mount())
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *Filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, oldParentVD vfs.VirtualDentry, oldName string, opts vfs.RenameOptions) error {
	fs.mu.Lock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.Unlock()

	// Resolve the destination directory first to verify that it's on this
	// Mount.
	dstDir, err := fs.walkParentDirLocked(ctx, rp)
	if err != nil {
		return err
	}

	// Only RENAME_NOREPLACE is supported.
	if opts.Flags&^linux.RENAME_NOREPLACE != 0 {
		return linuxerr.EINVAL
	}
	noReplace := opts.Flags&linux.RENAME_NOREPLACE != 0

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

	// Can we remove the src dentry?
	if err := checkDeleteLocked(ctx, rp, src); err != nil {
		return err
	}

	// Can we create the dst dentry?
	var dst *Dentry
	newName := rp.Component()
	if newName == "." || newName == ".." {
		if noReplace {
			return syserror.EEXIST
		}
		return syserror.EBUSY
	}

	err = checkCreateLocked(ctx, rp.Credentials(), newName, dstDir)
	switch {
	case err == nil:
		// Ok, continue with rename as replacement.
	case linuxerr.Equals(linuxerr.EEXIST, err):
		if noReplace {
			// Won't overwrite existing node since RENAME_NOREPLACE was requested.
			return syserror.EEXIST
		}
		dst = dstDir.children[newName]
		if dst == nil {
			panic(fmt.Sprintf("Child %q for parent Dentry %+v disappeared inside atomic section?", newName, dstDir))
		}
	default:
		return err
	}

	if srcDir == dstDir && oldName == newName {
		return nil
	}

	var dstVFSD *vfs.Dentry
	if dst != nil {
		dstVFSD = dst.VFSDentry()
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

	srcVFSD := src.VFSDentry()
	if err := virtfs.PrepareRenameDentry(mntns, srcVFSD, dstVFSD); err != nil {
		return err
	}
	err = srcDir.inode.Rename(ctx, src.name, newName, src.inode, dstDir.inode)
	if err != nil {
		virtfs.AbortRenameDentry(srcVFSD, dstVFSD)
		return err
	}
	delete(srcDir.children, src.name)
	if srcDir != dstDir {
		fs.deferDecRef(srcDir) // child (src) drops ref on old parent.
		dstDir.IncRef()        // child (src) takes a ref on the new parent.
	}
	src.parent = dstDir
	src.name = newName
	if dstDir.children == nil {
		dstDir.children = make(map[string]*Dentry)
	}
	replaced := dstDir.children[newName]
	dstDir.children[newName] = src
	var replaceVFSD *vfs.Dentry
	if replaced != nil {
		// deferDecRef so that fs.mu and dstDir.mu are unlocked by then.
		fs.deferDecRef(replaced)
		replaceVFSD = replaced.VFSDentry()
	}
	virtfs.CommitRenameReplaceDentry(ctx, srcVFSD, replaceVFSD)
	return nil
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *Filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.mu.Lock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.Unlock()

	d, err := fs.walkExistingLocked(ctx, rp)
	if err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	if err := checkDeleteLocked(ctx, rp, d); err != nil {
		return err
	}
	if !d.isDir() {
		return syserror.ENOTDIR
	}
	if d.inode.HasChildren() {
		return syserror.ENOTEMPTY
	}
	virtfs := rp.VirtualFilesystem()
	parentDentry := d.parent
	parentDentry.dirMu.Lock()
	defer parentDentry.dirMu.Unlock()

	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	vfsd := d.VFSDentry()
	if err := virtfs.PrepareDeleteDentry(mntns, vfsd); err != nil {
		return err
	}

	if err := parentDentry.inode.RmDir(ctx, d.name, d.inode); err != nil {
		virtfs.AbortDeleteDentry(vfsd)
		return err
	}
	delete(parentDentry.children, d.name)
	// Defer decref so that fs.mu and parentDentry.dirMu are unlocked by then.
	fs.deferDecRef(d)
	virtfs.CommitDeleteDentry(ctx, vfsd)
	return nil
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *Filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	fs.mu.RLock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.RUnlock()
	d, err := fs.walkExistingLocked(ctx, rp)
	if err != nil {
		return err
	}
	if opts.Stat.Mask == 0 {
		return nil
	}
	return d.inode.SetStat(ctx, fs.VFSFilesystem(), rp.Credentials(), opts)
}

// StatAt implements vfs.FilesystemImpl.StatAt.
func (fs *Filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	fs.mu.RLock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.RUnlock()
	d, err := fs.walkExistingLocked(ctx, rp)
	if err != nil {
		return linux.Statx{}, err
	}
	return d.inode.Stat(ctx, fs.VFSFilesystem(), opts)
}

// StatFSAt implements vfs.FilesystemImpl.StatFSAt.
func (fs *Filesystem) StatFSAt(ctx context.Context, rp *vfs.ResolvingPath) (linux.Statfs, error) {
	fs.mu.RLock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.RUnlock()
	d, err := fs.walkExistingLocked(ctx, rp)
	if err != nil {
		return linux.Statfs{}, err
	}
	return d.inode.StatFS(ctx, fs.VFSFilesystem())
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt.
func (fs *Filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	if rp.Done() {
		return syserror.EEXIST
	}
	fs.mu.Lock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.Unlock()
	parent, err := fs.walkParentDirLocked(ctx, rp)
	if err != nil {
		return err
	}
	parent.dirMu.Lock()
	defer parent.dirMu.Unlock()

	pc := rp.Component()
	if err := checkCreateLocked(ctx, rp.Credentials(), pc, parent); err != nil {
		return err
	}
	if rp.MustBeDir() {
		return syserror.ENOENT
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	childI, err := parent.inode.NewSymlink(ctx, pc, target)
	if err != nil {
		return err
	}
	var child Dentry
	child.Init(fs, childI)
	parent.insertChildLocked(pc, &child)
	return nil
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *Filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.mu.Lock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.Unlock()

	d, err := fs.walkExistingLocked(ctx, rp)
	if err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	if err := checkDeleteLocked(ctx, rp, d); err != nil {
		return err
	}
	if d.isDir() {
		return syserror.EISDIR
	}
	virtfs := rp.VirtualFilesystem()
	parentDentry := d.parent
	parentDentry.dirMu.Lock()
	defer parentDentry.dirMu.Unlock()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	vfsd := d.VFSDentry()
	if err := virtfs.PrepareDeleteDentry(mntns, vfsd); err != nil {
		return err
	}
	if err := parentDentry.inode.Unlink(ctx, d.name, d.inode); err != nil {
		virtfs.AbortDeleteDentry(vfsd)
		return err
	}
	delete(parentDentry.children, d.name)
	// Defer decref so that fs.mu and parentDentry.dirMu are unlocked by then.
	fs.deferDecRef(d)
	virtfs.CommitDeleteDentry(ctx, vfsd)
	return nil
}

// BoundEndpointAt implements vfs.FilesystemImpl.BoundEndpointAt.
func (fs *Filesystem) BoundEndpointAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.BoundEndpointOptions) (transport.BoundEndpoint, error) {
	fs.mu.RLock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.RUnlock()
	d, err := fs.walkExistingLocked(ctx, rp)
	if err != nil {
		return nil, err
	}
	if err := d.inode.CheckPermissions(ctx, rp.Credentials(), vfs.MayWrite); err != nil {
		return nil, err
	}
	return nil, syserror.ECONNREFUSED
}

// ListXattrAt implements vfs.FilesystemImpl.ListXattrAt.
func (fs *Filesystem) ListXattrAt(ctx context.Context, rp *vfs.ResolvingPath, size uint64) ([]string, error) {
	fs.mu.RLock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.RUnlock()
	_, err := fs.walkExistingLocked(ctx, rp)
	if err != nil {
		return nil, err
	}
	// kernfs currently does not support extended attributes.
	return nil, syserror.ENOTSUP
}

// GetXattrAt implements vfs.FilesystemImpl.GetXattrAt.
func (fs *Filesystem) GetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetXattrOptions) (string, error) {
	fs.mu.RLock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.RUnlock()
	_, err := fs.walkExistingLocked(ctx, rp)
	if err != nil {
		return "", err
	}
	// kernfs currently does not support extended attributes.
	return "", syserror.ENOTSUP
}

// SetXattrAt implements vfs.FilesystemImpl.SetXattrAt.
func (fs *Filesystem) SetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetXattrOptions) error {
	fs.mu.RLock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.RUnlock()
	_, err := fs.walkExistingLocked(ctx, rp)
	if err != nil {
		return err
	}
	// kernfs currently does not support extended attributes.
	return syserror.ENOTSUP
}

// RemoveXattrAt implements vfs.FilesystemImpl.RemoveXattrAt.
func (fs *Filesystem) RemoveXattrAt(ctx context.Context, rp *vfs.ResolvingPath, name string) error {
	fs.mu.RLock()
	defer fs.processDeferredDecRefs(ctx)
	defer fs.mu.RUnlock()
	_, err := fs.walkExistingLocked(ctx, rp)
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

func (fs *Filesystem) deferDecRefVD(ctx context.Context, vd vfs.VirtualDentry) {
	if d, ok := vd.Dentry().Impl().(*Dentry); ok && d.fs == fs {
		// The following is equivalent to vd.DecRef(ctx). This is needed
		// because if d belongs to this filesystem, we can not DecRef it right
		// away as we may be holding fs.mu. d.DecRef may acquire fs.mu. So we
		// defer the DecRef to when locks are dropped.
		vd.Mount().DecRef(ctx)
		fs.deferDecRef(d)
	} else {
		vd.DecRef(ctx)
	}
}
