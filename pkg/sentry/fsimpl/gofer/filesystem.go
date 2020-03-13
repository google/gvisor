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

package gofer

import (
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Sync implements vfs.FilesystemImpl.Sync.
func (fs *filesystem) Sync(ctx context.Context) error {
	// Snapshot current dentries and special files.
	fs.syncMu.Lock()
	ds := make([]*dentry, 0, len(fs.dentries))
	for d := range fs.dentries {
		ds = append(ds, d)
	}
	sffds := make([]*specialFileFD, 0, len(fs.specialFileFDs))
	for sffd := range fs.specialFileFDs {
		sffds = append(sffds, sffd)
	}
	fs.syncMu.Unlock()

	// Return the first error we encounter, but sync everything we can
	// regardless.
	var retErr error

	// Sync regular files.
	for _, d := range ds {
		if !d.TryIncRef() {
			continue
		}
		err := d.syncSharedHandle(ctx)
		d.DecRef()
		if err != nil && retErr == nil {
			retErr = err
		}
	}

	// Sync special files, which may be writable but do not use dentry shared
	// handles (so they won't be synced by the above).
	for _, sffd := range sffds {
		if !sffd.vfsfd.TryIncRef() {
			continue
		}
		err := sffd.Sync(ctx)
		sffd.vfsfd.DecRef()
		if err != nil && retErr == nil {
			retErr = err
		}
	}

	return retErr
}

// maxFilenameLen is the maximum length of a filename. This is dictated by 9P's
// encoding of strings, which uses 2 bytes for the length prefix.
const maxFilenameLen = (1 << 16) - 1

// dentrySlicePool is a pool of *[]*dentry used to store dentries for which
// dentry.checkCachingLocked() must be called. The pool holds pointers to
// slices because Go lacks generics, so sync.Pool operates on interface{}, so
// every call to (what should be) sync.Pool<[]*dentry>.Put() allocates a copy
// of the slice header on the heap.
var dentrySlicePool = sync.Pool{
	New: func() interface{} {
		ds := make([]*dentry, 0, 4) // arbitrary non-zero initial capacity
		return &ds
	},
}

func appendDentry(ds *[]*dentry, d *dentry) *[]*dentry {
	if ds == nil {
		ds = dentrySlicePool.Get().(*[]*dentry)
	}
	*ds = append(*ds, d)
	return ds
}

// Preconditions: ds != nil.
func putDentrySlice(ds *[]*dentry) {
	// Allow dentries to be GC'd.
	for i := range *ds {
		(*ds)[i] = nil
	}
	*ds = (*ds)[:0]
	dentrySlicePool.Put(ds)
}

// stepLocked resolves rp.Component() to an existing file, starting from the
// given directory.
//
// Dentries which may become cached as a result of the traversal are appended
// to *ds.
//
// Preconditions: fs.renameMu must be locked. d.dirMu must be locked.
// !rp.Done(). If fs.opts.interop == InteropModeShared, then d's cached
// metadata must be up to date.
func (fs *filesystem) stepLocked(ctx context.Context, rp *vfs.ResolvingPath, d *dentry, ds **[]*dentry) (*dentry, error) {
	if !d.isDir() {
		return nil, syserror.ENOTDIR
	}
	if err := d.checkPermissions(rp.Credentials(), vfs.MayExec, true); err != nil {
		return nil, err
	}
afterSymlink:
	name := rp.Component()
	if name == "." {
		rp.Advance()
		return d, nil
	}
	if name == ".." {
		parentVFSD, err := rp.ResolveParent(&d.vfsd)
		if err != nil {
			return nil, err
		}
		parent := parentVFSD.Impl().(*dentry)
		if fs.opts.interop == InteropModeShared {
			// We must assume that parentVFSD is correct, because if d has been
			// moved elsewhere in the remote filesystem so that its parent has
			// changed, we have no way of determining its new parent's location
			// in the filesystem. Get updated metadata for parentVFSD.
			_, attrMask, attr, err := parent.file.getAttr(ctx, dentryAttrMask())
			if err != nil {
				return nil, err
			}
			parent.updateFromP9Attrs(attrMask, &attr)
		}
		rp.Advance()
		return parent, nil
	}
	childVFSD, err := rp.ResolveChild(&d.vfsd, name)
	if err != nil {
		return nil, err
	}
	// FIXME(jamieliu): Linux performs revalidation before mount lookup
	// (fs/namei.c:lookup_fast() => __d_lookup_rcu(), d_revalidate(),
	// __follow_mount_rcu()).
	child, err := fs.revalidateChildLocked(ctx, rp.VirtualFilesystem(), d, name, childVFSD, ds)
	if err != nil {
		return nil, err
	}
	if child == nil {
		return nil, syserror.ENOENT
	}
	if child.isSymlink() && rp.ShouldFollowSymlink() {
		target, err := child.readlink(ctx, rp.Mount())
		if err != nil {
			return nil, err
		}
		if err := rp.HandleSymlink(target); err != nil {
			return nil, err
		}
		goto afterSymlink // don't check the current directory again
	}
	rp.Advance()
	return child, nil
}

// revalidateChildLocked must be called after a call to parent.vfsd.Child(name)
// or vfs.ResolvingPath.ResolveChild(name) returns childVFSD (which may be
// nil) to verify that the returned child (or lack thereof) is correct. If no file
// exists at name, revalidateChildLocked returns (nil, nil).
//
// Preconditions: fs.renameMu must be locked. parent.dirMu must be locked.
// parent.isDir(). name is not "." or "..".
//
// Postconditions: If revalidateChildLocked returns a non-nil dentry, its
// cached metadata is up to date.
func (fs *filesystem) revalidateChildLocked(ctx context.Context, vfsObj *vfs.VirtualFilesystem, parent *dentry, name string, childVFSD *vfs.Dentry, ds **[]*dentry) (*dentry, error) {
	if childVFSD != nil && fs.opts.interop != InteropModeShared {
		// We have a cached dentry that is assumed to be correct.
		return childVFSD.Impl().(*dentry), nil
	}
	// We either don't have a cached dentry or need to verify that it's still
	// correct, either of which requires a remote lookup. Check if this name is
	// valid before performing the lookup.
	if len(name) > maxFilenameLen {
		return nil, syserror.ENAMETOOLONG
	}
	// Check if we've already cached this lookup with a negative result.
	if _, ok := parent.negativeChildren[name]; ok {
		return nil, nil
	}
	// Perform the remote lookup.
	qid, file, attrMask, attr, err := parent.file.walkGetAttrOne(ctx, name)
	if err != nil && err != syserror.ENOENT {
		return nil, err
	}
	if childVFSD != nil {
		child := childVFSD.Impl().(*dentry)
		if !file.isNil() && qid.Path == child.ino {
			// The file at this path hasn't changed. Just update cached
			// metadata.
			file.close(ctx)
			child.updateFromP9Attrs(attrMask, &attr)
			return child, nil
		}
		// The file at this path has changed or no longer exists. Remove
		// the stale dentry from the tree, and re-evaluate its caching
		// status (i.e. if it has 0 references, drop it).
		vfsObj.ForceDeleteDentry(childVFSD)
		*ds = appendDentry(*ds, child)
		childVFSD = nil
	}
	if file.isNil() {
		// No file exists at this path now. Cache the negative lookup if
		// allowed.
		if fs.opts.interop != InteropModeShared {
			parent.cacheNegativeChildLocked(name)
		}
		return nil, nil
	}
	// Create a new dentry representing the file.
	child, err := fs.newDentry(ctx, file, qid, attrMask, &attr)
	if err != nil {
		file.close(ctx)
		return nil, err
	}
	parent.IncRef() // reference held by child on its parent
	parent.vfsd.InsertChild(&child.vfsd, name)
	// For now, child has 0 references, so our caller should call
	// child.checkCachingLocked().
	*ds = appendDentry(*ds, child)
	return child, nil
}

// walkParentDirLocked resolves all but the last path component of rp to an
// existing directory, starting from the given directory (which is usually
// rp.Start().Impl().(*dentry)). It does not check that the returned directory
// is searchable by the provider of rp.
//
// Preconditions: fs.renameMu must be locked. !rp.Done(). If fs.opts.interop ==
// InteropModeShared, then d's cached metadata must be up to date.
func (fs *filesystem) walkParentDirLocked(ctx context.Context, rp *vfs.ResolvingPath, d *dentry, ds **[]*dentry) (*dentry, error) {
	for !rp.Final() {
		d.dirMu.Lock()
		next, err := fs.stepLocked(ctx, rp, d, ds)
		d.dirMu.Unlock()
		if err != nil {
			return nil, err
		}
		d = next
	}
	if !d.isDir() {
		return nil, syserror.ENOTDIR
	}
	return d, nil
}

// resolveLocked resolves rp to an existing file.
//
// Preconditions: fs.renameMu must be locked.
func (fs *filesystem) resolveLocked(ctx context.Context, rp *vfs.ResolvingPath, ds **[]*dentry) (*dentry, error) {
	d := rp.Start().Impl().(*dentry)
	if fs.opts.interop == InteropModeShared {
		// Get updated metadata for rp.Start() as required by fs.stepLocked().
		if err := d.updateFromGetattr(ctx); err != nil {
			return nil, err
		}
	}
	for !rp.Done() {
		d.dirMu.Lock()
		next, err := fs.stepLocked(ctx, rp, d, ds)
		d.dirMu.Unlock()
		if err != nil {
			return nil, err
		}
		d = next
	}
	if rp.MustBeDir() && !d.isDir() {
		return nil, syserror.ENOTDIR
	}
	return d, nil
}

// doCreateAt checks that creating a file at rp is permitted, then invokes
// create to do so.
//
// Preconditions: !rp.Done(). For the final path component in rp,
// !rp.ShouldFollowSymlink().
func (fs *filesystem) doCreateAt(ctx context.Context, rp *vfs.ResolvingPath, dir bool, create func(parent *dentry, name string) error) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	start := rp.Start().Impl().(*dentry)
	if fs.opts.interop == InteropModeShared {
		// Get updated metadata for start as required by
		// fs.walkParentDirLocked().
		if err := start.updateFromGetattr(ctx); err != nil {
			return err
		}
	}
	parent, err := fs.walkParentDirLocked(ctx, rp, start, &ds)
	if err != nil {
		return err
	}
	if err := parent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec, true); err != nil {
		return err
	}
	if parent.isDeleted() {
		return syserror.ENOENT
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return syserror.EEXIST
	}
	if len(name) > maxFilenameLen {
		return syserror.ENAMETOOLONG
	}
	if !dir && rp.MustBeDir() {
		return syserror.ENOENT
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	parent.dirMu.Lock()
	defer parent.dirMu.Unlock()
	if fs.opts.interop == InteropModeShared {
		// The existence of a dentry at name would be inconclusive because the
		// file it represents may have been deleted from the remote filesystem,
		// so we would need to make an RPC to revalidate the dentry. Just
		// attempt the file creation RPC instead. If a file does exist, the RPC
		// will fail with EEXIST like we would have. If the RPC succeeds, and a
		// stale dentry exists, the dentry will fail revalidation next time
		// it's used.
		return create(parent, name)
	}
	if parent.vfsd.Child(name) != nil {
		return syserror.EEXIST
	}
	// No cached dentry exists; however, there might still be an existing file
	// at name. As above, we attempt the file creation RPC anyway.
	if err := create(parent, name); err != nil {
		return err
	}
	parent.touchCMtime(ctx)
	delete(parent.negativeChildren, name)
	parent.dirents = nil
	return nil
}

// Preconditions: !rp.Done().
func (fs *filesystem) unlinkAt(ctx context.Context, rp *vfs.ResolvingPath, dir bool) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	start := rp.Start().Impl().(*dentry)
	if fs.opts.interop == InteropModeShared {
		// Get updated metadata for start as required by
		// fs.walkParentDirLocked().
		if err := start.updateFromGetattr(ctx); err != nil {
			return err
		}
	}
	parent, err := fs.walkParentDirLocked(ctx, rp, start, &ds)
	if err != nil {
		return err
	}
	if err := parent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec, true); err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()

	name := rp.Component()
	if dir {
		if name == "." {
			return syserror.EINVAL
		}
		if name == ".." {
			return syserror.ENOTEMPTY
		}
	} else {
		if name == "." || name == ".." {
			return syserror.EISDIR
		}
	}
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef()
	parent.dirMu.Lock()
	defer parent.dirMu.Unlock()
	childVFSD := parent.vfsd.Child(name)
	var child *dentry
	// We only need a dentry representing the file at name if it can be a mount
	// point. If childVFSD is nil, then it can't be a mount point. If childVFSD
	// is non-nil but stale, the actual file can't be a mount point either; we
	// detect this case by just speculatively calling PrepareDeleteDentry and
	// only revalidating the dentry if that fails (indicating that the existing
	// dentry is a mount point).
	if childVFSD != nil {
		child = childVFSD.Impl().(*dentry)
		if err := vfsObj.PrepareDeleteDentry(mntns, childVFSD); err != nil {
			child, err = fs.revalidateChildLocked(ctx, vfsObj, parent, name, childVFSD, &ds)
			if err != nil {
				return err
			}
			if child != nil {
				childVFSD = &child.vfsd
				if err := vfsObj.PrepareDeleteDentry(mntns, childVFSD); err != nil {
					return err
				}
			} else {
				childVFSD = nil
			}
		}
	} else if _, ok := parent.negativeChildren[name]; ok {
		return syserror.ENOENT
	}
	flags := uint32(0)
	if dir {
		if child != nil && !child.isDir() {
			return syserror.ENOTDIR
		}
		flags = linux.AT_REMOVEDIR
	} else {
		if child != nil && child.isDir() {
			return syserror.EISDIR
		}
		if rp.MustBeDir() {
			return syserror.ENOTDIR
		}
	}
	err = parent.file.unlinkAt(ctx, name, flags)
	if err != nil {
		if childVFSD != nil {
			vfsObj.AbortDeleteDentry(childVFSD)
		}
		return err
	}
	if fs.opts.interop != InteropModeShared {
		parent.touchCMtime(ctx)
		parent.cacheNegativeChildLocked(name)
		parent.dirents = nil
	}
	if child != nil {
		child.setDeleted()
		vfsObj.CommitDeleteDentry(childVFSD)
		ds = appendDentry(ds, child)
	}
	return nil
}

// renameMuRUnlockAndCheckCaching calls fs.renameMu.RUnlock(), then calls
// dentry.checkCachingLocked on all dentries in *ds with fs.renameMu locked for
// writing.
//
// ds is a pointer-to-pointer since defer evaluates its arguments immediately,
// but dentry slices are allocated lazily, and it's much easier to say "defer
// fs.renameMuRUnlockAndCheckCaching(&ds)" than "defer func() {
// fs.renameMuRUnlockAndCheckCaching(ds) }()" to work around this.
func (fs *filesystem) renameMuRUnlockAndCheckCaching(ds **[]*dentry) {
	fs.renameMu.RUnlock()
	if *ds == nil {
		return
	}
	if len(**ds) != 0 {
		fs.renameMu.Lock()
		for _, d := range **ds {
			d.checkCachingLocked()
		}
		fs.renameMu.Unlock()
	}
	putDentrySlice(*ds)
}

func (fs *filesystem) renameMuUnlockAndCheckCaching(ds **[]*dentry) {
	if *ds == nil {
		fs.renameMu.Unlock()
		return
	}
	for _, d := range **ds {
		d.checkCachingLocked()
	}
	fs.renameMu.Unlock()
	putDentrySlice(*ds)
}

// AccessAt implements vfs.Filesystem.Impl.AccessAt.
func (fs *filesystem) AccessAt(ctx context.Context, rp *vfs.ResolvingPath, creds *auth.Credentials, ats vfs.AccessTypes) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return err
	}
	return d.checkPermissions(creds, ats, d.isDir())
}

// GetDentryAt implements vfs.FilesystemImpl.GetDentryAt.
func (fs *filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return nil, err
	}
	if opts.CheckSearchable {
		if !d.isDir() {
			return nil, syserror.ENOTDIR
		}
		if err := d.checkPermissions(rp.Credentials(), vfs.MayExec, true); err != nil {
			return nil, err
		}
	}
	d.IncRef()
	return &d.vfsd, nil
}

// GetParentDentryAt implements vfs.FilesystemImpl.GetParentDentryAt.
func (fs *filesystem) GetParentDentryAt(ctx context.Context, rp *vfs.ResolvingPath) (*vfs.Dentry, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	start := rp.Start().Impl().(*dentry)
	if fs.opts.interop == InteropModeShared {
		// Get updated metadata for start as required by
		// fs.walkParentDirLocked().
		if err := start.updateFromGetattr(ctx); err != nil {
			return nil, err
		}
	}
	d, err := fs.walkParentDirLocked(ctx, rp, start, &ds)
	if err != nil {
		return nil, err
	}
	d.IncRef()
	return &d.vfsd, nil
}

// LinkAt implements vfs.FilesystemImpl.LinkAt.
func (fs *filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	return fs.doCreateAt(ctx, rp, false /* dir */, func(parent *dentry, childName string) error {
		if rp.Mount() != vd.Mount() {
			return syserror.EXDEV
		}
		// 9P2000.L supports hard links, but we don't.
		return syserror.EPERM
	})
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	return fs.doCreateAt(ctx, rp, true /* dir */, func(parent *dentry, name string) error {
		creds := rp.Credentials()
		_, err := parent.file.mkdir(ctx, name, (p9.FileMode)(opts.Mode), (p9.UID)(creds.EffectiveKUID), (p9.GID)(creds.EffectiveKGID))
		return err
	})
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	return fs.doCreateAt(ctx, rp, false /* dir */, func(parent *dentry, name string) error {
		creds := rp.Credentials()
		_, err := parent.file.mknod(ctx, name, (p9.FileMode)(opts.Mode), opts.DevMajor, opts.DevMinor, (p9.UID)(creds.EffectiveKUID), (p9.GID)(creds.EffectiveKGID))
		return err
	})
}

// OpenAt implements vfs.FilesystemImpl.OpenAt.
func (fs *filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	// Reject O_TMPFILE, which is not supported; supporting it correctly in the
	// presence of other remote filesystem users requires remote filesystem
	// support, and it isn't clear that there's any way to implement this in
	// 9P.
	if opts.Flags&linux.O_TMPFILE != 0 {
		return nil, syserror.EOPNOTSUPP
	}
	mayCreate := opts.Flags&linux.O_CREAT != 0
	mustCreate := opts.Flags&(linux.O_CREAT|linux.O_EXCL) == (linux.O_CREAT | linux.O_EXCL)

	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)

	start := rp.Start().Impl().(*dentry)
	if fs.opts.interop == InteropModeShared {
		// Get updated metadata for start as required by fs.stepLocked().
		if err := start.updateFromGetattr(ctx); err != nil {
			return nil, err
		}
	}
	if rp.Done() {
		return start.openLocked(ctx, rp, &opts)
	}

afterTrailingSymlink:
	parent, err := fs.walkParentDirLocked(ctx, rp, start, &ds)
	if err != nil {
		return nil, err
	}
	// Check for search permission in the parent directory.
	if err := parent.checkPermissions(rp.Credentials(), vfs.MayExec, true); err != nil {
		return nil, err
	}
	// Determine whether or not we need to create a file.
	parent.dirMu.Lock()
	child, err := fs.stepLocked(ctx, rp, parent, &ds)
	if err == syserror.ENOENT && mayCreate {
		fd, err := parent.createAndOpenChildLocked(ctx, rp, &opts)
		parent.dirMu.Unlock()
		return fd, err
	}
	if err != nil {
		parent.dirMu.Unlock()
		return nil, err
	}
	// Open existing child or follow symlink.
	parent.dirMu.Unlock()
	if mustCreate {
		return nil, syserror.EEXIST
	}
	if child.isSymlink() && rp.ShouldFollowSymlink() {
		target, err := child.readlink(ctx, rp.Mount())
		if err != nil {
			return nil, err
		}
		if err := rp.HandleSymlink(target); err != nil {
			return nil, err
		}
		start = parent
		goto afterTrailingSymlink
	}
	return child.openLocked(ctx, rp, &opts)
}

// Preconditions: fs.renameMu must be locked.
func (d *dentry) openLocked(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	ats := vfs.AccessTypesForOpenFlags(opts)
	if err := d.checkPermissions(rp.Credentials(), ats, d.isDir()); err != nil {
		return nil, err
	}
	mnt := rp.Mount()
	filetype := d.fileType()
	switch {
	case filetype == linux.S_IFREG && !d.fs.opts.regularFilesUseSpecialFileFD:
		if err := d.ensureSharedHandle(ctx, ats&vfs.MayRead != 0, ats&vfs.MayWrite != 0, opts.Flags&linux.O_TRUNC != 0); err != nil {
			return nil, err
		}
		fd := &regularFileFD{}
		if err := fd.vfsfd.Init(fd, opts.Flags, mnt, &d.vfsd, &vfs.FileDescriptionOptions{
			AllowDirectIO: true,
		}); err != nil {
			return nil, err
		}
		return &fd.vfsfd, nil
	case filetype == linux.S_IFDIR:
		// Can't open directories with O_CREAT.
		if opts.Flags&linux.O_CREAT != 0 {
			return nil, syserror.EISDIR
		}
		// Can't open directories writably.
		if ats&vfs.MayWrite != 0 {
			return nil, syserror.EISDIR
		}
		if opts.Flags&linux.O_DIRECT != 0 {
			return nil, syserror.EINVAL
		}
		if err := d.ensureSharedHandle(ctx, ats&vfs.MayRead != 0, false /* write */, false /* trunc */); err != nil {
			return nil, err
		}
		fd := &directoryFD{}
		if err := fd.vfsfd.Init(fd, opts.Flags, mnt, &d.vfsd, &vfs.FileDescriptionOptions{}); err != nil {
			return nil, err
		}
		return &fd.vfsfd, nil
	case filetype == linux.S_IFLNK:
		// Can't open symlinks without O_PATH (which is unimplemented).
		return nil, syserror.ELOOP
	default:
		if opts.Flags&linux.O_DIRECT != 0 {
			return nil, syserror.EINVAL
		}
		h, err := openHandle(ctx, d.file, ats&vfs.MayRead != 0, ats&vfs.MayWrite != 0, opts.Flags&linux.O_TRUNC != 0)
		if err != nil {
			return nil, err
		}
		fd := &specialFileFD{
			handle: h,
		}
		if err := fd.vfsfd.Init(fd, opts.Flags, mnt, &d.vfsd, &vfs.FileDescriptionOptions{}); err != nil {
			h.close(ctx)
			return nil, err
		}
		return &fd.vfsfd, nil
	}
}

// Preconditions: d.fs.renameMu must be locked. d.dirMu must be locked.
func (d *dentry) createAndOpenChildLocked(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	if err := d.checkPermissions(rp.Credentials(), vfs.MayWrite, true); err != nil {
		return nil, err
	}
	if d.isDeleted() {
		return nil, syserror.ENOENT
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return nil, err
	}
	defer mnt.EndWrite()

	// 9P2000.L's lcreate takes a fid representing the parent directory, and
	// converts it into an open fid representing the created file, so we need
	// to duplicate the directory fid first.
	_, dirfile, err := d.file.walk(ctx, nil)
	if err != nil {
		return nil, err
	}
	creds := rp.Credentials()
	name := rp.Component()
	fdobj, openFile, createQID, _, err := dirfile.create(ctx, name, (p9.OpenFlags)(opts.Flags), (p9.FileMode)(opts.Mode), (p9.UID)(creds.EffectiveKUID), (p9.GID)(creds.EffectiveKGID))
	if err != nil {
		dirfile.close(ctx)
		return nil, err
	}
	// Then we need to walk to the file we just created to get a non-open fid
	// representing it, and to get its metadata. This must use d.file since, as
	// explained above, dirfile was invalidated by dirfile.Create().
	walkQID, nonOpenFile, attrMask, attr, err := d.file.walkGetAttrOne(ctx, name)
	if err != nil {
		openFile.close(ctx)
		if fdobj != nil {
			fdobj.Close()
		}
		return nil, err
	}
	// Sanity-check that we walked to the file we created.
	if createQID.Path != walkQID.Path {
		// Probably due to concurrent remote filesystem mutation?
		ctx.Warningf("gofer.dentry.createAndOpenChildLocked: created file has QID %v before walk, QID %v after (interop=%v)", createQID, walkQID, d.fs.opts.interop)
		nonOpenFile.close(ctx)
		openFile.close(ctx)
		if fdobj != nil {
			fdobj.Close()
		}
		return nil, syserror.EAGAIN
	}

	// Construct the new dentry.
	child, err := d.fs.newDentry(ctx, nonOpenFile, createQID, attrMask, &attr)
	if err != nil {
		nonOpenFile.close(ctx)
		openFile.close(ctx)
		if fdobj != nil {
			fdobj.Close()
		}
		return nil, err
	}
	// Incorporate the fid that was opened by lcreate.
	useRegularFileFD := child.fileType() == linux.S_IFREG && !d.fs.opts.regularFilesUseSpecialFileFD
	if useRegularFileFD {
		child.handleMu.Lock()
		child.handle.file = openFile
		if fdobj != nil {
			child.handle.fd = int32(fdobj.Release())
		}
		child.handleReadable = vfs.MayReadFileWithOpenFlags(opts.Flags)
		child.handleWritable = vfs.MayWriteFileWithOpenFlags(opts.Flags)
		child.handleMu.Unlock()
	}
	// Take a reference on the new dentry to be held by the new file
	// description. (This reference also means that the new dentry is not
	// eligible for caching yet, so we don't need to append to a dentry slice.)
	child.refs = 1
	// Insert the dentry into the tree.
	d.IncRef() // reference held by child on its parent d
	d.vfsd.InsertChild(&child.vfsd, name)
	if d.fs.opts.interop != InteropModeShared {
		d.touchCMtime(ctx)
		delete(d.negativeChildren, name)
		d.dirents = nil
	}

	// Finally, construct a file description representing the created file.
	var childVFSFD *vfs.FileDescription
	mnt.IncRef()
	if useRegularFileFD {
		fd := &regularFileFD{}
		if err := fd.vfsfd.Init(fd, opts.Flags, mnt, &child.vfsd, &vfs.FileDescriptionOptions{
			AllowDirectIO: true,
		}); err != nil {
			return nil, err
		}
		childVFSFD = &fd.vfsfd
	} else {
		fd := &specialFileFD{
			handle: handle{
				file: openFile,
				fd:   -1,
			},
		}
		if fdobj != nil {
			fd.handle.fd = int32(fdobj.Release())
		}
		if err := fd.vfsfd.Init(fd, opts.Flags, mnt, &child.vfsd, &vfs.FileDescriptionOptions{}); err != nil {
			fd.handle.close(ctx)
			return nil, err
		}
		childVFSFD = &fd.vfsfd
	}
	return childVFSFD, nil
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return "", err
	}
	if !d.isSymlink() {
		return "", syserror.EINVAL
	}
	return d.readlink(ctx, rp.Mount())
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, oldParentVD vfs.VirtualDentry, oldName string, opts vfs.RenameOptions) error {
	if opts.Flags != 0 {
		// Requires 9P support.
		return syserror.EINVAL
	}

	var ds *[]*dentry
	fs.renameMu.Lock()
	defer fs.renameMuUnlockAndCheckCaching(&ds)
	newParent, err := fs.walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry), &ds)
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
	if fs.opts.interop == InteropModeShared {
		if err := oldParent.updateFromGetattr(ctx); err != nil {
			return err
		}
	}
	if err := oldParent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec, true); err != nil {
		return err
	}
	vfsObj := rp.VirtualFilesystem()
	// We need a dentry representing the renamed file since, if it's a
	// directory, we need to check for write permission on it.
	oldParent.dirMu.Lock()
	defer oldParent.dirMu.Unlock()
	renamed, err := fs.revalidateChildLocked(ctx, vfsObj, oldParent, oldName, oldParent.vfsd.Child(oldName), &ds)
	if err != nil {
		return err
	}
	if renamed == nil {
		return syserror.ENOENT
	}
	if renamed.isDir() {
		if renamed == newParent || renamed.vfsd.IsAncestorOf(&newParent.vfsd) {
			return syserror.EINVAL
		}
		if oldParent != newParent {
			if err := renamed.checkPermissions(rp.Credentials(), vfs.MayWrite, true); err != nil {
				return err
			}
		}
	} else {
		if opts.MustBeDir || rp.MustBeDir() {
			return syserror.ENOTDIR
		}
	}

	if oldParent != newParent {
		if err := newParent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec, true); err != nil {
			return err
		}
		newParent.dirMu.Lock()
		defer newParent.dirMu.Unlock()
	}
	if newParent.isDeleted() {
		return syserror.ENOENT
	}
	replacedVFSD := newParent.vfsd.Child(newName)
	var replaced *dentry
	// This is similar to unlinkAt, except:
	//
	// - We revalidate the replaced dentry unconditionally for simplicity.
	//
	// - If rp.MustBeDir(), then we need a dentry representing the replaced
	// file regardless to confirm that it's a directory.
	if replacedVFSD != nil || rp.MustBeDir() {
		replaced, err = fs.revalidateChildLocked(ctx, vfsObj, newParent, newName, replacedVFSD, &ds)
		if err != nil {
			return err
		}
		if replaced != nil {
			if replaced.isDir() {
				if !renamed.isDir() {
					return syserror.EISDIR
				}
			} else {
				if rp.MustBeDir() || renamed.isDir() {
					return syserror.ENOTDIR
				}
			}
			replacedVFSD = &replaced.vfsd
		} else {
			replacedVFSD = nil
		}
	}

	if oldParent == newParent && oldName == newName {
		return nil
	}
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef()
	if err := vfsObj.PrepareRenameDentry(mntns, &renamed.vfsd, replacedVFSD); err != nil {
		return err
	}
	if err := renamed.file.rename(ctx, newParent.file, newName); err != nil {
		vfsObj.AbortRenameDentry(&renamed.vfsd, replacedVFSD)
		return err
	}
	if fs.opts.interop != InteropModeShared {
		oldParent.cacheNegativeChildLocked(oldName)
		oldParent.dirents = nil
		delete(newParent.negativeChildren, newName)
		newParent.dirents = nil
	}
	vfsObj.CommitRenameReplaceDentry(&renamed.vfsd, &newParent.vfsd, newName, replacedVFSD)
	return nil
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	return fs.unlinkAt(ctx, rp, true /* dir */)
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return err
	}
	return d.setStat(ctx, rp.Credentials(), &opts.Stat, rp.Mount())
}

// StatAt implements vfs.FilesystemImpl.StatAt.
func (fs *filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return linux.Statx{}, err
	}
	// Since walking updates metadata for all traversed dentries under
	// InteropModeShared, including the returned one, we can return cached
	// metadata here regardless of fs.opts.interop.
	var stat linux.Statx
	d.statTo(&stat)
	return stat, nil
}

// StatFSAt implements vfs.FilesystemImpl.StatFSAt.
func (fs *filesystem) StatFSAt(ctx context.Context, rp *vfs.ResolvingPath) (linux.Statfs, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return linux.Statfs{}, err
	}
	fsstat, err := d.file.statFS(ctx)
	if err != nil {
		return linux.Statfs{}, err
	}
	nameLen := uint64(fsstat.NameLength)
	if nameLen > maxFilenameLen {
		nameLen = maxFilenameLen
	}
	return linux.Statfs{
		// This is primarily for distinguishing a gofer file system in
		// tests. Testing is important, so instead of defining
		// something completely random, use a standard value.
		Type:            linux.V9FS_MAGIC,
		BlockSize:       int64(fsstat.BlockSize),
		Blocks:          fsstat.Blocks,
		BlocksFree:      fsstat.BlocksFree,
		BlocksAvailable: fsstat.BlocksAvailable,
		Files:           fsstat.Files,
		FilesFree:       fsstat.FilesFree,
		NameLength:      nameLen,
	}, nil
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt.
func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	return fs.doCreateAt(ctx, rp, false /* dir */, func(parent *dentry, name string) error {
		creds := rp.Credentials()
		_, err := parent.file.symlink(ctx, target, name, (p9.UID)(creds.EffectiveKUID), (p9.GID)(creds.EffectiveKGID))
		return err
	})
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	return fs.unlinkAt(ctx, rp, false /* dir */)
}

// ListxattrAt implements vfs.FilesystemImpl.ListxattrAt.
func (fs *filesystem) ListxattrAt(ctx context.Context, rp *vfs.ResolvingPath) ([]string, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return nil, err
	}
	return d.listxattr(ctx)
}

// GetxattrAt implements vfs.FilesystemImpl.GetxattrAt.
func (fs *filesystem) GetxattrAt(ctx context.Context, rp *vfs.ResolvingPath, name string) (string, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return "", err
	}
	return d.getxattr(ctx, name)
}

// SetxattrAt implements vfs.FilesystemImpl.SetxattrAt.
func (fs *filesystem) SetxattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetxattrOptions) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return err
	}
	return d.setxattr(ctx, &opts)
}

// RemovexattrAt implements vfs.FilesystemImpl.RemovexattrAt.
func (fs *filesystem) RemovexattrAt(ctx context.Context, rp *vfs.ResolvingPath, name string) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return err
	}
	return d.removexattr(ctx, name)
}

// PrependPath implements vfs.FilesystemImpl.PrependPath.
func (fs *filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	fs.renameMu.RLock()
	defer fs.renameMu.RUnlock()
	return vfs.GenericPrependPath(vfsroot, vd, b)
}
