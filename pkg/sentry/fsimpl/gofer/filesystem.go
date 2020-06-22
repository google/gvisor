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
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Sync implements vfs.FilesystemImpl.Sync.
func (fs *filesystem) Sync(ctx context.Context) error {
	// Snapshot current syncable dentries and special files.
	fs.syncMu.Lock()
	ds := make([]*dentry, 0, len(fs.syncableDentries))
	for d := range fs.syncableDentries {
		d.IncRef()
		ds = append(ds, d)
	}
	sffds := make([]*specialFileFD, 0, len(fs.specialFileFDs))
	for sffd := range fs.specialFileFDs {
		sffd.vfsfd.IncRef()
		sffds = append(sffds, sffd)
	}
	fs.syncMu.Unlock()

	// Return the first error we encounter, but sync everything we can
	// regardless.
	var retErr error

	// Sync regular files.
	for _, d := range ds {
		err := d.syncSharedHandle(ctx)
		d.DecRef()
		if err != nil && retErr == nil {
			retErr = err
		}
	}

	// Sync special files, which may be writable but do not use dentry shared
	// handles (so they won't be synced by the above).
	for _, sffd := range sffds {
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
// !rp.Done(). If !d.cachedMetadataAuthoritative(), then d's cached metadata
// must be up to date.
//
// Postconditions: The returned dentry's cached metadata is up to date.
func (fs *filesystem) stepLocked(ctx context.Context, rp *vfs.ResolvingPath, d *dentry, mayFollowSymlinks bool, ds **[]*dentry) (*dentry, error) {
	if !d.isDir() {
		return nil, syserror.ENOTDIR
	}
	if err := d.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
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
		// We must assume that d.parent is correct, because if d has been moved
		// elsewhere in the remote filesystem so that its parent has changed,
		// we have no way of determining its new parent's location in the
		// filesystem.
		//
		// Call rp.CheckMount() before updating d.parent's metadata, since if
		// we traverse to another mount then d.parent's metadata is irrelevant.
		if err := rp.CheckMount(&d.parent.vfsd); err != nil {
			return nil, err
		}
		if d != d.parent && !d.cachedMetadataAuthoritative() {
			_, attrMask, attr, err := d.parent.file.getAttr(ctx, dentryAttrMask())
			if err != nil {
				return nil, err
			}
			d.parent.updateFromP9Attrs(attrMask, &attr)
		}
		rp.Advance()
		return d.parent, nil
	}
	child, err := fs.getChildLocked(ctx, rp.VirtualFilesystem(), d, name, ds)
	if err != nil {
		return nil, err
	}
	if child == nil {
		return nil, syserror.ENOENT
	}
	if err := rp.CheckMount(&child.vfsd); err != nil {
		return nil, err
	}
	if child.isSymlink() && mayFollowSymlinks && rp.ShouldFollowSymlink() {
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

// getChildLocked returns a dentry representing the child of parent with the
// given name. If no such child exists, getChildLocked returns (nil, nil).
//
// Preconditions: fs.renameMu must be locked. parent.dirMu must be locked.
// parent.isDir(). name is not "." or "..".
//
// Postconditions: If getChildLocked returns a non-nil dentry, its cached
// metadata is up to date.
func (fs *filesystem) getChildLocked(ctx context.Context, vfsObj *vfs.VirtualFilesystem, parent *dentry, name string, ds **[]*dentry) (*dentry, error) {
	if len(name) > maxFilenameLen {
		return nil, syserror.ENAMETOOLONG
	}
	child, ok := parent.children[name]
	if (ok && fs.opts.interop != InteropModeShared) || parent.isSynthetic() {
		// Whether child is nil or not, it is cached information that is
		// assumed to be correct.
		return child, nil
	}
	// We either don't have cached information or need to verify that it's
	// still correct, either of which requires a remote lookup. Check if this
	// name is valid before performing the lookup.
	return fs.revalidateChildLocked(ctx, vfsObj, parent, name, child, ds)
}

// Preconditions: As for getChildLocked. !parent.isSynthetic().
func (fs *filesystem) revalidateChildLocked(ctx context.Context, vfsObj *vfs.VirtualFilesystem, parent *dentry, name string, child *dentry, ds **[]*dentry) (*dentry, error) {
	qid, file, attrMask, attr, err := parent.file.walkGetAttrOne(ctx, name)
	if err != nil && err != syserror.ENOENT {
		return nil, err
	}
	if child != nil {
		if !file.isNil() && qid.Path == child.ino {
			// The file at this path hasn't changed. Just update cached
			// metadata.
			file.close(ctx)
			child.updateFromP9Attrs(attrMask, &attr)
			return child, nil
		}
		if file.isNil() && child.isSynthetic() {
			// We have a synthetic file, and no remote file has arisen to
			// replace it.
			return child, nil
		}
		// The file at this path has changed or no longer exists. Mark the
		// dentry invalidated, and re-evaluate its caching status (i.e. if it
		// has 0 references, drop it). Wait to update parent.children until we
		// know what to replace the existing dentry with (i.e. one of the
		// returns below), to avoid a redundant map access.
		vfsObj.InvalidateDentry(&child.vfsd)
		if child.isSynthetic() {
			// Normally we don't mark invalidated dentries as deleted since
			// they may still exist (but at a different path), and also for
			// consistency with Linux. However, synthetic files are guaranteed
			// to become unreachable if their dentries are invalidated, so
			// treat their invalidation as deletion.
			child.setDeleted()
			parent.syntheticChildren--
			child.decRefLocked()
			parent.dirents = nil
		}
		*ds = appendDentry(*ds, child)
	}
	if file.isNil() {
		// No file exists at this path now. Cache the negative lookup if
		// allowed.
		parent.cacheNegativeLookupLocked(name)
		return nil, nil
	}
	// Create a new dentry representing the file.
	child, err = fs.newDentry(ctx, file, qid, attrMask, &attr)
	if err != nil {
		file.close(ctx)
		delete(parent.children, name)
		return nil, err
	}
	parent.cacheNewChildLocked(child, name)
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
// Preconditions: fs.renameMu must be locked. !rp.Done(). If
// !d.cachedMetadataAuthoritative(), then d's cached metadata must be up to
// date.
func (fs *filesystem) walkParentDirLocked(ctx context.Context, rp *vfs.ResolvingPath, d *dentry, ds **[]*dentry) (*dentry, error) {
	for !rp.Final() {
		d.dirMu.Lock()
		next, err := fs.stepLocked(ctx, rp, d, true /* mayFollowSymlinks */, ds)
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
	if !d.cachedMetadataAuthoritative() {
		// Get updated metadata for rp.Start() as required by fs.stepLocked().
		if err := d.updateFromGetattr(ctx); err != nil {
			return nil, err
		}
	}
	for !rp.Done() {
		d.dirMu.Lock()
		next, err := fs.stepLocked(ctx, rp, d, true /* mayFollowSymlinks */, ds)
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
// createInRemoteDir (if the parent directory is a real remote directory) or
// createInSyntheticDir (if the parent directory is synthetic) to do so.
//
// Preconditions: !rp.Done(). For the final path component in rp,
// !rp.ShouldFollowSymlink().
func (fs *filesystem) doCreateAt(ctx context.Context, rp *vfs.ResolvingPath, dir bool, createInRemoteDir func(parent *dentry, name string) error, createInSyntheticDir func(parent *dentry, name string) error) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	start := rp.Start().Impl().(*dentry)
	if !start.cachedMetadataAuthoritative() {
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
	if err := parent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
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
	if parent.isDeleted() {
		return syserror.ENOENT
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	parent.dirMu.Lock()
	defer parent.dirMu.Unlock()
	if parent.isSynthetic() {
		if child := parent.children[name]; child != nil {
			return syserror.EEXIST
		}
		if createInSyntheticDir == nil {
			return syserror.EPERM
		}
		if err := createInSyntheticDir(parent, name); err != nil {
			return err
		}
		parent.touchCMtime()
		parent.dirents = nil
		return nil
	}
	if fs.opts.interop == InteropModeShared {
		if child := parent.children[name]; child != nil && child.isSynthetic() {
			return syserror.EEXIST
		}
		// The existence of a non-synthetic dentry at name would be inconclusive
		// because the file it represents may have been deleted from the remote
		// filesystem, so we would need to make an RPC to revalidate the dentry.
		// Just attempt the file creation RPC instead. If a file does exist, the
		// RPC will fail with EEXIST like we would have. If the RPC succeeds, and a
		// stale dentry exists, the dentry will fail revalidation next time it's
		// used.
		return createInRemoteDir(parent, name)
	}
	if child := parent.children[name]; child != nil {
		return syserror.EEXIST
	}
	// No cached dentry exists; however, there might still be an existing file
	// at name. As above, we attempt the file creation RPC anyway.
	if err := createInRemoteDir(parent, name); err != nil {
		return err
	}
	if child, ok := parent.children[name]; ok && child == nil {
		// Delete the now-stale negative dentry.
		delete(parent.children, name)
	}
	parent.touchCMtime()
	parent.dirents = nil
	return nil
}

// Preconditions: !rp.Done().
func (fs *filesystem) unlinkAt(ctx context.Context, rp *vfs.ResolvingPath, dir bool) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	start := rp.Start().Impl().(*dentry)
	if !start.cachedMetadataAuthoritative() {
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
	if err := parent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
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
	child, ok := parent.children[name]
	if ok && child == nil {
		return syserror.ENOENT
	}
	// We only need a dentry representing the file at name if it can be a mount
	// point. If child is nil, then it can't be a mount point. If child is
	// non-nil but stale, the actual file can't be a mount point either; we
	// detect this case by just speculatively calling PrepareDeleteDentry and
	// only revalidating the dentry if that fails (indicating that the existing
	// dentry is a mount point).
	if child != nil {
		child.dirMu.Lock()
		defer child.dirMu.Unlock()
		if err := vfsObj.PrepareDeleteDentry(mntns, &child.vfsd); err != nil {
			if parent.cachedMetadataAuthoritative() {
				return err
			}
			child, err = fs.revalidateChildLocked(ctx, vfsObj, parent, name, child, &ds)
			if err != nil {
				return err
			}
			if child != nil {
				if err := vfsObj.PrepareDeleteDentry(mntns, &child.vfsd); err != nil {
					return err
				}
			}
		}
	}
	flags := uint32(0)
	// If a dentry exists, use it for best-effort checks on its deletability.
	if dir {
		if child != nil {
			// child must be an empty directory.
			if child.syntheticChildren != 0 {
				// This is definitely not an empty directory, irrespective of
				// fs.opts.interop.
				vfsObj.AbortDeleteDentry(&child.vfsd)
				return syserror.ENOTEMPTY
			}
			// If InteropModeShared is in effect and the first call to
			// PrepareDeleteDentry above succeeded, then child wasn't
			// revalidated (so we can't expect its file type to be correct) and
			// individually revalidating its children (to confirm that they
			// still exist) would be a waste of time.
			if child.cachedMetadataAuthoritative() {
				if !child.isDir() {
					vfsObj.AbortDeleteDentry(&child.vfsd)
					return syserror.ENOTDIR
				}
				for _, grandchild := range child.children {
					if grandchild != nil {
						vfsObj.AbortDeleteDentry(&child.vfsd)
						return syserror.ENOTEMPTY
					}
				}
			}
		}
		flags = linux.AT_REMOVEDIR
	} else {
		// child must be a non-directory file.
		if child != nil && child.isDir() {
			vfsObj.AbortDeleteDentry(&child.vfsd)
			return syserror.EISDIR
		}
		if rp.MustBeDir() {
			if child != nil {
				vfsObj.AbortDeleteDentry(&child.vfsd)
			}
			return syserror.ENOTDIR
		}
	}
	if parent.isSynthetic() {
		if child == nil {
			return syserror.ENOENT
		}
	} else if child == nil || !child.isSynthetic() {
		err = parent.file.unlinkAt(ctx, name, flags)
		if err != nil {
			if child != nil {
				vfsObj.AbortDeleteDentry(&child.vfsd)
			}
			return err
		}
	}
	if child != nil {
		vfsObj.CommitDeleteDentry(&child.vfsd)
		child.setDeleted()
		if child.isSynthetic() {
			parent.syntheticChildren--
			child.decRefLocked()
		}
		ds = appendDentry(ds, child)
	}
	parent.cacheNegativeLookupLocked(name)
	if parent.cachedMetadataAuthoritative() {
		parent.dirents = nil
		parent.touchCMtime()
		if dir {
			parent.decLinks()
		}
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
	return d.checkPermissions(creds, ats)
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
		if err := d.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
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
	if !start.cachedMetadataAuthoritative() {
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
	}, nil)
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	creds := rp.Credentials()
	return fs.doCreateAt(ctx, rp, true /* dir */, func(parent *dentry, name string) error {
		if _, err := parent.file.mkdir(ctx, name, (p9.FileMode)(opts.Mode), (p9.UID)(creds.EffectiveKUID), (p9.GID)(creds.EffectiveKGID)); err != nil {
			if !opts.ForSyntheticMountpoint || err == syserror.EEXIST {
				return err
			}
			ctx.Infof("Failed to create remote directory %q: %v; falling back to synthetic directory", name, err)
			parent.createSyntheticChildLocked(&createSyntheticOpts{
				name: name,
				mode: linux.S_IFDIR | opts.Mode,
				kuid: creds.EffectiveKUID,
				kgid: creds.EffectiveKGID,
			})
		}
		if fs.opts.interop != InteropModeShared {
			parent.incLinks()
		}
		return nil
	}, func(parent *dentry, name string) error {
		if !opts.ForSyntheticMountpoint {
			// Can't create non-synthetic files in synthetic directories.
			return syserror.EPERM
		}
		parent.createSyntheticChildLocked(&createSyntheticOpts{
			name: name,
			mode: linux.S_IFDIR | opts.Mode,
			kuid: creds.EffectiveKUID,
			kgid: creds.EffectiveKGID,
		})
		parent.incLinks()
		return nil
	})
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	return fs.doCreateAt(ctx, rp, false /* dir */, func(parent *dentry, name string) error {
		creds := rp.Credentials()
		_, err := parent.file.mknod(ctx, name, (p9.FileMode)(opts.Mode), opts.DevMajor, opts.DevMinor, (p9.UID)(creds.EffectiveKUID), (p9.GID)(creds.EffectiveKGID))
		// If the gofer does not allow creating a socket or pipe, create a
		// synthetic one, i.e. one that is kept entirely in memory.
		if err == syserror.EPERM {
			switch opts.Mode.FileType() {
			case linux.S_IFSOCK:
				parent.createSyntheticChildLocked(&createSyntheticOpts{
					name:     name,
					mode:     opts.Mode,
					kuid:     creds.EffectiveKUID,
					kgid:     creds.EffectiveKGID,
					endpoint: opts.Endpoint,
				})
				return nil
			case linux.S_IFIFO:
				parent.createSyntheticChildLocked(&createSyntheticOpts{
					name: name,
					mode: opts.Mode,
					kuid: creds.EffectiveKUID,
					kgid: creds.EffectiveKGID,
					pipe: pipe.NewVFSPipe(true /* isNamed */, pipe.DefaultPipeSize, usermem.PageSize),
				})
				return nil
			}
		}
		return err
	}, nil)
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
	if !start.cachedMetadataAuthoritative() {
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
	if err := parent.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, err
	}
	// Determine whether or not we need to create a file.
	parent.dirMu.Lock()
	child, err := fs.stepLocked(ctx, rp, parent, false /* mayFollowSymlinks */, &ds)
	if err == syserror.ENOENT && mayCreate {
		if parent.isSynthetic() {
			parent.dirMu.Unlock()
			return nil, syserror.EPERM
		}
		fd, err := parent.createAndOpenChildLocked(ctx, rp, &opts, &ds)
		parent.dirMu.Unlock()
		return fd, err
	}
	parent.dirMu.Unlock()
	if err != nil {
		return nil, err
	}
	if mustCreate {
		return nil, syserror.EEXIST
	}
	if !child.isDir() && rp.MustBeDir() {
		return nil, syserror.ENOTDIR
	}
	// Open existing child or follow symlink.
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
	if err := d.checkPermissions(rp.Credentials(), ats); err != nil {
		return nil, err
	}
	mnt := rp.Mount()
	switch d.fileType() {
	case linux.S_IFREG:
		if !d.fs.opts.regularFilesUseSpecialFileFD {
			if err := d.ensureSharedHandle(ctx, ats&vfs.MayRead != 0, ats&vfs.MayWrite != 0, opts.Flags&linux.O_TRUNC != 0); err != nil {
				return nil, err
			}
			fd := &regularFileFD{}
			fd.LockFD.Init(&d.locks)
			if err := fd.vfsfd.Init(fd, opts.Flags, mnt, &d.vfsd, &vfs.FileDescriptionOptions{
				AllowDirectIO: true,
			}); err != nil {
				return nil, err
			}
			return &fd.vfsfd, nil
		}
	case linux.S_IFDIR:
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
		if !d.isSynthetic() {
			if err := d.ensureSharedHandle(ctx, ats&vfs.MayRead != 0, false /* write */, false /* trunc */); err != nil {
				return nil, err
			}
		}
		fd := &directoryFD{}
		fd.LockFD.Init(&d.locks)
		if err := fd.vfsfd.Init(fd, opts.Flags, mnt, &d.vfsd, &vfs.FileDescriptionOptions{}); err != nil {
			return nil, err
		}
		return &fd.vfsfd, nil
	case linux.S_IFLNK:
		// Can't open symlinks without O_PATH (which is unimplemented).
		return nil, syserror.ELOOP
	case linux.S_IFSOCK:
		if d.isSynthetic() {
			return nil, syserror.ENXIO
		}
		if d.fs.iopts.OpenSocketsByConnecting {
			return d.connectSocketLocked(ctx, opts)
		}
	case linux.S_IFIFO:
		if d.isSynthetic() {
			return d.pipe.Open(ctx, mnt, &d.vfsd, opts.Flags, &d.locks)
		}
	}
	return d.openSpecialFileLocked(ctx, mnt, opts)
}

func (d *dentry) connectSocketLocked(ctx context.Context, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	if opts.Flags&linux.O_DIRECT != 0 {
		return nil, syserror.EINVAL
	}
	fdObj, err := d.file.connect(ctx, p9.AnonymousSocket)
	if err != nil {
		return nil, err
	}
	fd, err := host.NewFD(ctx, kernel.KernelFromContext(ctx).HostMount(), fdObj.FD(), &host.NewFDOptions{
		HaveFlags: true,
		Flags:     opts.Flags,
	})
	if err != nil {
		fdObj.Close()
		return nil, err
	}
	fdObj.Release()
	return fd, nil
}

func (d *dentry) openSpecialFileLocked(ctx context.Context, mnt *vfs.Mount, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	ats := vfs.AccessTypesForOpenFlags(opts)
	if opts.Flags&linux.O_DIRECT != 0 {
		return nil, syserror.EINVAL
	}
	// We assume that the server silently inserts O_NONBLOCK in the open flags
	// for all named pipes (because all existing gofers do this).
	//
	// NOTE(b/133875563): This makes named pipe opens racy, because the
	// mechanisms for translating nonblocking to blocking opens can only detect
	// the instantaneous presence of a peer holding the other end of the pipe
	// open, not whether the pipe was *previously* opened by a peer that has
	// since closed its end.
	isBlockingOpenOfNamedPipe := d.fileType() == linux.S_IFIFO && opts.Flags&linux.O_NONBLOCK == 0
retry:
	h, err := openHandle(ctx, d.file, ats.MayRead(), ats.MayWrite(), opts.Flags&linux.O_TRUNC != 0)
	if err != nil {
		if isBlockingOpenOfNamedPipe && ats == vfs.MayWrite && err == syserror.ENXIO {
			// An attempt to open a named pipe with O_WRONLY|O_NONBLOCK fails
			// with ENXIO if opening the same named pipe with O_WRONLY would
			// block because there are no readers of the pipe.
			if err := sleepBetweenNamedPipeOpenChecks(ctx); err != nil {
				return nil, err
			}
			goto retry
		}
		return nil, err
	}
	if isBlockingOpenOfNamedPipe && ats == vfs.MayRead && h.fd >= 0 {
		if err := blockUntilNonblockingPipeHasWriter(ctx, h.fd); err != nil {
			h.close(ctx)
			return nil, err
		}
	}
	fd, err := newSpecialFileFD(h, mnt, d, &d.locks, opts.Flags)
	if err != nil {
		h.close(ctx)
		return nil, err
	}
	return &fd.vfsfd, nil
}

// Preconditions: d.fs.renameMu must be locked. d.dirMu must be locked.
// !d.isSynthetic().
func (d *dentry) createAndOpenChildLocked(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions, ds **[]*dentry) (*vfs.FileDescription, error) {
	if err := d.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
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
	// Filter file creation flags and O_LARGEFILE out; the create RPC already
	// has the semantics of O_CREAT|O_EXCL, while some servers will choke on
	// O_LARGEFILE.
	createFlags := p9.OpenFlags(opts.Flags &^ (vfs.FileCreationFlags | linux.O_LARGEFILE))
	fdobj, openFile, createQID, _, err := dirfile.create(ctx, name, createFlags, (p9.FileMode)(opts.Mode), (p9.UID)(creds.EffectiveKUID), (p9.GID)(creds.EffectiveKGID))
	if err != nil {
		dirfile.close(ctx)
		return nil, err
	}
	// Then we need to walk to the file we just created to get a non-open fid
	// representing it, and to get its metadata. This must use d.file since, as
	// explained above, dirfile was invalidated by dirfile.Create().
	_, nonOpenFile, attrMask, attr, err := d.file.walkGetAttrOne(ctx, name)
	if err != nil {
		openFile.close(ctx)
		if fdobj != nil {
			fdobj.Close()
		}
		return nil, err
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
	*ds = appendDentry(*ds, child)
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
	// Insert the dentry into the tree.
	d.cacheNewChildLocked(child, name)
	if d.cachedMetadataAuthoritative() {
		d.touchCMtime()
		d.dirents = nil
	}

	// Finally, construct a file description representing the created file.
	var childVFSFD *vfs.FileDescription
	if useRegularFileFD {
		fd := &regularFileFD{}
		fd.LockFD.Init(&child.locks)
		if err := fd.vfsfd.Init(fd, opts.Flags, mnt, &child.vfsd, &vfs.FileDescriptionOptions{
			AllowDirectIO: true,
		}); err != nil {
			return nil, err
		}
		childVFSFD = &fd.vfsfd
	} else {
		h := handle{
			file: openFile,
			fd:   -1,
		}
		if fdobj != nil {
			h.fd = int32(fdobj.Release())
		}
		fd, err := newSpecialFileFD(h, mnt, child, &d.locks, opts.Flags)
		if err != nil {
			h.close(ctx)
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
	if !oldParent.cachedMetadataAuthoritative() {
		if err := oldParent.updateFromGetattr(ctx); err != nil {
			return err
		}
	}
	if err := oldParent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	vfsObj := rp.VirtualFilesystem()
	// We need a dentry representing the renamed file since, if it's a
	// directory, we need to check for write permission on it.
	oldParent.dirMu.Lock()
	defer oldParent.dirMu.Unlock()
	renamed, err := fs.getChildLocked(ctx, vfsObj, oldParent, oldName, &ds)
	if err != nil {
		return err
	}
	if renamed == nil {
		return syserror.ENOENT
	}
	if renamed.isDir() {
		if renamed == newParent || genericIsAncestorDentry(renamed, newParent) {
			return syserror.EINVAL
		}
		if oldParent != newParent {
			if err := renamed.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
				return err
			}
		}
	} else {
		if opts.MustBeDir || rp.MustBeDir() {
			return syserror.ENOTDIR
		}
	}

	if oldParent != newParent {
		if err := newParent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
			return err
		}
		newParent.dirMu.Lock()
		defer newParent.dirMu.Unlock()
	}
	if newParent.isDeleted() {
		return syserror.ENOENT
	}
	replaced, err := fs.getChildLocked(ctx, rp.VirtualFilesystem(), newParent, newName, &ds)
	if err != nil {
		return err
	}
	var replacedVFSD *vfs.Dentry
	if replaced != nil {
		replacedVFSD = &replaced.vfsd
		if replaced.isDir() {
			if !renamed.isDir() {
				return syserror.EISDIR
			}
		} else {
			if rp.MustBeDir() || renamed.isDir() {
				return syserror.ENOTDIR
			}
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

	// Update the remote filesystem.
	if !renamed.isSynthetic() {
		if err := renamed.file.rename(ctx, newParent.file, newName); err != nil {
			vfsObj.AbortRenameDentry(&renamed.vfsd, replacedVFSD)
			return err
		}
	} else if replaced != nil && !replaced.isSynthetic() {
		// We are replacing an existing real file with a synthetic one, so we
		// need to unlink the former.
		flags := uint32(0)
		if replaced.isDir() {
			flags = linux.AT_REMOVEDIR
		}
		if err := newParent.file.unlinkAt(ctx, newName, flags); err != nil {
			vfsObj.AbortRenameDentry(&renamed.vfsd, replacedVFSD)
			return err
		}
	}

	// Update the dentry tree.
	vfsObj.CommitRenameReplaceDentry(&renamed.vfsd, replacedVFSD)
	if replaced != nil {
		replaced.setDeleted()
		if replaced.isSynthetic() {
			newParent.syntheticChildren--
			replaced.decRefLocked()
		}
		ds = appendDentry(ds, replaced)
	}
	oldParent.cacheNegativeLookupLocked(oldName)
	// We don't use newParent.cacheNewChildLocked() since we don't want to mess
	// with reference counts and queue oldParent for checkCachingLocked if the
	// parent isn't actually changing.
	if oldParent != newParent {
		ds = appendDentry(ds, oldParent)
		newParent.IncRef()
		if renamed.isSynthetic() {
			oldParent.syntheticChildren--
			newParent.syntheticChildren++
		}
	}
	renamed.parent = newParent
	renamed.name = newName
	if newParent.children == nil {
		newParent.children = make(map[string]*dentry)
	}
	newParent.children[newName] = renamed

	// Update metadata.
	if renamed.cachedMetadataAuthoritative() {
		renamed.touchCtime()
	}
	if oldParent.cachedMetadataAuthoritative() {
		oldParent.dirents = nil
		oldParent.touchCMtime()
		if renamed.isDir() {
			oldParent.decLinks()
		}
	}
	if newParent.cachedMetadataAuthoritative() {
		newParent.dirents = nil
		newParent.touchCMtime()
		if renamed.isDir() && (replaced == nil || !replaced.isDir()) {
			// Increase the link count if we did not replace another directory.
			newParent.incLinks()
		}
	}
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
	// If d is synthetic, invoke statfs on the first ancestor of d that isn't.
	for d.isSynthetic() {
		d = d.parent
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
	}, nil)
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	return fs.unlinkAt(ctx, rp, false /* dir */)
}

// BoundEndpointAt implements FilesystemImpl.BoundEndpointAt.
func (fs *filesystem) BoundEndpointAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.BoundEndpointOptions) (transport.BoundEndpoint, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return nil, err
	}
	if err := d.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
		return nil, err
	}
	if d.isSocket() {
		if !d.isSynthetic() {
			d.IncRef()
			return &endpoint{
				dentry: d,
				file:   d.file.file,
				path:   opts.Addr,
			}, nil
		}
		return d.endpoint, nil
	}
	return nil, syserror.ECONNREFUSED
}

// ListxattrAt implements vfs.FilesystemImpl.ListxattrAt.
func (fs *filesystem) ListxattrAt(ctx context.Context, rp *vfs.ResolvingPath, size uint64) ([]string, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return nil, err
	}
	return d.listxattr(ctx, rp.Credentials(), size)
}

// GetxattrAt implements vfs.FilesystemImpl.GetxattrAt.
func (fs *filesystem) GetxattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetxattrOptions) (string, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(&ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return "", err
	}
	return d.getxattr(ctx, rp.Credentials(), &opts)
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
	return d.setxattr(ctx, rp.Credentials(), &opts)
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
	return d.removexattr(ctx, rp.Credentials(), name)
}

// PrependPath implements vfs.FilesystemImpl.PrependPath.
func (fs *filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	fs.renameMu.RLock()
	defer fs.renameMu.RUnlock()
	return genericPrependPath(vfsroot, vd.Mount(), vd.Dentry().Impl().(*dentry), b)
}
