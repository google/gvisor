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
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/fsmetric"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Sync implements vfs.FilesystemImpl.Sync.
func (fs *filesystem) Sync(ctx context.Context) error {
	// Snapshot current syncable dentries and special file FDs.
	fs.renameMu.RLock()
	fs.syncMu.Lock()
	ds := make([]*dentry, 0, len(fs.syncableDentries))
	for d := range fs.syncableDentries {
		// It's safe to use IncRef here even though fs.syncableDentries doesn't
		// hold references since we hold fs.renameMu. Note that we can't use
		// TryIncRef since cached dentries at zero references should still be
		// synced.
		d.IncRef()
		ds = append(ds, d)
	}
	fs.renameMu.RUnlock()
	sffds := make([]*specialFileFD, 0, len(fs.specialFileFDs))
	for sffd := range fs.specialFileFDs {
		// As above, fs.specialFileFDs doesn't hold references. However, unlike
		// dentries, an FD that has reached zero references can't be
		// resurrected, so we can use TryIncRef.
		if sffd.vfsfd.TryIncRef() {
			sffds = append(sffds, sffd)
		}
	}
	fs.syncMu.Unlock()

	// Return the first error we encounter, but sync everything we can
	// regardless.
	var retErr error

	// Sync syncable dentries.
	for _, d := range ds {
		err := d.syncCachedFile(ctx, true /* forFilesystemSync */)
		d.DecRef(ctx)
		if err != nil {
			ctx.Infof("gofer.filesystem.Sync: dentry.syncCachedFile failed: %v", err)
			if retErr == nil {
				retErr = err
			}
		}
	}

	// Sync special files, which may be writable but do not use dentry shared
	// handles (so they won't be synced by the above).
	for _, sffd := range sffds {
		err := sffd.sync(ctx, true /* forFilesystemSync */)
		sffd.vfsfd.DecRef(ctx)
		if err != nil {
			ctx.Infof("gofer.filesystem.Sync: specialFileFD.sync failed: %v", err)
			if retErr == nil {
				retErr = err
			}
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

// renameMuRUnlockAndCheckCaching calls fs.renameMu.RUnlock(), then calls
// dentry.checkCachingLocked on all dentries in *dsp with fs.renameMu locked
// for writing.
//
// dsp is a pointer-to-pointer since defer evaluates its arguments immediately,
// but dentry slices are allocated lazily, and it's much easier to say "defer
// fs.renameMuRUnlockAndCheckCaching(&ds)" than "defer func() {
// fs.renameMuRUnlockAndCheckCaching(ds) }()" to work around this.
func (fs *filesystem) renameMuRUnlockAndCheckCaching(ctx context.Context, dsp **[]*dentry) {
	fs.renameMu.RUnlock()
	if *dsp == nil {
		return
	}
	ds := **dsp
	for _, d := range ds {
		d.checkCachingLocked(ctx, false /* renameMuWriteLocked */)
	}
	putDentrySlice(*dsp)
}

func (fs *filesystem) renameMuUnlockAndCheckCaching(ctx context.Context, ds **[]*dentry) {
	if *ds == nil {
		fs.renameMu.Unlock()
		return
	}
	for _, d := range **ds {
		d.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
	}
	fs.renameMu.Unlock()
	putDentrySlice(*ds)
}

// stepLocked resolves rp.Component() to an existing file, starting from the
// given directory.
//
// Dentries which may become cached as a result of the traversal are appended
// to *ds.
//
// Preconditions:
// * fs.renameMu must be locked.
// * d.dirMu must be locked.
// * !rp.Done().
// * If !d.cachedMetadataAuthoritative(), then d's cached metadata must be up
//   to date.
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
		if isRoot, err := rp.CheckRoot(ctx, &d.vfsd); err != nil {
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
		if err := rp.CheckMount(ctx, &d.parent.vfsd); err != nil {
			return nil, err
		}
		if d != d.parent && !d.cachedMetadataAuthoritative() {
			if err := d.parent.updateFromGetattr(ctx); err != nil {
				return nil, err
			}
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
	if err := rp.CheckMount(ctx, &child.vfsd); err != nil {
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
// Preconditions:
// * fs.renameMu must be locked.
// * parent.dirMu must be locked.
// * parent.isDir().
// * name is not "." or "..".
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

// Preconditions: Same as getChildLocked, plus:
// * !parent.isSynthetic().
func (fs *filesystem) revalidateChildLocked(ctx context.Context, vfsObj *vfs.VirtualFilesystem, parent *dentry, name string, child *dentry, ds **[]*dentry) (*dentry, error) {
	if child != nil {
		// Need to lock child.metadataMu because we might be updating child
		// metadata. We need to hold the lock *before* getting metadata from the
		// server and release it after updating local metadata.
		child.metadataMu.Lock()
	}
	qid, file, attrMask, attr, err := parent.file.walkGetAttrOne(ctx, name)
	if err != nil && err != syserror.ENOENT {
		if child != nil {
			child.metadataMu.Unlock()
		}
		return nil, err
	}
	if child != nil {
		if !file.isNil() && qid.Path == child.qidPath {
			// The file at this path hasn't changed. Just update cached metadata.
			file.close(ctx)
			child.updateFromP9AttrsLocked(attrMask, &attr)
			child.metadataMu.Unlock()
			return child, nil
		}
		child.metadataMu.Unlock()
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
		vfsObj.InvalidateDentry(ctx, &child.vfsd)
		if child.isSynthetic() {
			// Normally we don't mark invalidated dentries as deleted since
			// they may still exist (but at a different path), and also for
			// consistency with Linux. However, synthetic files are guaranteed
			// to become unreachable if their dentries are invalidated, so
			// treat their invalidation as deletion.
			child.setDeleted()
			parent.syntheticChildren--
			child.decRefNoCaching()
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
// Preconditions:
// * fs.renameMu must be locked.
// * !rp.Done().
// * If !d.cachedMetadataAuthoritative(), then d's cached metadata must be up
//   to date.
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
// Preconditions:
// * !rp.Done().
// * For the final path component in rp, !rp.ShouldFollowSymlink().
func (fs *filesystem) doCreateAt(ctx context.Context, rp *vfs.ResolvingPath, dir bool, createInRemoteDir func(parent *dentry, name string, ds **[]*dentry) error, createInSyntheticDir func(parent *dentry, name string) error) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
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

	// Order of checks is important. First check if parent directory can be
	// executed, then check for existence, and lastly check if mount is writable.
	if err := parent.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return syserror.EEXIST
	}
	if parent.isDeleted() {
		return syserror.ENOENT
	}

	parent.dirMu.Lock()
	defer parent.dirMu.Unlock()

	child, err := fs.getChildLocked(ctx, rp.VirtualFilesystem(), parent, name, &ds)
	switch {
	case err != nil && err != syserror.ENOENT:
		return err
	case child != nil:
		return syserror.EEXIST
	}

	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()

	if err := parent.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
		return err
	}
	if !dir && rp.MustBeDir() {
		return syserror.ENOENT
	}
	if parent.isSynthetic() {
		if createInSyntheticDir == nil {
			return syserror.EPERM
		}
		if err := createInSyntheticDir(parent, name); err != nil {
			return err
		}
		parent.touchCMtime()
		parent.dirents = nil
		ev := linux.IN_CREATE
		if dir {
			ev |= linux.IN_ISDIR
		}
		parent.watches.Notify(ctx, name, uint32(ev), 0, vfs.InodeEvent, false /* unlinked */)
		return nil
	}
	// No cached dentry exists; however, in InteropModeShared there might still be
	// an existing file at name. Just attempt the file creation RPC anyways. If a
	// file does exist, the RPC will fail with EEXIST like we would have.
	if err := createInRemoteDir(parent, name, &ds); err != nil {
		return err
	}
	if fs.opts.interop != InteropModeShared {
		if child, ok := parent.children[name]; ok && child == nil {
			// Delete the now-stale negative dentry.
			delete(parent.children, name)
		}
		parent.touchCMtime()
		parent.dirents = nil
	}
	ev := linux.IN_CREATE
	if dir {
		ev |= linux.IN_ISDIR
	}
	parent.watches.Notify(ctx, name, uint32(ev), 0, vfs.InodeEvent, false /* unlinked */)
	return nil
}

// Preconditions: !rp.Done().
func (fs *filesystem) unlinkAt(ctx context.Context, rp *vfs.ResolvingPath, dir bool) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
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
	defer mntns.DecRef(ctx)
	parent.dirMu.Lock()
	defer parent.dirMu.Unlock()

	child, ok := parent.children[name]
	if ok && child == nil {
		return syserror.ENOENT
	}

	sticky := atomic.LoadUint32(&parent.mode)&linux.ModeSticky != 0
	if sticky {
		if !ok {
			// If the sticky bit is set, we need to retrieve the child to determine
			// whether removing it is allowed.
			child, err = fs.stepLocked(ctx, rp, parent, false /* mayFollowSymlinks */, &ds)
			if err != nil {
				return err
			}
		} else if child != nil && !child.cachedMetadataAuthoritative() {
			// Make sure the dentry representing the file at name is up to date
			// before examining its metadata.
			child, err = fs.revalidateChildLocked(ctx, vfsObj, parent, name, child, &ds)
			if err != nil {
				return err
			}
		}
		if err := parent.mayDelete(rp.Credentials(), child); err != nil {
			return err
		}
	}

	// If a child dentry exists, prepare to delete it. This should fail if it is
	// a mount point. We detect mount points by speculatively calling
	// PrepareDeleteDentry, which fails if child is a mount point. However, we
	// may need to revalidate the file in this case to make sure that it has not
	// been deleted or replaced on the remote fs, in which case the mount point
	// will have disappeared. If calling PrepareDeleteDentry fails again on the
	// up-to-date dentry, we can be sure that it is a mount point.
	//
	// Also note that if child is nil, then it can't be a mount point.
	if child != nil {
		// Hold child.dirMu so we can check child.children and
		// child.syntheticChildren. We don't access these fields until a bit later,
		// but locking child.dirMu after calling vfs.PrepareDeleteDentry() would
		// create an inconsistent lock ordering between dentry.dirMu and
		// vfs.Dentry.mu (in the VFS lock order, it would make dentry.dirMu both "a
		// FilesystemImpl lock" and "a lock acquired by a FilesystemImpl between
		// PrepareDeleteDentry and CommitDeleteDentry). To avoid this, lock
		// child.dirMu before calling PrepareDeleteDentry.
		child.dirMu.Lock()
		defer child.dirMu.Unlock()
		if err := vfsObj.PrepareDeleteDentry(mntns, &child.vfsd); err != nil {
			// We can skip revalidation in several cases:
			// - We are not in InteropModeShared
			// - The parent directory is synthetic, in which case the child must also
			//   be synthetic
			// - We already updated the child during the sticky bit check above
			if parent.cachedMetadataAuthoritative() || sticky {
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

	// Generate inotify events for rmdir or unlink.
	if dir {
		parent.watches.Notify(ctx, name, linux.IN_DELETE|linux.IN_ISDIR, 0, vfs.InodeEvent, true /* unlinked */)
	} else {
		var cw *vfs.Watches
		if child != nil {
			cw = &child.watches
		}
		vfs.InotifyRemoveChild(ctx, cw, &parent.watches, name)
	}

	if child != nil {
		vfsObj.CommitDeleteDentry(ctx, &child.vfsd)
		child.setDeleted()
		if child.isSynthetic() {
			parent.syntheticChildren--
			child.decRefNoCaching()
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

// AccessAt implements vfs.Filesystem.Impl.AccessAt.
func (fs *filesystem) AccessAt(ctx context.Context, rp *vfs.ResolvingPath, creds *auth.Credentials, ats vfs.AccessTypes) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
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
	defer fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
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
	defer fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
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
	return fs.doCreateAt(ctx, rp, false /* dir */, func(parent *dentry, childName string, _ **[]*dentry) error {
		if rp.Mount() != vd.Mount() {
			return syserror.EXDEV
		}
		d := vd.Dentry().Impl().(*dentry)
		if d.isDir() {
			return syserror.EPERM
		}
		gid := auth.KGID(atomic.LoadUint32(&d.gid))
		uid := auth.KUID(atomic.LoadUint32(&d.uid))
		mode := linux.FileMode(atomic.LoadUint32(&d.mode))
		if err := vfs.MayLink(rp.Credentials(), mode, uid, gid); err != nil {
			return err
		}
		if d.nlink == 0 {
			return syserror.ENOENT
		}
		if d.nlink == math.MaxUint32 {
			return syserror.EMLINK
		}
		if err := parent.file.link(ctx, d.file, childName); err != nil {
			return err
		}

		// Success!
		atomic.AddUint32(&d.nlink, 1)
		return nil
	}, nil)
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	creds := rp.Credentials()
	return fs.doCreateAt(ctx, rp, true /* dir */, func(parent *dentry, name string, _ **[]*dentry) error {
		// If the parent is a setgid directory, use the parent's GID
		// rather than the caller's and enable setgid.
		kgid := creds.EffectiveKGID
		mode := opts.Mode
		if atomic.LoadUint32(&parent.mode)&linux.S_ISGID != 0 {
			kgid = auth.KGID(atomic.LoadUint32(&parent.gid))
			mode |= linux.S_ISGID
		}
		if _, err := parent.file.mkdir(ctx, name, p9.FileMode(mode), (p9.UID)(creds.EffectiveKUID), p9.GID(kgid)); err != nil {
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
	return fs.doCreateAt(ctx, rp, false /* dir */, func(parent *dentry, name string, ds **[]*dentry) error {
		creds := rp.Credentials()
		_, err := parent.file.mknod(ctx, name, (p9.FileMode)(opts.Mode), opts.DevMajor, opts.DevMinor, (p9.UID)(creds.EffectiveKUID), (p9.GID)(creds.EffectiveKGID))
		if err != syserror.EPERM {
			return err
		}

		// EPERM means that gofer does not allow creating a socket or pipe. Fallback
		// to creating a synthetic one, i.e. one that is kept entirely in memory.

		// Check that we're not overriding an existing file with a synthetic one.
		_, err = fs.stepLocked(ctx, rp, parent, true, ds)
		switch {
		case err == nil:
			// Step succeeded, another file exists.
			return syserror.EEXIST
		case err != syserror.ENOENT:
			// Unexpected error.
			return err
		}

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
				pipe: pipe.NewVFSPipe(true /* isNamed */, pipe.DefaultPipeSize),
			})
			return nil
		}
		// Retain error from gofer if synthetic file cannot be created internally.
		return syserror.EPERM
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
	unlocked := false
	unlock := func() {
		if !unlocked {
			fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
			unlocked = true
		}
	}
	defer unlock()

	start := rp.Start().Impl().(*dentry)
	if !start.cachedMetadataAuthoritative() {
		// Get updated metadata for start as required by fs.stepLocked().
		if err := start.updateFromGetattr(ctx); err != nil {
			return nil, err
		}
	}
	if rp.Done() {
		// Reject attempts to open mount root directory with O_CREAT.
		if mayCreate && rp.MustBeDir() {
			return nil, syserror.EISDIR
		}
		if mustCreate {
			return nil, syserror.EEXIST
		}
		start.IncRef()
		defer start.DecRef(ctx)
		unlock()
		return start.open(ctx, rp, &opts)
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
	// Reject attempts to open directories with O_CREAT.
	if mayCreate && rp.MustBeDir() {
		return nil, syserror.EISDIR
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
	if rp.MustBeDir() && !child.isDir() {
		return nil, syserror.ENOTDIR
	}
	child.IncRef()
	defer child.DecRef(ctx)
	unlock()
	return child.open(ctx, rp, &opts)
}

// Preconditions: The caller must hold no locks (since opening pipes may block
// indefinitely).
func (d *dentry) open(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	ats := vfs.AccessTypesForOpenFlags(opts)
	if err := d.checkPermissions(rp.Credentials(), ats); err != nil {
		return nil, err
	}

	trunc := opts.Flags&linux.O_TRUNC != 0 && d.fileType() == linux.S_IFREG
	if trunc {
		// Lock metadataMu *while* we open a regular file with O_TRUNC because
		// open(2) will change the file size on server.
		d.metadataMu.Lock()
		defer d.metadataMu.Unlock()
	}

	var vfd *vfs.FileDescription
	var err error
	mnt := rp.Mount()
	switch d.fileType() {
	case linux.S_IFREG:
		if !d.fs.opts.regularFilesUseSpecialFileFD {
			if err := d.ensureSharedHandle(ctx, ats.MayRead(), ats.MayWrite(), trunc); err != nil {
				return nil, err
			}
			fd, err := newRegularFileFD(mnt, d, opts.Flags)
			if err != nil {
				return nil, err
			}
			vfd = &fd.vfsfd
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
		if atomic.LoadInt32(&d.readFD) >= 0 {
			fsmetric.GoferOpensHost.Increment()
		} else {
			fsmetric.GoferOpens9P.Increment()
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
			return d.openSocketByConnecting(ctx, opts)
		}
	case linux.S_IFIFO:
		if d.isSynthetic() {
			return d.pipe.Open(ctx, mnt, &d.vfsd, opts.Flags, &d.locks)
		}
	}

	if vfd == nil {
		if vfd, err = d.openSpecialFile(ctx, mnt, opts); err != nil {
			return nil, err
		}
	}

	if trunc {
		// If no errors occured so far then update file size in memory. This
		// step is required even if !d.cachedMetadataAuthoritative() because
		// d.mappings has to be updated.
		// d.metadataMu has already been acquired if trunc == true.
		d.updateSizeLocked(0)

		if d.cachedMetadataAuthoritative() {
			d.touchCMtimeLocked()
		}
	}
	return vfd, err
}

func (d *dentry) openSocketByConnecting(ctx context.Context, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
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

func (d *dentry) openSpecialFile(ctx context.Context, mnt *vfs.Mount, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
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
	fd, err := newSpecialFileFD(h, mnt, d, opts.Flags)
	if err != nil {
		h.close(ctx)
		return nil, err
	}
	return &fd.vfsfd, nil
}

// Preconditions:
// * d.fs.renameMu must be locked.
// * d.dirMu must be locked.
// * !d.isSynthetic().
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
	// We only want the access mode for creating the file.
	createFlags := p9.OpenFlags(opts.Flags) & p9.OpenFlagsModeMask

	// If the parent is a setgid directory, use the parent's GID rather
	// than the caller's.
	kgid := creds.EffectiveKGID
	if atomic.LoadUint32(&d.mode)&linux.S_ISGID != 0 {
		kgid = auth.KGID(atomic.LoadUint32(&d.gid))
	}

	fdobj, openFile, createQID, _, err := dirfile.create(ctx, name, createFlags, p9.FileMode(opts.Mode), (p9.UID)(creds.EffectiveKUID), p9.GID(kgid))
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
		openFD := int32(-1)
		if fdobj != nil {
			openFD = int32(fdobj.Release())
		}
		child.handleMu.Lock()
		if vfs.MayReadFileWithOpenFlags(opts.Flags) {
			child.readFile = openFile
			if fdobj != nil {
				child.readFD = openFD
				child.mmapFD = openFD
			}
		}
		if vfs.MayWriteFileWithOpenFlags(opts.Flags) {
			child.writeFile = openFile
			child.writeFD = openFD
		}
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
		fd, err := newRegularFileFD(mnt, child, opts.Flags)
		if err != nil {
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
		fd, err := newSpecialFileFD(h, mnt, child, opts.Flags)
		if err != nil {
			h.close(ctx)
			return nil, err
		}
		childVFSFD = &fd.vfsfd
	}
	d.watches.Notify(ctx, name, linux.IN_CREATE, 0, vfs.PathEvent, false /* unlinked */)
	return childVFSFD, nil
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
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
	defer fs.renameMuUnlockAndCheckCaching(ctx, &ds)
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
	creds := rp.Credentials()
	if err := oldParent.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
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
	if err := oldParent.mayDelete(creds, renamed); err != nil {
		return err
	}
	if renamed.isDir() {
		if renamed == newParent || genericIsAncestorDentry(renamed, newParent) {
			return syserror.EINVAL
		}
		if oldParent != newParent {
			if err := renamed.checkPermissions(creds, vfs.MayWrite); err != nil {
				return err
			}
		}
	} else {
		if opts.MustBeDir || rp.MustBeDir() {
			return syserror.ENOTDIR
		}
	}

	if oldParent != newParent {
		if err := newParent.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
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
			if genericIsAncestorDentry(replaced, renamed) {
				return syserror.ENOTEMPTY
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
	defer mntns.DecRef(ctx)
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
	vfsObj.CommitRenameReplaceDentry(ctx, &renamed.vfsd, replacedVFSD)
	if replaced != nil {
		replaced.setDeleted()
		if replaced.isSynthetic() {
			newParent.syntheticChildren--
			replaced.decRefNoCaching()
		}
		ds = appendDentry(ds, replaced)
	}
	oldParent.cacheNegativeLookupLocked(oldName)
	// We don't use newParent.cacheNewChildLocked() since we don't want to mess
	// with reference counts and queue oldParent for checkCachingLocked if the
	// parent isn't actually changing.
	if oldParent != newParent {
		oldParent.decRefNoCaching()
		ds = appendDentry(ds, oldParent)
		newParent.IncRef()
		if renamed.isSynthetic() {
			oldParent.syntheticChildren--
			newParent.syntheticChildren++
		}
		renamed.parent = newParent
	}
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
	vfs.InotifyRename(ctx, &renamed.watches, &oldParent.watches, &newParent.watches, oldName, newName, renamed.isDir())
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
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
		return err
	}
	err = d.setStat(ctx, rp.Credentials(), &opts, rp.Mount())
	fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
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
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
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
	defer fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
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
	return fs.doCreateAt(ctx, rp, false /* dir */, func(parent *dentry, name string, _ **[]*dentry) error {
		creds := rp.Credentials()
		_, err := parent.file.symlink(ctx, target, name, (p9.UID)(creds.EffectiveKUID), (p9.GID)(creds.EffectiveKGID))
		return err
	}, nil)
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	return fs.unlinkAt(ctx, rp, false /* dir */)
}

// BoundEndpointAt implements vfs.FilesystemImpl.BoundEndpointAt.
func (fs *filesystem) BoundEndpointAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.BoundEndpointOptions) (transport.BoundEndpoint, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
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
				path:   opts.Addr,
			}, nil
		}
		if d.endpoint != nil {
			return d.endpoint, nil
		}
	}
	return nil, syserror.ECONNREFUSED
}

// ListXattrAt implements vfs.FilesystemImpl.ListXattrAt.
func (fs *filesystem) ListXattrAt(ctx context.Context, rp *vfs.ResolvingPath, size uint64) ([]string, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return nil, err
	}
	return d.listXattr(ctx, rp.Credentials(), size)
}

// GetXattrAt implements vfs.FilesystemImpl.GetXattrAt.
func (fs *filesystem) GetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetXattrOptions) (string, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return "", err
	}
	return d.getXattr(ctx, rp.Credentials(), &opts)
}

// SetXattrAt implements vfs.FilesystemImpl.SetXattrAt.
func (fs *filesystem) SetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetXattrOptions) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
		return err
	}
	err = d.setXattr(ctx, rp.Credentials(), &opts)
	fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
	if err != nil {
		return err
	}

	d.InotifyWithParent(ctx, linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}

// RemoveXattrAt implements vfs.FilesystemImpl.RemoveXattrAt.
func (fs *filesystem) RemoveXattrAt(ctx context.Context, rp *vfs.ResolvingPath, name string) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
		return err
	}
	err = d.removeXattr(ctx, rp.Credentials(), name)
	fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
	if err != nil {
		return err
	}

	d.InotifyWithParent(ctx, linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}

// PrependPath implements vfs.FilesystemImpl.PrependPath.
func (fs *filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	fs.renameMu.RLock()
	defer fs.renameMu.RUnlock()
	return genericPrependPath(vfsroot, vd.Mount(), vd.Dentry().Impl().(*dentry), b)
}

type mopt struct {
	key   string
	value interface{}
}

func (m mopt) String() string {
	if m.value == nil {
		return fmt.Sprintf("%s", m.key)
	}
	return fmt.Sprintf("%s=%v", m.key, m.value)
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	optsKV := []mopt{
		{moptTransport, transportModeFD}, // Only valid value, currently.
		{moptReadFD, fs.opts.fd},         // Currently, read and write FD are the same.
		{moptWriteFD, fs.opts.fd},        // Currently, read and write FD are the same.
		{moptAname, fs.opts.aname},
		{moptDfltUID, fs.opts.dfltuid},
		{moptDfltGID, fs.opts.dfltgid},
		{moptMsize, fs.opts.msize},
		{moptVersion, fs.opts.version},
		{moptDentryCacheLimit, fs.opts.maxCachedDentries},
	}

	switch fs.opts.interop {
	case InteropModeExclusive:
		optsKV = append(optsKV, mopt{moptCache, cacheFSCache})
	case InteropModeWritethrough:
		optsKV = append(optsKV, mopt{moptCache, cacheFSCacheWritethrough})
	case InteropModeShared:
		if fs.opts.regularFilesUseSpecialFileFD {
			optsKV = append(optsKV, mopt{moptCache, cacheNone})
		} else {
			optsKV = append(optsKV, mopt{moptCache, cacheRemoteRevalidating})
		}
	}
	if fs.opts.forcePageCache {
		optsKV = append(optsKV, mopt{moptForcePageCache, nil})
	}
	if fs.opts.limitHostFDTranslation {
		optsKV = append(optsKV, mopt{moptLimitHostFDTranslation, nil})
	}
	if fs.opts.overlayfsStaleRead {
		optsKV = append(optsKV, mopt{moptOverlayfsStaleRead, nil})
	}

	opts := make([]string, 0, len(optsKV))
	for _, opt := range optsKV {
		opts = append(opts, opt.String())
	}
	return strings.Join(opts, ",")
}
