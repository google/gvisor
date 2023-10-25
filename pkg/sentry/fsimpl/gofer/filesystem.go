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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/fsmetric"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Sync implements vfs.FilesystemImpl.Sync.
func (fs *filesystem) Sync(ctx context.Context) error {
	// Snapshot current syncable dentries and special file FDs.
	fs.syncMu.Lock()
	ds := make([]*dentry, 0, fs.syncableDentries.Len())
	for elem := fs.syncableDentries.Front(); elem != nil; elem = elem.Next() {
		ds = append(ds, elem.d)
	}
	sffds := make([]*specialFileFD, 0, fs.specialFileFDs.Len())
	for sffd := fs.specialFileFDs.Front(); sffd != nil; sffd = sffd.Next() {
		sffds = append(sffds, sffd)
	}
	fs.syncMu.Unlock()

	// Return the first error we encounter, but sync everything we can
	// regardless.
	var retErr error

	// Note that lisafs is capable of batching FSync RPCs. However, we can not
	// batch all the FDIDs to be synced from ds and sffds. Because the error
	// handling varies based on file type. FSync errors are only considered for
	// regular file FDIDs that were opened for writing. We could do individual
	// RPCs for such FDIDs and batch the rest, but it increases code complexity
	// substantially. We could implement it in the future if need be.

	// Sync syncable dentries.
	for _, d := range ds {
		if err := d.syncCachedFile(ctx, true /* forFilesystemSync */); err != nil {
			ctx.Infof("gofer.filesystem.Sync: dentry.syncCachedFile failed: %v", err)
			if retErr == nil {
				retErr = err
			}
		}
	}

	// Sync special files, which may be writable but do not use dentry shared
	// handles (so they won't be synced by the above).
	for _, sffd := range sffds {
		if err := sffd.sync(ctx, true /* forFilesystemSync */); err != nil {
			ctx.Infof("gofer.filesystem.Sync: specialFileFD.sync failed: %v", err)
			if retErr == nil {
				retErr = err
			}
		}
	}

	return retErr
}

// MaxFilenameLen is the maximum length of a filename. This is dictated by 9P's
// encoding of strings, which uses 2 bytes for the length prefix.
const MaxFilenameLen = (1 << 16) - 1

// dentrySlicePool is a pool of *[]*dentry used to store dentries for which
// dentry.checkCachingLocked() must be called. The pool holds pointers to
// slices because Go lacks generics, so sync.Pool operates on any, so
// every call to (what should be) sync.Pool<[]*dentry>.Put() allocates a copy
// of the slice header on the heap.
var dentrySlicePool = sync.Pool{
	New: func() any {
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

// Precondition: !parent.isSynthetic() && !child.isSynthetic().
func appendNewChildDentry(ds **[]*dentry, parent *dentry, child *dentry) {
	// The new child was added to parent and took a ref on the parent (hence
	// parent can be removed from cache). A new child has 0 refs for now. So
	// checkCachingLocked() should be called on both. Call it first on the parent
	// as it may create space in the cache for child to be inserted - hence
	// avoiding a cache eviction.
	*ds = appendDentry(*ds, parent)
	*ds = appendDentry(*ds, child)
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
// +checklocksreleaseread:fs.renameMu
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

// +checklocksrelease:fs.renameMu
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
//   - fs.renameMu must be locked.
//   - d.opMu must be locked for reading.
//   - !rp.Done().
//   - If !d.cachedMetadataAuthoritative(), then d and all children that are
//     part of rp must have been revalidated.
//
// +checklocksread:d.opMu
func (fs *filesystem) stepLocked(ctx context.Context, rp resolvingPath, d *dentry, mayFollowSymlinks bool, ds **[]*dentry) (*dentry, bool, error) {
	if !d.isDir() {
		return nil, false, linuxerr.ENOTDIR
	}
	if err := d.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, false, err
	}
	name := rp.Component()
	if name == "." {
		rp.Advance()
		return d, false, nil
	}
	if name == ".." {
		if isRoot, err := rp.CheckRoot(ctx, &d.vfsd); err != nil {
			return nil, false, err
		} else if isRoot || d.parent.Load() == nil {
			rp.Advance()
			return d, false, nil
		}
		if err := rp.CheckMount(ctx, &d.parent.Load().vfsd); err != nil {
			return nil, false, err
		}
		rp.Advance()
		return d.parent.Load(), false, nil
	}
	child, err := fs.getChildAndWalkPathLocked(ctx, d, rp, ds)
	if err != nil {
		return nil, false, err
	}
	if err := rp.CheckMount(ctx, &child.vfsd); err != nil {
		return nil, false, err
	}
	if child.isSymlink() && mayFollowSymlinks && rp.ShouldFollowSymlink() {
		target, err := child.readlink(ctx, rp.Mount())
		if err != nil {
			return nil, false, err
		}
		followedSymlink, err := rp.HandleSymlink(target)
		return d, followedSymlink, err
	}
	rp.Advance()
	return child, false, nil
}

// getChildLocked returns a dentry representing the child of parent with the
// given name. Returns ENOENT if the child doesn't exist.
//
// Preconditions:
//   - fs.renameMu must be locked.
//   - parent.opMu must be locked.
//   - parent.isDir().
//   - name is not "." or "..".
//   - parent and the dentry at name have been revalidated.
//
// +checklocks:parent.opMu
func (fs *filesystem) getChildLocked(ctx context.Context, parent *dentry, name string, ds **[]*dentry) (*dentry, error) {
	if child, err := parent.getCachedChildLocked(name); child != nil || err != nil {
		return child, err
	}
	// We don't need to check for race here because parent.opMu is held for
	// writing.
	return fs.getRemoteChildLocked(ctx, parent, name, false /* checkForRace */, ds)
}

// getRemoteChildLocked is similar to getChildLocked, with the additional
// precondition that the child identified by name does not exist in cache.
//
// If checkForRace argument is true, then this method will check to see if the
// call has raced with another getRemoteChild call, and will handle the race if
// so.
//
// Preconditions:
//   - If checkForRace is false, then parent.opMu must be held for writing.
//   - Otherwise, parent.opMu must be held for reading.
//
// Postcondition: The returned dentry is already cached appropriately.
//
// +checklocksread:parent.opMu
func (fs *filesystem) getRemoteChildLocked(ctx context.Context, parent *dentry, name string, checkForRace bool, ds **[]*dentry) (*dentry, error) {
	child, err := parent.getRemoteChild(ctx, name)
	// Cache the result appropriately in the dentry tree.
	if err != nil {
		if linuxerr.Equals(linuxerr.ENOENT, err) {
			parent.childrenMu.Lock()
			defer parent.childrenMu.Unlock()
			parent.cacheNegativeLookupLocked(name)
		}
		return nil, err
	}

	parent.childrenMu.Lock()
	defer parent.childrenMu.Unlock()

	if checkForRace {
		// See if we raced with another getRemoteChild call that added
		// to the cache.
		if cachedChild, ok := parent.children[name]; ok && cachedChild != nil {
			// We raced. Destroy our child and return the cached
			// one. This child has no handles, no data, and has not
			// been cached, so destruction is quick and painless.
			child.destroyDisconnected(ctx)

			// All good. Return the cached child.
			return cachedChild, nil
		}
		// No race, continue with the child we got.
	}
	parent.cacheNewChildLocked(child, name)
	appendNewChildDentry(ds, parent, child)
	return child, nil
}

// getChildAndWalkPathLocked is the same as getChildLocked, except that it
// may prefetch the entire path represented by rp.
//
// +checklocksread:parent.opMu
func (fs *filesystem) getChildAndWalkPathLocked(ctx context.Context, parent *dentry, rp resolvingPath, ds **[]*dentry) (*dentry, error) {
	if child, err := parent.getCachedChildLocked(rp.Component()); child != nil || err != nil {
		return child, err
	}
	// dentry.getRemoteChildAndWalkPathLocked already handles dentry caching.
	return parent.getRemoteChildAndWalkPathLocked(ctx, rp, ds)
}

// getCachedChildLocked returns a child dentry if it was cached earlier. If no
// cached child dentry exists, (nil, nil) is returned.
//
// Preconditions:
//   - fs.renameMu must be locked.
//   - d.opMu must be locked for reading.
//   - d.isDir().
//   - name is not "." or "..".
//   - d and the dentry at name have been revalidated.
//
// +checklocksread:d.opMu
func (d *dentry) getCachedChildLocked(name string) (*dentry, error) {
	if len(name) > MaxFilenameLen {
		return nil, linuxerr.ENAMETOOLONG
	}
	d.childrenMu.Lock()
	defer d.childrenMu.Unlock()
	if child, ok := d.children[name]; ok || d.isSynthetic() {
		if child == nil {
			return nil, linuxerr.ENOENT
		}
		return child, nil
	}

	if d.childrenSet != nil {
		// Is the child even there? Don't make RPC if not.
		if _, ok := d.childrenSet[name]; !ok {
			return nil, linuxerr.ENOENT
		}
	}
	return nil, nil
}

// walkParentDirLocked resolves all but the last path component of rp to an
// existing directory, starting from the given directory (which is usually
// rp.Start().Impl().(*dentry)). It does not check that the returned directory
// is searchable by the provider of rp.
//
// Preconditions:
//   - fs.renameMu must be locked.
//   - !rp.Done().
//   - If !d.cachedMetadataAuthoritative(), then d's cached metadata must be up
//     to date.
func (fs *filesystem) walkParentDirLocked(ctx context.Context, vfsRP *vfs.ResolvingPath, d *dentry, ds **[]*dentry) (*dentry, error) {
	rp := resolvingPathParent(vfsRP)
	if err := fs.revalidatePath(ctx, rp, d, ds); err != nil {
		return nil, err
	}
	for !rp.done() {
		d.opMu.RLock()
		next, followedSymlink, err := fs.stepLocked(ctx, rp, d, true /* mayFollowSymlinks */, ds)
		d.opMu.RUnlock()
		if err != nil {
			return nil, err
		}
		d = next
		if followedSymlink {
			if err := fs.revalidatePath(ctx, rp, d, ds); err != nil {
				return nil, err
			}
		}
	}
	if !d.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	return d, nil
}

// resolveLocked resolves rp to an existing file.
//
// Preconditions: fs.renameMu must be locked.
func (fs *filesystem) resolveLocked(ctx context.Context, vfsRP *vfs.ResolvingPath, ds **[]*dentry) (*dentry, error) {
	rp := resolvingPathFull(vfsRP)
	d := rp.Start().Impl().(*dentry)
	if err := fs.revalidatePath(ctx, rp, d, ds); err != nil {
		return nil, err
	}
	for !rp.done() {
		d.opMu.RLock()
		next, followedSymlink, err := fs.stepLocked(ctx, rp, d, true /* mayFollowSymlinks */, ds)
		d.opMu.RUnlock()
		if err != nil {
			return nil, err
		}
		d = next
		if followedSymlink {
			if err := fs.revalidatePath(ctx, rp, d, ds); err != nil {
				return nil, err
			}
		}
	}
	if rp.MustBeDir() && !d.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	return d, nil
}

// doCreateAt checks that creating a file at rp is permitted, then invokes
// createInRemoteDir (if the parent directory is a real remote directory) or
// createInSyntheticDir (if the parent directory is synthetic) to do so.
//
// Preconditions:
//   - !rp.Done().
//   - For the final path component in rp, !rp.ShouldFollowSymlink().
func (fs *filesystem) doCreateAt(ctx context.Context, rp *vfs.ResolvingPath, dir bool, createInRemoteDir func(parent *dentry, name string, ds **[]*dentry) (*dentry, error), createInSyntheticDir func(parent *dentry, name string) (*dentry, error)) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
	start := rp.Start().Impl().(*dentry)
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
		return linuxerr.EEXIST
	}
	if parent.isDeleted() {
		return linuxerr.ENOENT
	}
	if err := fs.revalidateOne(ctx, rp.VirtualFilesystem(), parent, name, &ds); err != nil {
		return err
	}

	parent.opMu.Lock()
	defer parent.opMu.Unlock()

	if len(name) > MaxFilenameLen {
		return linuxerr.ENAMETOOLONG
	}
	// Check for existence only if caching information is available. Otherwise,
	// don't check for existence just yet. We will check for existence if the
	// checks for writability fail below. Existence check is done by the creation
	// RPCs themselves.
	parent.childrenMu.Lock()
	if child, ok := parent.children[name]; ok && child != nil {
		parent.childrenMu.Unlock()
		return linuxerr.EEXIST
	}
	if parent.childrenSet != nil {
		if _, ok := parent.childrenSet[name]; ok {
			parent.childrenMu.Unlock()
			return linuxerr.EEXIST
		}
	}
	parent.childrenMu.Unlock()
	checkExistence := func() error {
		if child, err := fs.getChildLocked(ctx, parent, name, &ds); err != nil && !linuxerr.Equals(linuxerr.ENOENT, err) {
			return err
		} else if child != nil {
			return linuxerr.EEXIST
		}
		return nil
	}

	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		// Existence check takes precedence.
		if existenceErr := checkExistence(); existenceErr != nil {
			return existenceErr
		}
		return err
	}
	defer mnt.EndWrite()

	if err := parent.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
		// Existence check takes precedence.
		if existenceErr := checkExistence(); existenceErr != nil {
			return existenceErr
		}
		return err
	}
	if !dir && rp.MustBeDir() {
		return linuxerr.ENOENT
	}
	if parent.isSynthetic() {
		if createInSyntheticDir == nil {
			return linuxerr.EPERM
		}
		child, err := createInSyntheticDir(parent, name)
		if err != nil {
			return err
		}
		parent.childrenMu.Lock()
		parent.cacheNewChildLocked(child, name)
		parent.syntheticChildren++
		parent.clearDirentsLocked()
		parent.childrenMu.Unlock()
		parent.touchCMtime()
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
	child, err := createInRemoteDir(parent, name, &ds)
	if err != nil {
		return err
	}
	parent.childrenMu.Lock()
	parent.cacheNewChildLocked(child, name)
	if child.isSynthetic() {
		parent.syntheticChildren++
		ds = appendDentry(ds, parent)
	} else {
		appendNewChildDentry(&ds, parent, child)
	}
	if fs.opts.interop != InteropModeShared {
		if child, ok := parent.children[name]; ok && child == nil {
			// Delete the now-stale negative dentry.
			delete(parent.children, name)
			parent.negativeChildren--
		}
		parent.clearDirentsLocked()
		parent.touchCMtime()
	}
	parent.childrenMu.Unlock()
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
	// We need to DecRef outside of fs.renameMu because forgetting a dead
	// mountpoint could result in this filesystem being released which acquires
	// fs.renameMu.
	var toDecRef []refs.RefCounter
	defer func() {
		for _, ref := range toDecRef {
			ref.DecRef(ctx)
		}
	}()
	defer fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
	start := rp.Start().Impl().(*dentry)
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
			return linuxerr.EINVAL
		}
		if name == ".." {
			return linuxerr.ENOTEMPTY
		}
	} else {
		if name == "." || name == ".." {
			return linuxerr.EISDIR
		}
	}

	vfsObj := rp.VirtualFilesystem()
	if err := fs.revalidateOne(ctx, vfsObj, parent, rp.Component(), &ds); err != nil {
		return err
	}

	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)

	parent.opMu.Lock()
	defer parent.opMu.Unlock()

	parent.childrenMu.Lock()
	if parent.childrenSet != nil {
		if _, ok := parent.childrenSet[name]; !ok {
			parent.childrenMu.Unlock()
			return linuxerr.ENOENT
		}
	}
	parent.childrenMu.Unlock()

	// Load child if sticky bit is set because we need to determine whether
	// deletion is allowed.
	var child *dentry
	if parent.mode.Load()&linux.ModeSticky == 0 {
		var ok bool
		parent.childrenMu.Lock()
		child, ok = parent.children[name]
		parent.childrenMu.Unlock()
		if ok && child == nil {
			// Hit a negative cached entry, child doesn't exist.
			return linuxerr.ENOENT
		}
	} else {
		child, _, err = fs.stepLocked(ctx, resolvingPathFull(rp), parent, false /* mayFollowSymlinks */, &ds)
		if err != nil {
			return err
		}
		if err := parent.mayDelete(rp.Credentials(), child); err != nil {
			return err
		}
	}

	// If a child dentry exists, prepare to delete it. This should fail if it is
	// a mount point. We detect mount points by speculatively calling
	// PrepareDeleteDentry, which fails if child is a mount point.
	//
	// Also note that if child is nil, then it can't be a mount point.
	if child != nil {
		// Hold child.childrenMu so we can check child.children and
		// child.syntheticChildren. We don't access these fields until a bit later,
		// but locking child.childrenMu after calling vfs.PrepareDeleteDentry() would
		// create an inconsistent lock ordering between dentry.childrenMu and
		// vfs.Dentry.mu (in the VFS lock order, it would make dentry.childrenMu both "a
		// FilesystemImpl lock" and "a lock acquired by a FilesystemImpl between
		// PrepareDeleteDentry and CommitDeleteDentry). To avoid this, lock
		// child.childrenMu before calling PrepareDeleteDentry.
		child.childrenMu.Lock()
		defer child.childrenMu.Unlock()
		if err := vfsObj.PrepareDeleteDentry(mntns, &child.vfsd); err != nil {
			return err
		}
	}
	flags := uint32(0)
	// If a dentry exists, use it for best-effort checks on its deletability.
	if dir {
		if child != nil {
			// child must be an empty directory.
			if child.syntheticChildren != 0 { // +checklocksforce: child.childrenMu is held if child != nil.
				// This is definitely not an empty directory, irrespective of
				// fs.opts.interop.
				vfsObj.AbortDeleteDentry(&child.vfsd) // +checklocksforce: PrepareDeleteDentry called if child != nil.
				return linuxerr.ENOTEMPTY
			}
			// If InteropModeShared is in effect and the first call to
			// PrepareDeleteDentry above succeeded, then child wasn't
			// revalidated (so we can't expect its file type to be correct) and
			// individually revalidating its children (to confirm that they
			// still exist) would be a waste of time.
			if child.cachedMetadataAuthoritative() {
				if !child.isDir() {
					vfsObj.AbortDeleteDentry(&child.vfsd) // +checklocksforce: see above.
					return linuxerr.ENOTDIR
				}
				for _, grandchild := range child.children { // +checklocksforce: child.childrenMu is held if child != nil.
					if grandchild != nil {
						vfsObj.AbortDeleteDentry(&child.vfsd) // +checklocksforce: see above.
						return linuxerr.ENOTEMPTY
					}
				}
			}
		}
		flags = linux.AT_REMOVEDIR
	} else {
		// child must be a non-directory file.
		if child != nil && child.isDir() {
			vfsObj.AbortDeleteDentry(&child.vfsd) // +checklocksforce: see above.
			return linuxerr.EISDIR
		}
		if rp.MustBeDir() {
			if child != nil {
				vfsObj.AbortDeleteDentry(&child.vfsd) // +checklocksforce: see above.
			}
			return linuxerr.ENOTDIR
		}
	}
	if parent.isSynthetic() {
		if child == nil {
			return linuxerr.ENOENT
		}
	} else if child == nil || !child.isSynthetic() {
		if err := parent.unlink(ctx, name, flags); err != nil {
			if child != nil {
				vfsObj.AbortDeleteDentry(&child.vfsd) // +checklocksforce: see above.
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

	parent.childrenMu.Lock()
	defer parent.childrenMu.Unlock()

	if child != nil {
		toDecRef = vfsObj.CommitDeleteDentry(ctx, &child.vfsd) // +checklocksforce: see above.
		child.setDeleted()
		if child.isSynthetic() {
			parent.syntheticChildren--
			child.decRefNoCaching()
		}
		ds = appendDentry(ds, child)
	}
	parent.cacheNegativeLookupLocked(name)
	if parent.cachedMetadataAuthoritative() {
		parent.clearDirentsLocked()
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
	if err := d.checkPermissions(creds, ats); err != nil {
		return err
	}
	if ats.MayWrite() && rp.Mount().ReadOnly() {
		return linuxerr.EROFS
	}
	return nil
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
			return nil, linuxerr.ENOTDIR
		}
		if err := d.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
			return nil, err
		}
	}
	d.IncRef()
	// Call d.checkCachingLocked() so it can be removed from the cache if needed.
	ds = appendDentry(ds, d)
	return &d.vfsd, nil
}

// GetParentDentryAt implements vfs.FilesystemImpl.GetParentDentryAt.
func (fs *filesystem) GetParentDentryAt(ctx context.Context, rp *vfs.ResolvingPath) (*vfs.Dentry, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckCaching(ctx, &ds)
	start := rp.Start().Impl().(*dentry)
	d, err := fs.walkParentDirLocked(ctx, rp, start, &ds)
	if err != nil {
		return nil, err
	}
	d.IncRef()
	// Call d.checkCachingLocked() so it can be removed from the cache if needed.
	ds = appendDentry(ds, d)
	return &d.vfsd, nil
}

// LinkAt implements vfs.FilesystemImpl.LinkAt.
func (fs *filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	err := fs.doCreateAt(ctx, rp, false /* dir */, func(parent *dentry, name string, ds **[]*dentry) (*dentry, error) {
		if rp.Mount() != vd.Mount() {
			return nil, linuxerr.EXDEV
		}
		d := vd.Dentry().Impl().(*dentry)
		if d.isDir() {
			return nil, linuxerr.EPERM
		}
		gid := auth.KGID(d.gid.Load())
		uid := auth.KUID(d.uid.Load())
		mode := linux.FileMode(d.mode.Load())
		if err := vfs.MayLink(rp.Credentials(), mode, uid, gid); err != nil {
			return nil, err
		}
		if d.nlink.Load() == 0 {
			return nil, linuxerr.ENOENT
		}
		if d.nlink.Load() == math.MaxUint32 {
			return nil, linuxerr.EMLINK
		}
		return parent.link(ctx, d, name)
	}, nil)

	if err == nil {
		// Success!
		vd.Dentry().Impl().(*dentry).incLinks()
	}
	return err
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	creds := rp.Credentials()
	return fs.doCreateAt(ctx, rp, true /* dir */, func(parent *dentry, name string, ds **[]*dentry) (*dentry, error) {
		// If the parent is a setgid directory, use the parent's GID
		// rather than the caller's and enable setgid.
		kgid := creds.EffectiveKGID
		mode := opts.Mode
		if parent.mode.Load()&linux.S_ISGID != 0 {
			kgid = auth.KGID(parent.gid.Load())
			mode |= linux.S_ISGID
		}

		child, err := parent.mkdir(ctx, name, mode, creds.EffectiveKUID, kgid)
		if err == nil {
			if fs.opts.interop != InteropModeShared {
				parent.incLinks()
			}
			return child, nil
		}

		if !opts.ForSyntheticMountpoint || linuxerr.Equals(linuxerr.EEXIST, err) {
			return nil, err
		}
		ctx.Infof("Failed to create remote directory %q: %v; falling back to synthetic directory", name, err)
		child = fs.newSyntheticDentry(&createSyntheticOpts{
			name: name,
			mode: linux.S_IFDIR | opts.Mode,
			kuid: creds.EffectiveKUID,
			kgid: creds.EffectiveKGID,
		})
		if fs.opts.interop != InteropModeShared {
			parent.incLinks()
		}
		return child, nil
	}, func(parent *dentry, name string) (*dentry, error) {
		if !opts.ForSyntheticMountpoint {
			// Can't create non-synthetic files in synthetic directories.
			return nil, linuxerr.EPERM
		}
		child := fs.newSyntheticDentry(&createSyntheticOpts{
			name: name,
			mode: linux.S_IFDIR | opts.Mode,
			kuid: creds.EffectiveKUID,
			kgid: creds.EffectiveKGID,
		})
		parent.incLinks()
		return child, nil
	})
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	return fs.doCreateAt(ctx, rp, false /* dir */, func(parent *dentry, name string, ds **[]*dentry) (*dentry, error) {
		creds := rp.Credentials()
		if child, err := parent.mknod(ctx, name, creds, &opts); err == nil {
			return child, nil
		} else if !linuxerr.Equals(linuxerr.EPERM, err) {
			return nil, err
		}

		// EPERM means that gofer does not allow creating a socket or pipe. Fallback
		// to creating a synthetic one, i.e. one that is kept entirely in memory.

		// Check that we're not overriding an existing file with a synthetic one.
		_, _, err := fs.stepLocked(ctx, resolvingPathFull(rp), parent, false /* mayFollowSymlinks */, ds) // +checklocksforce: parent.opMu taken by doCreateAt.
		switch {
		case err == nil:
			// Step succeeded, another file exists.
			return nil, linuxerr.EEXIST
		case !linuxerr.Equals(linuxerr.ENOENT, err):
			// Schrödinger. File/Cat may or may not exist.
			return nil, err
		}

		switch opts.Mode.FileType() {
		case linux.S_IFSOCK:
			return fs.newSyntheticDentry(&createSyntheticOpts{
				name:     name,
				mode:     opts.Mode,
				kuid:     creds.EffectiveKUID,
				kgid:     creds.EffectiveKGID,
				endpoint: opts.Endpoint,
			}), nil
		case linux.S_IFIFO:
			return fs.newSyntheticDentry(&createSyntheticOpts{
				name: name,
				mode: opts.Mode,
				kuid: creds.EffectiveKUID,
				kgid: creds.EffectiveKGID,
				pipe: pipe.NewVFSPipe(true /* isNamed */, pipe.DefaultPipeSize),
			}), nil
		}
		// Retain error from gofer if synthetic file cannot be created internally.
		return nil, linuxerr.EPERM
	}, nil)
}

// OpenAt implements vfs.FilesystemImpl.OpenAt.
func (fs *filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	// Reject O_TMPFILE, which is not supported; supporting it correctly in the
	// presence of other remote filesystem users requires remote filesystem
	// support, and it isn't clear that there's any way to implement this in
	// 9P.
	if opts.Flags&linux.O_TMPFILE != 0 {
		return nil, linuxerr.EOPNOTSUPP
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
	if rp.Done() {
		// Reject attempts to open mount root directory with O_CREAT.
		if mayCreate && rp.MustBeDir() {
			return nil, linuxerr.EISDIR
		}
		if mustCreate {
			return nil, linuxerr.EEXIST
		}
		if !start.cachedMetadataAuthoritative() {
			// Refresh dentry's attributes before opening.
			if err := start.updateMetadata(ctx); err != nil {
				return nil, err
			}
		}
		start.IncRef()
		defer start.DecRef(ctx)
		unlock()
		// start is intentionally not added to ds (which would remove it from the
		// cache) because doing so regresses performance in practice.
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
		return nil, linuxerr.EISDIR
	}
	if err := fs.revalidateOne(ctx, rp.VirtualFilesystem(), parent, rp.Component(), &ds); err != nil {
		return nil, err
	}
	// Determine whether or not we need to create a file.
	// NOTE(b/263297063): Don't hold opMu for writing here, to avoid
	// serializing OpenAt calls in the same directory in the common case
	// that the file exists.
	parent.opMu.RLock()
	child, followedSymlink, err := fs.stepLocked(ctx, resolvingPathFull(rp), parent, true /* mayFollowSymlinks */, &ds)
	parent.opMu.RUnlock()
	if followedSymlink {
		if mustCreate {
			// EEXIST must be returned if an existing symlink is opened with O_EXCL.
			return nil, linuxerr.EEXIST
		}
		if err != nil {
			// If followedSymlink && err != nil, then this symlink resolution error
			// must be handled by the VFS layer.
			return nil, err
		}
		start = parent
		goto afterTrailingSymlink
	}
	if linuxerr.Equals(linuxerr.ENOENT, err) && mayCreate {
		if parent.isSynthetic() {
			return nil, linuxerr.EPERM
		}

		// Take opMu for writing, but note that the file may have been
		// created by another goroutine since we checked for existence
		// a few lines ago. We must handle that case.
		parent.opMu.Lock()
		fd, createErr := parent.createAndOpenChildLocked(ctx, rp, &opts, &ds)
		if !linuxerr.Equals(linuxerr.EEXIST, createErr) {
			// Either the creation was a success, or we got an
			// unexpected error. Either way we can return here.
			parent.opMu.Unlock()
			return fd, createErr
		}

		// We raced, and now the file exists.
		if mustCreate {
			parent.opMu.Unlock()
			return nil, linuxerr.EEXIST
		}

		// Step to the file again. Since we still hold opMu for
		// writing, there can't be a race here.
		child, _, err = fs.stepLocked(ctx, resolvingPathFull(rp), parent, false /* mayFollowSymlinks */, &ds)
		parent.opMu.Unlock()
	}
	if err != nil {
		return nil, err
	}
	if mustCreate {
		return nil, linuxerr.EEXIST
	}
	if rp.MustBeDir() && !child.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	child.IncRef()
	defer child.DecRef(ctx)
	unlock()
	// child is intentionally not added to ds (which would remove it from the
	// cache) because doing so regresses performance in practice.
	return child.open(ctx, rp, &opts)
}

// Preconditions: The caller must hold no locks (since opening pipes may block
// indefinitely).
func (d *dentry) open(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	ats := vfs.AccessTypesForOpenFlags(opts)
	if err := d.checkPermissions(rp.Credentials(), ats); err != nil {
		return nil, err
	}

	if !d.isSynthetic() {
		// renameMu is locked here because it is required by d.openHandle(), which
		// is called by d.ensureSharedHandle() and d.openSpecialFile() below. It is
		// also required by d.connect() which is called by
		// d.openSocketByConnecting(). Note that opening non-synthetic pipes may
		// block, renameMu is unlocked separately in d.openSpecialFile() for pipes.
		d.fs.renameMu.RLock()
		defer d.fs.renameMu.RUnlock()
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
			return nil, linuxerr.EISDIR
		}
		// Can't open directories writably.
		if ats&vfs.MayWrite != 0 {
			return nil, linuxerr.EISDIR
		}
		if opts.Flags&linux.O_DIRECT != 0 {
			return nil, linuxerr.EINVAL
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
		if d.readFD.Load() >= 0 {
			fsmetric.GoferOpensHost.Increment()
		} else {
			fsmetric.GoferOpens9P.Increment()
		}
		return &fd.vfsfd, nil
	case linux.S_IFLNK:
		// Can't open symlinks without O_PATH, which is handled at the VFS layer.
		return nil, linuxerr.ELOOP
	case linux.S_IFSOCK:
		if d.isSynthetic() {
			return nil, linuxerr.ENXIO
		}
		if d.fs.iopts.OpenSocketsByConnecting {
			return d.openSocketByConnecting(ctx, opts)
		}
	case linux.S_IFIFO:
		if d.isSynthetic() {
			return d.pipe.Open(ctx, mnt, &d.vfsd, opts.Flags, &d.locks)
		}
		if d.fs.opts.disableFifoOpen {
			return nil, linuxerr.EPERM
		}
	}

	if vfd == nil {
		if vfd, err = d.openSpecialFile(ctx, mnt, opts); err != nil {
			return nil, err
		}
	}

	if trunc {
		// If no errors occurred so far then update file size in memory. This
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

// Precondition: fs.renameMu is locked.
func (d *dentry) openSocketByConnecting(ctx context.Context, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	if opts.Flags&linux.O_DIRECT != 0 {
		return nil, linuxerr.EINVAL
	}
	// Note that special value of linux.SockType = 0 is interpreted by lisafs
	// as "do not care about the socket type". Analogous to p9.AnonymousSocket.
	sockFD, err := d.connect(ctx, 0 /* sockType */)
	if err != nil {
		return nil, err
	}
	fd, err := host.NewFD(ctx, kernel.KernelFromContext(ctx).HostMount(), sockFD, &host.NewFDOptions{
		HaveFlags: true,
		Flags:     opts.Flags,
	})
	if err != nil {
		unix.Close(sockFD)
		return nil, err
	}
	return fd, nil
}

// Preconditions:
//   - !d.isSynthetic().
//   - fs.renameMu is locked. It may be released temporarily while pipe blocks.
//   - If d is a pipe, no other locks (other than fs.renameMu) should be held.
func (d *dentry) openSpecialFile(ctx context.Context, mnt *vfs.Mount, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	ats := vfs.AccessTypesForOpenFlags(opts)
	if opts.Flags&linux.O_DIRECT != 0 && !d.isRegularFile() {
		return nil, linuxerr.EINVAL
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
	h, err := d.openHandle(ctx, ats.MayRead(), ats.MayWrite(), opts.Flags&linux.O_TRUNC != 0)
	if err != nil {
		if isBlockingOpenOfNamedPipe && ats == vfs.MayWrite && linuxerr.Equals(linuxerr.ENXIO, err) {
			// An attempt to open a named pipe with O_WRONLY|O_NONBLOCK fails
			// with ENXIO if opening the same named pipe with O_WRONLY would
			// block because there are no readers of the pipe. Release renameMu
			// while blocking.
			d.fs.renameMu.RUnlock()
			err := sleepBetweenNamedPipeOpenChecks(ctx)
			d.fs.renameMu.RLock()
			if err != nil {
				return nil, err
			}
			goto retry
		}
		return nil, err
	}
	if isBlockingOpenOfNamedPipe && ats == vfs.MayRead && h.fd >= 0 {
		// Release renameMu while blocking.
		d.fs.renameMu.RUnlock()
		err := blockUntilNonblockingPipeHasWriter(ctx, h.fd)
		d.fs.renameMu.RLock()
		if err != nil {
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
//   - d.fs.renameMu must be locked.
//   - d.opMu must be locked for writing.
//   - !d.isSynthetic().
//
// +checklocks:d.opMu
func (d *dentry) createAndOpenChildLocked(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions, ds **[]*dentry) (*vfs.FileDescription, error) {
	if err := d.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
		return nil, err
	}
	if d.isDeleted() {
		return nil, linuxerr.ENOENT
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return nil, err
	}
	defer mnt.EndWrite()

	creds := rp.Credentials()
	name := rp.Component()
	// If the parent is a setgid directory, use the parent's GID rather
	// than the caller's.
	kgid := creds.EffectiveKGID
	if d.mode.Load()&linux.S_ISGID != 0 {
		kgid = auth.KGID(d.gid.Load())
	}

	child, h, err := d.openCreate(ctx, name, opts.Flags&linux.O_ACCMODE, opts.Mode, creds.EffectiveKUID, kgid)
	if err != nil {
		return nil, err
	}

	// Incorporate the fid that was opened by lcreate.
	useRegularFileFD := child.fileType() == linux.S_IFREG && !d.fs.opts.regularFilesUseSpecialFileFD
	if useRegularFileFD {
		var readable, writable bool
		child.handleMu.Lock()
		if vfs.MayReadFileWithOpenFlags(opts.Flags) {
			readable = true
			if h.fd != -1 {
				child.readFD = atomicbitops.FromInt32(h.fd)
				child.mmapFD = atomicbitops.FromInt32(h.fd)
			}
		}
		if vfs.MayWriteFileWithOpenFlags(opts.Flags) {
			writable = true
			child.writeFD = atomicbitops.FromInt32(h.fd)
		}
		child.updateHandles(ctx, h, readable, writable)
		child.handleMu.Unlock()
	}
	// Insert the dentry into the tree.
	d.childrenMu.Lock()
	// We have d.opMu for writing, so there can not be a cached child with
	// this name.  We could not have raced.
	d.cacheNewChildLocked(child, name)
	appendNewChildDentry(ds, d, child)
	if d.cachedMetadataAuthoritative() {
		d.touchCMtime()
		d.clearDirentsLocked()
	}
	d.childrenMu.Unlock()

	// Finally, construct a file description representing the created file.
	var childVFSFD *vfs.FileDescription
	if useRegularFileFD {
		fd, err := newRegularFileFD(mnt, child, opts.Flags)
		if err != nil {
			return nil, err
		}
		childVFSFD = &fd.vfsfd
	} else {
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
		return "", linuxerr.EINVAL
	}
	return d.readlink(ctx, rp.Mount())
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, oldParentVD vfs.VirtualDentry, oldName string, opts vfs.RenameOptions) error {
	// Resolve newParent first to verify that it's on this Mount.
	var ds *[]*dentry
	fs.renameMu.Lock()
	// We need to DecRef outside of fs.mu because forgetting a dead mountpoint
	// could result in this filesystem being released which acquires fs.mu.
	var toDecRef []refs.RefCounter
	defer func() {
		for _, ref := range toDecRef {
			ref.DecRef(ctx)
		}
	}()
	defer fs.renameMuUnlockAndCheckCaching(ctx, &ds)
	newParent, err := fs.walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry), &ds)
	if err != nil {
		return err
	}

	if opts.Flags&^linux.RENAME_NOREPLACE != 0 {
		return linuxerr.EINVAL
	}
	if fs.opts.interop == InteropModeShared && opts.Flags&linux.RENAME_NOREPLACE != 0 {
		// Requires 9P support to synchronize with other remote filesystem
		// users.
		return linuxerr.EINVAL
	}

	newName := rp.Component()
	if newName == "." || newName == ".." {
		if opts.Flags&linux.RENAME_NOREPLACE != 0 {
			return linuxerr.EEXIST
		}
		return linuxerr.EBUSY
	}
	if len(newName) > MaxFilenameLen {
		return linuxerr.ENAMETOOLONG
	}
	mnt := rp.Mount()
	if mnt != oldParentVD.Mount() {
		return linuxerr.EXDEV
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()

	oldParent := oldParentVD.Dentry().Impl().(*dentry)
	if !oldParent.cachedMetadataAuthoritative() {
		if err := oldParent.updateMetadata(ctx); err != nil {
			return err
		}
	}
	creds := rp.Credentials()
	if err := oldParent.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}

	vfsObj := rp.VirtualFilesystem()
	if err := fs.revalidateOne(ctx, vfsObj, newParent, newName, &ds); err != nil {
		return err
	}
	if err := fs.revalidateOne(ctx, vfsObj, oldParent, oldName, &ds); err != nil {
		return err
	}

	// We need a dentry representing the renamed file since, if it's a
	// directory, we need to check for write permission on it.
	oldParent.opMu.Lock()
	defer oldParent.opMu.Unlock()
	renamed, err := fs.getChildLocked(ctx, oldParent, oldName, &ds)
	if err != nil {
		return err
	}
	if err := oldParent.mayDelete(creds, renamed); err != nil {
		return err
	}
	if renamed.isDir() {
		if renamed == newParent || genericIsAncestorDentry(renamed, newParent) {
			return linuxerr.EINVAL
		}
		if oldParent != newParent {
			if err := renamed.checkPermissions(creds, vfs.MayWrite); err != nil {
				return err
			}
		}
	} else {
		if opts.MustBeDir || rp.MustBeDir() {
			return linuxerr.ENOTDIR
		}
	}

	if oldParent != newParent {
		if err := newParent.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
			return err
		}
		newParent.opMu.Lock()
		defer newParent.opMu.Unlock()
	}
	if newParent.isDeleted() {
		return linuxerr.ENOENT
	}
	replaced, err := fs.getChildLocked(ctx, newParent, newName, &ds) // +checklocksforce: newParent.opMu taken if newParent != oldParent.
	if err != nil && !linuxerr.Equals(linuxerr.ENOENT, err) {
		return err
	}
	var replacedVFSD *vfs.Dentry
	if replaced != nil {
		if opts.Flags&linux.RENAME_NOREPLACE != 0 {
			return linuxerr.EEXIST
		}
		replacedVFSD = &replaced.vfsd
		if replaced.isDir() {
			if !renamed.isDir() {
				return linuxerr.EISDIR
			}
			if genericIsAncestorDentry(replaced, renamed) {
				return linuxerr.ENOTEMPTY
			}
		} else {
			if rp.MustBeDir() || renamed.isDir() {
				return linuxerr.ENOTDIR
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
		if err := oldParent.rename(ctx, oldName, newParent, newName); err != nil {
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
		if err := newParent.unlink(ctx, newName, flags); err != nil {
			vfsObj.AbortRenameDentry(&renamed.vfsd, replacedVFSD)
			return err
		}
	}

	// Update the dentry tree.
	newParent.childrenMu.Lock()
	defer newParent.childrenMu.Unlock()
	if oldParent != newParent {
		oldParent.childrenMu.Lock()
		defer oldParent.childrenMu.Unlock()
	}

	toDecRef = vfsObj.CommitRenameReplaceDentry(ctx, &renamed.vfsd, replacedVFSD)
	if replaced != nil {
		replaced.setDeleted()
		if replaced.isSynthetic() {
			newParent.syntheticChildren--
			replaced.decRefNoCaching()
		}
		ds = appendDentry(ds, replaced)
		// Remove the replaced entry from its parent's cache.
		delete(newParent.children, newName)
	}
	oldParent.cacheNegativeLookupLocked(oldName) // +checklocksforce: oldParent.childrenMu is held if oldParent != newParent.
	if renamed.isSynthetic() {
		oldParent.syntheticChildren--
		newParent.syntheticChildren++
	}
	// We have d.opMu for writing, so no need to check for existence of a
	// child with the given name. We could not have raced.
	newParent.cacheNewChildLocked(renamed, newName)
	oldParent.decRefNoCaching()
	if oldParent != newParent {
		ds = appendDentry(ds, newParent)
		ds = appendDentry(ds, oldParent)
	}

	// Update metadata.
	if renamed.cachedMetadataAuthoritative() {
		renamed.touchCtime()
	}
	if oldParent.cachedMetadataAuthoritative() {
		oldParent.clearDirentsLocked()
		oldParent.touchCMtime()
		if renamed.isDir() {
			oldParent.decLinks()
		}
	}
	if newParent.cachedMetadataAuthoritative() {
		newParent.clearDirentsLocked()
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
		d = d.parent.Load()
	}
	statfs, err := d.statfs(ctx)
	if err != nil {
		return linux.Statfs{}, err
	}
	if statfs.NameLength == 0 || statfs.NameLength > MaxFilenameLen {
		statfs.NameLength = MaxFilenameLen
	}
	// This is primarily for distinguishing a gofer file system in
	// tests. Testing is important, so instead of defining
	// something completely random, use a standard value.
	statfs.Type = linux.V9FS_MAGIC
	return statfs, nil
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt.
func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	return fs.doCreateAt(ctx, rp, false /* dir */, func(parent *dentry, name string, ds **[]*dentry) (*dentry, error) {
		child, err := parent.symlink(ctx, name, target, rp.Credentials())
		if err != nil {
			return nil, err
		}
		if parent.fs.opts.interop != InteropModeShared {
			// Cache the symlink target on creation. In practice, this helps avoid a
			// lot of ReadLink RPCs. Note that when InteropModeShared is in effect,
			// we are forced to make Readlink RPCs. Because in this mode, we use host
			// timestamps, not timestamps based on our internal clock. And readlink
			// updates the atime on the host.
			child.haveTarget = true
			child.target = target
		}
		return child, nil
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
	if !d.isSocket() {
		return nil, linuxerr.ECONNREFUSED
	}
	if d.endpoint != nil {
		return d.endpoint, nil
	}
	if !d.isSynthetic() {
		d.IncRef()
		ds = appendDentry(ds, d)
		return &endpoint{
			dentry: d,
			path:   opts.Addr,
		}, nil
	}
	return nil, linuxerr.ECONNREFUSED
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
	return d.listXattr(ctx, size)
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
	value any
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
	}

	switch fs.opts.interop {
	case InteropModeExclusive:
		optsKV = append(optsKV, mopt{moptCache, cacheFSCache})
	case InteropModeWritethrough:
		optsKV = append(optsKV, mopt{moptCache, cacheFSCacheWritethrough})
	case InteropModeShared:
		optsKV = append(optsKV, mopt{moptCache, cacheRemoteRevalidating})
	}
	if fs.opts.regularFilesUseSpecialFileFD {
		optsKV = append(optsKV, mopt{moptDisableFileHandleSharing, nil})
	}
	if fs.opts.disableFifoOpen {
		optsKV = append(optsKV, mopt{moptDisableFifoOpen, nil})
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
	if fs.opts.directfs.enabled {
		optsKV = append(optsKV, mopt{moptDirectfs, nil})
	}

	opts := make([]string, 0, len(optsKV))
	for _, opt := range optsKV {
		opts = append(opts, opt.String())
	}
	return strings.Join(opts, ",")
}

// IsDescendant implements vfs.FilesystemImpl.IsDescendant.
func (fs *filesystem) IsDescendant(vfsroot, vd vfs.VirtualDentry) bool {
	return genericIsDescendant(vfsroot.Dentry(), vd.Dentry().Impl().(*dentry))
}
