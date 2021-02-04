// Copyright 2020 The gVisor Authors.
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

package overlay

import (
	"fmt"
	"strings"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// _OVL_XATTR_PREFIX is an extended attribute key prefix to identify overlayfs
// attributes.
// Linux: fs/overlayfs/overlayfs.h:OVL_XATTR_PREFIX
const _OVL_XATTR_PREFIX = linux.XATTR_TRUSTED_PREFIX + "overlay."

// _OVL_XATTR_OPAQUE is an extended attribute key whose value is set to "y" for
// opaque directories.
// Linux: fs/overlayfs/overlayfs.h:OVL_XATTR_OPAQUE
const _OVL_XATTR_OPAQUE = _OVL_XATTR_PREFIX + "opaque"

func isWhiteout(stat *linux.Statx) bool {
	return stat.Mode&linux.S_IFMT == linux.S_IFCHR && stat.RdevMajor == 0 && stat.RdevMinor == 0
}

// Sync implements vfs.FilesystemImpl.Sync.
func (fs *filesystem) Sync(ctx context.Context) error {
	if fs.opts.UpperRoot.Ok() {
		return fs.opts.UpperRoot.Mount().Filesystem().Impl().Sync(ctx)
	}
	return nil
}

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

// renameMuRUnlockAndCheckDrop calls fs.renameMu.RUnlock(), then calls
// dentry.checkDropLocked on all dentries in *dsp with fs.renameMu locked for
// writing.
//
// dsp is a pointer-to-pointer since defer evaluates its arguments immediately,
// but dentry slices are allocated lazily, and it's much easier to say "defer
// fs.renameMuRUnlockAndCheckDrop(&ds)" than "defer func() {
// fs.renameMuRUnlockAndCheckDrop(ds) }()" to work around this.
func (fs *filesystem) renameMuRUnlockAndCheckDrop(ctx context.Context, dsp **[]*dentry) {
	fs.renameMu.RUnlock()
	if *dsp == nil {
		return
	}
	ds := **dsp
	// Only go through calling dentry.checkDropLocked() (which requires
	// re-locking renameMu) if we actually have any dentries with zero refs.
	checkAny := false
	for i := range ds {
		if atomic.LoadInt64(&ds[i].refs) == 0 {
			checkAny = true
			break
		}
	}
	if checkAny {
		fs.renameMu.Lock()
		for _, d := range ds {
			d.checkDropLocked(ctx)
		}
		fs.renameMu.Unlock()
	}
	putDentrySlice(*dsp)
}

func (fs *filesystem) renameMuUnlockAndCheckDrop(ctx context.Context, ds **[]*dentry) {
	if *ds == nil {
		fs.renameMu.Unlock()
		return
	}
	for _, d := range **ds {
		d.checkDropLocked(ctx)
	}
	fs.renameMu.Unlock()
	putDentrySlice(*ds)
}

// stepLocked resolves rp.Component() to an existing file, starting from the
// given directory.
//
// Dentries which may have a reference count of zero, and which therefore
// should be dropped once traversal is complete, are appended to ds.
//
// Preconditions:
// * fs.renameMu must be locked.
// * d.dirMu must be locked.
// * !rp.Done().
func (fs *filesystem) stepLocked(ctx context.Context, rp *vfs.ResolvingPath, d *dentry, mayFollowSymlinks bool, ds **[]*dentry) (*dentry, lookupLayer, error) {
	if !d.isDir() {
		return nil, lookupLayerNone, syserror.ENOTDIR
	}
	if err := d.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, lookupLayerNone, err
	}
afterSymlink:
	name := rp.Component()
	if name == "." {
		rp.Advance()
		return d, d.topLookupLayer(), nil
	}
	if name == ".." {
		if isRoot, err := rp.CheckRoot(ctx, &d.vfsd); err != nil {
			return nil, lookupLayerNone, err
		} else if isRoot || d.parent == nil {
			rp.Advance()
			return d, d.topLookupLayer(), nil
		}
		if err := rp.CheckMount(ctx, &d.parent.vfsd); err != nil {
			return nil, lookupLayerNone, err
		}
		rp.Advance()
		return d.parent, d.parent.topLookupLayer(), nil
	}
	child, topLookupLayer, err := fs.getChildLocked(ctx, d, name, ds)
	if err != nil {
		return nil, topLookupLayer, err
	}
	if err := rp.CheckMount(ctx, &child.vfsd); err != nil {
		return nil, lookupLayerNone, err
	}
	if child.isSymlink() && mayFollowSymlinks && rp.ShouldFollowSymlink() {
		target, err := child.readlink(ctx)
		if err != nil {
			return nil, lookupLayerNone, err
		}
		if err := rp.HandleSymlink(target); err != nil {
			return nil, topLookupLayer, err
		}
		goto afterSymlink // don't check the current directory again
	}
	rp.Advance()
	return child, topLookupLayer, nil
}

// Preconditions:
// * fs.renameMu must be locked.
// * d.dirMu must be locked.
func (fs *filesystem) getChildLocked(ctx context.Context, parent *dentry, name string, ds **[]*dentry) (*dentry, lookupLayer, error) {
	if child, ok := parent.children[name]; ok {
		return child, child.topLookupLayer(), nil
	}
	child, topLookupLayer, err := fs.lookupLocked(ctx, parent, name)
	if err != nil {
		return nil, topLookupLayer, err
	}
	if parent.children == nil {
		parent.children = make(map[string]*dentry)
	}
	parent.children[name] = child
	// child's refcount is initially 0, so it may be dropped after traversal.
	*ds = appendDentry(*ds, child)
	return child, topLookupLayer, nil
}

// Preconditions:
// * fs.renameMu must be locked.
// * parent.dirMu must be locked.
func (fs *filesystem) lookupLocked(ctx context.Context, parent *dentry, name string) (*dentry, lookupLayer, error) {
	childPath := fspath.Parse(name)
	child := fs.newDentry()
	topLookupLayer := lookupLayerNone
	var lookupErr error

	vfsObj := fs.vfsfs.VirtualFilesystem()
	parent.iterLayers(func(parentVD vfs.VirtualDentry, isUpper bool) bool {
		childVD, err := vfsObj.GetDentryAt(ctx, fs.creds, &vfs.PathOperation{
			Root:  parentVD,
			Start: parentVD,
			Path:  childPath,
		}, &vfs.GetDentryOptions{})
		if err == syserror.ENOENT || err == syserror.ENAMETOOLONG {
			// The file doesn't exist on this layer. Proceed to the next one.
			return true
		}
		if err != nil {
			lookupErr = err
			return false
		}
		defer childVD.DecRef(ctx)

		mask := uint32(linux.STATX_TYPE)
		if topLookupLayer == lookupLayerNone {
			// Mode, UID, GID, and (for non-directories) inode number come from
			// the topmost layer on which the file exists.
			mask |= linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID | linux.STATX_INO
		}
		stat, err := vfsObj.StatAt(ctx, fs.creds, &vfs.PathOperation{
			Root:  childVD,
			Start: childVD,
		}, &vfs.StatOptions{
			Mask: mask,
		})
		if err != nil {
			lookupErr = err
			return false
		}
		if stat.Mask&mask != mask {
			lookupErr = syserror.EREMOTE
			return false
		}

		if isWhiteout(&stat) {
			// This is a whiteout, so it "doesn't exist" on this layer, and
			// layers below this one are ignored.
			if isUpper {
				topLookupLayer = lookupLayerUpperWhiteout
			}
			return false
		}
		isDir := stat.Mode&linux.S_IFMT == linux.S_IFDIR
		if topLookupLayer != lookupLayerNone && !isDir {
			// Directories are not merged with non-directory files from lower
			// layers; instead, layers including and below the first
			// non-directory file are ignored. (This file must be a directory
			// on previous layers, since lower layers aren't searched for
			// non-directory files.)
			return false
		}

		// Update child to include this layer.
		childVD.IncRef()
		if isUpper {
			child.upperVD = childVD
			child.copiedUp = 1
		} else {
			child.lowerVDs = append(child.lowerVDs, childVD)
		}
		if topLookupLayer == lookupLayerNone {
			if isUpper {
				topLookupLayer = lookupLayerUpper
			} else {
				topLookupLayer = lookupLayerLower
			}
			child.mode = uint32(stat.Mode)
			child.uid = stat.UID
			child.gid = stat.GID
			child.devMajor = stat.DevMajor
			child.devMinor = stat.DevMinor
			child.ino = stat.Ino
		}

		// For non-directory files, only the topmost layer that contains a file
		// matters.
		if !isDir {
			return false
		}

		// Directories are merged with directories from lower layers if they
		// are not explicitly opaque.
		opaqueVal, err := vfsObj.GetXattrAt(ctx, fs.creds, &vfs.PathOperation{
			Root:  childVD,
			Start: childVD,
		}, &vfs.GetXattrOptions{
			Name: _OVL_XATTR_OPAQUE,
			Size: 1,
		})
		return !(err == nil && opaqueVal == "y")
	})

	if lookupErr != nil {
		child.destroyLocked(ctx)
		return nil, topLookupLayer, lookupErr
	}
	if !topLookupLayer.existsInOverlay() {
		child.destroyLocked(ctx)
		return nil, topLookupLayer, syserror.ENOENT
	}

	// Device and inode numbers were copied from the topmost layer above;
	// override them if necessary.
	if child.isDir() {
		child.devMajor = linux.UNNAMED_MAJOR
		child.devMinor = fs.dirDevMinor
		child.ino = fs.newDirIno()
	} else if !child.upperVD.Ok() {
		childDevMinor, err := fs.getLowerDevMinor(child.devMajor, child.devMinor)
		if err != nil {
			ctx.Infof("overlay.filesystem.lookupLocked: failed to map lower layer device number (%d, %d) to an overlay-specific device number: %v", child.devMajor, child.devMinor, err)
			child.destroyLocked(ctx)
			return nil, topLookupLayer, err
		}
		child.devMajor = linux.UNNAMED_MAJOR
		child.devMinor = childDevMinor
	}

	parent.IncRef()
	child.parent = parent
	child.name = name
	return child, topLookupLayer, nil
}

// lookupLayerLocked is similar to lookupLocked, but only returns information
// about the file rather than a dentry.
//
// Preconditions:
// * fs.renameMu must be locked.
// * parent.dirMu must be locked.
func (fs *filesystem) lookupLayerLocked(ctx context.Context, parent *dentry, name string) (lookupLayer, error) {
	childPath := fspath.Parse(name)
	lookupLayer := lookupLayerNone
	var lookupErr error

	parent.iterLayers(func(parentVD vfs.VirtualDentry, isUpper bool) bool {
		stat, err := fs.vfsfs.VirtualFilesystem().StatAt(ctx, fs.creds, &vfs.PathOperation{
			Root:  parentVD,
			Start: parentVD,
			Path:  childPath,
		}, &vfs.StatOptions{
			Mask: linux.STATX_TYPE,
		})
		if err == syserror.ENOENT || err == syserror.ENAMETOOLONG {
			// The file doesn't exist on this layer. Proceed to the next
			// one.
			return true
		}
		if err != nil {
			lookupErr = err
			return false
		}
		if stat.Mask&linux.STATX_TYPE == 0 {
			// Linux's overlayfs tends to return EREMOTE in cases where a file
			// is unusable for reasons that are not better captured by another
			// errno.
			lookupErr = syserror.EREMOTE
			return false
		}
		if isWhiteout(&stat) {
			// This is a whiteout, so it "doesn't exist" on this layer, and
			// layers below this one are ignored.
			if isUpper {
				lookupLayer = lookupLayerUpperWhiteout
			}
			return false
		}
		// The file exists; we can stop searching.
		if isUpper {
			lookupLayer = lookupLayerUpper
		} else {
			lookupLayer = lookupLayerLower
		}
		return false
	})

	return lookupLayer, lookupErr
}

type lookupLayer int

const (
	// lookupLayerNone indicates that no file exists at the given path on the
	// upper layer, and is either whited out or does not exist on lower layers.
	// Therefore, the file does not exist in the overlay filesystem, and file
	// creation may proceed normally (if an upper layer exists).
	lookupLayerNone lookupLayer = iota

	// lookupLayerLower indicates that no file exists at the given path on the
	// upper layer, but exists on a lower layer. Therefore, the file exists in
	// the overlay filesystem, but must be copied-up before mutation.
	lookupLayerLower

	// lookupLayerUpper indicates that a non-whiteout file exists at the given
	// path on the upper layer. Therefore, the file exists in the overlay
	// filesystem, and is already copied-up.
	lookupLayerUpper

	// lookupLayerUpperWhiteout indicates that a whiteout exists at the given
	// path on the upper layer. Therefore, the file does not exist in the
	// overlay filesystem, and file creation must remove the whiteout before
	// proceeding.
	lookupLayerUpperWhiteout
)

func (ll lookupLayer) existsInOverlay() bool {
	return ll == lookupLayerLower || ll == lookupLayerUpper
}

// walkParentDirLocked resolves all but the last path component of rp to an
// existing directory, starting from the given directory (which is usually
// rp.Start().Impl().(*dentry)). It does not check that the returned directory
// is searchable by the provider of rp.
//
// Preconditions:
// * fs.renameMu must be locked.
// * !rp.Done().
func (fs *filesystem) walkParentDirLocked(ctx context.Context, rp *vfs.ResolvingPath, d *dentry, ds **[]*dentry) (*dentry, error) {
	for !rp.Final() {
		d.dirMu.Lock()
		next, _, err := fs.stepLocked(ctx, rp, d, true /* mayFollowSymlinks */, ds)
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
	for !rp.Done() {
		d.dirMu.Lock()
		next, _, err := fs.stepLocked(ctx, rp, d, true /* mayFollowSymlinks */, ds)
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
// Preconditions:
// * !rp.Done().
// * For the final path component in rp, !rp.ShouldFollowSymlink().
func (fs *filesystem) doCreateAt(ctx context.Context, rp *vfs.ResolvingPath, dir bool, create func(parent *dentry, name string, haveUpperWhiteout bool) error) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	start := rp.Start().Impl().(*dentry)
	parent, err := fs.walkParentDirLocked(ctx, rp, start, &ds)
	if err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return syserror.EEXIST
	}
	if parent.vfsd.IsDead() {
		return syserror.ENOENT
	}

	if err := parent.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return err
	}

	parent.dirMu.Lock()
	defer parent.dirMu.Unlock()

	// Determine if a file already exists at name.
	if _, ok := parent.children[name]; ok {
		return syserror.EEXIST
	}
	childLayer, err := fs.lookupLayerLocked(ctx, parent, name)
	if err != nil {
		return err
	}
	if childLayer.existsInOverlay() {
		return syserror.EEXIST
	}

	if !dir && rp.MustBeDir() {
		return syserror.ENOENT
	}

	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	if err := parent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	// Ensure that the parent directory is copied-up so that we can create the
	// new file in the upper layer.
	if err := parent.copyUpLocked(ctx); err != nil {
		return err
	}

	// Finally create the new file.
	if err := create(parent, name, childLayer == lookupLayerUpperWhiteout); err != nil {
		return err
	}

	parent.dirents = nil
	ev := linux.IN_CREATE
	if dir {
		ev |= linux.IN_ISDIR
	}
	parent.watches.Notify(ctx, name, uint32(ev), 0 /* cookie */, vfs.InodeEvent, false /* unlinked */)
	return nil
}

// Preconditions: pop's parent directory has been copied up.
func (fs *filesystem) createWhiteout(ctx context.Context, vfsObj *vfs.VirtualFilesystem, pop *vfs.PathOperation) error {
	return vfsObj.MknodAt(ctx, fs.creds, pop, &vfs.MknodOptions{
		Mode: linux.S_IFCHR, // permissions == include/linux/fs.h:WHITEOUT_MODE == 0
		// DevMajor == DevMinor == 0, from include/linux/fs.h:WHITEOUT_DEV
	})
}

func (fs *filesystem) cleanupRecreateWhiteout(ctx context.Context, vfsObj *vfs.VirtualFilesystem, pop *vfs.PathOperation) {
	if err := fs.createWhiteout(ctx, vfsObj, pop); err != nil {
		panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to recreate whiteout after failed file creation: %v", err))
	}
}

// AccessAt implements vfs.Filesystem.Impl.AccessAt.
func (fs *filesystem) AccessAt(ctx context.Context, rp *vfs.ResolvingPath, creds *auth.Credentials, ats vfs.AccessTypes) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return err
	}
	return d.checkPermissions(creds, ats)
}

// BoundEndpointAt implements vfs.FilesystemImpl.BoundEndpointAt.
func (fs *filesystem) BoundEndpointAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.BoundEndpointOptions) (transport.BoundEndpoint, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return nil, err
	}
	if err := d.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
		return nil, err
	}
	layerVD := d.topLayer()
	return fs.vfsfs.VirtualFilesystem().BoundEndpointAt(ctx, fs.creds, &vfs.PathOperation{
		Root:  layerVD,
		Start: layerVD,
	}, &opts)
}

// GetDentryAt implements vfs.FilesystemImpl.GetDentryAt.
func (fs *filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
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
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	start := rp.Start().Impl().(*dentry)
	d, err := fs.walkParentDirLocked(ctx, rp, start, &ds)
	if err != nil {
		return nil, err
	}
	d.IncRef()
	return &d.vfsd, nil
}

// LinkAt implements vfs.FilesystemImpl.LinkAt.
func (fs *filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	return fs.doCreateAt(ctx, rp, false /* dir */, func(parent *dentry, childName string, haveUpperWhiteout bool) error {
		if rp.Mount() != vd.Mount() {
			return syserror.EXDEV
		}
		old := vd.Dentry().Impl().(*dentry)
		if old.isDir() {
			return syserror.EPERM
		}
		if err := old.copyUpLocked(ctx); err != nil {
			return err
		}
		vfsObj := fs.vfsfs.VirtualFilesystem()
		newpop := vfs.PathOperation{
			Root:  parent.upperVD,
			Start: parent.upperVD,
			Path:  fspath.Parse(childName),
		}
		if haveUpperWhiteout {
			if err := vfsObj.UnlinkAt(ctx, fs.creds, &newpop); err != nil {
				return err
			}
		}
		if err := vfsObj.LinkAt(ctx, fs.creds, &vfs.PathOperation{
			Root:  old.upperVD,
			Start: old.upperVD,
		}, &newpop); err != nil {
			if haveUpperWhiteout {
				fs.cleanupRecreateWhiteout(ctx, vfsObj, &newpop)
			}
			return err
		}
		creds := rp.Credentials()
		if err := vfsObj.SetStatAt(ctx, fs.creds, &newpop, &vfs.SetStatOptions{
			Stat: linux.Statx{
				Mask: linux.STATX_UID | linux.STATX_GID,
				UID:  uint32(creds.EffectiveKUID),
				GID:  uint32(creds.EffectiveKGID),
			},
		}); err != nil {
			if cleanupErr := vfsObj.UnlinkAt(ctx, fs.creds, &newpop); cleanupErr != nil {
				panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to delete upper layer file after LinkAt metadata update failure: %v", cleanupErr))
			} else if haveUpperWhiteout {
				fs.cleanupRecreateWhiteout(ctx, vfsObj, &newpop)
			}
			return err
		}
		old.watches.Notify(ctx, "", linux.IN_ATTRIB, 0 /* cookie */, vfs.InodeEvent, false /* unlinked */)
		return nil
	})
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	return fs.doCreateAt(ctx, rp, true /* dir */, func(parent *dentry, childName string, haveUpperWhiteout bool) error {
		vfsObj := fs.vfsfs.VirtualFilesystem()
		pop := vfs.PathOperation{
			Root:  parent.upperVD,
			Start: parent.upperVD,
			Path:  fspath.Parse(childName),
		}
		if haveUpperWhiteout {
			if err := vfsObj.UnlinkAt(ctx, fs.creds, &pop); err != nil {
				return err
			}
		}
		if err := vfsObj.MkdirAt(ctx, fs.creds, &pop, &opts); err != nil {
			if haveUpperWhiteout {
				fs.cleanupRecreateWhiteout(ctx, vfsObj, &pop)
			}
			return err
		}
		creds := rp.Credentials()
		if err := vfsObj.SetStatAt(ctx, fs.creds, &pop, &vfs.SetStatOptions{
			Stat: linux.Statx{
				Mask: linux.STATX_UID | linux.STATX_GID,
				UID:  uint32(creds.EffectiveKUID),
				GID:  uint32(creds.EffectiveKGID),
			},
		}); err != nil {
			if cleanupErr := vfsObj.RmdirAt(ctx, fs.creds, &pop); cleanupErr != nil {
				panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to delete upper layer directory after MkdirAt metadata update failure: %v", cleanupErr))
			} else if haveUpperWhiteout {
				fs.cleanupRecreateWhiteout(ctx, vfsObj, &pop)
			}
			return err
		}
		if haveUpperWhiteout {
			// There may be directories on lower layers (previously hidden by
			// the whiteout) that the new directory should not be merged with.
			// Mark it opaque to prevent merging.
			if err := vfsObj.SetXattrAt(ctx, fs.creds, &pop, &vfs.SetXattrOptions{
				Name:  _OVL_XATTR_OPAQUE,
				Value: "y",
			}); err != nil {
				if cleanupErr := vfsObj.RmdirAt(ctx, fs.creds, &pop); cleanupErr != nil {
					panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to delete upper layer directory after MkdirAt set-opaque failure: %v", cleanupErr))
				} else {
					fs.cleanupRecreateWhiteout(ctx, vfsObj, &pop)
				}
				return err
			}
		}
		return nil
	})
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	return fs.doCreateAt(ctx, rp, false /* dir */, func(parent *dentry, childName string, haveUpperWhiteout bool) error {
		// Disallow attempts to create whiteouts.
		if opts.Mode&linux.S_IFMT == linux.S_IFCHR && opts.DevMajor == 0 && opts.DevMinor == 0 {
			return syserror.EPERM
		}
		vfsObj := fs.vfsfs.VirtualFilesystem()
		pop := vfs.PathOperation{
			Root:  parent.upperVD,
			Start: parent.upperVD,
			Path:  fspath.Parse(childName),
		}
		if haveUpperWhiteout {
			if err := vfsObj.UnlinkAt(ctx, fs.creds, &pop); err != nil {
				return err
			}
		}
		if err := vfsObj.MknodAt(ctx, fs.creds, &pop, &opts); err != nil {
			if haveUpperWhiteout {
				fs.cleanupRecreateWhiteout(ctx, vfsObj, &pop)
			}
			return err
		}
		creds := rp.Credentials()
		if err := vfsObj.SetStatAt(ctx, fs.creds, &pop, &vfs.SetStatOptions{
			Stat: linux.Statx{
				Mask: linux.STATX_UID | linux.STATX_GID,
				UID:  uint32(creds.EffectiveKUID),
				GID:  uint32(creds.EffectiveKGID),
			},
		}); err != nil {
			if cleanupErr := vfsObj.UnlinkAt(ctx, fs.creds, &pop); cleanupErr != nil {
				panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to delete upper layer file after MknodAt metadata update failure: %v", cleanupErr))
			} else if haveUpperWhiteout {
				fs.cleanupRecreateWhiteout(ctx, vfsObj, &pop)
			}
			return err
		}
		return nil
	})
}

// OpenAt implements vfs.FilesystemImpl.OpenAt.
func (fs *filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	mayCreate := opts.Flags&linux.O_CREAT != 0
	mustCreate := opts.Flags&(linux.O_CREAT|linux.O_EXCL) == (linux.O_CREAT | linux.O_EXCL)
	mayWrite := vfs.AccessTypesForOpenFlags(&opts).MayWrite()

	var ds *[]*dentry
	fs.renameMu.RLock()
	unlocked := false
	unlock := func() {
		if !unlocked {
			fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
			unlocked = true
		}
	}
	defer unlock()

	start := rp.Start().Impl().(*dentry)
	if rp.Done() {
		if mayCreate && rp.MustBeDir() {
			return nil, syserror.EISDIR
		}
		if mustCreate {
			return nil, syserror.EEXIST
		}
		if start.isRegularFile() && mayWrite {
			if err := start.copyUpLocked(ctx); err != nil {
				return nil, err
			}
		}
		start.IncRef()
		defer start.DecRef(ctx)
		unlock()
		return start.openCopiedUp(ctx, rp, &opts)
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
	child, topLookupLayer, err := fs.stepLocked(ctx, rp, parent, false /* mayFollowSymlinks */, &ds)
	if err == syserror.ENOENT && mayCreate {
		fd, err := fs.createAndOpenLocked(ctx, rp, parent, &opts, &ds, topLookupLayer == lookupLayerUpperWhiteout)
		parent.dirMu.Unlock()
		return fd, err
	}
	parent.dirMu.Unlock()
	if err != nil {
		return nil, err
	}
	// Open existing child or follow symlink.
	if mustCreate {
		return nil, syserror.EEXIST
	}
	if child.isSymlink() && rp.ShouldFollowSymlink() {
		target, err := child.readlink(ctx)
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
	if child.isRegularFile() && mayWrite {
		if err := child.copyUpLocked(ctx); err != nil {
			return nil, err
		}
	}
	child.IncRef()
	defer child.DecRef(ctx)
	unlock()
	return child.openCopiedUp(ctx, rp, &opts)
}

// Preconditions: If vfs.AccessTypesForOpenFlags(opts).MayWrite(), then d has
// been copied up.
func (d *dentry) openCopiedUp(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	ats := vfs.AccessTypesForOpenFlags(opts)
	if err := d.checkPermissions(rp.Credentials(), ats); err != nil {
		return nil, err
	}
	mnt := rp.Mount()

	// Directory FDs open FDs from each layer when directory entries are read,
	// so they don't require opening an FD from d.topLayer() up front.
	ftype := atomic.LoadUint32(&d.mode) & linux.S_IFMT
	if ftype == linux.S_IFDIR {
		// Can't open directories with O_CREAT.
		if opts.Flags&linux.O_CREAT != 0 {
			return nil, syserror.EISDIR
		}
		// Can't open directories writably.
		if ats.MayWrite() {
			return nil, syserror.EISDIR
		}
		if opts.Flags&linux.O_DIRECT != 0 {
			return nil, syserror.EINVAL
		}
		fd := &directoryFD{}
		fd.LockFD.Init(&d.locks)
		if err := fd.vfsfd.Init(fd, opts.Flags, mnt, &d.vfsd, &vfs.FileDescriptionOptions{
			UseDentryMetadata: true,
		}); err != nil {
			return nil, err
		}
		return &fd.vfsfd, nil
	}

	layerVD, isUpper := d.topLayerInfo()
	layerFD, err := rp.VirtualFilesystem().OpenAt(ctx, d.fs.creds, &vfs.PathOperation{
		Root:  layerVD,
		Start: layerVD,
	}, opts)
	if err != nil {
		return nil, err
	}
	if ftype != linux.S_IFREG {
		return layerFD, nil
	}
	layerFlags := layerFD.StatusFlags()
	fd := &regularFileFD{
		copiedUp:    isUpper,
		cachedFD:    layerFD,
		cachedFlags: layerFlags,
	}
	fd.LockFD.Init(&d.locks)
	layerFDOpts := layerFD.Options()
	if err := fd.vfsfd.Init(fd, layerFlags, mnt, &d.vfsd, &layerFDOpts); err != nil {
		layerFD.DecRef(ctx)
		return nil, err
	}
	return &fd.vfsfd, nil
}

// Preconditions:
// * parent.dirMu must be locked.
// * parent does not already contain a child named rp.Component().
func (fs *filesystem) createAndOpenLocked(ctx context.Context, rp *vfs.ResolvingPath, parent *dentry, opts *vfs.OpenOptions, ds **[]*dentry, haveUpperWhiteout bool) (*vfs.FileDescription, error) {
	creds := rp.Credentials()
	if err := parent.checkPermissions(creds, vfs.MayWrite); err != nil {
		return nil, err
	}
	if parent.vfsd.IsDead() {
		return nil, syserror.ENOENT
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return nil, err
	}
	defer mnt.EndWrite()

	if err := parent.copyUpLocked(ctx); err != nil {
		return nil, err
	}

	vfsObj := fs.vfsfs.VirtualFilesystem()
	childName := rp.Component()
	pop := vfs.PathOperation{
		Root:  parent.upperVD,
		Start: parent.upperVD,
		Path:  fspath.Parse(childName),
	}
	// Unlink the whiteout if it exists.
	if haveUpperWhiteout {
		if err := vfsObj.UnlinkAt(ctx, fs.creds, &pop); err != nil {
			log.Warningf("overlay.filesystem.createAndOpenLocked: failed to unlink whiteout: %v", err)
			return nil, err
		}
	}
	// Create the file on the upper layer, and get an FD representing it.
	upperFD, err := vfsObj.OpenAt(ctx, fs.creds, &pop, &vfs.OpenOptions{
		Flags: opts.Flags&^vfs.FileCreationFlags | linux.O_CREAT | linux.O_EXCL,
		Mode:  opts.Mode,
	})
	if err != nil {
		if haveUpperWhiteout {
			fs.cleanupRecreateWhiteout(ctx, vfsObj, &pop)
		}
		return nil, err
	}
	// Change the file's owner to the caller. We can't use upperFD.SetStat()
	// because it will pick up creds from ctx.
	if err := vfsObj.SetStatAt(ctx, fs.creds, &pop, &vfs.SetStatOptions{
		Stat: linux.Statx{
			Mask: linux.STATX_UID | linux.STATX_GID,
			UID:  uint32(creds.EffectiveKUID),
			GID:  uint32(creds.EffectiveKGID),
		},
	}); err != nil {
		if cleanupErr := vfsObj.UnlinkAt(ctx, fs.creds, &pop); cleanupErr != nil {
			panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to delete upper layer file after OpenAt(O_CREAT) metadata update failure: %v", cleanupErr))
		} else if haveUpperWhiteout {
			fs.cleanupRecreateWhiteout(ctx, vfsObj, &pop)
		}
		return nil, err
	}
	// Re-lookup to get a dentry representing the new file, which is needed for
	// the returned FD.
	child, _, err := fs.getChildLocked(ctx, parent, childName, ds)
	if err != nil {
		if cleanupErr := vfsObj.UnlinkAt(ctx, fs.creds, &pop); cleanupErr != nil {
			panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to delete upper layer file after OpenAt(O_CREAT) dentry lookup failure: %v", cleanupErr))
		} else if haveUpperWhiteout {
			fs.cleanupRecreateWhiteout(ctx, vfsObj, &pop)
		}
		return nil, err
	}
	// Finally construct the overlay FD. Below this point, we don't perform
	// cleanup (the file was created successfully even if we can no longer open
	// it for some reason).
	parent.dirents = nil
	upperFlags := upperFD.StatusFlags()
	fd := &regularFileFD{
		copiedUp:    true,
		cachedFD:    upperFD,
		cachedFlags: upperFlags,
	}
	fd.LockFD.Init(&child.locks)
	upperFDOpts := upperFD.Options()
	if err := fd.vfsfd.Init(fd, upperFlags, mnt, &child.vfsd, &upperFDOpts); err != nil {
		upperFD.DecRef(ctx)
		return nil, err
	}
	parent.watches.Notify(ctx, childName, linux.IN_CREATE, 0 /* cookie */, vfs.PathEvent, false /* unlinked */)
	return &fd.vfsfd, nil
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return "", err
	}
	layerVD := d.topLayer()
	return fs.vfsfs.VirtualFilesystem().ReadlinkAt(ctx, d.fs.creds, &vfs.PathOperation{
		Root:  layerVD,
		Start: layerVD,
	})
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, oldParentVD vfs.VirtualDentry, oldName string, opts vfs.RenameOptions) error {
	if opts.Flags != 0 {
		return syserror.EINVAL
	}

	var ds *[]*dentry
	fs.renameMu.Lock()
	defer fs.renameMuUnlockAndCheckDrop(ctx, &ds)
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
	creds := rp.Credentials()
	if err := oldParent.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	// We need a dentry representing the renamed file since, if it's a
	// directory, we need to check for write permission on it.
	oldParent.dirMu.Lock()
	defer oldParent.dirMu.Unlock()
	renamed, _, err := fs.getChildLocked(ctx, oldParent, oldName, &ds)
	if err != nil {
		return err
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
	if newParent.vfsd.IsDead() {
		return syserror.ENOENT
	}
	var (
		replaced      *dentry
		replacedVFSD  *vfs.Dentry
		replacedLayer lookupLayer
		whiteouts     map[string]bool
	)
	replaced, replacedLayer, err = fs.getChildLocked(ctx, newParent, newName, &ds)
	if err != nil && err != syserror.ENOENT {
		return err
	}
	if replaced != nil {
		replacedVFSD = &replaced.vfsd
		if replaced.isDir() {
			if !renamed.isDir() {
				return syserror.EISDIR
			}
			if genericIsAncestorDentry(replaced, renamed) {
				return syserror.ENOTEMPTY
			}
			replaced.dirMu.Lock()
			defer replaced.dirMu.Unlock()
			whiteouts, err = replaced.collectWhiteoutsForRmdirLocked(ctx)
			if err != nil {
				return err
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

	// renamed and oldParent need to be copied-up before they're renamed on the
	// upper layer.
	if err := renamed.copyUpLocked(ctx); err != nil {
		return err
	}
	// If renamed is a directory, all of its descendants need to be copied-up
	// before they're renamed on the upper layer.
	if renamed.isDir() {
		if err := renamed.copyUpDescendantsLocked(ctx, &ds); err != nil {
			return err
		}
	}
	// newParent must be copied-up before it can contain renamed on the upper
	// layer.
	if err := newParent.copyUpLocked(ctx); err != nil {
		return err
	}
	// If replaced exists, it doesn't need to be copied-up, but we do need to
	// serialize with copy-up. Holding renameMu for writing should be
	// sufficient, but out of an abundance of caution...
	if replaced != nil {
		replaced.copyMu.RLock()
		defer replaced.copyMu.RUnlock()
	}

	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	if err := vfsObj.PrepareRenameDentry(mntns, &renamed.vfsd, replacedVFSD); err != nil {
		return err
	}

	newpop := vfs.PathOperation{
		Root:  newParent.upperVD,
		Start: newParent.upperVD,
		Path:  fspath.Parse(newName),
	}

	needRecreateWhiteouts := false
	cleanupRecreateWhiteouts := func() {
		if !needRecreateWhiteouts {
			return
		}
		for whiteoutName, whiteoutUpper := range whiteouts {
			if !whiteoutUpper {
				continue
			}
			if err := fs.createWhiteout(ctx, vfsObj, &vfs.PathOperation{
				Root:  replaced.upperVD,
				Start: replaced.upperVD,
				Path:  fspath.Parse(whiteoutName),
			}); err != nil && err != syserror.EEXIST {
				panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to recreate deleted whiteout after RenameAt failure: %v", err))
			}
		}
	}
	if renamed.isDir() {
		if replacedLayer == lookupLayerUpper {
			// Remove whiteouts from the directory being replaced.
			needRecreateWhiteouts = true
			for whiteoutName, whiteoutUpper := range whiteouts {
				if !whiteoutUpper {
					continue
				}
				if err := vfsObj.UnlinkAt(ctx, fs.creds, &vfs.PathOperation{
					Root:  replaced.upperVD,
					Start: replaced.upperVD,
					Path:  fspath.Parse(whiteoutName),
				}); err != nil {
					cleanupRecreateWhiteouts()
					vfsObj.AbortRenameDentry(&renamed.vfsd, replacedVFSD)
					return err
				}
			}
		} else if replacedLayer == lookupLayerUpperWhiteout {
			// We need to explicitly remove the whiteout since otherwise rename
			// on the upper layer will fail with ENOTDIR.
			if err := vfsObj.UnlinkAt(ctx, fs.creds, &newpop); err != nil {
				vfsObj.AbortRenameDentry(&renamed.vfsd, replacedVFSD)
				return err
			}
		}
	}

	// Essentially no gVisor filesystem supports RENAME_WHITEOUT, so just do a
	// regular rename and create the whiteout at the origin manually. Unlike
	// RENAME_WHITEOUT, this isn't atomic with respect to other users of the
	// upper filesystem, but this is already the case for virtually all other
	// overlay filesystem operations too.
	oldpop := vfs.PathOperation{
		Root:  oldParent.upperVD,
		Start: oldParent.upperVD,
		Path:  fspath.Parse(oldName),
	}
	if err := vfsObj.RenameAt(ctx, creds, &oldpop, &newpop, &opts); err != nil {
		cleanupRecreateWhiteouts()
		vfsObj.AbortRenameDentry(&renamed.vfsd, replacedVFSD)
		return err
	}

	// Below this point, the renamed dentry is now at newpop, and anything we
	// replaced is gone forever. Commit the rename, update the overlay
	// filesystem tree, and abandon attempts to recover from errors.
	vfsObj.CommitRenameReplaceDentry(ctx, &renamed.vfsd, replacedVFSD)
	delete(oldParent.children, oldName)
	if replaced != nil {
		ds = appendDentry(ds, replaced)
	}
	if oldParent != newParent {
		newParent.dirents = nil
		// This can't drop the last reference on oldParent because one is held
		// by oldParentVD, so lock recursion is impossible.
		oldParent.DecRef(ctx)
		ds = appendDentry(ds, oldParent)
		newParent.IncRef()
		renamed.parent = newParent
	}
	renamed.name = newName
	if newParent.children == nil {
		newParent.children = make(map[string]*dentry)
	}
	newParent.children[newName] = renamed
	oldParent.dirents = nil

	if err := fs.createWhiteout(ctx, vfsObj, &oldpop); err != nil {
		panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to create whiteout at origin after RenameAt: %v", err))
	}
	if renamed.isDir() {
		if err := vfsObj.SetXattrAt(ctx, fs.creds, &newpop, &vfs.SetXattrOptions{
			Name:  _OVL_XATTR_OPAQUE,
			Value: "y",
		}); err != nil {
			panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to make renamed directory opaque: %v", err))
		}
	}

	vfs.InotifyRename(ctx, &renamed.watches, &oldParent.watches, &newParent.watches, oldName, newName, renamed.isDir())
	return nil
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
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
	if name == "." {
		return syserror.EINVAL
	}
	if name == ".." {
		return syserror.ENOTEMPTY
	}
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	parent.dirMu.Lock()
	defer parent.dirMu.Unlock()

	// Ensure that parent is copied-up before potentially holding child.copyMu
	// below.
	if err := parent.copyUpLocked(ctx); err != nil {
		return err
	}

	// Unlike UnlinkAt, we need a dentry representing the child directory being
	// removed in order to verify that it's empty.
	child, _, err := fs.getChildLocked(ctx, parent, name, &ds)
	if err != nil {
		return err
	}
	if !child.isDir() {
		return syserror.ENOTDIR
	}
	if err := parent.mayDelete(rp.Credentials(), child); err != nil {
		return err
	}
	child.dirMu.Lock()
	defer child.dirMu.Unlock()
	whiteouts, err := child.collectWhiteoutsForRmdirLocked(ctx)
	if err != nil {
		return err
	}
	child.copyMu.RLock()
	defer child.copyMu.RUnlock()
	if err := vfsObj.PrepareDeleteDentry(mntns, &child.vfsd); err != nil {
		return err
	}

	pop := vfs.PathOperation{
		Root:  parent.upperVD,
		Start: parent.upperVD,
		Path:  fspath.Parse(name),
	}
	if child.upperVD.Ok() {
		cleanupRecreateWhiteouts := func() {
			if !child.upperVD.Ok() {
				return
			}
			for whiteoutName, whiteoutUpper := range whiteouts {
				if !whiteoutUpper {
					continue
				}
				if err := fs.createWhiteout(ctx, vfsObj, &vfs.PathOperation{
					Root:  child.upperVD,
					Start: child.upperVD,
					Path:  fspath.Parse(whiteoutName),
				}); err != nil && err != syserror.EEXIST {
					panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to recreate deleted whiteout after RmdirAt failure: %v", err))
				}
			}
		}
		// Remove existing whiteouts on the upper layer.
		for whiteoutName, whiteoutUpper := range whiteouts {
			if !whiteoutUpper {
				continue
			}
			if err := vfsObj.UnlinkAt(ctx, fs.creds, &vfs.PathOperation{
				Root:  child.upperVD,
				Start: child.upperVD,
				Path:  fspath.Parse(whiteoutName),
			}); err != nil {
				cleanupRecreateWhiteouts()
				vfsObj.AbortDeleteDentry(&child.vfsd)
				return err
			}
		}
		// Remove the existing directory on the upper layer.
		if err := vfsObj.RmdirAt(ctx, fs.creds, &pop); err != nil {
			cleanupRecreateWhiteouts()
			vfsObj.AbortDeleteDentry(&child.vfsd)
			return err
		}
	}
	if err := fs.createWhiteout(ctx, vfsObj, &pop); err != nil {
		// Don't attempt to recover from this: the original directory is
		// already gone, so any dentries representing it are invalid, and
		// creating a new directory won't undo that.
		panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to create whiteout during RmdirAt: %v", err))
	}

	vfsObj.CommitDeleteDentry(ctx, &child.vfsd)
	delete(parent.children, name)
	ds = appendDentry(ds, child)
	parent.dirents = nil
	parent.watches.Notify(ctx, name, linux.IN_DELETE|linux.IN_ISDIR, 0 /* cookie */, vfs.InodeEvent, true /* unlinked */)
	return nil
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
		return err
	}
	err = d.setStatLocked(ctx, rp, opts)
	fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	if err != nil {
		return err
	}

	if ev := vfs.InotifyEventFromStatMask(opts.Stat.Mask); ev != 0 {
		d.InotifyWithParent(ctx, ev, 0 /* cookie */, vfs.InodeEvent)
	}
	return nil
}

// Precondition: d.fs.renameMu must be held for reading.
func (d *dentry) setStatLocked(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	mode := linux.FileMode(atomic.LoadUint32(&d.mode))
	if err := vfs.CheckSetStat(ctx, rp.Credentials(), &opts, mode, auth.KUID(atomic.LoadUint32(&d.uid)), auth.KGID(atomic.LoadUint32(&d.gid))); err != nil {
		return err
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	if err := d.copyUpLocked(ctx); err != nil {
		return err
	}
	// Changes to d's attributes are serialized by d.copyMu.
	d.copyMu.Lock()
	defer d.copyMu.Unlock()
	if err := d.fs.vfsfs.VirtualFilesystem().SetStatAt(ctx, d.fs.creds, &vfs.PathOperation{
		Root:  d.upperVD,
		Start: d.upperVD,
	}, &opts); err != nil {
		return err
	}
	d.updateAfterSetStatLocked(&opts)
	return nil
}

// StatAt implements vfs.FilesystemImpl.StatAt.
func (fs *filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return linux.Statx{}, err
	}

	var stat linux.Statx
	if layerMask := opts.Mask &^ statInternalMask; layerMask != 0 {
		layerVD := d.topLayer()
		stat, err = fs.vfsfs.VirtualFilesystem().StatAt(ctx, fs.creds, &vfs.PathOperation{
			Root:  layerVD,
			Start: layerVD,
		}, &vfs.StatOptions{
			Mask: layerMask,
			Sync: opts.Sync,
		})
		if err != nil {
			return linux.Statx{}, err
		}
	}
	d.statInternalTo(ctx, &opts, &stat)
	return stat, nil
}

// StatFSAt implements vfs.FilesystemImpl.StatFSAt.
func (fs *filesystem) StatFSAt(ctx context.Context, rp *vfs.ResolvingPath) (linux.Statfs, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	_, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return linux.Statfs{}, err
	}
	return fs.statFS(ctx)
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt.
func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	return fs.doCreateAt(ctx, rp, false /* dir */, func(parent *dentry, childName string, haveUpperWhiteout bool) error {
		vfsObj := fs.vfsfs.VirtualFilesystem()
		pop := vfs.PathOperation{
			Root:  parent.upperVD,
			Start: parent.upperVD,
			Path:  fspath.Parse(childName),
		}
		if haveUpperWhiteout {
			if err := vfsObj.UnlinkAt(ctx, fs.creds, &pop); err != nil {
				return err
			}
		}
		if err := vfsObj.SymlinkAt(ctx, fs.creds, &pop, target); err != nil {
			if haveUpperWhiteout {
				fs.cleanupRecreateWhiteout(ctx, vfsObj, &pop)
			}
			return err
		}
		creds := rp.Credentials()
		if err := vfsObj.SetStatAt(ctx, fs.creds, &pop, &vfs.SetStatOptions{
			Stat: linux.Statx{
				Mask: linux.STATX_UID | linux.STATX_GID,
				UID:  uint32(creds.EffectiveKUID),
				GID:  uint32(creds.EffectiveKGID),
			},
		}); err != nil {
			if cleanupErr := vfsObj.UnlinkAt(ctx, fs.creds, &pop); cleanupErr != nil {
				panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to delete upper layer file after SymlinkAt metadata update failure: %v", cleanupErr))
			} else if haveUpperWhiteout {
				fs.cleanupRecreateWhiteout(ctx, vfsObj, &pop)
			}
			return err
		}
		return nil
	})
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
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
	if name == "." || name == ".." {
		return syserror.EISDIR
	}
	if rp.MustBeDir() {
		return syserror.ENOTDIR
	}
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	parent.dirMu.Lock()
	defer parent.dirMu.Unlock()

	// Ensure that parent is copied-up before potentially holding child.copyMu
	// below.
	if err := parent.copyUpLocked(ctx); err != nil {
		return err
	}

	parentMode := atomic.LoadUint32(&parent.mode)
	child := parent.children[name]
	var childLayer lookupLayer
	if child == nil {
		if parentMode&linux.S_ISVTX != 0 {
			// If the parent's sticky bit is set, we need a child dentry to get
			// its owner.
			child, _, err = fs.getChildLocked(ctx, parent, name, &ds)
			if err != nil {
				return err
			}
		} else {
			// Determine if the file being unlinked actually exists. Holding
			// parent.dirMu prevents a dentry from being instantiated for the file,
			// which in turn prevents it from being copied-up, so this result is
			// stable.
			childLayer, err = fs.lookupLayerLocked(ctx, parent, name)
			if err != nil {
				return err
			}
			if !childLayer.existsInOverlay() {
				return syserror.ENOENT
			}
		}
	}
	if child != nil {
		if child.isDir() {
			return syserror.EISDIR
		}
		if err := parent.mayDelete(rp.Credentials(), child); err != nil {
			return err
		}
		if err := vfsObj.PrepareDeleteDentry(mntns, &child.vfsd); err != nil {
			return err
		}
		// Hold child.copyMu to prevent it from being copied-up during
		// deletion.
		child.copyMu.RLock()
		defer child.copyMu.RUnlock()
		if child.upperVD.Ok() {
			childLayer = lookupLayerUpper
		} else {
			childLayer = lookupLayerLower
		}
	}

	pop := vfs.PathOperation{
		Root:  parent.upperVD,
		Start: parent.upperVD,
		Path:  fspath.Parse(name),
	}
	if childLayer == lookupLayerUpper {
		// Remove the existing file on the upper layer.
		if err := vfsObj.UnlinkAt(ctx, fs.creds, &pop); err != nil {
			if child != nil {
				vfsObj.AbortDeleteDentry(&child.vfsd)
			}
			return err
		}
	}
	if err := fs.createWhiteout(ctx, vfsObj, &pop); err != nil {
		panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to create whiteout during UnlinkAt: %v", err))
	}

	var cw *vfs.Watches
	if child != nil {
		vfsObj.CommitDeleteDentry(ctx, &child.vfsd)
		delete(parent.children, name)
		ds = appendDentry(ds, child)
		cw = &child.watches
	}
	vfs.InotifyRemoveChild(ctx, cw, &parent.watches, name)
	parent.dirents = nil
	return nil
}

// isOverlayXattr returns whether the given extended attribute configures the
// overlay.
func isOverlayXattr(name string) bool {
	return strings.HasPrefix(name, _OVL_XATTR_PREFIX)
}

// ListXattrAt implements vfs.FilesystemImpl.ListXattrAt.
func (fs *filesystem) ListXattrAt(ctx context.Context, rp *vfs.ResolvingPath, size uint64) ([]string, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return nil, err
	}

	return fs.listXattr(ctx, d, size)
}

func (fs *filesystem) listXattr(ctx context.Context, d *dentry, size uint64) ([]string, error) {
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	top := d.topLayer()
	names, err := vfsObj.ListXattrAt(ctx, fs.creds, &vfs.PathOperation{Root: top, Start: top}, size)
	if err != nil {
		return nil, err
	}

	// Filter out all overlay attributes.
	n := 0
	for _, name := range names {
		if !isOverlayXattr(name) {
			names[n] = name
			n++
		}
	}
	return names[:n], err
}

// GetXattrAt implements vfs.FilesystemImpl.GetXattrAt.
func (fs *filesystem) GetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetXattrOptions) (string, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return "", err
	}

	return fs.getXattr(ctx, d, rp.Credentials(), &opts)
}

func (fs *filesystem) getXattr(ctx context.Context, d *dentry, creds *auth.Credentials, opts *vfs.GetXattrOptions) (string, error) {
	if err := d.checkXattrPermissions(creds, opts.Name, vfs.MayRead); err != nil {
		return "", err
	}

	// Return EOPNOTSUPP when fetching an overlay attribute.
	// See fs/overlayfs/super.c:ovl_own_xattr_get().
	if isOverlayXattr(opts.Name) {
		return "", syserror.EOPNOTSUPP
	}

	// Analogous to fs/overlayfs/super.c:ovl_other_xattr_get().
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	top := d.topLayer()
	return vfsObj.GetXattrAt(ctx, fs.creds, &vfs.PathOperation{Root: top, Start: top}, opts)
}

// SetXattrAt implements vfs.FilesystemImpl.SetXattrAt.
func (fs *filesystem) SetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetXattrOptions) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
		return err
	}

	err = fs.setXattrLocked(ctx, d, rp.Mount(), rp.Credentials(), &opts)
	fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	if err != nil {
		return err
	}

	d.InotifyWithParent(ctx, linux.IN_ATTRIB, 0 /* cookie */, vfs.InodeEvent)
	return nil
}

// Precondition: fs.renameMu must be locked.
func (fs *filesystem) setXattrLocked(ctx context.Context, d *dentry, mnt *vfs.Mount, creds *auth.Credentials, opts *vfs.SetXattrOptions) error {
	if err := d.checkXattrPermissions(creds, opts.Name, vfs.MayWrite); err != nil {
		return err
	}

	// Return EOPNOTSUPP when setting an overlay attribute.
	// See fs/overlayfs/super.c:ovl_own_xattr_set().
	if isOverlayXattr(opts.Name) {
		return syserror.EOPNOTSUPP
	}

	// Analogous to fs/overlayfs/super.c:ovl_other_xattr_set().
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	if err := d.copyUpLocked(ctx); err != nil {
		return err
	}
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	return vfsObj.SetXattrAt(ctx, fs.creds, &vfs.PathOperation{Root: d.upperVD, Start: d.upperVD}, opts)
}

// RemoveXattrAt implements vfs.FilesystemImpl.RemoveXattrAt.
func (fs *filesystem) RemoveXattrAt(ctx context.Context, rp *vfs.ResolvingPath, name string) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
		return err
	}

	err = fs.removeXattrLocked(ctx, d, rp.Mount(), rp.Credentials(), name)
	fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	if err != nil {
		return err
	}

	d.InotifyWithParent(ctx, linux.IN_ATTRIB, 0 /* cookie */, vfs.InodeEvent)
	return nil
}

// Precondition: fs.renameMu must be locked.
func (fs *filesystem) removeXattrLocked(ctx context.Context, d *dentry, mnt *vfs.Mount, creds *auth.Credentials, name string) error {
	if err := d.checkXattrPermissions(creds, name, vfs.MayWrite); err != nil {
		return err
	}

	// Like SetXattrAt, return EOPNOTSUPP when removing an overlay attribute.
	// Linux passes the remove request to xattr_handler->set.
	// See fs/xattr.c:vfs_removexattr().
	if isOverlayXattr(name) {
		return syserror.EOPNOTSUPP
	}

	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	if err := d.copyUpLocked(ctx); err != nil {
		return err
	}
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	return vfsObj.RemoveXattrAt(ctx, fs.creds, &vfs.PathOperation{Root: d.upperVD, Start: d.upperVD}, name)
}

// PrependPath implements vfs.FilesystemImpl.PrependPath.
func (fs *filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	fs.renameMu.RLock()
	defer fs.renameMu.RUnlock()
	return genericPrependPath(vfsroot, vd.Mount(), vd.Dentry().Impl().(*dentry), b)
}
