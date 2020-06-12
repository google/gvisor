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
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// _OVL_XATTR_OPAQUE is an extended attribute key whose value is set to "y" for
// opaque directories.
// Linux: fs/overlayfs/overlayfs.h:OVL_XATTR_OPAQUE
const _OVL_XATTR_OPAQUE = "trusted.overlay.opaque"

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
// dentry.checkDropLocked on all dentries in *ds with fs.renameMu locked for
// writing.
//
// ds is a pointer-to-pointer since defer evaluates its arguments immediately,
// but dentry slices are allocated lazily, and it's much easier to say "defer
// fs.renameMuRUnlockAndCheckDrop(&ds)" than "defer func() {
// fs.renameMuRUnlockAndCheckDrop(ds) }()" to work around this.
func (fs *filesystem) renameMuRUnlockAndCheckDrop(ds **[]*dentry) {
	fs.renameMu.RUnlock()
	if *ds == nil {
		return
	}
	if len(**ds) != 0 {
		fs.renameMu.Lock()
		for _, d := range **ds {
			d.checkDropLocked()
		}
		fs.renameMu.Unlock()
	}
	putDentrySlice(*ds)
}

func (fs *filesystem) renameMuUnlockAndCheckDrop(ds **[]*dentry) {
	if *ds == nil {
		fs.renameMu.Unlock()
		return
	}
	for _, d := range **ds {
		d.checkDropLocked()
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
// Preconditions: fs.renameMu must be locked. d.dirMu must be locked.
// !rp.Done().
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
		if err := rp.CheckMount(&d.parent.vfsd); err != nil {
			return nil, err
		}
		rp.Advance()
		return d.parent, nil
	}
	child, err := fs.getChildLocked(ctx, d, name, ds)
	if err != nil {
		return nil, err
	}
	if err := rp.CheckMount(&child.vfsd); err != nil {
		return nil, err
	}
	if child.isSymlink() && mayFollowSymlinks && rp.ShouldFollowSymlink() {
		target, err := child.readlink(ctx)
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

// Preconditions: fs.renameMu must be locked. d.dirMu must be locked.
func (fs *filesystem) getChildLocked(ctx context.Context, parent *dentry, name string, ds **[]*dentry) (*dentry, error) {
	if child, ok := parent.children[name]; ok {
		return child, nil
	}
	child, err := fs.lookupLocked(ctx, parent, name)
	if err != nil {
		return nil, err
	}
	if parent.children == nil {
		parent.children = make(map[string]*dentry)
	}
	parent.children[name] = child
	// child's refcount is initially 0, so it may be dropped after traversal.
	*ds = appendDentry(*ds, child)
	return child, nil
}

// Preconditions: fs.renameMu must be locked. parent.dirMu must be locked.
func (fs *filesystem) lookupLocked(ctx context.Context, parent *dentry, name string) (*dentry, error) {
	childPath := fspath.Parse(name)
	child := fs.newDentry()
	existsOnAnyLayer := false
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

		mask := uint32(linux.STATX_TYPE)
		if !existsOnAnyLayer {
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
			return false
		}
		isDir := stat.Mode&linux.S_IFMT == linux.S_IFDIR
		if existsOnAnyLayer && !isDir {
			// Directories are not merged with non-directory files from lower
			// layers; instead, layers including and below the first
			// non-directory file are ignored. (This file must be a directory
			// on previous layers, since lower layers aren't searched for
			// non-directory files.)
			return false
		}

		// Update child to include this layer.
		if isUpper {
			child.upperVD = childVD
			child.copiedUp = 1
		} else {
			child.lowerVDs = append(child.lowerVDs, childVD)
		}
		if !existsOnAnyLayer {
			existsOnAnyLayer = true
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
		opaqueVal, err := vfsObj.GetxattrAt(ctx, fs.creds, &vfs.PathOperation{
			Root:  childVD,
			Start: childVD,
		}, &vfs.GetxattrOptions{
			Name: _OVL_XATTR_OPAQUE,
			Size: 1,
		})
		return !(err == nil && opaqueVal == "y")
	})

	if lookupErr != nil {
		child.destroyLocked()
		return nil, lookupErr
	}
	if !existsOnAnyLayer {
		child.destroyLocked()
		return nil, syserror.ENOENT
	}

	// Device and inode numbers were copied from the topmost layer above;
	// override them if necessary.
	if child.isDir() {
		child.devMajor = linux.UNNAMED_MAJOR
		child.devMinor = fs.dirDevMinor
		child.ino = fs.newDirIno()
	} else if !child.upperVD.Ok() {
		child.devMajor = linux.UNNAMED_MAJOR
		child.devMinor = fs.lowerDevMinors[child.lowerVDs[0].Mount().Filesystem()]
	}

	parent.IncRef()
	child.parent = parent
	child.name = name
	return child, nil
}

// lookupLayerLocked is similar to lookupLocked, but only returns information
// about the file rather than a dentry.
//
// Preconditions: fs.renameMu must be locked. parent.dirMu must be locked.
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
// Preconditions: fs.renameMu must be locked. !rp.Done().
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
// create to do so.
//
// Preconditions: !rp.Done(). For the final path component in rp,
// !rp.ShouldFollowSymlink().
func (fs *filesystem) doCreateAt(ctx context.Context, rp *vfs.ResolvingPath, dir bool, create func(parent *dentry, name string, haveUpperWhiteout bool) error) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(&ds)
	start := rp.Start().Impl().(*dentry)
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
	if !dir && rp.MustBeDir() {
		return syserror.ENOENT
	}
	if parent.vfsd.IsDead() {
		return syserror.ENOENT
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
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
		ctx.Warningf("Unrecoverable overlayfs inconsistency: failed to recreate whiteout after failed file creation: %v", err)
	}
}

// AccessAt implements vfs.Filesystem.Impl.AccessAt.
func (fs *filesystem) AccessAt(ctx context.Context, rp *vfs.ResolvingPath, creds *auth.Credentials, ats vfs.AccessTypes) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(&ds)
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
	defer fs.renameMuRUnlockAndCheckDrop(&ds)
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
	defer fs.renameMuRUnlockAndCheckDrop(&ds)
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
	defer fs.renameMuRUnlockAndCheckDrop(&ds)
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
				ctx.Warningf("Unrecoverable overlayfs inconsistency: failed to delete upper layer file after LinkAt metadata update failure: %v", cleanupErr)
			} else if haveUpperWhiteout {
				fs.cleanupRecreateWhiteout(ctx, vfsObj, &newpop)
			}
			return err
		}
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
				ctx.Warningf("Unrecoverable overlayfs inconsistency: failed to delete upper layer directory after MkdirAt metadata update failure: %v", cleanupErr)
			} else if haveUpperWhiteout {
				fs.cleanupRecreateWhiteout(ctx, vfsObj, &pop)
			}
			return err
		}
		if haveUpperWhiteout {
			// There may be directories on lower layers (previously hidden by
			// the whiteout) that the new directory should not be merged with.
			// Mark it opaque to prevent merging.
			if err := vfsObj.SetxattrAt(ctx, fs.creds, &pop, &vfs.SetxattrOptions{
				Name:  _OVL_XATTR_OPAQUE,
				Value: "y",
			}); err != nil {
				if cleanupErr := vfsObj.RmdirAt(ctx, fs.creds, &pop); cleanupErr != nil {
					ctx.Warningf("Unrecoverable overlayfs inconsistency: failed to delete upper layer directory after MkdirAt set-opaque failure: %v", cleanupErr)
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
				ctx.Warningf("Unrecoverable overlayfs inconsistency: failed to delete upper layer file after MknodAt metadata update failure: %v", cleanupErr)
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

	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(&ds)

	start := rp.Start().Impl().(*dentry)
	if rp.Done() {
		if mustCreate {
			return nil, syserror.EEXIST
		}
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
		fd, err := fs.createAndOpenLocked(ctx, rp, parent, &opts, &ds)
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
	return child.openLocked(ctx, rp, &opts)
}

// Preconditions: fs.renameMu must be locked.
func (d *dentry) openLocked(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	ats := vfs.AccessTypesForOpenFlags(opts)
	if err := d.checkPermissions(rp.Credentials(), ats); err != nil {
		return nil, err
	}
	if ats.MayWrite() {
		if err := d.copyUpLocked(ctx); err != nil {
			return nil, err
		}
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
		if ats&vfs.MayWrite != 0 {
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
	layerFlags := layerFD.StatusFlags()
	fd := &nonDirectoryFD{
		copiedUp:    isUpper,
		cachedFD:    layerFD,
		cachedFlags: layerFlags,
	}
	fd.LockFD.Init(&d.locks)
	layerFDOpts := layerFD.Options()
	if err := fd.vfsfd.Init(fd, layerFlags, mnt, &d.vfsd, &layerFDOpts); err != nil {
		layerFD.DecRef()
		return nil, err
	}
	return &fd.vfsfd, nil
}

// Preconditions: parent.dirMu must be locked. parent does not already contain
// a child named rp.Component().
func (fs *filesystem) createAndOpenLocked(ctx context.Context, rp *vfs.ResolvingPath, parent *dentry, opts *vfs.OpenOptions, ds **[]*dentry) (*vfs.FileDescription, error) {
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
	// We don't know if a whiteout exists on the upper layer; speculatively
	// unlink it.
	//
	// TODO(gvisor.dev/issue/1199): Modify OpenAt => stepLocked so that we do
	// know whether a whiteout exists.
	var haveUpperWhiteout bool
	switch err := vfsObj.UnlinkAt(ctx, fs.creds, &pop); err {
	case nil:
		haveUpperWhiteout = true
	case syserror.ENOENT:
		haveUpperWhiteout = false
	default:
		return nil, err
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
			ctx.Warningf("Unrecoverable overlayfs inconsistency: failed to delete upper layer file after OpenAt(O_CREAT) metadata update failure: %v", cleanupErr)
		} else if haveUpperWhiteout {
			fs.cleanupRecreateWhiteout(ctx, vfsObj, &pop)
		}
		return nil, err
	}
	// Re-lookup to get a dentry representing the new file, which is needed for
	// the returned FD.
	child, err := fs.getChildLocked(ctx, parent, childName, ds)
	if err != nil {
		if cleanupErr := vfsObj.UnlinkAt(ctx, fs.creds, &pop); cleanupErr != nil {
			ctx.Warningf("Unrecoverable overlayfs inconsistency: failed to delete upper layer file after OpenAt(O_CREAT) dentry lookup failure: %v", cleanupErr)
		} else if haveUpperWhiteout {
			fs.cleanupRecreateWhiteout(ctx, vfsObj, &pop)
		}
		return nil, err
	}
	// Finally construct the overlay FD.
	upperFlags := upperFD.StatusFlags()
	fd := &nonDirectoryFD{
		copiedUp:    true,
		cachedFD:    upperFD,
		cachedFlags: upperFlags,
	}
	fd.LockFD.Init(&child.locks)
	upperFDOpts := upperFD.Options()
	if err := fd.vfsfd.Init(fd, upperFlags, mnt, &child.vfsd, &upperFDOpts); err != nil {
		upperFD.DecRef()
		// Don't bother with cleanup; the file was created successfully, we
		// just can't open it anymore for some reason.
		return nil, err
	}
	return &fd.vfsfd, nil
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(&ds)
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
	defer fs.renameMuUnlockAndCheckDrop(&ds)
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

	// FIXME(gvisor.dev/issue/1199): Actually implement rename.
	_ = newParent
	return syserror.EXDEV
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(&ds)
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
	defer mntns.DecRef()
	parent.dirMu.Lock()
	defer parent.dirMu.Unlock()

	// Ensure that parent is copied-up before potentially holding child.copyMu
	// below.
	if err := parent.copyUpLocked(ctx); err != nil {
		return err
	}

	// Unlike UnlinkAt, we need a dentry representing the child directory being
	// removed in order to verify that it's empty.
	child, err := fs.getChildLocked(ctx, parent, name, &ds)
	if err != nil {
		return err
	}
	if !child.isDir() {
		return syserror.ENOTDIR
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
					ctx.Warningf("Unrecoverable overlayfs inconsistency: failed to recreate deleted whiteout after RmdirAt failure: %v", err)
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
		ctx.Warningf("Unrecoverable overlayfs inconsistency: failed to create whiteout during RmdirAt: %v", err)
		vfsObj.AbortDeleteDentry(&child.vfsd)
		return err
	}

	vfsObj.CommitDeleteDentry(&child.vfsd)
	delete(parent.children, name)
	ds = appendDentry(ds, child)
	parent.dirents = nil
	return nil
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(&ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return err
	}

	mode := linux.FileMode(atomic.LoadUint32(&d.mode))
	if err := vfs.CheckSetStat(ctx, rp.Credentials(), &opts.Stat, mode, auth.KUID(atomic.LoadUint32(&d.uid)), auth.KGID(atomic.LoadUint32(&d.gid))); err != nil {
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
	defer fs.renameMuRUnlockAndCheckDrop(&ds)
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
	defer fs.renameMuRUnlockAndCheckDrop(&ds)
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
				ctx.Warningf("Unrecoverable overlayfs inconsistency: failed to delete upper layer file after SymlinkAt metadata update failure: %v", cleanupErr)
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
	defer fs.renameMuRUnlockAndCheckDrop(&ds)
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
	defer mntns.DecRef()
	parent.dirMu.Lock()
	defer parent.dirMu.Unlock()

	// Ensure that parent is copied-up before potentially holding child.copyMu
	// below.
	if err := parent.copyUpLocked(ctx); err != nil {
		return err
	}

	child := parent.children[name]
	var childLayer lookupLayer
	if child != nil {
		if child.isDir() {
			return syserror.EISDIR
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
		ctx.Warningf("Unrecoverable overlayfs inconsistency: failed to create whiteout during UnlinkAt: %v", err)
		if child != nil {
			vfsObj.AbortDeleteDentry(&child.vfsd)
		}
		return err
	}

	if child != nil {
		vfsObj.CommitDeleteDentry(&child.vfsd)
		delete(parent.children, name)
		ds = appendDentry(ds, child)
	}
	parent.dirents = nil
	return nil
}

// ListxattrAt implements vfs.FilesystemImpl.ListxattrAt.
func (fs *filesystem) ListxattrAt(ctx context.Context, rp *vfs.ResolvingPath, size uint64) ([]string, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(&ds)
	_, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return nil, err
	}
	// TODO(gvisor.dev/issue/1199): Linux overlayfs actually allows listxattr,
	// but not any other xattr syscalls. For now we just reject all of them.
	return nil, syserror.ENOTSUP
}

// GetxattrAt implements vfs.FilesystemImpl.GetxattrAt.
func (fs *filesystem) GetxattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetxattrOptions) (string, error) {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(&ds)
	_, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return "", err
	}
	return "", syserror.ENOTSUP
}

// SetxattrAt implements vfs.FilesystemImpl.SetxattrAt.
func (fs *filesystem) SetxattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetxattrOptions) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(&ds)
	_, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return err
	}
	return syserror.ENOTSUP
}

// RemovexattrAt implements vfs.FilesystemImpl.RemovexattrAt.
func (fs *filesystem) RemovexattrAt(ctx context.Context, rp *vfs.ResolvingPath, name string) error {
	var ds *[]*dentry
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndCheckDrop(&ds)
	_, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return err
	}
	return syserror.ENOTSUP
}

// PrependPath implements vfs.FilesystemImpl.PrependPath.
func (fs *filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	fs.renameMu.RLock()
	defer fs.renameMu.RUnlock()
	return genericPrependPath(vfsroot, vd.Mount(), vd.Dentry().Impl().(*dentry), b)
}
